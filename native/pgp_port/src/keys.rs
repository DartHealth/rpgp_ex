use crate::error::{Code, Failure};
use pgp::composed::{Deserializable, SignedPublicKey, SignedPublicSubKey, SignedSecretKey};
use pgp::packet::{PublicKey, SignatureType};
use pgp::types::{KeyDetails, Tag, Timestamp};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub struct InspectRequest {
    pub key: String,
}

pub fn key_id_hex(id: impl AsRef<[u8]>) -> String {
    hex::encode_upper(id)
}

/// Parses only; subkey bindings are verified per subkey in `usable_for_encryption`.
/// (Whole-cert `verify_bindings()` also checks every user-ID signature and so rejects
/// partner keys that carry third-party certifications.)
pub fn parse_public(armored: &str) -> Result<SignedPublicKey, Failure> {
    let (cert, _) = SignedPublicKey::from_reader_single(armored.as_bytes())
        .map_err(|e| Failure::new(Code::Malformed, format!("public key: {e}")))?;
    Ok(cert)
}

pub fn parse_secret(armored: &str) -> Result<SignedSecretKey, Failure> {
    let (key, _) = SignedSecretKey::from_reader_single(armored.as_bytes())
        .map_err(|e| Failure::new(Code::Malformed, format!("secret key: {e}")))?;
    Ok(key)
}

/// Whether any (sub)key of `key` named in `ids` is passphrase-protected.
pub fn matching_key_is_protected(key: &SignedSecretKey, ids: &[String]) -> bool {
    let primary = std::iter::once((key.primary_key.legacy_key_id(), key.primary_key.secret_params()));
    let subkeys = key
        .secret_subkeys
        .iter()
        .map(|sk| (sk.key.legacy_key_id(), sk.key.secret_params()));
    primary
        .chain(subkeys)
        .any(|(id, params)| ids.contains(&key_id_hex(id)) && params.is_encrypted())
}

/// Key IDs of the primary key and every secret subkey, as PKESK packets name them.
pub fn secret_key_ids(key: &SignedSecretKey) -> Vec<String> {
    std::iter::once(key_id_hex(key.primary_key.legacy_key_id()))
        .chain(key.secret_subkeys.iter().map(|sk| key_id_hex(sk.key.legacy_key_id())))
        .collect()
}

/// The key a PKESK is addressed to: an encryption subkey, or the primary key itself
/// (single-key certs, e.g. an RSA-4096 primary key flagged for encryption with no subkeys).
pub enum EncryptionKey<'a> {
    Subkey(&'a SignedPublicSubKey),
    Primary(&'a PublicKey),
}

impl EncryptionKey<'_> {
    pub fn key_id(&self) -> String {
        match self {
            Self::Subkey(sk) => key_id_hex(sk.key.legacy_key_id()),
            Self::Primary(pk) => key_id_hex(pk.legacy_key_id()),
        }
    }
}

/// Like GnuPG: the newest usable encryption subkey, else the primary key if usable.
pub fn encryption_key(cert: &SignedPublicKey) -> Result<EncryptionKey<'_>, Failure> {
    if let Ok(sk) = encryption_subkey(cert) {
        return Ok(EncryptionKey::Subkey(sk));
    }
    if primary_usable_for_encryption(cert, Timestamp::now().as_secs()) {
        return Ok(EncryptionKey::Primary(&cert.primary_key));
    }
    Err(Failure::new(Code::Unsupported, "no usable encryption key"))
}

/// The newest subkey whose binding (and any revocation) signatures verify against the
/// primary key, that is flagged for encryption, not revoked and not expired.
/// PoC limit: the primary key's own revocation/expiry is not checked on this path.
pub fn encryption_subkey(cert: &SignedPublicKey) -> Result<&SignedPublicSubKey, Failure> {
    let now = Timestamp::now().as_secs();
    cert.public_subkeys
        .iter()
        .filter(|sk| usable_for_encryption(&cert.primary_key, sk, now))
        .max_by_key(|sk| sk.key.created_at().as_secs())
        .ok_or_else(|| Failure::new(Code::Unsupported, "no usable encryption subkey"))
}

/// The primary key is usable if no key revocation verifies and its newest verifying
/// self-signature (user-ID certification or direct-key) flags it for encryption and
/// has not expired it. PoC limit: GnuPG prefers the primary user ID's self-signature;
/// this takes the newest across all user IDs.
fn primary_usable_for_encryption(cert: &SignedPublicKey, now: u32) -> bool {
    let primary = &cert.primary_key;
    if !primary.algorithm().can_encrypt() {
        return false;
    }
    if cert
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.verify_key(primary).is_ok())
    {
        return false;
    }
    let user_sigs = cert.details.users.iter().flat_map(|u| {
        u.signatures
            .iter()
            .filter(move |s| s.verify_certification(primary, Tag::UserId, &u.id).is_ok())
    });
    let direct_sigs = cert
        .details
        .direct_signatures
        .iter()
        .filter(|s| s.verify_key(primary).is_ok());
    let Some(sig) = user_sigs
        .chain(direct_sigs)
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
    else {
        return false;
    };
    let flags = sig.key_flags();
    if !(flags.encrypt_comms() || flags.encrypt_storage()) {
        return false;
    }
    match sig.key_expiration_time() {
        Some(d) if d.as_secs() > 0 => primary.created_at().as_secs().saturating_add(d.as_secs()) > now,
        _ => true,
    }
}

fn usable_for_encryption(primary: &PublicKey, sk: &SignedPublicSubKey, now: u32) -> bool {
    // Verifies every binding and revocation signature on the subkey, so a revocation
    // counted below is a genuine one (and a forged one makes the subkey unusable).
    if sk.verify_bindings(primary).is_err() {
        return false;
    }
    if sk
        .signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
    {
        return false;
    }
    let Some(binding) = sk
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
    else {
        return false;
    };
    let flags = binding.key_flags();
    if !(flags.encrypt_comms() || flags.encrypt_storage()) || !sk.key.algorithm().can_encrypt() {
        return false;
    }
    match binding.key_expiration_time() {
        Some(d) if d.as_secs() > 0 => sk.key.created_at().as_secs().saturating_add(d.as_secs()) > now,
        _ => true,
    }
}

pub fn inspect(req: &InspectRequest) -> Result<Value, Failure> {
    let cert = parse_public(&req.key)?;
    let now = Timestamp::now().as_secs();
    let subkeys: Vec<Value> = cert
        .public_subkeys
        .iter()
        .map(|sk| {
            json!({
                "key_id": key_id_hex(sk.key.legacy_key_id()),
                "fingerprint": format!("{:X}", sk.key.fingerprint()),
                "algorithm": format!("{:?}", sk.key.algorithm()),
                "created_at": sk.key.created_at().as_secs(),
                "usable_for_encryption": usable_for_encryption(&cert.primary_key, sk, now),
            })
        })
        .collect();
    let chosen = encryption_key(&cert).ok().map(|k| k.key_id());
    Ok(json!({
        "fingerprint": format!("{:X}", cert.primary_key.fingerprint()),
        "key_id": key_id_hex(cert.primary_key.legacy_key_id()),
        "algorithm": format!("{:?}", cert.primary_key.algorithm()),
        "subkeys": subkeys,
        // Kept under its old name; it is the primary key's ID when no subkey is usable.
        "encryption_subkey": chosen,
    }))
}
