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

/// What a key's self-signatures say about it, read without deciding whether it can be used.
struct Status {
    revoked: bool,
    /// Unix seconds; `None` if the key never expires.
    expires_at: Option<u32>,
    /// Flagged for encryption and of an encryption-capable algorithm.
    encrypts: bool,
    /// Its binding or self-signature verifies against the primary key.
    bound: bool,
}

impl Status {
    fn expired(&self, now: u32) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    fn usable(&self, now: u32) -> bool {
        self.bound && self.encrypts && !self.revoked && !self.expired(now)
    }
}

fn expiry(created: u32, sig: &pgp::packet::Signature) -> Option<u32> {
    match sig.key_expiration_time() {
        Some(d) if d.as_secs() > 0 => Some(created.saturating_add(d.as_secs())),
        _ => None,
    }
}

fn encryption_flags(sig: &pgp::packet::Signature) -> bool {
    let flags = sig.key_flags();
    flags.encrypt_comms() || flags.encrypt_storage()
}

/// The primary key's status from its newest verifying self-signature (user-ID certification or
/// direct-key) and any verifying key revocation. Limit: GnuPG prefers the primary user ID's
/// self-signature; this takes the newest across all user IDs.
fn primary_status(cert: &SignedPublicKey) -> Status {
    let primary = &cert.primary_key;
    let revoked = cert
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.verify_key(primary).is_ok());
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
    let newest = user_sigs
        .chain(direct_sigs)
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0));
    match newest {
        Some(sig) => Status {
            revoked,
            expires_at: expiry(primary.created_at().as_secs(), sig),
            encrypts: encryption_flags(sig) && primary.algorithm().can_encrypt(),
            bound: true,
        },
        None => Status {
            revoked,
            expires_at: None,
            encrypts: false,
            bound: false,
        },
    }
}

/// A subkey's status from its newest binding signature. `verify_bindings` checks every binding
/// and revocation signature on the subkey, so a revocation counted here is genuine, and a forged
/// signature leaves the subkey unbound (unusable).
fn subkey_status(primary: &PublicKey, sk: &SignedPublicSubKey) -> Status {
    let bound = sk.verify_bindings(primary).is_ok();
    let revoked = bound
        && sk
            .signatures
            .iter()
            .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation));
    let binding = sk
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0));
    match binding {
        Some(sig) if bound => Status {
            revoked,
            expires_at: expiry(sk.key.created_at().as_secs(), sig),
            encrypts: encryption_flags(sig) && sk.key.algorithm().can_encrypt(),
            bound,
        },
        _ => Status {
            revoked,
            expires_at: None,
            encrypts: false,
            bound: false,
        },
    }
}

/// Like GnuPG: the newest usable encryption subkey, else the primary key if it is usable for
/// encryption itself. A revoked or expired primary key makes the whole certificate unusable.
pub fn encryption_key(cert: &SignedPublicKey) -> Result<EncryptionKey<'_>, Failure> {
    let now = Timestamp::now().as_secs();
    let primary = primary_status(cert);
    if primary.revoked {
        return Err(Failure::new(Code::KeyRevoked, "the primary key is revoked"));
    }
    if primary.expired(now) {
        return Err(Failure::new(Code::KeyExpired, "the primary key has expired"));
    }
    let subkeys: Vec<(&SignedPublicSubKey, Status)> = cert
        .public_subkeys
        .iter()
        .map(|sk| (sk, subkey_status(&cert.primary_key, sk)))
        .collect();
    if let Some((sk, _)) = subkeys
        .iter()
        .filter(|(_, st)| st.usable(now))
        .max_by_key(|(sk, _)| sk.key.created_at().as_secs())
    {
        return Ok(EncryptionKey::Subkey(sk));
    }
    if primary.usable(now) {
        return Ok(EncryptionKey::Primary(&cert.primary_key));
    }
    // Nothing usable: report why, looking only at keys that could otherwise have encrypted.
    let candidates: Vec<&Status> = subkeys
        .iter()
        .map(|(_, st)| st)
        .chain(std::iter::once(&primary))
        .filter(|st| st.bound && st.encrypts)
        .collect();
    if candidates.iter().any(|st| st.expired(now)) {
        Err(Failure::new(
            Code::KeyExpired,
            "every encryption key has expired or is revoked",
        ))
    } else if candidates.iter().any(|st| st.revoked) {
        Err(Failure::new(Code::KeyRevoked, "every encryption key is revoked"))
    } else {
        Err(Failure::new(
            Code::NoEncryptionKey,
            "the key has no encryption-capable (sub)key",
        ))
    }
}

pub fn inspect(req: &InspectRequest) -> Result<Value, Failure> {
    let cert = parse_public(&req.key)?;
    let now = Timestamp::now().as_secs();
    let primary = primary_status(&cert);
    let subkeys: Vec<Value> = cert
        .public_subkeys
        .iter()
        .map(|sk| {
            let st = subkey_status(&cert.primary_key, sk);
            json!({
                "key_id": key_id_hex(sk.key.legacy_key_id()),
                "fingerprint": format!("{:X}", sk.key.fingerprint()),
                "algorithm": format!("{:?}", sk.key.algorithm()),
                "created_at": sk.key.created_at().as_secs(),
                "expires_at": st.expires_at,
                "revoked": st.revoked,
                "can_encrypt": st.usable(now),
            })
        })
        .collect();
    let chosen = encryption_key(&cert).ok().map(|k| k.key_id());
    Ok(json!({
        "fingerprint": format!("{:X}", cert.primary_key.fingerprint()),
        "key_id": key_id_hex(cert.primary_key.legacy_key_id()),
        "algorithm": format!("{:?}", cert.primary_key.algorithm()),
        "created_at": cert.primary_key.created_at().as_secs(),
        "expires_at": primary.expires_at,
        "revoked": primary.revoked,
        "can_encrypt": chosen.is_some(),
        // The primary key's own ID when it is the key a message would be encrypted to.
        "encryption_key_id": chosen,
        "subkeys": subkeys,
    }))
}
