use crate::error::{self, Code, Failure};
use crate::keys;
use crate::watchdog;
use pgp::composed::{ArmorOptions, DecryptionOptions, Esk, Message, MessageBuilder, SignedSecretKey, TheRing};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::errors::Error as PgpError;
use pgp::types::{KeyDetails, Password, Seipdv1ReadMode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Capacity of the input `BufReader`s, the decrypt copy-loop buffer and the output `BufWriter`
/// (N3: with hardware AES, 1 MiB for all three took decrypt from ~350 to ~610 MB/s; 3 MiB per
/// concurrent op). `recipients` keeps std's default: it reads only the message headers.
const IO_BUF: usize = 1 << 20;
/// std's `BufReader::new` capacity.
const DEFAULT_BUF: usize = 8 * 1024;

fn open_message(input: &Path, capacity: usize) -> Result<Message<'static>, Failure> {
    let file = File::open(input)?;
    let source = BufReader::with_capacity(capacity, file);
    // Past a successful open, a failure is the message's shape (e.g. truncated headers), not the disk.
    let (msg, _headers) = Message::from_reader(source).map_err(error::classify_read)?;
    Ok(msg)
}

fn recipient_ids(msg: &Message<'_>) -> Result<Vec<String>, Failure> {
    let Message::Encrypted { esk, .. } = msg else {
        return Err(Failure::new(Code::Malformed, "not an encrypted OpenPGP message"));
    };
    esk.iter()
        .filter_map(|e| match e {
            Esk::PublicKeyEncryptedSessionKey(pkesk) => Some(pkesk),
            Esk::SymKeyEncryptedSessionKey(_) => None,
        })
        .map(|pkesk| pkesk.id().map(keys::key_id_hex).map_err(Failure::from))
        .collect()
}

pub fn recipients(input: &Path) -> Result<Value, Failure> {
    let msg = open_message(input, DEFAULT_BUF)?;
    Ok(json!({"recipients": recipient_ids(&msg)?}))
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub secret_keys: Vec<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

pub fn decrypt(input: &Path, output: &Path, req: &DecryptRequest) -> Result<Value, Failure> {
    let secret_keys = req
        .secret_keys
        .iter()
        .map(|k| keys::parse_secret(k))
        .collect::<Result<Vec<_>, _>>()?;
    let password = Password::from(req.passphrase.as_deref().unwrap_or(""));

    let msg = open_message(input, IO_BUF)?;
    let recipients = recipient_ids(&msg)?;
    let matching: Vec<&SignedSecretKey> = secret_keys
        .iter()
        .filter(|k| keys::secret_key_ids(k).iter().any(|id| recipients.contains(id)))
        .collect();
    if matching.is_empty() {
        return Err(Failure::new(
            Code::NoMatchingKey,
            format!("message is for {recipients:?}"),
        ));
    }
    let protected = matching.iter().any(|k| keys::matching_key_is_protected(k, &recipients));

    // One key per ring: rPGP resets per-key RingResult for every PKESK, so a multi-key ring
    // cannot say which key produced the session key. The first key reuses the message opened
    // above, so with one matching key the input is read exactly once, front to back (it can be
    // a pipe or FIFO). Further keys reopen it; opening is lazy, so that is cheap for a file.
    let mut opened = Some(msg);
    let mut decrypted = None;
    let mut first_error = None;
    for key in &matching {
        let ring = TheRing {
            secret_keys: vec![*key],
            key_passwords: vec![&password],
            // Streaming releases unauthenticated plaintext; write_atomically only
            // publishes it after EOF without an MDC/AEAD error.
            decrypt_options: DecryptionOptions::new()
                .enable_gnupg_aead()
                .set_seipdv1_read_mode(Seipdv1ReadMode::Streaming),
            ..Default::default()
        };
        let msg = match opened.take() {
            Some(msg) => msg,
            None => open_message(input, IO_BUF)?,
        };
        match msg.decrypt_the_ring(ring, true) {
            Ok((plain, _)) => {
                decrypted = Some((*key, plain));
                break;
            }
            Err(PgpError::MissingKey) => {}
            Err(other) => {
                first_error.get_or_insert_with(|| error::classify_read(other));
            }
        }
    }
    let Some((key, mut plain)) = decrypted else {
        return Err(first_error.unwrap_or_else(|| {
            // A key ID matched but no session key came out: a wrong passphrase if a matching
            // (sub)key is locked, otherwise the PKESK itself is broken.
            if protected {
                Failure::new(Code::BadPassphrase, "matching key could not be unlocked")
            } else {
                Failure::new(Code::Malformed, "session key could not be decrypted")
            }
        }));
    };

    // Lazy: decompress() only wraps the reader, so nothing is read until the copy loop.
    while plain.is_compressed() {
        plain = plain.decompress().map_err(error::classify_read)?;
    }
    if !(plain.is_literal() || plain.is_signed()) {
        return Err(Failure::new(
            Code::Malformed,
            "decrypted content is not a literal message",
        ));
    }
    let signed = plain.is_signed();
    write_atomically(output, |w| {
        let mut buf = vec![0u8; IO_BUF];
        loop {
            // Read errors come from parsing/decrypting the ciphertext; write errors are the disk.
            let n = match plain.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(error::classify_read(e)),
            };
            w.write_all(&buf[..n])?;
        }
    })?;

    Ok(json!({
        "recipients": recipients,
        "matched_key": format!("{:X}", key.primary_key.fingerprint()),
        "signed": signed,
    }))
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub recipients: Vec<String>,
}

/// SEIPDv1 + AES-256: every GnuPG version in use can read it.
pub fn encrypt(input: &Path, output: &Path, armor: bool, req: &EncryptRequest) -> Result<Value, Failure> {
    if req.recipients.is_empty() {
        return Err(Failure::new(Code::Usage, "no recipients"));
    }
    let certs = req
        .recipients
        .iter()
        .map(|k| keys::parse_public(k))
        .collect::<Result<Vec<_>, _>>()?;
    let enc_keys = certs.iter().map(keys::encryption_key).collect::<Result<Vec<_>, _>>()?;

    let mut rng = rand::thread_rng();
    // from_reader with an empty name: from_file would embed the input's basename in the literal packet.
    let source = BufReader::with_capacity(IO_BUF, File::open(input)?);
    let mut builder = MessageBuilder::from_reader("", source).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    for k in &enc_keys {
        match k {
            keys::EncryptionKey::Subkey(sk) => builder.encrypt_to_key(&mut rng, *sk)?,
            keys::EncryptionKey::Primary(pk) => builder.encrypt_to_key(&mut rng, *pk)?,
        };
    }
    write_atomically(output, |w| {
        if armor {
            builder.to_armored_writer(&mut rng, ArmorOptions::default(), w)?;
        } else {
            builder.to_writer(&mut rng, w)?;
        }
        Ok(())
    })?;

    Ok(json!({
        "recipients": enc_keys.iter().map(keys::EncryptionKey::key_id).collect::<Vec<_>>(),
    }))
}

/// Removes OUT.partial on drop (error return, failed rename, or unwinding panic) unless `keep` is set.
/// If the stdin watchdog is running, it is registered with it for its whole life, so stdin EOF
/// removes it too; with the watchdog off (`PGP_PORT_NO_WATCHDOG`) registration is skipped.
struct PartialFile {
    path: PathBuf,
    keep: bool,
}

impl PartialFile {
    fn create(path: PathBuf) -> io::Result<(Self, File)> {
        let mut registered = watchdog::partial();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        // Registered only after create_new succeeded, so we never delete someone else's file.
        if let Some(slot) = registered.as_deref_mut() {
            *slot = Some(path.clone());
        }
        Ok((Self { path, keep: false }, file))
    }

    fn publish(mut self, output: &Path) -> io::Result<()> {
        let mut registered = watchdog::partial();
        let renamed = fs::rename(&self.path, output);
        if renamed.is_ok() {
            self.keep = true;
            if let Some(slot) = registered.as_deref_mut() {
                *slot = None;
            }
        }
        drop(registered);
        renamed
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if !self.keep {
            let mut registered = watchdog::partial();
            let _ = fs::remove_file(&self.path);
            if let Some(slot) = registered.as_deref_mut() {
                *slot = None;
            }
        }
    }
}

/// Writes to OUT.partial (0600), renames to OUT only if `write` succeeds, deletes OUT.partial otherwise.
fn write_atomically(
    output: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let (partial, file) = PartialFile::create(partial_path(output))?;
    let mut w = BufWriter::with_capacity(IO_BUF, file);
    write(&mut w)?;
    w.flush()?;
    drop(w);
    partial.publish(output)?;
    Ok(())
}

fn partial_path(output: &Path) -> PathBuf {
    let mut s = output.as_os_str().to_owned();
    s.push(".partial");
    PathBuf::from(s)
}
