use pgp::crypto::aead::Error as AeadError;
use pgp::errors::Error as PgpError;
use std::io;

/// Error codes shared with the Elixir side. Keep in sync with RpgpEx.Error's whitelist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    NoMatchingKey,
    BadPassphrase,
    IntegrityCheckFailed,
    Unsupported,
    Malformed,
    Io,
    Usage,
    /// A recipient key (or its primary key) has expired.
    KeyExpired,
    /// A recipient key (or its primary key) is revoked.
    KeyRevoked,
    /// A recipient certificate has no key that can encrypt.
    NoEncryptionKey,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::NoMatchingKey => "no_matching_key",
            Code::BadPassphrase => "bad_passphrase",
            Code::IntegrityCheckFailed => "integrity_check_failed",
            Code::Unsupported => "unsupported",
            Code::Malformed => "malformed",
            Code::Io => "io",
            Code::Usage => "usage",
            Code::KeyExpired => "key_expired",
            Code::KeyRevoked => "key_revoked",
            Code::NoEncryptionKey => "no_encryption_key",
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub code: Code,
    pub message: String,
}

impl Failure {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<PgpError> for Failure {
    fn from(e: PgpError) -> Self {
        Failure::new(classify(&e), e.to_string())
    }
}

/// rPGP reports MDC/AEAD failures during streaming as `io::Error::other(pgp::errors::Error)`.
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::new(classify_io(&e), e.to_string())
    }
}

/// For errors raised while reading ciphertext after the input is open (decrypt_the_ring's eager
/// first AEAD chunk, decompress, the plaintext copy loop): the message is being parsed on the
/// fly, so anything `classify_io` would call `io` (truncation, short chunks, trailing packets)
/// is a problem with the message, not the disk, and is reported as `malformed`.
/// An `io::Error` carrying an OS errno anywhere in the source chain is a real disk/OS failure and stays `io`.
pub fn classify_read<E: std::error::Error + Into<Failure> + 'static>(e: E) -> Failure {
    let os_error = std::iter::successors(Some(&e as &(dyn std::error::Error + 'static)), |e| e.source()).any(|e| {
        e.downcast_ref::<io::Error>()
            .is_some_and(|io| io.raw_os_error().is_some())
    });
    let f: Failure = e.into();
    if f.code == Code::Io && !os_error {
        Failure::new(Code::Malformed, f.message)
    } else {
        f
    }
}

fn classify(e: &PgpError) -> Code {
    match e {
        PgpError::MdcError | PgpError::Aead { .. } => Code::IntegrityCheckFailed,
        PgpError::MissingKey => Code::NoMatchingKey,
        PgpError::Unsupported { .. } | PgpError::Unimplemented { .. } => Code::Unsupported,
        PgpError::IO { source, .. } => classify_io(source),
        _ => Code::Malformed,
    }
}

fn classify_io(e: &io::Error) -> Code {
    let Some(inner) = e.get_ref() else {
        return Code::Io;
    };
    if let Some(pgp) = inner.downcast_ref::<PgpError>() {
        return classify(pgp);
    }
    // OCB/EAX tag failures arrive as io::Error wrapping aead::Error directly (not pgp::errors::Error).
    if let Some(AeadError::Decrypt { .. }) = inner.downcast_ref::<AeadError>() {
        return Code::IntegrityCheckFailed;
    }
    Code::Io
}
