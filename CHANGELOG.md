# Changelog

All notable changes to rpgp_ex are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, a minor release may break the API.

## [0.1.0] - Unreleased

First release.

### Added

- `RpgpEx.encrypt_file/4`, `decrypt_file/4`, `recipients/2` and `inspect_key/2`, backed by
  [rPGP](https://github.com/rpgp/rpgp) 0.21 in a short-lived native process (`pgp_port`) per
  call.
- Decryption of SEIPDv1 and GnuPG's OCB (AEAD) messages, binary or armored, choosing the
  secret key by the message's recipient key IDs. Plaintext is written to `out_path <> ".partial"`
  and renamed to `out_path` only after the whole message has been authenticated.
- Encryption, binary or armored, to one or more recipients. A revoked or expired recipient key,
  or a certificate with no key that can encrypt, is refused.
- Tagged errors: every function returns `{:ok, map}` or `{:error, %RpgpEx.Error{}}` with a
  stable `code`.
- `:timeout` per call. A timed-out or crashed `pgp_port` is killed and its partial output removed.
- Prebuilt, checksum-verified `pgp_port` binaries for macOS and Linux (arm64 and x86_64),
  installed when rpgp_ex compiles, with a cargo build as the fallback.
