# rpgp_ex

OpenPGP encryption and decryption for Elixir, backed by [rPGP](https://github.com/rpgp/rpgp), a
pure-Rust OpenPGP implementation. No `gpg` executable or C crypto library is involved.

> **Status:** pre-release. Not yet published to Hex; the API may change before 0.1.0.

## Installation

```elixir
def deps do
  [{:rpgp_ex, github: "DartHealth/rpgp_ex", tag: "v0.1.0"}]
end
```

Compiling rpgp_ex installs its native executable, `pgp_port`, into its `priv/bin`, so it
ships in `mix release`. On macOS (arm64 and x86_64) and Linux (arm64 and x86_64, any libc)
it downloads a prebuilt binary from this repository's GitHub releases, and installs it only if
the binary's sha256 matches `checksums-pgp_port.exs` in the package. Elsewhere it builds
`pgp_port` from source, which needs Rust 1.88 or later. To change this, set one of these in
`config/config.exs`:

- `pgp_port_path: "/path/to/pgp_port"` to run a binary you provide;
- `build_from_source: true` to always build with cargo;
- `artifact_base_url: "https://..."` to download from a mirror.

Downloads honour `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, including credentials in the proxy
URL (`http://user:password@proxy:3128`).

When you build a release for another platform, such as a Linux image on a Mac, set
`RPGP_EX_TARGET` (for example `x86_64-unknown-linux-musl`) when compiling. When the
application starts, it logs a warning if `pgp_port` is missing or is from another version.

## How it works

Each operation runs one short-lived native process (`pgp_port`) over an Erlang Port. File
contents never enter the BEAM, so memory stays flat for large files, and a crash or timeout in
the native code returns an error instead of taking the VM down. Keys and passphrases are passed
on the process's stdin, never in arguments or on disk.

```elixir
{:ok, %{"recipients" => [_key_id]}} =
  RpgpEx.encrypt_file("report.csv", "report.csv.pgp", [recipient_public_key], armor: true)

{:ok, %{"matched_key" => _fingerprint}} =
  RpgpEx.decrypt_file("inbound.pgp", "inbound.csv", [our_secret_key], passphrase: passphrase)
```

## Security

### Decrypted output

OpenPGP messages are authenticated only at the end: SEIPDv1 by its MDC after the last byte, and
OCB chunk by chunk, with truncation detected only at the end. So decryption streams plaintext to
`out_path <> ".partial"` (created new, mode 0600) and renames it to `out_path` only once the whole
message has been authenticated. On any failure, the `.partial` file it created is removed.

- Never read the `.partial` file, and never use `out_path` until the call has returned `{:ok, _}`.
  Until then the plaintext may be forged or truncated.
- Decrypt into a private directory per job. If the `.partial` path already exists, decryption fails
  with `:io` rather than overwrite it, so after a power loss or a killed VM, remove stale
  `*.partial` files when your application starts.

### Keys and passphrases

Keys and passphrases reach `pgp_port` on its stdin, never in arguments, the environment or on disk.
rpgp_ex never logs them. Keep them out of your own logs and telemetry too: log key IDs,
fingerprints and error codes, never keys, passphrases or plaintext.

### Choosing a decryption key

- **Use a Curve25519 (Cv25519) key.** Decrypting with an RSA secret key uses the `rsa` crate,
  whose private-key operations are not constant-time
  ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), the Marvin attack; no
  fixed release exists). NIST P-256/P-384/P-521 and X448 secret keys use `crypto-bigint` 0.5,
  some of whose operations meant to be constant-time are not
  ([RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387); fixed only in 0.7, which
  rPGP 0.21 cannot use). An attacker who can time many decryptions may recover the key.
  Encrypting to an RSA, NIST P-curve or X448 public key is unaffected.
- **Leave AEAD out of the key's preferences** if you want senders to use SEIPDv1. GnuPG 2.4 and
  later send OCB to any key that advertises AEAD, which GnuPG's default preferences do. rpgp_ex
  decrypts both, but SEIPDv1 streams in a few MiB, while OCB holds a chunk of up to 4 MiB in
  memory. To generate a key without AEAD, pass GnuPG a preference list such as
  `--default-preference-list "AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed"`
  (see `test/fixtures/gen.sh`).

### Known limits

- Signatures are not verified. `decrypt_file` reports only whether the message was signed
  (`"signed"`).
- `recipients` and key matching read v3 PKESK packets only. v6 PKESKs and anonymous (wildcard)
  recipients are not supported.
- Only public-key encryption is supported: password-encrypted (SKESK) messages are not.
- When a certificate has no usable encryption subkey, the primary key is used if it can encrypt.
  Its status comes from its newest self-signature across all user IDs, not GnuPG's primary user
  ID rule.
- A crash or abort in `pgp_port` cannot take the VM down, but in a memory-limited container the
  kernel's out-of-memory killer may choose the BEAM rather than `pgp_port`.
- Windows is not supported.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

Requires Elixir 1.18+ and Rust 1.88+. In this repository `mix compile` builds `native/pgp_port`
with cargo (`config/config.exs` sets `build_from_source`). Releases are described in
[RELEASING.md](https://github.com/DartHealth/rpgp_ex/blob/main/RELEASING.md).

## License

Licensed under either of the
[Apache License, Version 2.0](https://github.com/DartHealth/rpgp_ex/blob/main/LICENSE-APACHE) or the
[MIT license](https://github.com/DartHealth/rpgp_ex/blob/main/LICENSE-MIT), at your option.
