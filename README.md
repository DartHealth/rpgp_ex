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

Decryption writes to `out_path <> ".partial"` and renames it to `out_path` only once the whole
message has been authenticated. Never read the `.partial` file, and never use `out_path` until
the call has returned `{:ok, _}`.

## Security

Decrypting with an RSA secret key uses the `rsa` crate, whose private-key operations are not
constant-time ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), the Marvin
attack; no fixed release exists). An attacker who can time many decryptions may recover the key.
Use a Curve25519 (Cv25519) key for decryption. Encrypting to an RSA public key is unaffected.

## Development

Requires Elixir 1.18+ and Rust 1.88+. In this repository `mix compile` builds `native/pgp_port`
with cargo (`config/config.exs` sets `build_from_source`). Releases are described in
[RELEASING.md](https://github.com/DartHealth/rpgp_ex/blob/main/RELEASING.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
