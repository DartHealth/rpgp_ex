# rpgp_ex

OpenPGP encryption and decryption for Elixir, backed by [rPGP](https://github.com/rpgp/rpgp), a
pure-Rust OpenPGP implementation. No `gpg` executable or C crypto library is involved.

> **Status:** pre-release. Not yet published to Hex; the API may change before 0.1.0.

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

Requires Elixir 1.18+ and Rust 1.88+. `mix test` builds `native/pgp_port` with cargo first.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
