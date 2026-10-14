# Releasing

rpgp_ex has two kinds of release, tagged separately:

- **`pgp_port-v<version>`**: the prebuilt `pgp_port` executables, a GitHub release built by
  `.github/workflows/port-release.yml`. `<version>` is the `version` in
  `native/pgp_port/Cargo.toml`.
- **`v<version>`**: the Elixir package. `<version>` is `@version` in `mix.exs`.

They are separate because the package must contain the checksums of the executables it
downloads, and those exist only once the executables are built. A package release that
changes nothing in `native/pgp_port` reuses the previous executables.

## 1. Executables (only when `native/pgp_port` changed)

1. Bump `version` in `native/pgp_port/Cargo.toml` and run `cargo build` to update
   `Cargo.lock`. Merge it to `main`.
2. Tag the merge commit and push the tag:

   ```sh
   git tag pgp_port-v0.1.0
   git push origin pgp_port-v0.1.0
   ```

3. The workflow builds the four targets on native runners and runs each binary. It then writes
   `checksums-pgp_port.exs`, and installs the x86_64 Linux archive into a scratch project the
   way a dependency would, with a round trip. Finally it attests build provenance and creates
   the GitHub release with the four archives and the checksum file.

Never move or re-push a tag whose release exists: the checksums already published would stop
matching. Bump the version instead.

## 2. The package

1. Download `checksums-pgp_port.exs` from the `pgp_port-v<version>` release into the repository
   root, and commit it with the `mix.exs` version bump and the CHANGELOG entry:

   ```sh
   gh release download pgp_port-v0.1.0 --pattern checksums-pgp_port.exs --clobber
   ```

2. Check the package contents: `mix hex.build --unpack`.
3. Merge to `main`, tag the merge commit `v<version>`, and push the tag.
4. Publish to Hex with `mix hex.publish`.

Git dependencies work from the `v<version>` tag, because the checksum file is committed.

## Supported targets

`aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-musl` and
`x86_64-unknown-linux-musl`. The Linux executables are static, so they also run on glibc
distributions. Other platforms build from source with cargo.
