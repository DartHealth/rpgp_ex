# Build pgp_port from source and point the library at it. cargo is a no-op when nothing changed.
native = Path.expand("../native/pgp_port", __DIR__)
{output, status} = System.cmd("cargo", ["build", "--release", "--locked"], cd: native, stderr_to_stdout: true)
if status != 0, do: raise("cargo build failed:\n" <> output)
Application.put_env(:rpgp_ex, :pgp_port_path, Path.join(native, "target/release/pgp_port"))

ExUnit.start(exclude: [:gpg_agent, :large])
