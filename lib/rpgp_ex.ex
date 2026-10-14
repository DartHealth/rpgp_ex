defmodule RpgpEx do
  @moduledoc """
  OpenPGP encryption and decryption for Elixir, built on [rPGP](https://github.com/rpgp/rpgp),
  a pure-Rust OpenPGP implementation. No `gpg` executable is involved.

  Every operation works on files, so memory stays flat however large the file is. Decryption
  writes to `out_path <> ".partial"` and renames it to `out_path` only after the whole message
  has been authenticated: never read the `.partial` file, and never use `out_path` before the
  call has returned `{:ok, _}`.

  Every function returns `{:ok, map}` or `{:error, %RpgpEx.Error{}}`; see `RpgpEx.Error` for the
  codes. Common options:

    * `:timeout` - milliseconds before the operation is killed (default 60 000)
  """

  @doc """
  Decrypts `in_path` (binary or armored) to `out_path`, choosing the key by the message's
  recipient key IDs.

  Options: `:passphrase` (for protected keys), `:timeout`.
  """
  @spec decrypt_file(Path.t(), Path.t(), [String.t()], keyword()) :: RpgpEx.Backend.result(map())
  def decrypt_file(in_path, out_path, secret_keys, opts \\ []),
    do: backend().decrypt_file(in_path, out_path, secret_keys, opts)

  @doc """
  Encrypts `in_path` to `out_path` for every key in `recipients` (armored public keys).

  Options: `:armor` (ASCII-armored output), `:timeout`.
  """
  @spec encrypt_file(Path.t(), Path.t(), [String.t()], keyword()) :: RpgpEx.Backend.result(map())
  def encrypt_file(in_path, out_path, recipients, opts \\ []),
    do: backend().encrypt_file(in_path, out_path, recipients, opts)

  @doc "Lists the key IDs the message at `path` is encrypted to, without decrypting it."
  @spec recipients(Path.t(), keyword()) :: RpgpEx.Backend.result(map())
  def recipients(path, opts \\ []), do: backend().recipients(path, opts)

  @doc "Describes an armored public key: fingerprint, key ID, algorithm and subkeys."
  @spec inspect_key(String.t(), keyword()) :: RpgpEx.Backend.result(map())
  def inspect_key(armored, opts \\ []), do: backend().inspect_key(armored, opts)

  defp backend, do: Application.get_env(:rpgp_ex, :backend, RpgpEx.Port)
end
