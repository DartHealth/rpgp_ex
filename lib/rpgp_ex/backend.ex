defmodule RpgpEx.Backend do
  @moduledoc """
  The operations every backend implements. `RpgpEx` delegates to the configured backend:

      config :rpgp_ex, backend: RpgpEx.Port

  `RpgpEx.Port` is the default and, today, the only backend. The callbacks take file paths and
  armored keys, never library-specific types, so a backend can be swapped without changing callers.
  Result maps use string keys.
  """

  @type result(t) :: {:ok, t} | {:error, RpgpEx.Error.t()}

  @doc """
  Decrypts `in_path` to `out_path` with whichever of `secret_keys` (armored) the message is
  addressed to. Returns `"recipients"`, `"matched_key"` (fingerprint) and `"signed"`.
  """
  @callback decrypt_file(in_path :: Path.t(), out_path :: Path.t(), secret_keys :: [String.t()], keyword()) ::
              result(%{String.t() => term()})

  @doc "Encrypts `in_path` to `out_path` for every armored public key in `recipients`. Returns `\"recipients\"`."
  @callback encrypt_file(in_path :: Path.t(), out_path :: Path.t(), recipients :: [String.t()], keyword()) ::
              result(%{String.t() => term()})

  @doc "Lists the key IDs a message is encrypted to, without decrypting it. Returns `\"recipients\"`."
  @callback recipients(path :: Path.t(), keyword()) :: result(%{String.t() => term()})

  @doc """
  Describes an armored public key: `"fingerprint"`, `"key_id"`, `"algorithm"`, `"created_at"`
  and `"expires_at"` (`DateTime`, or `nil` if it never expires), `"revoked"`, `"can_encrypt"`,
  `"encryption_key_id"` (the key a message would be encrypted to, or `nil`) and `"subkeys"`.
  """
  @callback inspect_key(armored :: String.t(), keyword()) :: result(%{String.t() => term()})
end
