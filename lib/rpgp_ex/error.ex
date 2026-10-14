defmodule RpgpEx.Error do
  @moduledoc """
  A failed operation. `code` is part of the public API (removing or renaming one is a breaking
  change); `message` is human-readable detail and may change between releases.

  Codes reported by the native core (`codes/0`):

    * `:no_matching_key` - none of the supplied secret keys is a recipient of the message
    * `:bad_passphrase` - a matching key is passphrase-protected and could not be unlocked
    * `:integrity_check_failed` - the message was modified (MDC or AEAD tag mismatch)
    * `:unsupported` - an algorithm or packet the library does not implement
    * `:malformed` - the input is not a well-formed OpenPGP message or key
    * `:io` - an operating-system error reading or writing a file
    * `:usage` - invalid arguments, e.g. no recipients
    * `:key_expired` - a recipient key, or its primary key, has expired
    * `:key_revoked` - a recipient key, or its primary key, is revoked
    * `:no_encryption_key` - a recipient certificate has no key that can encrypt
    * `:cancelled` - reserved for a future in-process backend; never returned today

  Codes added on the Elixir side:

    * `:timeout` - the operation exceeded its `:timeout` and was killed
    * `:crashed` - the native process died or produced unreadable output
    * `:unknown` - the native process reported a code this version does not recognise

  Match on the codes you handle and keep a catch-all clause: new codes may be added in minor
  releases.
  """
  defexception [:code, :message]

  @type t :: %__MODULE__{code: atom(), message: String.t()}

  # Keep in sync with pgp_port's error::Code. Never String.to_atom untrusted output.
  @codes Map.new(
           ~w(no_matching_key bad_passphrase integrity_check_failed unsupported malformed io usage
             key_expired key_revoked no_encryption_key cancelled)a,
           &{Atom.to_string(&1), &1}
         )

  @doc "The error codes the Rust core can report."
  @spec codes() :: [atom()]
  def codes, do: Map.values(@codes)

  @doc "Builds an error from a Rust-side code string; unknown codes become `:unknown`."
  @spec from_native(String.t(), String.t()) :: t()
  def from_native(code, message) when is_binary(message),
    do: %__MODULE__{code: Map.get(@codes, code, :unknown), message: message}
end
