defmodule RpgpEx.Port do
  @moduledoc """
  The default backend: each call runs one short-lived `pgp_port` OS process.

  File contents never enter the BEAM. Keys and passphrases travel over the port's stdin as one
  JSON line, never in arguments or on disk. A crash, abort or timeout in `pgp_port` cannot take
  the VM down: the caller gets `{:error, %RpgpEx.Error{code: :crashed | :timeout}}`.
  """

  @behaviour RpgpEx.Backend

  alias RpgpEx.Port.Runner

  @impl true
  def decrypt_file(in_path, out_path, secret_keys, opts \\ []) do
    payload = %{secret_keys: secret_keys, passphrase: opts[:passphrase]}
    args = ["decrypt", "--in", in_path, "--out", out_path]
    Runner.run(args, payload, Keyword.put(opts, :partial, out_path <> ".partial"))
  end

  @impl true
  def encrypt_file(in_path, out_path, recipients, opts \\ []) do
    args = ["encrypt", "--in", in_path, "--out", out_path] ++ if(opts[:armor], do: ["--armor"], else: [])
    Runner.run(args, %{recipients: recipients}, Keyword.put(opts, :partial, out_path <> ".partial"))
  end

  @impl true
  def recipients(path, opts \\ []), do: Runner.run(["recipients", "--in", path], nil, opts)

  @impl true
  def inspect_key(armored, opts \\ []), do: Runner.run(["inspect-key"], %{key: armored}, opts)
end
