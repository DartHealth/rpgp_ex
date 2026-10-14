defmodule RpgpEx.Application do
  @moduledoc false

  use Application
  require Logger

  @impl Application
  def start(_type, _args) do
    check_pgp_port()
    Supervisor.start_link([], strategy: :one_for_one, name: RpgpEx.Supervisor)
  end

  # A warning, not a crash: an application that never encrypts should still boot. A binary
  # from another version may not speak the same protocol, so calls are likely to fail.
  @doc false
  def check_pgp_port(opts \\ []) do
    expected = RpgpEx.Installer.pgp_port_version()

    case RpgpEx.Port.Runner.run(["--version"], nil, Keyword.put_new(opts, :timeout, 5_000)) do
      {:ok, %{"version" => ^expected}} ->
        :ok

      {:ok, %{"version" => actual}} ->
        Logger.warning("rpgp_ex expects pgp_port #{expected}, but #{RpgpEx.Port.Runner.binary(opts)} is #{actual}")
        {:mismatch, actual}

      {:error, error} ->
        Logger.warning("rpgp_ex cannot run pgp_port --version: #{Exception.message(error)}")
        {:error, error}
    end
  end
end
