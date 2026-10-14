defmodule Mix.Tasks.Compile.PgpPort do
  @shortdoc "Installs the pgp_port executable into rpgp_ex's priv/bin"
  @moduledoc """
  Installs the `pgp_port` executable that rpgp_ex runs, into `priv/bin` of rpgp_ex's build
  directory, so it ships in `mix release`. It runs as part of `mix compile`.

  By default it downloads the prebuilt binary for this platform from the GitHub release, and
  installs it only if its sha256 matches `checksums-pgp_port.exs` in the package. Where there
  is no prebuilt binary, it builds `native/pgp_port` with cargo. Configure it in your
  `config/config.exs` (`config/runtime.exs` is read too late):

    * `config :rpgp_ex, pgp_port_path: "/path/to/pgp_port"` - use your own build; nothing is
      installed. The same setting tells rpgp_ex which binary to run.
    * `config :rpgp_ex, build_from_source: true` - always build with cargo.
    * `config :rpgp_ex, artifact_base_url: "https://mirror.example/rpgp_ex"` - download the
      release assets from a mirror. The checksums still come from the package.

  Set the `RPGP_EX_TARGET` environment variable to install the binary for another platform,
  such as `x86_64-unknown-linux-musl` when you build a Linux release on macOS.
  """
  use Mix.Task.Compiler

  @impl Mix.Task.Compiler
  def run(_args) do
    config = Application.get_all_env(:rpgp_ex)

    opts =
      [
        dest: Path.join(Mix.Project.app_path(), "priv/bin/pgp_port"),
        root: Path.dirname(Mix.Project.project_file()),
        target: System.get_env("RPGP_EX_TARGET"),
        cargo: System.find_executable("cargo")
      ] ++ Keyword.take(config, [:pgp_port_path, :build_from_source, :artifact_base_url])

    case RpgpEx.Installer.install(opts) do
      {:ok, result} when result in [:skipped, :up_to_date] ->
        {:noop, []}

      {:ok, result} ->
        Mix.shell().info("rpgp_ex: pgp_port #{result} (#{RpgpEx.Installer.pgp_port_version()})")
        {:ok, []}

      {:error, message} ->
        Mix.raise("rpgp_ex: " <> message)
    end
  end
end
