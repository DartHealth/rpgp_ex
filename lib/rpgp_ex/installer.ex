defmodule RpgpEx.Installer do
  @moduledoc false

  # Puts the pgp_port executable at `:dest` when rpgp_ex compiles (see Mix.Tasks.Compile.PgpPort).
  #
  # In order:
  #   1. `:pgp_port_path` is configured: use that binary, install nothing.
  #   2. `:build_from_source` is not set and checksums-pgp_port.exs lists an artifact for this
  #      target: download it, check its sha256, then install it.
  #   3. cargo is on PATH: build native/pgp_port from source and install the result.
  #   4. Otherwise fail, naming every option.
  #
  # An install never writes over `:dest` in place. It writes a temporary file in the same
  # directory and renames it, so a running pgp_port keeps its inode and macOS rechecks the code
  # signature of the new file.

  @cargo_toml Path.expand("../../native/pgp_port/Cargo.toml", __DIR__)
  @external_resource @cargo_toml
  @pgp_port_version (case Regex.run(~r/^version = "([^"]+)"$/m, File.read!(@cargo_toml)) do
                       [_, version] -> version
                       nil -> raise "no version in #{@cargo_toml}"
                     end)

  @checksums "checksums-pgp_port.exs"
  @repository "https://github.com/DartHealth/rpgp_ex"

  @doc "The pgp_port version this release of rpgp_ex was built for (the crate's version)."
  @spec pgp_port_version() :: String.t()
  def pgp_port_version, do: @pgp_port_version

  @doc """
  The release target for a BEAM `:system_architecture` string, or `explicit` when given.

  Linux hosts get the static musl build whatever their libc, because it has no libc dependency.
  """
  @spec target(String.t(), String.t() | nil) :: {:ok, String.t()} | :error
  def target(_system_architecture, explicit) when is_binary(explicit) and explicit != "", do: {:ok, explicit}

  def target(system_architecture, _explicit) do
    [arch | _] = String.split(system_architecture, "-")

    arch =
      case arch do
        a when a in ["x86_64", "amd64"] -> "x86_64"
        a when a in ["aarch64", "arm64"] -> "aarch64"
        _ -> nil
      end

    cond do
      arch && system_architecture =~ "-apple-darwin" -> {:ok, "#{arch}-apple-darwin"}
      arch && system_architecture =~ "-linux-" -> {:ok, "#{arch}-unknown-linux-musl"}
      true -> :error
    end
  end

  @doc "The release asset name for a target."
  @spec artifact(String.t()) :: String.t()
  def artifact(target), do: "pgp_port-v#{@pgp_port_version}-#{target}.tar.gz"

  @doc """
  Installs pgp_port. Options:

    * `:dest` (required) - where to install the executable
    * `:root` (required) - the package root, holding #{@checksums} and native/pgp_port
    * `:pgp_port_path` - a binary to use instead; nothing is installed
    * `:build_from_source` - build with cargo even when an artifact exists
    * `:artifact_base_url` - where release artifacts are downloaded from
    * `:target` - the release target, overriding detection
    * `:system_architecture` - the BEAM's, by default
    * `:cargo` - the cargo executable, or nil when there is none
  """
  @spec install(keyword()) :: {:ok, :skipped | :up_to_date | :installed | :built} | {:error, String.t()}
  def install(opts) do
    cond do
      opts[:pgp_port_path] -> {:ok, :skipped}
      opts[:build_from_source] -> build(opts, "build_from_source is set")
      true -> install_artifact(opts)
    end
  end

  defp install_artifact(opts) do
    arch = Keyword.get_lazy(opts, :system_architecture, &system_architecture/0)

    with {:target, {:ok, target}} <- {:target, target(arch, opts[:target])},
         {:ok, checksums} <- read_checksums(Path.join(opts[:root], @checksums)),
         {:ok, checksum} <- Map.fetch(checksums, artifact(target)) |> found(target) do
      install_checksummed(opts, artifact(target), checksum)
    else
      {:target, :error} -> build(opts, "cannot tell the release target for #{arch}; set RPGP_EX_TARGET")
      {:no_artifact, reason} -> build(opts, reason)
      {:error, _} = error -> error
    end
  end

  defp found({:ok, checksum}, _target), do: {:ok, checksum}
  defp found(:error, target), do: {:no_artifact, "no prebuilt pgp_port for #{target}"}

  defp install_checksummed(opts, artifact, checksum) do
    dest = opts[:dest]
    stamp = dest <> ".artifact"
    stamp_contents = "#{artifact} #{checksum}\n"

    if File.read(stamp) == {:ok, stamp_contents} and File.regular?(dest) do
      {:ok, :up_to_date}
    else
      url = "#{base_url(opts)}/#{artifact}"

      with {:ok, data} <- download(url),
           :ok <- verify(data, checksum, artifact),
           {:ok, binary} <- unpack(data, artifact),
           :ok <- put(dest, binary),
           :ok <- put(stamp, stamp_contents, 0o644) do
        {:ok, :installed}
      end
    end
  end

  defp base_url(opts) do
    opts[:artifact_base_url] || "#{@repository}/releases/download/pgp_port-v#{@pgp_port_version}"
  end

  defp verify(data, "sha256:" <> expected, artifact) do
    actual = Base.encode16(:crypto.hash(:sha256, data), case: :lower)

    if actual == String.downcase(expected),
      do: :ok,
      else: {:error, "checksum mismatch for #{artifact}: expected sha256:#{expected}, got sha256:#{actual}"}
  end

  defp verify(_data, checksum, artifact), do: {:error, "unsupported checksum #{inspect(checksum)} for #{artifact}"}

  # Extracted in memory, so no archive entry can name a path outside `dest`.
  defp unpack(data, artifact) do
    case :erl_tar.extract({:binary, data}, [:compressed, :memory]) do
      {:ok, [{~c"pgp_port", binary}]} ->
        {:ok, binary}

      {:ok, entries} ->
        {:error, "#{artifact}: expected one file named pgp_port, got #{inspect(Enum.map(entries, &elem(&1, 0)))}"}

      {:error, reason} ->
        {:error, "#{artifact}: not a gzipped tar archive (#{inspect(reason)})"}
    end
  end

  # The checksum file is data: it is parsed, never evaluated.
  defp read_checksums(path) do
    with {:ok, source} <- File.read(path),
         {:ok, {:%{}, _, pairs}} <- Code.string_to_quoted(source),
         true <- Enum.all?(pairs, fn {k, v} -> is_binary(k) and is_binary(v) end) do
      {:ok, Map.new(pairs)}
    else
      # No releases yet (a git checkout before the first one): only a source build can work.
      {:error, :enoent} -> {:ok, %{}}
      _ -> {:error, "#{path} is not a map of file names to checksums"}
    end
  end

  defp build(opts, reason) do
    case opts[:cargo] do
      nil ->
        {:error,
         """
         #{reason}, and cargo is not on PATH. Either:
           * install Rust (https://rustup.rs), so rpgp_ex can build pgp_port from source;
           * build pgp_port yourself and set `config :rpgp_ex, pgp_port_path: "/path/to/pgp_port"`; or
           * use a target with a prebuilt binary: #{Enum.join(supported_targets(), ", ")}.
         """}

      cargo ->
        crate = Path.join(opts[:root], "native/pgp_port")
        # An explicit target is built for that target, never silently for the host.
        target = if is_binary(opts[:target]) and opts[:target] != "", do: opts[:target]
        target_args = if target, do: ["--target", target], else: []

        case System.cmd(cargo, ["build", "--release", "--locked"] ++ target_args, cd: crate, stderr_to_stdout: true) do
          {_, 0} -> with :ok <- put(opts[:dest], File.read!(built_binary(crate, target))), do: {:ok, :built}
          {output, status} -> {:error, "cargo build failed (exit #{status}):\n#{output}"}
        end
    end
  end

  defp built_binary(crate, target) do
    target_dir = Path.expand(System.get_env("CARGO_TARGET_DIR") || "target", crate)
    Path.join([target_dir, target || "", "release", "pgp_port"])
  end

  defp put(path, contents, mode \\ 0o755) do
    dir = Path.dirname(path)
    tmp = Path.join(dir, ".#{Path.basename(path)}.#{System.unique_integer([:positive])}.tmp")

    with :ok <- File.mkdir_p(dir),
         :ok <- File.write(tmp, contents, [:exclusive]),
         :ok <- File.chmod(tmp, mode),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp)
        {:error, "cannot write #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp download(url) do
    {:ok, _} = Application.ensure_all_started([:inets, :ssl])
    profile = :rpgp_ex_installer

    case :inets.start(:httpc, profile: profile) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
    end

    :ok = :httpc.set_options(proxy_options(), profile)

    ssl = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      depth: 4,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    http_opts = [ssl: ssl, timeout: 120_000, connect_timeout: 30_000, autoredirect: true]

    case :httpc.request(:get, {String.to_charlist(url), []}, http_opts, [body_format: :binary], profile) do
      {:ok, {{_, 200, _}, _headers, body}} -> {:ok, body}
      {:ok, {{_, status, _}, _headers, _body}} -> {:error, "could not download #{url}: HTTP #{status}"}
      {:error, reason} -> {:error, "could not download #{url}: #{inspect(reason)}"}
    end
  end

  # HTTP_PROXY / HTTPS_PROXY / NO_PROXY, as curl and Mix read them.
  defp proxy_options do
    no_proxy =
      (System.get_env("NO_PROXY") || System.get_env("no_proxy") || "")
      |> String.split(",", trim: true)
      |> Enum.map(&(&1 |> String.trim() |> String.to_charlist()))

    for {key, names} <- [proxy: ["HTTP_PROXY", "http_proxy"], https_proxy: ["HTTPS_PROXY", "https_proxy"]],
        url = Enum.find_value(names, &System.get_env/1),
        %URI{host: host, port: port} when is_binary(host) <- [URI.parse(url)] do
      {key, {{String.to_charlist(host), port}, no_proxy}}
    end
  end

  defp system_architecture, do: List.to_string(:erlang.system_info(:system_architecture))

  defp supported_targets,
    do: ~w(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl)
end
