defmodule RpgpEx.InstallerTest do
  use ExUnit.Case, async: true

  alias RpgpEx.Installer

  @moduletag :tmp_dir
  @version Installer.pgp_port_version()
  @target "aarch64-apple-darwin"
  @artifact "pgp_port-v#{@version}-#{@target}.tar.gz"
  @binary "#!/bin/sh\necho downloaded\n"

  describe "target/2" do
    test "maps the BEAM's architecture to a release target" do
      assert Installer.target("aarch64-apple-darwin24.6.0", nil) == {:ok, "aarch64-apple-darwin"}
      assert Installer.target("x86_64-apple-darwin23.1.0", nil) == {:ok, "x86_64-apple-darwin"}
      # Static musl executables serve glibc and musl hosts alike.
      assert Installer.target("x86_64-pc-linux-gnu", nil) == {:ok, "x86_64-unknown-linux-musl"}
      assert Installer.target("x86_64-alpine-linux-musl", nil) == {:ok, "x86_64-unknown-linux-musl"}
      assert Installer.target("aarch64-unknown-linux-gnu", nil) == {:ok, "aarch64-unknown-linux-musl"}
      assert Installer.target("amd64-portbld-freebsd14.1", nil) == :error
      assert Installer.target("win32", nil) == :error
    end

    test "an explicit target wins, for releases built on another platform" do
      assert Installer.target("aarch64-apple-darwin24.6.0", "x86_64-unknown-linux-musl") ==
               {:ok, "x86_64-unknown-linux-musl"}
    end
  end

  test "pgp_port_version/0 is the crate version" do
    cargo_toml = File.read!(Path.expand("../../native/pgp_port/Cargo.toml", __DIR__))
    assert cargo_toml =~ ~s(\nversion = "#{@version}"\n)
  end

  describe "install/1 from a release artifact" do
    setup %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "package")
      www = Path.join(tmp_dir, "www")
      File.mkdir_p!(root)
      File.mkdir_p!(www)
      {base_url, httpd} = start_httpd(www)
      on_exit(fn -> :inets.stop(:httpd, httpd) end)

      opts = [
        dest: Path.join(tmp_dir, "build/priv/bin/pgp_port"),
        root: root,
        target: @target,
        artifact_base_url: base_url,
        cargo: nil
      ]

      %{root: root, www: www, opts: opts, httpd: httpd}
    end

    test "downloads, verifies and installs an executable", %{root: root, www: www, opts: opts} do
      publish(www, root, tarball([{"pgp_port", @binary}]))

      assert Installer.install(opts) == {:ok, :installed}
      dest = opts[:dest]
      assert File.read!(dest) == @binary
      assert File.stat!(dest).mode |> Bitwise.band(0o777) == 0o755
      assert {"downloaded\n", 0} = System.cmd(dest, [])
      assert ls(Path.dirname(dest)) == ["pgp_port", "pgp_port.artifact"]
    end

    test "does nothing once the same artifact is installed", %{root: root, www: www, opts: opts, httpd: httpd} do
      publish(www, root, tarball([{"pgp_port", @binary}]))
      assert Installer.install(opts) == {:ok, :installed}

      :ok = :inets.stop(:httpd, httpd)
      assert Installer.install(opts) == {:ok, :up_to_date}
    end

    test "replaces a binary installed from a different artifact", %{root: root, www: www, opts: opts} do
      File.mkdir_p!(Path.dirname(opts[:dest]))
      File.write!(opts[:dest], "old")
      publish(www, root, tarball([{"pgp_port", @binary}]))

      assert Installer.install(opts) == {:ok, :installed}
      assert File.read!(opts[:dest]) == @binary
    end

    test "refuses a download whose checksum does not match", %{root: root, www: www, opts: opts} do
      publish(www, root, tarball([{"pgp_port", @binary}]))
      File.write!(Path.join(www, @artifact), tarball([{"pgp_port", "#!/bin/sh\necho tampered\n"}]))

      assert {:error, message} = Installer.install(opts)
      assert message =~ "checksum mismatch"
      assert message =~ @artifact
      dir = Path.dirname(opts[:dest])
      assert not File.exists?(dir) or ls(dir) == []
    end

    test "refuses an archive that is not exactly one pgp_port file", %{root: root, www: www, opts: opts} do
      for entries <- [[{"pgp_port", @binary}, {"extra", "x"}], [{"other", @binary}], [{"bin/pgp_port", @binary}]] do
        publish(www, root, tarball(entries))
        assert {:error, message} = Installer.install(opts)
        assert message =~ "expected one file named pgp_port"
        refute File.exists?(opts[:dest])
      end
    end

    test "reports a failed download", %{root: root, opts: opts} do
      write_checksums(root, %{@artifact => "sha256:" <> String.duplicate("0", 64)})

      assert {:error, message} = Installer.install(opts)
      assert message =~ "could not download"
      assert message =~ "404"
    end
  end

  describe "install/1 without a release artifact" do
    test "builds from source with cargo", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "package")
      File.mkdir_p!(Path.join(root, "native/pgp_port"))
      opts = [dest: Path.join(tmp_dir, "priv/bin/pgp_port"), root: root, target: nil, cargo: fake_cargo(tmp_dir)]

      assert Installer.install(opts) == {:ok, :built}
      assert File.read!(opts[:dest]) == "#!/bin/sh\necho built\n"
      assert File.stat!(opts[:dest]).mode |> Bitwise.band(0o777) == 0o755
      assert File.read!(Path.join(tmp_dir, "cargo-args")) == "build --release --locked\n"
    end

    test "builds for an explicit target, never silently for the host", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "package")
      File.mkdir_p!(Path.join(root, "native/pgp_port"))
      target = "riscv64gc-unknown-linux-gnu"
      opts = [dest: Path.join(tmp_dir, "priv/bin/pgp_port"), root: root, target: target, cargo: fake_cargo(tmp_dir)]

      assert Installer.install(opts) == {:ok, :built}
      assert File.read!(Path.join(tmp_dir, "cargo-args")) == "build --release --locked --target #{target}\n"
      assert File.read!(opts[:dest]) == "#!/bin/sh\necho built for #{target}\n"
    end

    test "build_from_source skips the download even when an artifact exists", %{tmp_dir: tmp_dir} do
      root = Path.join(tmp_dir, "package")
      File.mkdir_p!(Path.join(root, "native/pgp_port"))
      write_checksums(root, %{@artifact => "sha256:" <> String.duplicate("0", 64)})

      opts = [
        dest: Path.join(tmp_dir, "priv/bin/pgp_port"),
        root: root,
        target: @target,
        cargo: fake_cargo(tmp_dir),
        build_from_source: true,
        artifact_base_url: "http://127.0.0.1:1"
      ]

      assert Installer.install(opts) == {:ok, :built}
    end

    test "fails with every option when there is no artifact and no cargo", %{tmp_dir: tmp_dir} do
      opts = [
        dest: Path.join(tmp_dir, "priv/bin/pgp_port"),
        root: tmp_dir,
        target: "riscv64gc-unknown-linux-gnu",
        cargo: nil
      ]

      assert {:error, message} = Installer.install(opts)
      assert message =~ "no prebuilt pgp_port for riscv64gc-unknown-linux-gnu"
      assert message =~ "config :rpgp_ex, pgp_port_path:"
      assert message =~ "cargo"
    end

    test "fails when the platform is not recognised and no target is given", %{tmp_dir: tmp_dir} do
      opts = [
        dest: Path.join(tmp_dir, "priv/bin/pgp_port"),
        root: tmp_dir,
        target: nil,
        system_architecture: "win32",
        cargo: nil
      ]

      assert {:error, message} = Installer.install(opts)
      assert message =~ "RPGP_EX_TARGET"
    end
  end

  test "pgp_port_path skips installation entirely", %{tmp_dir: tmp_dir} do
    opts = [dest: Path.join(tmp_dir, "priv/bin/pgp_port"), root: tmp_dir, pgp_port_path: "/usr/local/bin/pgp_port"]

    assert Installer.install(opts) == {:ok, :skipped}
    refute File.exists?(Path.join(tmp_dir, "priv"))
  end

  test "a checksum file that is not a literal map is rejected", %{tmp_dir: tmp_dir} do
    File.write!(Path.join(tmp_dir, "checksums-pgp_port.exs"), ~s|%{"a" => System.cmd("touch", ["x"])}|)
    opts = [dest: Path.join(tmp_dir, "priv/bin/pgp_port"), root: tmp_dir, target: @target, cargo: nil]

    assert {:error, message} = Installer.install(opts)
    assert message =~ "checksums-pgp_port.exs"
  end

  describe "proxy_settings/2" do
    test "reads HTTP_PROXY, HTTPS_PROXY and NO_PROXY" do
      env = %{
        "HTTP_PROXY" => "http://plain.example:3128",
        "https_proxy" => "http://secure.example:8080",
        "NO_PROXY" => "localhost, .internal.example"
      }

      assert Installer.proxy_settings("https://github.com/x", &env[&1]) ==
               {[
                  proxy: {{~c"plain.example", 3128}, [~c"localhost", ~c".internal.example"]},
                  https_proxy: {{~c"secure.example", 8080}, [~c"localhost", ~c".internal.example"]}
                ], []}
    end

    test "passes credentials in the proxy URL as proxy_auth, decoded" do
      env = %{"HTTPS_PROXY" => "http://us%40er:p%3Ass@proxy.example:3128"}

      assert {[https_proxy: {{~c"proxy.example", 3128}, []}], [proxy_auth: {~c"us@er", ~c"p:ss"}]} =
               Installer.proxy_settings("https://github.com/x", &env[&1])
    end

    test "uses the credentials of the proxy that serves the URL's scheme" do
      env = %{"HTTP_PROXY" => "http://a:1@plain.example:3128", "HTTPS_PROXY" => "http://b:2@secure.example:3128"}

      assert {_, [proxy_auth: {~c"b", ~c"2"}]} = Installer.proxy_settings("https://github.com/x", &env[&1])
      assert {_, [proxy_auth: {~c"a", ~c"1"}]} = Installer.proxy_settings("http://mirror.example/x", &env[&1])
    end

    test "a user without a password, and no proxy at all" do
      env = %{"HTTPS_PROXY" => "http://token@proxy.example:3128"}
      assert {_, [proxy_auth: {~c"token", ~c""}]} = Installer.proxy_settings("https://github.com/x", &env[&1])

      assert Installer.proxy_settings("https://github.com/x", fn _ -> nil end) == {[], []}
    end
  end

  ## Helpers

  defp start_httpd(www) do
    {:ok, _} = Application.ensure_all_started(:inets)

    {:ok, pid} =
      :inets.start(:httpd,
        port: 0,
        bind_address: {127, 0, 0, 1},
        server_name: ~c"localhost",
        server_root: String.to_charlist(www),
        document_root: String.to_charlist(www)
      )

    {"http://127.0.0.1:#{:httpd.info(pid)[:port]}", pid}
  end

  defp tarball(entries) do
    path = Path.join(System.tmp_dir!(), "rpgp_ex_installer_#{System.unique_integer([:positive])}.tar.gz")
    {:ok, tar} = :erl_tar.open(String.to_charlist(path), [:write, :compressed])
    for {name, contents} <- entries, do: :ok = :erl_tar.add(tar, contents, String.to_charlist(name), [])
    :ok = :erl_tar.close(tar)
    data = File.read!(path)
    File.rm!(path)
    data
  end

  defp publish(www, root, data) do
    File.write!(Path.join(www, @artifact), data)
    write_checksums(root, %{@artifact => "sha256:" <> Base.encode16(:crypto.hash(:sha256, data), case: :lower)})
  end

  defp write_checksums(root, map), do: File.write!(Path.join(root, "checksums-pgp_port.exs"), inspect(map))

  # Records its arguments and writes target/[TARGET/]release/pgp_port, as cargo would.
  defp fake_cargo(tmp_dir) do
    path = Path.join(tmp_dir, "cargo")

    File.write!(path, """
    #!/bin/sh
    echo "$@" > #{Path.join(tmp_dir, "cargo-args")}
    if [ "$4" = --target ]; then dir="target/$5/release" suffix=" for $5"; else dir=target/release suffix=; fi
    mkdir -p "$dir"
    printf '#!/bin/sh\\necho built%s\\n' "$suffix" > "$dir/pgp_port"
    """)

    File.chmod!(path, 0o755)
    path
  end

  defp ls(dir), do: dir |> File.ls!() |> Enum.sort()
end
