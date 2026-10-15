defmodule RpgpEx.ApplicationTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  @fakes Path.expand("../support/fakes", __DIR__)

  test "the installed pgp_port is the version this rpgp_ex was built for" do
    assert RpgpEx.Application.check_pgp_port() == :ok
  end

  test "warns about a pgp_port from another version" do
    binary = Path.join(@fakes, "old_version.sh")

    log =
      capture_log(fn -> assert RpgpEx.Application.check_pgp_port(binary: binary) == {:mismatch, "0.0.1"} end)

    assert log =~ "rpgp_ex expects pgp_port #{RpgpEx.Installer.pgp_port_version()}"
    assert log =~ "old_version.sh is 0.0.1"
  end

  test "warns when pgp_port cannot run" do
    log =
      capture_log(fn ->
        assert {:error, %RpgpEx.Error{}} = RpgpEx.Application.check_pgp_port(binary: "/nonexistent/pgp_port")
      end)

    assert log =~ "rpgp_ex cannot run pgp_port --version"
  end
end
