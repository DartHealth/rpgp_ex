defmodule RpgpExTest do
  use ExUnit.Case, async: true

  alias RpgpEx.Error

  @moduletag :tmp_dir
  @fixtures Path.expand("fixtures", __DIR__)
  @fakes Path.expand("support/fakes", __DIR__)

  defp fixture(rel), do: Path.join(@fixtures, rel)
  defp key(name), do: File.read!(fixture("keys/#{name}"))
  defp fake(name), do: Path.join(@fakes, name)

  # The shell's built-in kill, like PortRunner: slim images have no kill executable.
  defp os_alive?(os_pid),
    do: match?({_, 0}, System.cmd("/bin/sh", ["-c", ~s(kill -0 "$1"), "sh", os_pid], stderr_to_stdout: true))

  # Polls `fun` every 20 ms; returns its first truthy value, or nil after `timeout_ms`.
  defp wait_until(fun, timeout_ms), do: poll(fun, System.monotonic_time(:millisecond) + timeout_ms)

  defp poll(fun, deadline) do
    cond do
      value = fun.() -> value
      System.monotonic_time(:millisecond) > deadline -> nil
      true -> Process.sleep(20) && poll(fun, deadline)
    end
  end

  # sleep_with_partial.sh writes the pid file after OUT.partial, so it proves OUT.partial existed.
  defp read_os_pid(pid_file) do
    wait_until(
      fn ->
        case File.read(pid_file) do
          {:ok, contents} -> if contents =~ ~r/^\d+\n$/, do: String.trim(contents)
          _ -> nil
        end
      end,
      3_000
    )
  end

  test "recipients/1 lists both key IDs" do
    assert {:ok, %{"recipients" => ids}} = RpgpEx.recipients(fixture("msg/both.seipdv1.small.txt.gpg"))
    assert length(ids) == 2
  end

  test "decrypt_file/4 handles gpg OCB and SEIPDv1 output", %{tmp_dir: tmp} do
    for mode <- ~w(ocb seipdv1) do
      out = Path.join(tmp, mode)
      msg = fixture("msg/cv25519.#{mode}.small.txt.asc")
      assert {:ok, %{"matched_key" => _}} = RpgpEx.decrypt_file(msg, out, [key("cv25519.sec.asc")])
      assert File.read!(out) == File.read!(fixture("plain/small.txt"))
    end
  end

  test "decrypt_file/4 error codes", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")

    assert {:error, %Error{code: :no_matching_key}} =
             RpgpEx.decrypt_file(fixture("msg/stranger.seipdv1.small.txt.gpg"), out, [key("cv25519.sec.asc")])

    assert {:error, %Error{code: :bad_passphrase}} =
             RpgpEx.decrypt_file(fixture("msg/locked.ocb.small.txt.gpg"), out, [key("locked.sec.asc")],
               passphrase: "wrong"
             )

    assert {:error, %Error{code: :integrity_check_failed}} =
             RpgpEx.decrypt_file(fixture("msg/tampered.seipdv1.random.bin.gpg"), out, [key("cv25519.sec.asc")])

    refute File.exists?(out)
    refute File.exists?(out <> ".partial")
  end

  test "encrypt_file/4 round trips and can armor", %{tmp_dir: tmp} do
    enc = Path.join(tmp, "msg.asc")
    out = Path.join(tmp, "plain")

    assert {:ok, %{"recipients" => [_]}} =
             RpgpEx.encrypt_file(fixture("plain/random.bin"), enc, [key("rsa4096.pub.asc")], armor: true)

    assert "-----BEGIN PGP MESSAGE-----" <> _ = File.read!(enc)
    assert {:ok, _} = RpgpEx.decrypt_file(enc, out, [key("rsa4096.sec.asc")])
    assert File.read!(out) == File.read!(fixture("plain/random.bin"))
  end

  test "inspect_key/1 reports the chosen encryption subkey" do
    assert {:ok, %{"fingerprint" => fpr, "encryption_key_id" => sub}} = RpgpEx.inspect_key(key("cv25519.pub.asc"))
    assert byte_size(fpr) == 40
    assert byte_size(sub) == 16
  end

  test "inspect_key/1 returns timestamps as DateTimes" do
    assert {:ok, %{"created_at" => %DateTime{}, "expires_at" => nil, "subkeys" => [subkey]}} =
             RpgpEx.inspect_key(key("cv25519.pub.asc"))

    assert %{"created_at" => %DateTime{}, "expires_at" => nil} = subkey

    assert {:ok, %{"expires_at" => %DateTime{} = expired, "can_encrypt" => false}} =
             RpgpEx.inspect_key(key("expired-primary.pub.asc"))

    assert DateTime.before?(expired, DateTime.utc_now())
  end

  test "encrypt_file/4 says why a recipient key cannot be used", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")

    for {name, code} <- [
          {"expired-sub", :key_expired},
          {"revoked-primary", :key_revoked},
          {"signonly", :no_encryption_key}
        ] do
      assert {:error, %Error{code: ^code}} =
               RpgpEx.encrypt_file(fixture("plain/small.txt"), out, [key("#{name}.pub.asc")]),
             name

      refute File.exists?(out)
    end
  end

  test "exit 1 without a JSON line is :crashed" do
    assert {:error, %Error{code: :crashed}} =
             RpgpEx.recipients(fixture("msg/both.seipdv1.small.txt.gpg"), binary: "/usr/bin/false")
  end

  test "timeouts kill the process and remove partial output", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")
    on_exit(fn -> File.rm(out <> ".pid") end)

    assert {:error, %Error{code: :timeout}} =
             RpgpEx.decrypt_file(fixture("msg/cv25519.seipdv1.small.txt.gpg"), out, [key("cv25519.sec.asc")],
               binary: fake("sleep_with_partial.sh"),
               timeout: 300
             )

    assert File.exists?(out <> ".pid")
    refute File.exists?(out <> ".partial")
    refute os_alive?(read_os_pid(out <> ".pid"))
  end

  test "a killed process is :crashed and its partial output is removed", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")

    assert {:error, %Error{code: :crashed, message: "exit 137" <> _}} =
             RpgpEx.decrypt_file(fixture("msg/cv25519.seipdv1.small.txt.gpg"), out, [key("cv25519.sec.asc")],
               binary: fake("crash_with_partial.sh")
             )

    refute File.exists?(out <> ".partial")
  end

  test "exiting before draining a large stdin payload returns :crashed instead of killing the caller", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")
    # ~200 KB, several times a pipe buffer: the write can fail with EPIPE.
    keys = List.duplicate(key("rsa4096.sec.asc"), 30)

    # Whether a run hits EPIPE or sees the exit status first is timing-dependent; the test
    # process surviving to collect the results is the point.
    messages =
      for _ <- 1..10 do
        assert {:error, %Error{code: :crashed, message: message}} =
                 RpgpEx.decrypt_file(fixture("msg/cv25519.seipdv1.small.txt.gpg"), out, keys,
                   binary: fake("exit_early.sh")
                 )

        message
      end

    assert "port exited: :epipe" in messages, inspect(Enum.frequencies(messages))
  end

  test "killing the caller kills the process and removes partial output", %{tmp_dir: tmp} do
    out = Path.join(tmp, "out")
    on_exit(fn -> File.rm(out <> ".pid") end)
    msg = fixture("msg/cv25519.seipdv1.small.txt.gpg")
    keys = [key("cv25519.sec.asc")]

    caller =
      spawn(fn -> RpgpEx.decrypt_file(msg, out, keys, binary: fake("sleep_with_partial.sh"), timeout: 10_000) end)

    assert os_pid = read_os_pid(out <> ".pid")
    assert File.exists?(out <> ".pid")
    Process.exit(caller, :kill)

    assert wait_until(fn -> not os_alive?(os_pid) and not File.exists?(out <> ".partial") end, 3_000),
           "OS process #{os_pid} alive: #{os_alive?(os_pid)}, OUT.partial exists: #{File.exists?(out <> ".partial")}"
  end

  describe "malformed pgp_port output is :crashed" do
    defp recipients_printing(tmp, stdout, status) do
      in_path = Path.join(tmp, "stdout")
      File.write!(in_path, stdout)
      File.write!(in_path <> ".status", Integer.to_string(status))
      RpgpEx.recipients(in_path, binary: fake("stdout_from_in.sh"))
    end

    test "a non-string message", %{tmp_dir: tmp} do
      assert {:error, %Error{code: :crashed}} =
               recipients_printing(tmp, ~s({"ok":false,"error":"io","message":42}\n), 1)
    end

    test "raw stdout in the message is truncated to 200 bytes", %{tmp_dir: tmp} do
      assert {:error, %Error{code: :crashed, message: message}} =
               recipients_printing(tmp, String.duplicate("x", 1_000), 2)

      assert message == "exit 2: " <> String.duplicate("x", 200)
    end

    test "stdout beyond 64 KiB", %{tmp_dir: tmp} do
      assert {:error, %Error{code: :crashed, message: "stdout exceeded 65536 bytes"}} =
               recipients_printing(tmp, String.duplicate("x", 100_000), 0)
    end
  end

  test "a well-formed failure leaves a pre-existing OUT.partial alone", %{tmp_dir: tmp} do
    # Another decrypt to the same OUT owns this file; pgp_port's create_new refuses to touch it.
    out = Path.join(tmp, "out")
    File.write!(out <> ".partial", "KEEP")

    assert {:error, %Error{code: :io}} =
             RpgpEx.decrypt_file(fixture("msg/cv25519.seipdv1.small.txt.gpg"), out, [key("cv25519.sec.asc")])

    assert File.read!(out <> ".partial") == "KEEP"
  end

  test "no port or worker messages leak into the caller's mailbox", %{tmp_dir: tmp} do
    Process.flag(:trap_exit, true)
    out = Path.join(tmp, "out")
    on_exit(fn -> File.rm(out <> ".pid") end)
    msg = fixture("msg/cv25519.seipdv1.small.txt.gpg")
    keys = [key("cv25519.sec.asc")]

    assert {:ok, _} = RpgpEx.decrypt_file(msg, out, keys)
    File.rm!(out)

    assert {:error, %Error{code: :timeout}} =
             RpgpEx.decrypt_file(msg, out, keys, binary: fake("sleep_with_partial.sh"), timeout: 300)

    assert {:error, %Error{code: :crashed}} = RpgpEx.decrypt_file(msg, out, keys, binary: fake("crash_with_partial.sh"))

    assert Process.info(self(), :messages) == {:messages, []}
  end

  test "timeout must be a non-negative integer" do
    for timeout <- [:infinity, -1, 1.5] do
      assert_raise ArgumentError, fn -> RpgpEx.inspect_key(key("cv25519.pub.asc"), timeout: timeout) end
    end
  end

  @tag :gpg_agent
  test "GnuPG decrypts what encrypt_file/4 produces", %{tmp_dir: tmp} do
    # Short GNUPGHOME: gpg-agent's socket path must stay under ~104 bytes on macOS.
    home = "/tmp/gs#{System.unique_integer([:positive])}"
    File.mkdir_p!(home)
    File.chmod!(home, 0o700)
    env = [{"GNUPGHOME", home}]

    on_exit(fn ->
      try do
        System.cmd("gpgconf", ["--kill", "gpg-agent"], env: env, stderr_to_stdout: true)
      rescue
        _ -> :ok
      end

      File.rm_rf!(home)
    end)

    # Keys are generated inside GNUPGHOME: gpg 2.5.24 cannot use a cv25519 secret subkey after
    # an export/import round trip (keygrip mismatch).
    gpg_batch = ~w(--batch --quiet --pinentry-mode loopback --passphrase) ++ [""]

    # {name, primary algorithm, primary usage, encryption subkey algorithm or nil}. The last is a
    # single RSA-4096 primary key flagged for encryption, with no subkeys.
    shapes = [
      {"cv25519", "ed25519", "sign,cert", "cv25519"},
      {"rsa4096", "rsa4096", "sign,cert", "rsa4096"},
      {"rsaonly", "rsa4096", "sign,cert,encr", nil}
    ]

    for {algo, primary, usage, subkey} <- shapes do
      uid = "Smoke #{algo} <#{algo}@smoke.test>"
      {_, 0} = System.cmd("gpg", gpg_batch ++ ["--quick-gen-key", uid, primary, usage, "never"], env: env)
      {listing, 0} = System.cmd("gpg", ["--with-colons", "--list-keys", "#{algo}@smoke.test"], env: env)
      [fpr | _] = for "fpr:" <> _ = line <- String.split(listing, "\n"), do: Enum.at(String.split(line, ":"), 9)

      if subkey,
        do: {_, 0} = System.cmd("gpg", gpg_batch ++ ["--quick-add-key", fpr, subkey, "encr", "never"], env: env)

      {public_key, 0} = System.cmd("gpg", ["--armor", "--export", fpr], env: env)

      enc = Path.join(tmp, "#{algo}.gpg")
      assert {:ok, _} = RpgpEx.encrypt_file(fixture("plain/random.bin"), enc, [public_key])
      assert {plain, 0} = System.cmd("gpg", ["--batch", "--quiet", "--decrypt", enc], env: env)
      assert plain == File.read!(fixture("plain/random.bin"))
    end
  end

  @tag :large
  @tag timeout: 1_800_000
  test "1 GiB decrypt: BEAM memory stays flat (pgp_port RSS is measured by bench/measure.sh)", %{tmp_dir: tmp} do
    plain = Path.join(tmp, "plain")
    enc = Path.join(tmp, "enc")
    out = Path.join(tmp, "out")
    assert {_, 0} = System.cmd("sh", ["-c", "head -c 1073741824 /dev/urandom > \"$1\"", "sh", plain])
    assert {:ok, _} = RpgpEx.encrypt_file(plain, enc, [key("cv25519.pub.asc")], timeout: 900_000)

    :erlang.garbage_collect()
    baseline = {:erlang.memory(:total), :erlang.memory(:binary)}
    sampler = Task.async(fn -> sample_peak(baseline) end)
    assert {:ok, _} = RpgpEx.decrypt_file(enc, out, [key("cv25519.sec.asc")], timeout: 900_000)
    send(sampler.pid, :stop)
    {peak, peak_binary} = Task.await(sampler)

    {total, binary} = baseline
    mb = &div(&1, 1_048_576)

    IO.puts(
      "BEAM total baseline #{mb.(total)} MB, peak #{mb.(peak)} MB; binary baseline #{mb.(binary)} MB, peak #{mb.(peak_binary)} MB"
    )

    assert peak - total < 50 * 1_048_576
    assert {_, 0} = System.cmd("cmp", [plain, out])
  end

  defp sample_peak({total, binary} = peak) do
    receive do
      :stop -> peak
    after
      100 -> sample_peak({max(total, :erlang.memory(:total)), max(binary, :erlang.memory(:binary))})
    end
  end
end
