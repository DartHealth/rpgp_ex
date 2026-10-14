defmodule RpgpEx.Port.Runner do
  @moduledoc false

  # Each call runs in its own worker process, which owns the port and traps exits:
  #   * a port that dies with :epipe (pgp_port exited before draining stdin) cannot take the
  #     caller down with it, and no port messages reach the caller's mailbox;
  #   * the worker monitors the caller and kills pgp_port if the caller dies (pgp_port's
  #     stdin-EOF watchdog is the second line of defence).

  alias RpgpEx.Error

  @default_timeout 60_000
  # How long to wait for the OS to report a killed pgp_port's exit before cleaning up anyway.
  @kill_wait 1_000
  # The caller's own deadline beyond `timeout`, in case the worker itself gets stuck.
  @caller_margin @kill_wait + 4_000
  # pgp_port prints one short JSON line; anything longer is a malfunction.
  @max_output 64 * 1024
  @max_crash_output 200

  @spec run([String.t()], map() | nil, keyword()) :: {:ok, map()} | {:error, Error.t()}
  def run(args, payload, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    unless is_integer(timeout) and timeout >= 0 do
      raise ArgumentError, "timeout must be a non-negative integer (ms), got: #{inspect(timeout)}"
    end

    caller = self()
    reply_to = Process.alias()
    {worker, monitor} = spawn_monitor(fn -> send(reply_to, {reply_to, work(caller, args, payload, opts, timeout)}) end)

    # The worker cleans up OUT.partial itself; only if it died or had to be killed do we.
    result =
      receive do
        {^reply_to, result} ->
          result

        {:DOWN, ^monitor, :process, ^worker, reason} ->
          discard(crashed("worker exited: #{inspect(reason)}"), opts)
      after
        timeout + @caller_margin ->
          Process.exit(worker, :kill)

          discard(
            {:error, %Error{code: :timeout, message: "pgp_port exceeded #{timeout} ms (worker unresponsive)"}},
            opts
          )
      end

    # Unaliasing stops later replies; flush one that arrived before it.
    Process.unalias(reply_to)

    receive do
      {^reply_to, _} -> :ok
    after
      0 -> :ok
    end

    Process.demonitor(monitor, [:flush])
    result
  end

  # Runs in the worker process.
  defp work(caller, args, payload, opts, timeout) do
    Process.flag(:trap_exit, true)
    caller_ref = Process.monitor(caller)
    deadline = System.monotonic_time(:millisecond) + timeout

    case open(opts, args) do
      {:ok, port} ->
        if payload, do: write(port, [JSON.encode!(payload), "\n"])
        port |> collect(caller_ref, [], 0, deadline) |> finish(port, opts, timeout)

      # Nothing ran, so any OUT.partial belongs to someone else.
      {:error, reason} ->
        crashed("cannot start #{binary(opts)}: #{inspect(reason)}")
    end
  end

  defp open(opts, args) do
    {:ok, Port.open({:spawn_executable, binary(opts)}, [:binary, :exit_status, :use_stdio, args: args])}
  rescue
    e in ErlangError -> {:error, e.original}
  end

  # One write only: the first command to a port is queued even if it exceeds the busy limit,
  # so this never suspends the worker. The port may already be gone (fast exit).
  defp write(port, data) do
    Port.command(port, data)
  rescue
    ArgumentError -> :ok
  end

  defp collect(port, caller_ref, acc, size, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        size = size + byte_size(data)

        if size > @max_output,
          do: :output_too_large,
          else: collect(port, caller_ref, [acc, data], size, deadline)

      {^port, {:exit_status, status}} ->
        {:exit, status, IO.iodata_to_binary(acc)}

      # An exit_status always arrives before the port's own :EXIT, so this is a port failure
      # such as :epipe (pgp_port closed stdin before we finished writing). No kill here: the
      # port is dead, so Port.info has no os_pid, a pid saved earlier may already be reused, and
      # pgp_port's stdin watchdog exits on its own now that its stdin is closed.
      {:EXIT, ^port, reason} ->
        {:port_exit, reason}

      {:DOWN, ^caller_ref, :process, _, _} ->
        :caller_down
    after
      remaining -> :timeout
    end
  end

  # A well-formed result (exit 0/1 with a JSON line) means pgp_port cleaned up after itself.
  # Its OUT.partial is only ours to remove if it crashed; an `io` error may even mean the file
  # belongs to a concurrent decrypt to the same OUT (pgp_port's create_new refused it).
  defp finish({:exit, status, output}, _port, opts, _timeout) do
    case interpret(status, output) do
      {:error, %Error{code: :crashed}} = crash -> discard(crash, opts)
      result -> result
    end
  end

  defp finish({:port_exit, reason}, _port, opts, _timeout),
    do: discard(crashed("port exited: #{inspect(reason)}"), opts)

  defp finish(:timeout, port, opts, timeout) do
    kill(port)
    discard({:error, %Error{code: :timeout, message: "pgp_port exceeded #{timeout} ms"}}, opts)
  end

  defp finish(:output_too_large, port, opts, _timeout) do
    kill(port)
    discard(crashed("stdout exceeded #{@max_output} bytes"), opts)
  end

  # Nobody is waiting for the result: clean up and go.
  defp finish(:caller_down, port, opts, _timeout) do
    kill(port)
    remove_partial(opts)
    exit(:normal)
  end

  # SIGKILL, then wait (bounded) for the OS to confirm the exit, so OUT.partial is only removed
  # once nothing can write to it any more. Uses /bin/sh's built-in kill: slim container images
  # (e.g. Debian slim) have no kill executable, but the BEAM always needs /bin/sh.
  defp kill(port) do
    with {:os_pid, os_pid} <- Port.info(port, :os_pid) do
      System.cmd("/bin/sh", ["-c", ~s(kill -KILL "$1"), "sh", Integer.to_string(os_pid)], stderr_to_stdout: true)

      receive do
        {^port, {:exit_status, _}} -> :ok
        {:EXIT, ^port, _} -> :ok
      after
        @kill_wait -> :ok
      end
    end
  after
    close(port)
  end

  defp close(port) do
    Port.close(port)
  rescue
    ArgumentError -> :ok
  end

  # A killed or crashed pgp_port can leave OUT.partial (unauthenticated plaintext) behind.
  defp discard(error, opts) do
    remove_partial(opts)
    error
  end

  defp remove_partial(opts) do
    if partial = opts[:partial], do: File.rm(partial)
  end

  @doc false
  def binary(opts) do
    opts[:binary] || Application.get_env(:rpgp_ex, :pgp_port_path) ||
      Application.app_dir(:rpgp_ex, "priv/bin/pgp_port")
  end

  defp interpret(status, output) when status in [0, 1] do
    case JSON.decode(String.trim(output)) do
      {:ok, %{"ok" => true} = result} ->
        {:ok, Map.delete(result, "ok")}

      {:ok, %{"ok" => false, "error" => code, "message" => message}} when is_binary(message) ->
        {:error, Error.from_native(code, message)}

      _ ->
        crashed("exit #{status}: #{truncate(output)}")
    end
  end

  defp interpret(status, output), do: crashed("exit #{status}: #{truncate(output)}")

  defp truncate(output) when byte_size(output) > @max_crash_output,
    do: binary_part(output, 0, @max_crash_output)

  defp truncate(output), do: output

  defp crashed(message), do: {:error, %Error{code: :crashed, message: message}}
end
