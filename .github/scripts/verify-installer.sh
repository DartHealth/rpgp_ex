#!/usr/bin/env bash
# Installs pgp_port the way a project that depends on rpgp_ex does: from release artifacts,
# checked against checksums-pgp_port.exs, then runs it. The package is this commit as
# `git archive` delivers it.
#
#   .github/scripts/verify-installer.sh DIST
#
# DIST holds the pgp_port-v*.tar.gz files and checksums-pgp_port.exs, and is served on
# 127.0.0.1:$PORT (default 8765) for the duration of the run.
set -euo pipefail

dist=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/verify-installer.XXXXXX")
port=${PORT:-8765}

git -C "$root" archive HEAD --prefix=pkg/ | tar -x -C "$work"
cp "$dist/checksums-pgp_port.exs" "$work/pkg/"

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$dist" >"$work/http.log" 2>&1 &
server=$!
trap 'kill "$server"' EXIT

cd "$work"
mix new consumer >/dev/null
cd consumer
sed -i.bak 's|# {:dep_from_hexpm, "~> 0.3.0"},|{:rpgp_ex, path: "../pkg"},|' mix.exs
grep -q 'rpgp_ex, path:' mix.exs
mkdir -p config
printf 'import Config\nconfig :rpgp_ex, artifact_base_url: "http://127.0.0.1:%s"\n' "$port" >config/config.exs

mix compile 2>&1 | tee "$work/compile.log"
# "installed" means downloaded and verified; "built" would mean cargo ran instead.
grep -q 'rpgp_ex: pgp_port installed' "$work/compile.log"

mix run -e '
:ok = RpgpEx.Application.check_pgp_port()
keys = "../pkg/test/fixtures/keys"
File.write!("in.txt", "rpgp_ex installer check\n")
{:ok, _} = RpgpEx.encrypt_file("in.txt", "out.pgp", [File.read!(Path.join(keys, "cv25519.pub.asc"))])
{:ok, _} = RpgpEx.decrypt_file("out.pgp", "back.txt", [File.read!(Path.join(keys, "cv25519.sec.asc"))])
true = File.read!("back.txt") == File.read!("in.txt")
IO.puts("pgp_port #{RpgpEx.Installer.pgp_port_version()}: installed from the release artifact, round trip OK")
'
