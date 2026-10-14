#!/usr/bin/env bash
# Regenerates every fixture with the local gpg. Needs gpg-agent, so it cannot
# run inside the Claude Code sandbox: run it yourself with `! fixtures/gen.sh`.
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/pgpfx.XXXXXX")
export GNUPGHOME
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

rm -rf "$DIR/keys" "$DIR/plain" "$DIR/msg"
mkdir -p "$DIR/keys" "$DIR/plain" "$DIR/msg"

# No AEAD algorithm in the preference list => the key does not advertise the AEAD
# feature, so gpg senders fall back to SEIPDv1 unless forced (see keygen.c).
PREFS="AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed"

gpg_batch() { gpg --batch --yes --quiet --pinentry-mode loopback "$@"; }

gen_key() {
  local name=$1 primary=$2 sub=$3 pass=$4 fpr
  gpg_batch --default-preference-list "$PREFS" --passphrase "$pass" --quick-gen-key "Spike $name <$name@spike.test>" "$primary" sign,cert never
  fpr=$(gpg --with-colons --list-keys "$name@spike.test" | awk -F: '/^fpr/ {print $10; exit}')
  gpg_batch --passphrase "$pass" --quick-add-key "$fpr" "$sub" encr never
  gpg --armor --export "$fpr" > "$DIR/keys/$name.pub.asc"
  gpg_batch --passphrase "$pass" --armor --export-secret-keys "$fpr" > "$DIR/keys/$name.sec.asc"
}

gen_key cv25519  ed25519 cv25519 ""
gen_key rsa4096  rsa4096 rsa4096 ""
gen_key locked   ed25519 cv25519 "correct horse battery staple"
gen_key stranger ed25519 cv25519 ""
rm "$DIR/keys/stranger.sec.asc"   # we must not hold the stranger's secret key

for i in $(seq 1 200); do echo "member-$i,O'Brien,gold"; done > "$DIR/plain/small.txt"
head -c 65536 /dev/urandom > "$DIR/plain/random.bin"

# enc OUT MODE EXT INPUT KEY...
enc() {
  local out=$1 mode=$2 ext=$3 input=$4; shift 4
  local args=()
  if [[ $mode == ocb ]]; then args+=(--force-ocb); fi
  if [[ $ext == asc ]]; then args+=(--armor); fi
  for k in "$@"; do args+=(--recipient-file "$DIR/keys/$k.pub.asc"); done
  gpg_batch "${args[@]}" --output "$DIR/msg/$out" --encrypt "$DIR/plain/$input"
}

for key in cv25519 rsa4096; do
  for mode in ocb seipdv1; do
    for input in small.txt random.bin; do
      for ext in gpg asc; do
        enc "$key.$mode.$input.$ext" "$mode" "$ext" "$input" "$key"
      done
    done
  done
done
enc both.seipdv1.small.txt.gpg     seipdv1 gpg small.txt cv25519 rsa4096
enc locked.ocb.small.txt.gpg       ocb     gpg small.txt locked
enc stranger.seipdv1.small.txt.gpg seipdv1 gpg small.txt stranger

# Flip one bit near the end: the MDC (SEIPDv1) or the final OCB tag.
tamper() {
  python3 - "$DIR/msg/$1" "$DIR/msg/$2" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[-3] ^= 0x01
open(sys.argv[2], "wb").write(data)
PY
}
tamper cv25519.seipdv1.random.bin.gpg tampered.seipdv1.random.bin.gpg
tamper cv25519.ocb.random.bin.gpg tampered.ocb.random.bin.gpg

# Record which encryption container gpg chose for each message.
for f in "$DIR"/msg/*; do
  kind=$(gpg --batch --list-packets "$f" 2>/dev/null | grep -Eo '^:(encrypted data|aead encrypted|ocb encrypted)[^:]*packet' | head -1 || true)
  printf '%s\t%s\n' "$(basename "$f")" "$kind"
done > "$DIR/PACKETS.txt"

echo "fixtures regenerated in $DIR"
