#!/usr/bin/env bash
# Regenerates every fixture with the local gpg. Key generation needs gpg-agent.
# Run from anywhere: test/fixtures/gen.sh
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# Short path: gpg-agent's socket path must stay under ~104 bytes on macOS.
GNUPGHOME=$(mktemp -d /tmp/rpgpfx.XXXXXX)
export GNUPGHOME
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

rm -rf "$DIR/keys" "$DIR/plain" "$DIR/msg"
mkdir -p "$DIR/keys" "$DIR/plain" "$DIR/msg"

# No AEAD algorithm in the preference list => the key does not advertise the AEAD
# feature, so gpg senders fall back to SEIPDv1 unless forced (see keygen.c).
PREFS="AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed"
# Keys that must already be expired are created at this (frozen) time with a 1-day lifetime.
PAST="20200101T000000!"

gpg_batch() { gpg --batch --yes --quiet --pinentry-mode loopback "$@"; }

uid() { echo "rpgp_ex test $1 <$1@rpgp-ex.test>"; }
fpr_of() { gpg --with-colons --list-keys "$1@rpgp-ex.test" | awk -F: '/^fpr/ {print $10; exit}'; }

export_pub() { gpg --armor --export "$(fpr_of "$1")" > "$DIR/keys/$1.pub.asc"; }
export_sec() { gpg_batch --passphrase "$2" --armor --export-secret-keys "$(fpr_of "$1")" > "$DIR/keys/$1.sec.asc"; }

# gen_key NAME PRIMARY_ALGO SUBKEY_ALGO PASSPHRASE: signing primary + encryption subkey, no expiry.
gen_key() {
  local name=$1 primary=$2 sub=$3 pass=$4
  gpg_batch --default-preference-list "$PREFS" --passphrase "$pass" --quick-gen-key "$(uid "$name")" "$primary" sign,cert never
  gpg_batch --passphrase "$pass" --quick-add-key "$(fpr_of "$name")" "$sub" encr never
  export_pub "$name"
  export_sec "$name" "$pass"
}

gen_key cv25519  ed25519 cv25519 ""
gen_key rsa4096  rsa4096 rsa4096 ""
gen_key locked   ed25519 cv25519 "correct horse battery staple"
gen_key stranger ed25519 cv25519 ""
rm "$DIR/keys/stranger.sec.asc"   # we must not hold the stranger's secret key

# A single RSA-4096 primary key that is itself flagged for encryption, with no subkeys.
gpg_batch --default-preference-list "$PREFS" --passphrase "" --quick-gen-key "$(uid rsaonly)" rsa4096 sign,cert,encr never
export_pub rsaonly
export_sec rsaonly ""

# A key that cannot encrypt at all.
gpg_batch --default-preference-list "$PREFS" --passphrase "" --quick-gen-key "$(uid signonly)" ed25519 sign,cert never
export_pub signonly

# The encryption subkey expired; the primary key never expires.
gpg_batch --faked-system-time "$PAST" --default-preference-list "$PREFS" --passphrase "" \
  --quick-gen-key "$(uid expired-sub)" ed25519 sign,cert never
gpg_batch --faked-system-time "$PAST" --passphrase "" --quick-add-key "$(fpr_of expired-sub)" cv25519 encr 1d
export_pub expired-sub

# The primary key expired; its encryption subkey has no expiry of its own.
gpg_batch --faked-system-time "$PAST" --default-preference-list "$PREFS" --passphrase "" \
  --quick-gen-key "$(uid expired-primary)" ed25519 sign,cert 1d
gpg_batch --faked-system-time "$PAST" --passphrase "" --quick-add-key "$(fpr_of expired-primary)" cv25519 encr never
export_pub expired-primary

# The encryption subkey is revoked; the primary key is fine.
gen_key revoked-sub ed25519 cv25519 ""
rm "$DIR/keys/revoked-sub.sec.asc"
# key 1 / revkey / confirm / reason 0 (no reason) / empty description / confirm / save
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' |
  gpg --batch --yes --quiet --pinentry-mode loopback --passphrase "" --command-fd 0 --status-fd 2 \
    --edit-key "$(fpr_of revoked-sub)" 2>/dev/null
export_pub revoked-sub

# The primary key is revoked (its encryption subkey is not), using the revocation certificate
# gpg writes at key creation. The certificate's first line is prefixed with ':' to stop an
# accidental import.
gen_key revoked-primary ed25519 cv25519 ""
rm "$DIR/keys/revoked-primary.sec.asc"
fpr=$(fpr_of revoked-primary)
sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$fpr.rev" | gpg --batch --quiet --import
export_pub revoked-primary

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
enc rsaonly.seipdv1.small.txt.gpg  seipdv1 gpg small.txt rsaonly

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

# Record which encryption container gpg chose for each message. --list-packets also tries to
# decrypt; --pinentry-mode cancel stops it asking for the locked key's passphrase.
for f in "$DIR"/msg/*; do
  kind=$(gpg --batch --pinentry-mode cancel --list-packets "$f" 2>/dev/null | grep -Eo '^:(encrypted data|aead encrypted|ocb encrypted)[^:]*packet' | head -1 || true)
  printf '%s\t%s\n' "$(basename "$f")" "$kind"
done > "$DIR/PACKETS.txt"

# Summary for review: validity (e = expired, r = revoked, - = ok) and capabilities per (sub)key.
echo "gpg $(gpg --version | head -1 | awk '{print $3}'); key validity and capabilities:"
gpg --with-colons --list-keys | awk -F: '$1 == "uid" {print "  " $10} $1 == "pub" || $1 == "sub" {print "    " $1 " validity=" $2 " algo=" $4 " expires=" $7 " caps=" $12}'
echo "fixtures regenerated in $DIR"
