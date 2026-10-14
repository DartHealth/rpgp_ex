use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/fixtures")
        .join(rel)
}

fn key(name: &str) -> String {
    std::fs::read_to_string(fixture(&format!("keys/{name}"))).unwrap()
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Runs pgp_port, writing `stdin` as one JSON line, and returns (stdout JSON, exit code).
/// Like an Erlang port, stdin stays open until pgp_port exits: EOF on stdin means "owner gone".
fn run(args: &[&str], stdin: Option<Value>) -> (Value, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pgp_port"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child_stdin = child.stdin.take().unwrap();
    if let Some(v) = stdin {
        writeln!(child_stdin, "{v}").unwrap();
    }
    let mut line = String::new();
    child.stdout.take().unwrap().read_to_string(&mut line).unwrap();
    let status = child.wait().unwrap();
    drop(child_stdin);
    let value =
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("stdout was not one JSON line: {line:?}: {e}"));
    (value, status.code().unwrap_or(-1))
}

#[test]
fn unknown_command_is_a_usage_error() {
    let (v, status) = run(&["frobnicate"], None);
    assert_eq!(status, 1);
    assert_eq!(v["ok"], json!(false));
    assert_eq!(v["error"], json!("usage"));
}

fn inspect(name: &str) -> Value {
    let (v, status) = run(&["inspect-key"], Some(json!({"key": key(name)})));
    assert_eq!(status, 0, "{v}");
    v
}

#[test]
fn inspect_key_picks_the_encryption_subkey() {
    for name in ["cv25519.pub.asc", "rsa4096.pub.asc"] {
        let v = inspect(name);
        assert_eq!(v["fingerprint"].as_str().unwrap().len(), 40, "{v}");
        let subkeys = v["subkeys"].as_array().unwrap();
        assert_eq!(subkeys.len(), 1, "{v}");
        assert_eq!(v["encryption_subkey"], subkeys[0]["key_id"], "{v}");
    }
}

#[test]
fn recipients_lists_every_pkesk_key_id() {
    let (v, status) = run(
        &["recipients", "--in", p(&fixture("msg/both.seipdv1.small.txt.gpg"))],
        None,
    );
    assert_eq!(status, 0, "{v}");
    let mut got: Vec<String> = serde_json::from_value(v["recipients"].clone()).unwrap();
    let mut want = vec![
        inspect("cv25519.pub.asc")["encryption_subkey"]
            .as_str()
            .unwrap()
            .to_string(),
        inspect("rsa4096.pub.asc")["encryption_subkey"]
            .as_str()
            .unwrap()
            .to_string(),
    ];
    got.sort();
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn recipients_reads_armored_messages() {
    let (v, status) = run(
        &["recipients", "--in", p(&fixture("msg/cv25519.ocb.small.txt.asc"))],
        None,
    );
    assert_eq!(status, 0, "{v}");
    assert_eq!(v["recipients"].as_array().unwrap().len(), 1);
}

#[test]
fn recipients_rejects_non_messages() {
    let (v, status) = run(&["recipients", "--in", p(&fixture("plain/random.bin"))], None);
    assert_eq!(status, 1);
    assert_eq!(v["error"], json!("malformed"), "{v}");
}

fn decrypt(msg: &str, keys: &[&str], passphrase: Option<&str>, out: &Path) -> (Value, i32) {
    decrypt_path(&fixture(msg), keys, passphrase, out)
}

fn decrypt_path(msg: &Path, keys: &[&str], passphrase: Option<&str>, out: &Path) -> (Value, i32) {
    let secret_keys: Vec<String> = keys.iter().map(|k| key(k)).collect();
    run(
        &["decrypt", "--in", p(msg), "--out", p(out)],
        Some(json!({"secret_keys": secret_keys, "passphrase": passphrase})),
    )
}

fn partial(out: &Path) -> PathBuf {
    PathBuf::from(format!("{}.partial", out.display()))
}

#[test]
fn decrypts_every_gpg_fixture() {
    let dir = tempfile::tempdir().unwrap();
    for k in ["cv25519", "rsa4096"] {
        for mode in ["ocb", "seipdv1"] {
            for input in ["small.txt", "random.bin"] {
                for ext in ["gpg", "asc"] {
                    let msg = format!("msg/{k}.{mode}.{input}.{ext}");
                    let out = dir.path().join(format!("{k}.{mode}.{input}.{ext}.out"));
                    let (v, status) = decrypt(&msg, &[&format!("{k}.sec.asc")], None, &out);
                    assert_eq!(status, 0, "{msg}: {v}");
                    assert_eq!(
                        std::fs::read(&out).unwrap(),
                        std::fs::read(fixture(&format!("plain/{input}"))).unwrap(),
                        "{msg}"
                    );
                    assert!(!partial(&out).exists());
                }
            }
        }
    }
}

#[test]
fn decrypt_picks_the_matching_key_from_several() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (v, status) = decrypt(
        "msg/rsa4096.seipdv1.small.txt.gpg",
        &["cv25519.sec.asc", "rsa4096.sec.asc"],
        None,
        &out,
    );
    assert_eq!(status, 0, "{v}");
    assert_eq!(v["matched_key"], inspect("rsa4096.pub.asc")["fingerprint"]);
}

#[test]
fn decrypt_reports_no_matching_key() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (v, status) = decrypt("msg/stranger.seipdv1.small.txt.gpg", &["cv25519.sec.asc"], None, &out);
    assert_eq!(status, 1);
    assert_eq!(v["error"], json!("no_matching_key"), "{v}");
    assert!(!out.exists());
}

#[test]
fn decrypt_unlocks_with_passphrase_and_reports_bad_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (v, status) = decrypt(
        "msg/locked.ocb.small.txt.gpg",
        &["locked.sec.asc"],
        Some("correct horse battery staple"),
        &out,
    );
    assert_eq!(status, 0, "{v}");

    let out2 = dir.path().join("out2");
    let (v, status) = decrypt(
        "msg/locked.ocb.small.txt.gpg",
        &["locked.sec.asc"],
        Some("wrong"),
        &out2,
    );
    assert_eq!(status, 1);
    assert_eq!(v["error"], json!("bad_passphrase"), "{v}");
    assert!(!out2.exists());
}

#[test]
fn tampered_messages_fail_integrity_and_leave_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    for mode in ["seipdv1", "ocb"] {
        let out = dir.path().join(format!("{mode}.out"));
        let (v, status) = decrypt(
            &format!("msg/tampered.{mode}.random.bin.gpg"),
            &["cv25519.sec.asc"],
            None,
            &out,
        );
        assert_eq!(status, 1, "{mode}: {v}");
        assert_eq!(v["error"], json!("integrity_check_failed"), "{mode}: {v}");
        assert!(!out.exists(), "{mode}: plaintext left at OUT");
        assert!(!partial(&out).exists(), "{mode}: plaintext left at OUT.partial");
    }
}

fn encrypt(input: &Path, out: &Path, recipients: &[&str], armor: bool) -> (Value, i32) {
    let keys: Vec<String> = recipients.iter().map(|k| key(k)).collect();
    let mut args = vec!["encrypt", "--in", p(input), "--out", p(out)];
    if armor {
        args.push("--armor");
    }
    run(&args, Some(json!({"recipients": keys})))
}

#[test]
fn encrypt_round_trips_through_our_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    for (k, armor) in [("cv25519", false), ("rsa4096", false), ("cv25519", true)] {
        let enc = dir.path().join(format!("{k}.{armor}.pgp"));
        let (v, status) = encrypt(&fixture("plain/random.bin"), &enc, &[&format!("{k}.pub.asc")], armor);
        assert_eq!(status, 0, "{v}");
        assert_eq!(
            v["recipients"][0],
            inspect(&format!("{k}.pub.asc"))["encryption_subkey"]
        );
        if armor {
            assert!(
                std::fs::read_to_string(&enc)
                    .unwrap()
                    .starts_with("-----BEGIN PGP MESSAGE-----")
            );
        }

        let out = dir.path().join(format!("{k}.{armor}.out"));
        let (v, status) = run(
            &["decrypt", "--in", p(&enc), "--out", p(&out)],
            Some(json!({"secret_keys": [key(&format!("{k}.sec.asc"))]})),
        );
        assert_eq!(status, 0, "{v}");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            std::fs::read(fixture("plain/random.bin")).unwrap()
        );
    }
}

#[test]
fn encrypt_to_several_recipients_lists_them_all() {
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("both.pgp");
    let (v, status) = encrypt(
        &fixture("plain/small.txt"),
        &enc,
        &["cv25519.pub.asc", "rsa4096.pub.asc"],
        false,
    );
    assert_eq!(status, 0, "{v}");
    let (r, _) = run(&["recipients", "--in", p(&enc)], None);
    assert_eq!(r["recipients"].as_array().unwrap().len(), 2);
}

#[test]
fn encrypt_requires_a_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let (v, status) = encrypt(&fixture("plain/small.txt"), &dir.path().join("x"), &[], false);
    assert_eq!(status, 1);
    assert_eq!(v["error"], json!("usage"));
}

#[test]
fn truncated_and_corrupted_ciphertexts_fail_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let seipdv1 = std::fs::read(fixture("msg/cv25519.seipdv1.random.bin.gpg")).unwrap();
    let ocb = std::fs::read(fixture("msg/cv25519.ocb.random.bin.gpg")).unwrap();
    let mut junk = seipdv1.clone();
    junk.extend_from_slice(&[0xA5; 16]);
    let mut flipped = seipdv1.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;
    let variants: Vec<(&str, Vec<u8>)> = vec![
        ("seipdv1_truncated_half", seipdv1[..seipdv1.len() / 2].to_vec()),
        ("seipdv1_truncated_in_mdc", seipdv1[..seipdv1.len() - 10].to_vec()),
        ("seipdv1_trailing_junk", junk),
        ("ocb_truncated_half", ocb[..ocb.len() / 2].to_vec()),
        ("seipdv1_bit_flipped", flipped),
    ];
    let mut failures = Vec::new();
    for (name, bytes) in variants {
        let msg = dir.path().join(format!("{name}.gpg"));
        std::fs::write(&msg, bytes).unwrap();
        let out = dir.path().join(format!("{name}.out"));
        let (v, status) = decrypt_path(&msg, &["cv25519.sec.asc"], None, &out);
        let code = v["error"].as_str().unwrap_or("<none>").to_string();
        eprintln!("{name}: status={status} error={code} message={}", v["message"]);
        if status != 1 || !(code == "integrity_check_failed" || code == "malformed") {
            failures.push(format!("{name}: status={status} error={code} ({v})"));
        }
        if out.exists() {
            failures.push(format!("{name}: OUT exists"));
        }
        if partial(&out).exists() {
            failures.push(format!("{name}: OUT.partial exists"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn corrupted_pkesk_with_unprotected_key_is_not_bad_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = std::fs::read(fixture("msg/cv25519.seipdv1.small.txt.gpg")).unwrap();
    bytes[20] ^= 0xFF;
    let msg = dir.path().join("corrupt_pkesk.gpg");
    std::fs::write(&msg, bytes).unwrap();
    let out = dir.path().join("out");
    let (v, status) = decrypt_path(&msg, &["cv25519.sec.asc"], None, &out);
    assert_eq!(status, 1, "{v}");
    assert_ne!(v["error"], json!("bad_passphrase"), "{v}");
    assert_eq!(v["error"], json!("malformed"), "{v}");
    assert!(!out.exists());
    assert!(!partial(&out).exists());
}

#[test]
fn truncated_headers_are_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(fixture("msg/cv25519.seipdv1.small.txt.gpg")).unwrap();
    // Old-format PKESK (tag 1) with a one-byte length.
    assert_eq!(
        bytes[0], 0x84,
        "fixture no longer starts with an old-format one-byte-length PKESK"
    );
    let pkesk_end = 2 + bytes[1] as usize;
    let variants = [
        ("five_byte_prefix", &bytes[..5]),
        ("cut_inside_pkesk", &bytes[..pkesk_end / 2]),
        ("pkesk_without_data", &bytes[..pkesk_end]),
    ];
    let mut failures = Vec::new();
    for (name, data) in variants {
        let msg = dir.path().join(format!("{name}.gpg"));
        std::fs::write(&msg, data).unwrap();

        let (v, status) = run(&["recipients", "--in", p(&msg)], None);
        eprintln!("{name} recipients: status={status} {v}");
        if status != 1 || v["error"] != json!("malformed") {
            failures.push(format!("{name} recipients: status={status} {v}"));
        }

        let out = dir.path().join(format!("{name}.out"));
        let (v, status) = decrypt_path(&msg, &["cv25519.sec.asc"], None, &out);
        eprintln!("{name} decrypt: status={status} {v}");
        if status != 1 || v["error"] != json!("malformed") {
            failures.push(format!("{name} decrypt: status={status} {v}"));
        }
        if out.exists() || partial(&out).exists() {
            failures.push(format!("{name} decrypt: OUT or OUT.partial left behind"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn matched_key_names_the_key_that_decrypted() {
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("three.pgp");
    let (v, status) = encrypt(
        &fixture("plain/small.txt"),
        &enc,
        &["locked.pub.asc", "cv25519.pub.asc", "stranger.pub.asc"],
        false,
    );
    assert_eq!(status, 0, "{v}");

    let out = dir.path().join("out");
    let (v, status) = decrypt_path(&enc, &["locked.sec.asc", "cv25519.sec.asc"], None, &out);
    assert_eq!(status, 0, "{v}");
    assert_eq!(v["matched_key"], inspect("cv25519.pub.asc")["fingerprint"], "{v}");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(fixture("plain/small.txt")).unwrap()
    );
}

#[test]
fn stdin_eof_kills_decrypt_and_removes_partial_output() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain");
    // Relies on the (debug) test build taking seconds to decrypt 64 MiB, far longer than the poll below.
    let mut random = std::fs::File::open("/dev/urandom").unwrap().take(64 << 20);
    std::io::copy(&mut random, &mut std::fs::File::create(&plain).unwrap()).unwrap();
    let enc = dir.path().join("enc");
    let (v, status) = encrypt(&plain, &enc, &["cv25519.pub.asc"], false);
    assert_eq!(status, 0, "{v}");

    let out = dir.path().join("out");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pgp_port"))
        .args(["decrypt", "--in", p(&enc), "--out", p(&out)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", json!({"secret_keys": [key("cv25519.sec.asc")]})).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !partial(&out).exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "decrypt exited before OUT.partial was observed"
        );
        assert!(Instant::now() < deadline, "OUT.partial never appeared");
        std::thread::sleep(Duration::from_millis(1));
    }
    // The owner is gone: stdin reaches EOF while pgp_port is still writing plaintext.
    drop(stdin);
    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(3), "{status}");
    assert!(!partial(&out).exists(), "unauthenticated plaintext left at OUT.partial");
    assert!(!out.exists(), "OUT published after stdin EOF");
}
