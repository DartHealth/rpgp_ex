use pgp_port::error::{Code, Failure};
use pgp_port::{keys, ops, watchdog};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (line, status) = match run(&args) {
        Ok(mut v) => {
            v["ok"] = json!(true);
            (v, 0)
        }
        Err(f) => (json!({"ok": false, "error": f.code.as_str(), "message": f.message}), 1),
    };
    println!("{line}");
    std::process::exit(status);
}

fn run(args: &[String]) -> Result<Value, Failure> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| Failure::new(Code::Usage, "missing command"))?;
    let flags = Flags::parse(rest)?;
    match cmd.as_str() {
        "recipients" => {
            watchdog::spawn();
            ops::recipients(flags.path("--in")?)
        }
        "decrypt" => ops::decrypt(flags.path("--in")?, flags.path("--out")?, &read_stdin_json()?),
        "encrypt" => ops::encrypt(
            flags.path("--in")?,
            flags.path("--out")?,
            flags.has("--armor"),
            &read_stdin_json()?,
        ),
        "inspect-key" => keys::inspect(&read_stdin_json()?),
        other => Err(Failure::new(Code::Usage, format!("unknown command {other}"))),
    }
}

/// Stdin carries exactly one JSON line; Erlang ports cannot half-close stdin, so we never wait for EOF.
/// After it, stdin stays open for as long as the owner lives; the watchdog treats EOF as its death.
fn read_stdin_json<T: serde::de::DeserializeOwned>() -> Result<T, Failure> {
    let mut line = String::new();
    let n = std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Failure::new(Code::Io, format!("stdin: {e}")))?;
    if n == 0 {
        return Err(Failure::new(Code::Usage, "stdin JSON: no request line"));
    }
    watchdog::spawn();
    serde_json::from_str(&line).map_err(|e| Failure::new(Code::Usage, format!("stdin JSON: {e}")))
}

struct Flags {
    values: HashMap<String, String>,
    switches: HashSet<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let mut values = HashMap::new();
        let mut switches = HashSet::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--armor" => {
                    switches.insert(a.clone());
                }
                "--in" | "--out" => {
                    let v = it
                        .next()
                        .ok_or_else(|| Failure::new(Code::Usage, format!("{a} needs a value")))?;
                    values.insert(a.clone(), v.clone());
                }
                _ => return Err(Failure::new(Code::Usage, format!("unknown argument {a}"))),
            }
        }
        Ok(Self { values, switches })
    }

    fn path(&self, name: &str) -> Result<&Path, Failure> {
        self.values
            .get(name)
            .map(Path::new)
            .ok_or_else(|| Failure::new(Code::Usage, format!("missing {name}")))
    }

    fn has(&self, name: &str) -> bool {
        self.switches.contains(name)
    }
}
