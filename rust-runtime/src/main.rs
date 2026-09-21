//! Bounded CLI bridge for metrics, governance, and a durable verified Rust
//! segment store. The established Python event log remains authoritative.

use jarvis_runtime::{live_metrics, open_store, persist_segment, should_defer, Ingest};
use std::io::{self, BufRead};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("metrics") => {
            let m = live_metrics();
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "cpu_pct": m.cpu_pct,
                    "mem_available_pct": m.mem_available_pct,
                    "pressured": m.pressured,
                    "reason": m.reason,
                }))
                .unwrap_or_default()
            );
        }
        Some("defer") => {
            let job = args.get(2).cloned().unwrap_or_default();
            let pressured = args
                .get(3)
                .map(|s| s == "1" || s == "true")
                .unwrap_or(false);
            println!("{}", should_defer(&job, pressured));
        }
        Some("ingest") => {
            // JSON events on stdin are durably sealed beneath the supplied
            // root. The existing chain is fully verified before extension.
            let root = match args.get(2) {
                Some(value) => Path::new(value),
                None => {
                    eprintln!("ingest requires a store root");
                    std::process::exit(2);
                }
            };
            let state = match open_store(root) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("cannot open runtime store: {error}");
                    std::process::exit(1);
                }
            };
            let mut ing = Ingest::new(
                state.sealed_through,
                &state.previous_hash,
                state.next_segment,
            );
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(ev) => match ing.push(ev) {
                        Ok(seq) => {
                            println!("{{\"ok\":true,\"seq\":{seq}}}");
                            if ing.due() {
                                if let Err(error) = seal_to(root, &mut ing) {
                                    eprintln!("failed to persist segment: {error}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(e) => println!("{{\"ok\":false,\"error\":{}}}", serde_json::json!(e)),
                    },
                    Err(e) => println!(
                        "{{\"ok\":false,\"error\":{}}}",
                        serde_json::json!(e.to_string())
                    ),
                }
            }
            if let Err(error) = seal_to(root, &mut ing) {
                eprintln!("failed to persist segment: {error}");
                std::process::exit(1);
            }
            println!(
                "{}",
                serde_json::json!({
                    "ok": true, "persisted": true, "last_seq": ing.next_seq,
                    "next_segment": ing.segment_no,
                })
            );
        }
        Some("verify") => {
            let root = match args.get(2) {
                Some(value) => Path::new(value),
                None => {
                    eprintln!("verify requires a store root");
                    std::process::exit(2);
                }
            };
            match open_store(root) {
                Ok(state) => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true, "segments": state.segments,
                        "last_seq": state.sealed_through,
                        "head": state.previous_hash,
                    })
                ),
                Err(error) => {
                    eprintln!("verification failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: jarvis-runtime (metrics|defer <job> <pressured>|ingest <root>|verify <root>)");
            std::process::exit(2);
        }
    }
}

fn seal_to(root: &Path, ing: &mut Ingest) -> Result<(), String> {
    if let Some((header, compressed)) = ing.seal()? {
        persist_segment(root, &header, &compressed)?;
    }
    Ok(())
}
