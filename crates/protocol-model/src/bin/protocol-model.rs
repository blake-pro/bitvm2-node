use protocol_model::{ProtocolEvent, ProtocolState, apply_event};
use serde::Serialize;
use std::io::{self, BufRead};

#[derive(Serialize)]
struct StepResult<'a> {
    ok: bool,
    state: &'a ProtocolState,
    error: Option<String>,
}

fn main() {
    let required = std::env::args().nth(1).and_then(|value| value.parse().ok()).unwrap_or(1);
    let mut state = ProtocolState::new(required);
    for line in io::stdin().lock().lines() {
        let line = match line {
            Ok(line) if !line.trim().is_empty() => line,
            Ok(_) => continue,
            Err(error) => {
                eprintln!("failed to read event: {error}");
                std::process::exit(2);
            }
        };
        let event: ProtocolEvent = match serde_json::from_str(&line) {
            Ok(event) => event,
            Err(error) => {
                eprintln!("invalid event JSON: {error}");
                std::process::exit(2);
            }
        };
        match apply_event(&state, event) {
            Ok(next) => {
                state = next;
                println!(
                    "{}",
                    serde_json::to_string(&StepResult { ok: true, state: &state, error: None })
                        .expect("serialize state")
                );
            }
            Err(error) => {
                println!(
                    "{}",
                    serde_json::to_string(&StepResult {
                        ok: false,
                        state: &state,
                        error: Some(error.to_string()),
                    })
                    .expect("serialize state")
                );
            }
        }
    }
}
