//! Tenant or provider process: hold one session key; seal or open. No shared memory.

use private_inference_rent::bid::{EncryptedBidEnvelope, PlaintextBid};
use std::io::{Read, Write};

fn key_from_hex(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim()).expect("key hex");
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    k
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().expect("seal|open");
    let key = key_from_hex(&args.next().expect("session-key-hex"));
    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body).unwrap();
    match cmd.as_str() {
        "seal" => {
            let bid: PlaintextBid = serde_json::from_str(&body).expect("bid json");
            let env = EncryptedBidEnvelope::seal(&bid, &key).expect("seal");
            println!("{}", serde_json::to_string(&env).unwrap());
        }
        "open" => {
            let env: EncryptedBidEnvelope = serde_json::from_str(&body).expect("env json");
            match env.open(&key) {
                Ok(p) => println!("{}", serde_json::to_string(&p).unwrap()),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("usage: pir-party seal|open <key-hex> < json");
            std::process::exit(1);
        }
    }
    let _ = std::io::stdout().flush();
}
