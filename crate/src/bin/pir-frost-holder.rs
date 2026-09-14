//! One FROST KeyPackage in this OS process. Line protocol on stdin/stdout.

use frost_ed25519::keys::KeyPackage;
use frost_ed25519::{round1, round2, Identifier, SigningPackage};
use private_inference_rent::frost::FrostSeat;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

fn main() {
    let seat_hex = std::env::args()
        .nth(1)
        .expect("usage: pir-frost-holder <seat-hex>");
    let seat = FrostSeat::decode(&seat_hex).expect("decode seat");
    let pkg_hex = seat_hex.split_once(':').expect("fmt").1;
    let package = KeyPackage::deserialize(&hex::decode(pkg_hex).expect("hex")).expect("pkg");
    let identifier = Identifier::deserialize(&seat.identifier_bytes()).expect("id");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut nonce = None;
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let line = line.trim();
        if line == "COMMIT" {
            let (n, c) = round1::commit(package.signing_share(), &mut OsRng);
            nonce = Some(n);
            let bytes = c.serialize().expect("commit ser");
            writeln!(stdout, "C {}", hex::encode(bytes)).unwrap();
            stdout.flush().unwrap();
        } else if let Some(rest) = line.strip_prefix("SIGN ") {
            let n = nonce.take().expect("COMMIT first");
            let (msg_hex, rest) = rest.split_once(' ').expect("SIGN msg commits");
            let msg = hex::decode(msg_hex).expect("msg");
            let mut commits = BTreeMap::new();
            for part in rest.split(',') {
                let (idh, ch) = part.split_once(':').expect("id:c");
                let id = Identifier::deserialize(&hex::decode(idh).unwrap()).unwrap();
                let c = round1::SigningCommitments::deserialize(&hex::decode(ch).unwrap()).unwrap();
                commits.insert(id, c);
            }
            let pkg = SigningPackage::new(commits, &msg);
            let sh = round2::sign(&pkg, &n, &package).expect("round2");
            writeln!(stdout, "S {}", hex::encode(sh.serialize())).unwrap();
            stdout.flush().unwrap();
        } else if line == "QUIT" {
            break;
        }
        let _ = identifier;
    }
}
