//! Exercise the forked provider engine (`akash-provider-pir`) locally.
//! `cargo test --test provider_engine`

use std::process::Command;

#[test]
fn provider_pir_go_tests() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../akash-provider-pir");
    if !root.join("go.mod").is_file() {
        panic!("akash-provider-pir missing — clone github.com/akash-network/provider");
    }
    let go = Command::new("go")
        .args([
            "test",
            "./gateway/pir",
            "./bidengine",
            "-count=1",
            "-timeout",
            "120s",
            "-run",
            "Bearer|Accept|PirAllocation",
        ])
        .current_dir(&root)
        .output();
    match go {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "go test provider engine failed:\n{}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => {
            if std::env::var("PIR_REQUIRE_PROVIDER_ENGINE").ok().as_deref() == Some("1") {
                panic!("go required: {e}");
            }
            eprintln!("skip: go not available ({e})");
        }
    }
}
