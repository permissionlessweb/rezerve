//! Native re-zerve workflow on the forked provider engine.
//! Ask/bid hex → allocate gate → derived bearer accept → foreign deny → close deny.

use std::process::Command;

fn provider_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../akash-provider-pir")
}

#[test]
fn provider_native_market_workflow_go() {
    let root = provider_root();
    if !root.join("go.mod").is_file() {
        panic!("akash-provider-pir missing");
    }
    let go = Command::new("go")
        .args([
            "test",
            "./gateway/pir",
            "./pirgate",
            "./bidengine",
            "-count=1",
            "-timeout",
            "120s",
            "-run",
            "PirAllocation|MarketWorkflow|BearerFileReload|BearerMatches|ServeSpawns|Envelope|Cosmwasm",
        ])
        .current_dir(&root)
        .output();
    match go {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "provider native workflow failed:\n{}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => {
            if std::env::var("PIR_REQUIRE_PROVIDER_ENGINE").ok().as_deref() == Some("1") {
                panic!("go required for provider workflow: {e}");
            }
            eprintln!("skip: go not available ({e})");
        }
    }
}

#[test]
fn rust_lease_book_same_rules_as_provider() {
    use private_inference_rent::{DerivedAccess, LeaseAccessError, LeaseBook};
    let session = [1u8; 32];
    let bid = [2u8; 32];
    let winner = DerivedAccess::from_session("ask-1", &session, &bid);
    let foreign = DerivedAccess::from_session("ask-other", &session, &bid);
    let mut book = LeaseBook::new();
    book.accept_bid("lease-1", winner.bearer_hex());
    assert!(book.access("lease-1", &winner.bearer_hex()).is_ok());
    assert_eq!(
        book.access("lease-1", &foreign.bearer_hex()),
        Err(LeaseAccessError::Unauthorized)
    );
    book.close("lease-1");
    assert_eq!(
        book.access("lease-1", &winner.bearer_hex()),
        Err(LeaseAccessError::Closed)
    );
}
