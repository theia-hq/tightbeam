use std::collections::HashSet;

use bifrost::Transport as _;
use bifrost_mem::MemTransport;

use crate::nauthy::{Approvals, Gate};

#[test]
fn open_permits_any_and_strict_restricts() {
    let listed = MemTransport::bind().node_id();
    let other = MemTransport::bind().node_id();

    assert!(Gate::Open.permits(other));

    let strict = Gate::Strict(HashSet::from([listed]));
    assert!(strict.permits(listed));
    assert!(!strict.permits(other));
}

#[tokio::test]
async fn approvals_persist_and_gate_pairs() {
    let path = std::env::temp_dir().join(format!("tightbeam-nauthy-test-{}", std::process::id()));
    let _ = tokio::fs::remove_file(&path).await;

    let approved = MemTransport::bind().node_id();
    let other = MemTransport::bind().node_id();

    let mut approvals = Approvals::load_from(path.clone()).await.unwrap();
    approvals.approve(approved).await.unwrap();

    let reloaded = Approvals::load_from(path.clone()).await.unwrap();
    let gate = Gate::Paired(reloaded);
    assert!(gate.permits(approved));
    assert!(!gate.permits(other));

    tokio::fs::remove_file(&path).await.unwrap();
}
