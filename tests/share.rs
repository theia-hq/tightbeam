// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts
// only test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `tightbeam share`, run as the binary: a link is minted only when the node trusts no root or trusts
//! its own key. Under a foreign root a link would be rooted at a key no gate admits, so the verb refuses
//! and prints nothing to stdout.

use std::path::PathBuf;
use std::process::Output;

use bifrost::NodeId;

/// The node's own secret; its public key is what a pin of "self" names.
const OWN_SECRET: [u8; 32] = [7u8; 32];

/// A unique directory under the system temp root, removed on drop even when an assertion fails.
struct TempDir(PathBuf);

impl TempDir {
    /// Make a fresh directory for `tag`; a leftover from a previous crashed run is cleared first.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("tb-share-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Persist the node's identity in `dir`, pin `root` (none: no root file), and run `share ssh`.
async fn share_under(dir: &TempDir, root: Option<NodeId>) -> Output {
    let key = dir.0.join("identity.key");
    let root_path = dir.0.join("root");
    tightbeam::identity::write(&OWN_SECRET, Some(&key))
        .await
        .expect("persist the node identity");
    if let Some(root) = root {
        std::fs::write(&root_path, format!("{root}\n")).expect("pin the root");
    }
    std::process::Command::new(env!("CARGO_BIN_EXE_tightbeam"))
        .args(["share", "ssh"])
        .env("HOME", &dir.0)
        .env("TIGHTBEAM_KEY", &key)
        .env("TIGHTBEAM_ROOT", &root_path)
        .output()
        .expect("run tightbeam share")
}

fn own_id() -> NodeId {
    NodeId::from_ed25519_secret(&OWN_SECRET)
}

/// The printed text is a link rooted at this node's key: it parses, it starts with the key, and nothing
/// stands before the key.
fn assert_is_own_link(link: &str) {
    assert!(
        link.parse::<nauthy::Link>().is_ok(),
        "the printed text parses as a link: {link}"
    );
    assert!(
        link.starts_with(&format!("{}.", own_id())),
        "the link starts with this node's key: {link}"
    );
    assert!(!link.contains(':'), "the link carries no prefix: {link}");
}

#[tokio::test]
async fn tightbeam_share_refuses_under_a_foreign_pin() {
    let dir = TempDir::new("foreign");
    let foreign = NodeId::from_ed25519_secret(&[9u8; 32]);
    let output = share_under(&dir, Some(foreign)).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "share must fail under a foreign pin"
    );
    assert!(
        output.stdout.is_empty(),
        "no link may be printed under a foreign pin, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("this node trusts root {foreign}")),
        "the refusal names the pinned root: {stderr}"
    );
    assert!(
        stderr.contains(&format!("this node's key ({})", own_id())),
        "the refusal names the key the link would carry: {stderr}"
    );
    assert!(
        stderr.contains("Make the link with `tightbeam share` on the node whose key is that root"),
        "the refusal says where the link can be made: {stderr}"
    );
}

/// With no `TIGHTBEAM_ROOT`, the pin is read from `root` in the config directory, so a foreign key written
/// there refuses the link exactly as the override does.
#[tokio::test]
async fn tightbeam_share_reads_the_pin_from_the_config_root_file() {
    let dir = TempDir::new("config-root");
    let key = dir.0.join("identity.key");
    tightbeam::identity::write(&OWN_SECRET, Some(&key))
        .await
        .expect("persist the node identity");
    let config = dir.0.join(".config").join("tightbeam");
    std::fs::create_dir_all(&config).expect("create the config dir");
    let foreign = NodeId::from_ed25519_secret(&[9u8; 32]);
    std::fs::write(config.join("root"), format!("{foreign}\n")).expect("pin the root");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tightbeam"))
        .args(["share", "ssh"])
        .env("HOME", &dir.0)
        .env("TIGHTBEAM_KEY", &key)
        .env_remove("TIGHTBEAM_ROOT")
        .output()
        .expect("run tightbeam share");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "share must fail under the foreign root in the config dir"
    );
    assert!(
        stderr.contains(&format!("this node trusts root {foreign}")),
        "the refusal names the root read from the config dir: {stderr}"
    );
}

#[tokio::test]
async fn tightbeam_share_mints_under_its_own_pin() {
    let dir = TempDir::new("own");
    let output = share_under(&dir, Some(own_id())).await;
    assert!(
        output.status.success(),
        "share under its own pin must mint: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let link = String::from_utf8(output.stdout).expect("utf-8 link");
    assert_is_own_link(link.trim());
}

#[tokio::test]
async fn tightbeam_share_mints_with_no_pin() {
    let dir = TempDir::new("unpinned");
    let output = share_under(&dir, None).await;
    assert!(
        output.status.success(),
        "share with no root must mint: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let link = String::from_utf8(output.stdout).expect("utf-8 link");
    assert_is_own_link(link.trim());
}

/// The link `share` prints is the library's own text, `<key>.<token>`, exactly: the same bytes a peer
/// presents on the wire, with no scheme in front for anyone to strip.
#[tokio::test]
async fn share_prints_a_link_with_no_prefix() {
    let dir = TempDir::new("bare");
    let output = share_under(&dir, None).await;
    assert!(
        output.status.success(),
        "share must mint: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).expect("utf-8 link");
    let printed = printed.trim();
    let link = printed
        .parse::<nauthy::Link>()
        .expect("the printed text is a link");
    assert_eq!(
        link.as_str(),
        printed,
        "the printed text is the link's own text"
    );
    let (key, token) = printed.split_once('.').expect("a link holds a `.`");
    assert_eq!(
        key,
        own_id().to_string(),
        "the text before the `.` is the key"
    );
    assert!(
        !token.is_empty() && !token.contains('.'),
        "one `.`, then the token"
    );
}
