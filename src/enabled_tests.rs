//! Unit tests for the [`FileDisabledList`] oracle: an absent file enables everything, a listed name is
//! disabled, a write after load flips the answer LIVE (mtime-watched), and a deletion fails closed (keeps the
//! last-known disabled set rather than silently re-enabling).

use std::path::PathBuf;

use super::{AllEnabled, EnabledServices as _, FileDisabledList, STAT_DEBOUNCE};

/// A unique temp path per test, so parallel tests never share a backing file.
fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tb-disabled-{tag}-{}", std::process::id()))
}

/// The default oracle enables every service unconditionally.
#[test]
fn all_enabled_never_disables() {
    let all = AllEnabled;
    assert!(all.is_enabled("ping"));
    assert!(all.is_enabled("speed"));
}

/// An absent file loads to an empty disabled set: every service is enabled.
#[tokio::test]
async fn absent_file_enables_everything() {
    let path = temp_path("absent");
    let _ = std::fs::remove_file(&path);
    let list = FileDisabledList::load(path.clone()).await.expect("load");
    assert!(list.is_enabled("ping"));
    assert!(list.is_enabled("speed"));
    let _ = std::fs::remove_file(&path);
}

/// A name in the file is disabled; every other name stays enabled.
#[tokio::test]
async fn a_listed_name_is_disabled() {
    let path = temp_path("listed");
    std::fs::write(&path, "speed\n").expect("write disabled file");
    let list = FileDisabledList::load(path.clone()).await.expect("load");
    assert!(!list.is_enabled("speed"), "speed is disabled");
    assert!(list.is_enabled("ping"), "ping is untouched");
    let _ = std::fs::remove_file(&path);
}

/// The load-bearing property: a `disable` written AFTER the oracle loaded is honored live (a re-read on the
/// mtime change), and a later `enable` restores the service, both with no reconstruction. This is the
/// no-restart toggle the exposer relies on.
#[tokio::test]
async fn a_write_after_load_flips_the_answer_live() {
    let path = temp_path("live");
    let _ = std::fs::remove_file(&path);
    let list = FileDisabledList::load(path.clone()).await.expect("load");
    assert!(list.is_enabled("speed"), "enabled before any disable");

    // Disable it: a separate writer grows the file. Wait past the debounce so the next check re-stats.
    std::fs::write(&path, "speed\n").expect("disable speed");
    std::thread::sleep(STAT_DEBOUNCE * 2);
    assert!(
        !list.is_enabled("speed"),
        "disabled after the write, no restart"
    );

    // Re-enable it: rewrite the file without the name. Again wait past the debounce.
    std::fs::write(&path, "\n").expect("enable speed");
    std::thread::sleep(STAT_DEBOUNCE * 2);
    assert!(
        list.is_enabled("speed"),
        "restored after the re-enable, no restart"
    );

    let _ = std::fs::remove_file(&path);
}

/// Fail-closed: deleting the backing file keeps the last-known disabled set, so a `rm` never silently
/// re-enables a service the operator turned off.
#[tokio::test]
async fn deletion_fails_closed() {
    let path = temp_path("delete");
    std::fs::write(&path, "speed\n").expect("write disabled file");
    let list = FileDisabledList::load(path.clone()).await.expect("load");
    assert!(!list.is_enabled("speed"), "disabled while the file exists");

    std::fs::remove_file(&path).expect("remove the disabled file");
    std::thread::sleep(STAT_DEBOUNCE * 2);
    assert!(
        !list.is_enabled("speed"),
        "still disabled after deletion (fail-closed), not silently re-enabled"
    );
}
