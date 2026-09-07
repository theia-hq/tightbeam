//! Live service enable/disable: the [`EnabledServices`] oracle the exposer's per-stream gate consults, and
//! a file-backed [`FileDisabledList`] that implements it.
//!
//! An operator turns a served service off without stopping the node: the exposer is built once, so this is
//! NOT a mutation of the running exposer. Instead it mirrors the [`Revocations`](nauthy::Revocations) shape
//! exactly: a small, node-local set the gate consults per stream, backed by a file another process (an
//! `enable`/`disable` command) writes. The set here is DISABLED service names; a stream requesting a name in
//! the set is refused at the same seam a revoked capability is, with the same indistinguishable refusal, so a
//! disabled service reads to a dialer exactly like a gated or absent one (no enumeration oracle).
//!
//! [`EnabledServices`] is the seam. It is a synchronous, one-method trait, so a consumer whose state lives in
//! a database or a config reload implements it over that store and needs no file. The batteries-included impl
//! is [`FileDisabledList`] (behind default tokio-fs use), a persisted set of disabled names on disk.
//!
//! Toggling through [`FileDisabledList`] is LIVE: [`is_enabled`](FileDisabledList::is_enabled) re-reads the
//! backing file when its mtime changes, so a `disable` written by a separate process takes effect on the next
//! stream to a long-running exposer, and a later `enable` restores the service, both without a restart. The
//! file's mtime is the freshness signal; the reload is a small, rare read (only when the file actually
//! changed), guarded by interior mutability so the gate's synchronous admit path stays synchronous.

use core::time::Duration;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, SystemTime};

/// The enable/disable oracle the exposer consults per inbound stream, right where it consults the gate.
///
/// Synchronous by design: admission is synchronous policy, so the enabled check must never require an async
/// runtime. A consumer whose state lives elsewhere (a database, a live config) implements this over that
/// store; the provided file-backed impl is [`FileDisabledList`].
pub trait EnabledServices {
    /// Whether the named service is currently enabled (servable). A service the operator has disabled returns
    /// `false`; every other name returns `true`. The exposer refuses a stream for a name this reports `false`.
    fn is_enabled(&self, service: &str) -> bool;
}

/// Every service is enabled: the default when a caller wires no disabled-list, so a node that never toggles
/// pays nothing and behaves exactly as before this oracle existed.
///
/// The exposer defaults to this, so [`Exposer::with_enabled`](crate::tunnel::Exposer::with_enabled) is a
/// deliberate opt-in, never a hidden requirement on the many callers and tests that build an exposer.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllEnabled;

impl EnabledServices for AllEnabled {
    fn is_enabled(&self, _service: &str) -> bool {
        true
    }
}

/// A persisted set of DISABLED service names (one name per line), and the batteries-included
/// [`EnabledServices`] impl.
///
/// The consuming process owns the file location; this type owns only the load / check logic over a path. The
/// loaded set is behind a [`Mutex`] with the mtime it was read at, so a check can refresh it in place when the
/// file changed underneath a running exposer.
///
/// FAIL-CLOSED, matching [`FileDenylist`](nauthy::FileDenylist): a stat error, a read error, or the file
/// DISAPPEARING all keep the last-known disabled set, so a `rm` of the file (a botched cleanup, or a local
/// attacker) never silently RE-ENABLES a service the operator turned off. A list that never had a file stays
/// empty (nothing is disabled); a disable only ever grows the file, and a fresh file appearing is picked up.
pub struct FileDisabledList {
    path: PathBuf,
    state: Mutex<State>,
}

/// The loaded disabled names, the `(mtime, len)` stamp of the file they were read at (`None` = absent when
/// loaded), and the last moment we stat'd the file. The length pairs with mtime so a change within one coarse
/// mtime tick is still seen: an edit that keeps the byte count identical is rare, and the mtime moves on it.
struct State {
    disabled: HashSet<String>,
    stamp: Option<(SystemTime, u64)>,
    last_stat: Option<Instant>,
}

/// The admit hot path calls [`is_enabled`](FileDisabledList::is_enabled) once per stream, but a toggle written
/// by another process only needs to be seen within a short window. So the refresh stats the file at most once
/// per this interval rather than on every check under the lock; a toggle goes live within one interval, well
/// inside "the next stream". This mirrors nauthy's `STAT_DEBOUNCE` so the two oracles behave identically.
const STAT_DEBOUNCE: Duration = Duration::from_millis(100);

impl FileDisabledList {
    /// Load the disabled list from `path`; an absent file is an empty set (nothing disabled).
    pub async fn load(path: PathBuf) -> Result<Self, DisabledListError> {
        let (disabled, stamp) = read_names(&path).await?;
        Ok(Self {
            path,
            state: Mutex::new(State {
                disabled,
                stamp,
                last_stat: None,
            }),
        })
    }

    /// The file backing this list.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the named service is currently enabled: `false` iff it is in the disabled set.
    ///
    /// Refreshes from disk first if the file changed since the last read, so a `disable` (or a later `enable`)
    /// written by another process is honored by a long-running exposer without a restart. The stat is
    /// debounced (see `STAT_DEBOUNCE`); the file is re-read only when it actually changed.
    pub fn is_enabled(&self, service: &str) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state);
        !state.disabled.contains(service)
    }

    /// Reload the names in place if the backing file's mtime differs from what we last read. Synchronous and
    /// on the admit hot path, so it debounces the stat to at most once per [`STAT_DEBOUNCE`] and re-reads only
    /// on change.
    ///
    /// Fail closed on every uncertainty: a stat/read error OR the file DISAPPEARING leaves the last-known set
    /// intact and returns. Deletion is not "nothing is disabled now": a `rm` of the file must never silently
    /// re-enable every service the operator turned off. A list that never had a file stays empty (nothing to
    /// re-enable); a fresh file appearing is picked up through the `Ok` stat arm below.
    // `core::io::ErrorKind` is still unstable, so any NotFound handling reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn refresh(&self, state: &mut State) {
        // Debounce: skip the stat entirely if we checked within the last STAT_DEBOUNCE. The first check after
        // construction (`last_stat` is None) always stats, so a freshly-loaded list sees the current file at once.
        if let Some(last) = state.last_stat
            && last.elapsed() < STAT_DEBOUNCE
        {
            return;
        }
        state.last_stat = Some(Instant::now());
        let current = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.modified().ok().map(|mtime| (mtime, meta.len())),
            // Missing file: keep the last-known set. If one was ever loaded, this is deletion, not empty.
            Err(_) => return,
        };
        if current == state.stamp {
            return;
        }
        let names = match std::fs::read_to_string(&self.path) {
            Ok(text) => parse_names(&text),
            // Raced away between stat and read: keep last-known rather than dropping the disabled set.
            Err(_) => return,
        };
        state.disabled = names;
        state.stamp = current;
    }
}

impl EnabledServices for FileDisabledList {
    fn is_enabled(&self, service: &str) -> bool {
        FileDisabledList::is_enabled(self, service)
    }
}

/// Read and decode the disabled-list file; an absent file is an empty set. Returns the names and the file's
/// `(mtime, len)` stamp (`None` if absent).
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn read_names(
    path: &Path,
) -> Result<(HashSet<String>, Option<(SystemTime, u64)>), DisabledListError> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => {
            let names = parse_names(&text);
            let stamp = tokio::fs::metadata(path)
                .await
                .ok()
                .and_then(|meta| Some((meta.modified().ok()?, meta.len())));
            Ok((names, stamp))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((HashSet::new(), None)),
        Err(error) => Err(DisabledListError::Io(error)),
    }
}

/// Decode a disabled-list file body into a set of service names: one trimmed, non-empty name per line. There
/// is no parse failure mode (any name is a valid thing to disable; a name the node does not serve is a
/// serve-side no-op), so this is total, unlike the denylist's hex-id decode.
fn parse_names(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Why loading the disabled list failed.
#[derive(Debug, thiserror::Error)]
pub enum DisabledListError {
    /// The backing file could not be read.
    #[error("access disabled-services list")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
#[path = "enabled_tests.rs"]
mod enabled_tests;
