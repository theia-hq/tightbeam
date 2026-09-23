//! Test-only: capture the host log lines one test emits, without losing them to a parallel test.
//!
//! A scoped subscriber (`tracing::subscriber::set_default`) is the natural way to read one test's log,
//! and on its own it is flaky. tracing caches each callsite's interest once, globally, when the callsite
//! is first hit. While exactly one dispatcher is registered, that interest is computed from the default
//! of whichever thread got there first. So a parallel test thread with no subscriber that reaches a log
//! line first marks it uninteresting to EVERY thread, and the capturing test's own line is then never
//! emitted. That was `raw_stream_fanout`'s lag-log test failing on CI with an empty capture while its data
//! assertions held.
//!
//! [`Captured::install`] first registers a second dispatcher that is never dropped. With two registered,
//! the interest is always computed from every registered dispatcher, never from one thread's default, so
//! the line stays live and each thread's own default decides whether it is written.

use std::io;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// A host-log sink: every line the installed subscriber formats lands in one shared buffer.
#[derive(Clone, Default)]
pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Self(lines) = self;
        lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Capture this thread's `WARN` and above for as long as the guard lives.
    ///
    /// Every test that reads its own log goes through here, never through `set_default` directly: one
    /// that did not would be exposed to the race in the module doc, since the second dispatcher is what
    /// closes it.
    pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
        // Never dropped: the registry holds dispatchers weakly, so this one counts only while it lives.
        static SECOND: OnceLock<tracing::Dispatch> = OnceLock::new();
        SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let sink = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(move || sink.clone())
                .finish(),
        )
    }

    /// Every captured line containing `needle`, in order.
    pub(crate) fn lines(&self, needle: &str) -> Vec<String> {
        let Self(lines) = self;
        let lines = lines.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&lines)
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect()
    }
}
