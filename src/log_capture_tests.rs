use crate::log_capture::Captured;

/// A log line this test alone emits, so its callsite is unregistered until this test first reaches it.
fn probe() {
    tracing::warn!("log capture probe");
}

#[test]
fn a_line_first_reached_on_another_thread_is_still_captured_here() {
    // The race, made deterministic: while this thread's capture is the only live subscriber, another
    // thread with none reaches the line first. That once cached the line as uninteresting everywhere,
    // and this thread's own `probe` then wrote nothing.
    let log = Captured::default();
    let _capture = log.install();
    std::thread::spawn(probe)
        .join()
        .expect("the other thread emits");
    probe();
    assert_eq!(
        log.lines("log capture probe").len(),
        1,
        "this thread's line is captured, and the other thread's, with no subscriber, is not"
    );
}
