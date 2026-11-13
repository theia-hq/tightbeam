use core::error::Error as _;
#[cfg(any(unix, windows))]
use std::path::Path;

use super::{Delivery, Endpoint, Primitive, TargetSpec, TargetSyntaxError};

#[test]
fn every_primitive_uses_the_existing_case_sensitive_grammar() {
    for text in [
        "tcp:host:0",
        "tcp:host:+80",
        "tcp:[::1]:65535",
        "tcp:a:b:80",
        "tcp: :1",
        "unix:socket",
        "unix:/:socket",
        "file:~/.bytes",
        "fifo:./pipe",
        "stdin:",
        "echo:",
    ] {
        let spec = text.parse::<TargetSpec>().expect(text);
        assert_eq!(spec.as_str(), text);
        assert_eq!(TargetSpec::clone(&spec), spec);
        assert_eq!(spec.as_str().parse::<TargetSpec>().unwrap(), spec);
    }
    for (text, cause) in [
        ("", TargetSyntaxError::MissingScheme),
        ("host", TargetSyntaxError::MissingScheme),
        ("TCP:host:80", TargetSyntaxError::UnknownScheme),
        ("unknown:secret", TargetSyntaxError::UnknownScheme),
        ("tcp::80", TargetSyntaxError::InvalidEndpoint),
        ("tcp:host:", TargetSyntaxError::InvalidEndpoint),
        ("tcp:host:65536", TargetSyntaxError::InvalidEndpoint),
        ("tcp:host:-1", TargetSyntaxError::InvalidEndpoint),
        ("tcp:host: 1", TargetSyntaxError::InvalidEndpoint),
        ("tcp:host", TargetSyntaxError::InvalidEndpoint),
        ("unix:", TargetSyntaxError::InvalidEndpoint),
        ("file:", TargetSyntaxError::MissingPath),
        ("fifo:", TargetSyntaxError::MissingPath),
        ("stdin:arg", TargetSyntaxError::UnexpectedArgument),
        ("echo:arg", TargetSyntaxError::UnexpectedArgument),
    ] {
        assert_eq!(text.parse::<TargetSpec>().unwrap_err(), cause, "{text}");
    }
}

#[test]
fn only_complete_targets_interpret_one_final_lossy_suffix() {
    for text in ["fifo:pipe+lossy", "fifo:pipe+lossy+lossy", "stdin:+lossy"] {
        let spec = text.parse::<TargetSpec>().unwrap();
        assert_eq!(spec.as_str(), text);
        assert!(matches!(
            spec.primitive(),
            Primitive::Fifo(_, Delivery::Lossy) | Primitive::Stdin(Delivery::Lossy)
        ));
    }
    let twice = "fifo:pipe+lossy+lossy".parse::<TargetSpec>().unwrap();
    assert!(matches!(
        twice.primitive(),
        Primitive::Fifo("pipe+lossy", Delivery::Lossy)
    ));
    for text in [
        "echo:+lossy",
        "file:path+lossy",
        "unix:path+lossy",
        "tcp:host:80+lossy",
        "unknown:+lossy",
    ] {
        assert_eq!(
            text.parse::<TargetSpec>().unwrap_err(),
            TargetSyntaxError::UnsupportedLossy
        );
    }
    assert_eq!(
        "fifo:+lossy".parse::<TargetSpec>().unwrap_err(),
        TargetSyntaxError::MissingPath
    );
    assert_eq!(
        "stdin:+lossy+lossy".parse::<TargetSpec>().unwrap_err(),
        TargetSyntaxError::UnexpectedArgument
    );
    assert!("unix:path+lossy".parse::<Endpoint>().is_ok());
    assert!("unix:+lossy".parse::<Endpoint>().is_ok());
    assert!("tcp:host:80+lossy".parse::<Endpoint>().is_err());
}

#[cfg(unix)]
#[test]
fn anchoring_preserves_raw_spelling_and_retained_text_equality() {
    let cwd = Path::new("/base/./dir//");
    for (text, expected) in [
        (
            "unix:~//./sock/../end",
            "unix:/base/./dir//~//./sock/../end",
        ),
        ("file:./bytes//../end", "file:/base/./dir//./bytes//../end"),
        (
            "fifo:~//./pipe+lossy+lossy",
            "fifo:/base/./dir//~//./pipe+lossy+lossy",
        ),
        ("fifo:./pipe/", "fifo:/base/./dir//./pipe/"),
    ] {
        let spec = text.parse::<TargetSpec>().unwrap();
        let anchored = spec.anchored(cwd).unwrap();
        assert_eq!(anchored.as_str(), expected);
        assert_eq!(anchored.as_str().parse::<TargetSpec>().unwrap(), anchored);
        assert_eq!(
            anchored.anchored(Path::new("/elsewhere")).unwrap(),
            anchored
        );
        assert_eq!(spec.as_str(), text);
        assert_ne!(spec, anchored);
    }
    for text in [
        "unix:/./sock//../end",
        "file:/abs/../bytes",
        "fifo:/abs/pipe+lossy+lossy",
        "tcp:host:00080",
        "stdin:",
        "stdin:+lossy",
        "echo:",
    ] {
        let spec = text.parse::<TargetSpec>().unwrap();
        assert_eq!(spec.anchored(cwd).unwrap().as_str(), text);
        assert_eq!(
            spec.anchored(Path::new("relative")).unwrap_err(),
            TargetSyntaxError::RelativeWorkingDirectory
        );
    }
    for (left, right) in [
        ("tcp:host:80", "tcp:host:080"),
        ("file:/base/./bytes", "file:/base/bytes"),
        ("fifo:/base//pipe", "fifo:/base/pipe"),
    ] {
        assert_ne!(
            left.parse::<TargetSpec>().unwrap(),
            right.parse::<TargetSpec>().unwrap()
        );
    }
    for text in ["file:", "fifo:", "unix:", "fifo:+lossy"] {
        assert!(text.parse::<TargetSpec>().is_err());
    }

    for text in ["unix:D:leaf", "file:D:leaf", "fifo:D:leaf+lossy+lossy"] {
        let spec = text.parse::<TargetSpec>().unwrap();
        let anchored = spec.anchored(Path::new("/base")).unwrap();
        assert_eq!(
            anchored.as_str(),
            format!("{}:/base/{}", &text[..4], &text[5..])
        );
        assert_eq!(anchored.as_str().parse::<TargetSpec>().unwrap(), anchored);
    }

    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        use std::path::PathBuf;

        let cwd = PathBuf::from(OsString::from_vec(b"/base/\xff".to_vec()));
        for text in ["file:bytes", "unix:sock", "fifo:pipe+lossy"] {
            assert_eq!(
                text.parse::<TargetSpec>()
                    .unwrap()
                    .anchored(&cwd)
                    .unwrap_err(),
                TargetSyntaxError::PathEncoding
            );
        }
        for text in ["file:/bytes", "fifo:/pipe+lossy", "echo:"] {
            assert_eq!(
                text.parse::<TargetSpec>()
                    .unwrap()
                    .anchored(&cwd)
                    .unwrap()
                    .as_str(),
                text
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_drive_relative_and_root_relative_paths_are_refused_without_raw_error_context() {
    for path in [
        r"C:leaf",
        r"c:leaf",
        r"D:leaf",
        r"C:",
        r"D:",
        r"\leaf",
        "/leaf",
        r"\",
        "/",
        r"C:credential-secret",
    ] {
        for (scheme, suffix) in [("unix", ""), ("file", ""), ("fifo", ""), ("fifo", "+lossy")] {
            let text = format!("{scheme}:{path}{suffix}");
            let spec = text.parse::<TargetSpec>().unwrap();
            for cwd in [r"C:\base", r"D:\base", r"\\?\C:\base"] {
                let error = spec.anchored(Path::new(cwd)).unwrap_err();
                assert_eq!(
                    error,
                    TargetSyntaxError::UnsupportedPathAnchoring,
                    "{text} under {cwd}"
                );
                assert!(!error.to_string().contains("credential-secret"));
                assert!(!format!("{error:?}").contains("credential-secret"));
                assert!(error.source().is_none());
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_absolute_paths_are_unchanged_but_still_require_absolute_cwd() {
    for path in [
        r"C:\base\.\leaf\..\end",
        "C:/base//./leaf",
        r"\\server\share\leaf",
        r"\\?\C:\base\.\leaf\..\end",
        r"\\?\UNC\server\share\leaf",
        r"\\.\pipe\leaf",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\leaf",
    ] {
        assert!(Path::new(path).is_absolute(), "{path}");
        for (scheme, suffix) in [
            ("unix", ""),
            ("file", ""),
            ("fifo", ""),
            ("fifo", "+lossy+lossy"),
        ] {
            let text = format!("{scheme}:{path}{suffix}");
            let spec = text.parse::<TargetSpec>().unwrap();
            let anchored = spec.anchored(Path::new(r"D:\elsewhere")).unwrap();
            assert_eq!(anchored.as_str(), text);
            assert_eq!(anchored, spec);
            assert_eq!(anchored.as_str().parse::<TargetSpec>().unwrap(), anchored);
            for cwd in ["relative", r"C:relative", r"\relative", "/relative"] {
                assert_eq!(
                    spec.anchored(Path::new(cwd)).unwrap_err(),
                    TargetSyntaxError::RelativeWorkingDirectory
                );
            }
        }
    }
    for text in ["tcp:host:00080", "stdin:", "stdin:+lossy", "echo:"] {
        let spec = text.parse::<TargetSpec>().unwrap();
        assert_eq!(spec.anchored(Path::new(r"C:\base")).unwrap(), spec);
        for cwd in ["relative", r"C:relative", r"\relative", "/relative"] {
            assert_eq!(
                spec.anchored(Path::new(cwd)).unwrap_err(),
                TargetSyntaxError::RelativeWorkingDirectory
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_anchoring_appends_literal_spelling_instead_of_normalizing_verbatim_cwd() {
    for (cwd, prefix) in [
        (r"C:\base", r"C:\base\"),
        (r"C:\base\\", r"C:\base\\"),
        ("C:/base//", "C:/base//"),
        (r"C:\base\.\parent\..", r"C:\base\.\parent\..\"),
        (r"\\server\share\base", r"\\server\share\base\"),
        (r"\\?\C:\base\.\parent\..", r"\\?\C:\base\.\parent\..\"),
        (r"\\?\C:\base\\", r"\\?\C:\base\\"),
        (r"\\?\C:\base/", r"\\?\C:\base/\"),
        (
            r"\\?\UNC\server\share\base\.\..",
            r"\\?\UNC\server\share\base\.\..\",
        ),
        (r"C:\básé", r"C:\básé\"),
    ] {
        assert!(Path::new(cwd).is_absolute(), "{cwd}");
        for tail in [
            r".\leaf",
            r"~\\.\leaf\..\end//",
            "./leaf//../end/",
            ".",
            "..",
            "字",
        ] {
            for (scheme, suffix) in [
                ("unix", ""),
                ("file", ""),
                ("fifo", ""),
                ("fifo", "+lossy+lossy"),
            ] {
                let text = format!("{scheme}:{tail}{suffix}");
                let spec = text.parse::<TargetSpec>().unwrap();
                let anchored = spec.anchored(Path::new(cwd)).unwrap();
                assert_eq!(
                    anchored.as_str(),
                    format!("{scheme}:{prefix}{tail}{suffix}")
                );
                assert_eq!(anchored.as_str().parse::<TargetSpec>().unwrap(), anchored);
                assert_eq!(
                    anchored.anchored(Path::new(r"E:\elsewhere")).unwrap(),
                    anchored
                );
                assert_eq!(spec.as_str(), text);
                assert_ne!(spec, anchored);
            }
        }
    }
    for (left, right) in [
        (r"file:C:\base\.\leaf", r"file:C:\base\leaf"),
        (r"fifo:C:\base\\pipe", r"fifo:C:\base\pipe"),
        (r"file:C:\base\leaf", "file:C:/base/leaf"),
    ] {
        assert_ne!(
            left.parse::<TargetSpec>().unwrap(),
            right.parse::<TargetSpec>().unwrap()
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_rejects_non_utf8_joined_paths_without_rejecting_unchanged_targets() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use std::path::PathBuf;

    let cwd = PathBuf::from(OsString::from_wide(&[0x0043, 0x003a, 0x005c, 0xd800]));
    assert!(cwd.is_absolute());
    assert!(cwd.to_str().is_none());
    for text in ["unix:socket", "file:bytes", "fifo:pipe+lossy+lossy"] {
        assert_eq!(
            text.parse::<TargetSpec>()
                .unwrap()
                .anchored(&cwd)
                .unwrap_err(),
            TargetSyntaxError::PathEncoding
        );
    }
    for text in [
        r"file:C:\bytes",
        r"fifo:C:\pipe+lossy+lossy",
        "tcp:host:0",
        "stdin:",
        "echo:",
    ] {
        assert_eq!(
            text.parse::<TargetSpec>()
                .unwrap()
                .anchored(&cwd)
                .unwrap()
                .as_str(),
            text
        );
    }
}

#[test]
fn syntax_errors_never_retain_rejected_target_text() {
    for text in [
        "credential-secret",
        "credential-secret:path",
        "stdin:credential-secret",
        "echo:credential-secret",
        "tcp:credential-secret:not-a-port",
        "file:credential-secret+lossy",
    ] {
        let error = text.parse::<TargetSpec>().unwrap_err();
        assert!(!error.to_string().contains("credential-secret"));
        assert!(!format!("{error:?}").contains("credential-secret"));
        assert!(error.source().is_none());
    }
}
