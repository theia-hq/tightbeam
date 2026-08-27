use crate::fetch::{allowed_method, forward_headers};

#[test]
fn get_and_head_allowed_others_refused() {
    assert!(allowed_method("GET").is_ok());
    assert!(allowed_method("HEAD").is_ok());
    assert!(allowed_method("POST").is_err());
    assert!(allowed_method("CONNECT").is_err());
}

#[test]
fn forward_drops_hop_by_hop_and_host_keeps_range() {
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Range".to_string(), "bytes=0-1023".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    let names: Vec<&str> = forward_headers(&headers)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(names.contains(&"Range"));
    assert!(names.contains(&"Accept"));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("host")));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("connection")));
}
