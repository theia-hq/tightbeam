use crate::protocol::{Request, Response};

#[tokio::test]
async fn request_roundtrips_without_a_capability() {
    let request = Request {
        service: "svc".to_owned(),
        capability: None,
        membership: None,
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn request_roundtrips_with_a_capability() {
    let request = Request {
        service: "svc".to_owned(),
        capability: Some("sheer:bf01abc.def".to_owned()),
        membership: None,
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn request_roundtrips_with_both_slots() {
    // TB03: a signet-bound dial carries slot 1 (the slip) AND slot 2 (a badge under the foreign fleet). Both
    // present must round-trip byte-for-byte, so the gate reads the same two tokens the dialer wrote.
    let request = Request {
        service: "ssh".to_owned(),
        capability: Some("sheer:bf01abc.def".to_owned()),
        membership: Some("sheer:bf02ghi.jkl".to_owned()),
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.unwrap();
    assert_eq!(Request::read(&mut buf.as_slice()).await.unwrap(), request);
}

#[tokio::test]
async fn response_roundtrips() {
    for response in [Response::Ok, Response::Error("unknown service".to_owned())] {
        let mut buf = Vec::new();
        response.write(&mut buf).await.unwrap();
        assert_eq!(Response::read(&mut buf.as_slice()).await.unwrap(), response);
    }
}

#[tokio::test]
async fn rejects_foreign_stream() {
    let mut buf = b"XXXXnonsense".as_slice();
    assert!(Request::read(&mut buf).await.is_err());
}
