use crate::protocol::{Request, Response};

#[tokio::test]
async fn request_roundtrips_without_a_capability() {
    let request = Request {
        service: "svc".to_owned(),
        capability: None,
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
