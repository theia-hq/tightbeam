use crate::protocol::{Request, Response};

#[tokio::test]
async fn request_roundtrips() {
    let mut buf = Vec::new();
    Request {
        service: "ssh".to_owned(),
    }
    .write(&mut buf)
    .await
    .unwrap();
    let decoded = Request::read(&mut buf.as_slice()).await.unwrap();
    assert_eq!(
        decoded,
        Request {
            service: "ssh".to_owned()
        }
    );
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
