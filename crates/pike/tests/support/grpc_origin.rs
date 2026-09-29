//! Real tonic codecs and services, without generated build-time/protoc artifacts.
use axum::body::Body;
use futures::StreamExt;
use hyper::{Request, Response};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tonic::{
    codegen::{BoxFuture, BoxStream},
    Status,
};

#[derive(Clone, PartialEq, prost::Message)]
pub struct Message {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct Fixture {
    pub active: Arc<AtomicUsize>,
    pub cancelled: Arc<AtomicUsize>,
}
struct CancelGuard(Fixture);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.cancelled.fetch_add(1, Ordering::SeqCst);
    }
}

impl tonic::server::UnaryService<Message> for Fixture {
    type Response = Message;
    type Future = BoxFuture<tonic::Response<Message>, Status>;
    fn call(&mut self, request: tonic::Request<Message>) -> Self::Future {
        let fixture = self.clone();
        Box::pin(async move {
            if request.get_ref().data == b"deadline" {
                // A real origin handler enforces the remaining propagated budget.
                let header = request
                    .metadata()
                    .get("grpc-timeout")
                    .ok_or_else(|| Status::internal("missing timeout"))?
                    .to_str()
                    .unwrap()
                    .to_owned();
                let split = header.len() - 1;
                let value: u64 = header[..split].parse().unwrap();
                let nanos = match &header[split..] {
                    "H" => value * 3_600_000_000_000,
                    "M" => value * 60_000_000_000,
                    "S" => value * 1_000_000_000,
                    "m" => value * 1_000_000,
                    "u" => value * 1_000,
                    "n" => value,
                    _ => return Err(Status::invalid_argument("timeout")),
                };
                fixture.active.fetch_add(1, Ordering::SeqCst);
                let _guard = CancelGuard(fixture);
                tokio::time::sleep(std::time::Duration::from_nanos(nanos)).await;
                return Err(Status::deadline_exceeded("origin deadline"));
            }
            if request.get_ref().data == b"error" {
                let mut metadata = tonic::metadata::MetadataMap::new();
                metadata.insert("x-error-detail", "preserved".parse().unwrap());
                return Err(Status::with_metadata(
                    tonic::Code::PermissionDenied,
                    "fixture denied",
                    metadata,
                ));
            }
            let mut reply = tonic::Response::new(request.into_inner());
            reply
                .metadata_mut()
                .insert("x-origin", "tonic".parse().unwrap());
            Ok(reply)
        })
    }
}
impl tonic::server::ClientStreamingService<Message> for Fixture {
    type Response = Message;
    type Future = BoxFuture<tonic::Response<Message>, Status>;
    fn call(&mut self, request: tonic::Request<tonic::Streaming<Message>>) -> Self::Future {
        Box::pin(async move {
            let mut input = request.into_inner();
            let mut data = vec![];
            while let Some(message) = input.message().await? {
                data.extend(message.data);
            }
            Ok(tonic::Response::new(Message { data }))
        })
    }
}
impl tonic::server::ServerStreamingService<Message> for Fixture {
    type Response = Message;
    type ResponseStream = BoxStream<Message>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, Status>;
    fn call(&mut self, request: tonic::Request<Message>) -> Self::Future {
        let fixture = self.clone();
        Box::pin(async move {
            let data = request.into_inner().data;
            let stream: BoxStream<Message> = if data == b"cancel" {
                fixture.active.fetch_add(1, Ordering::SeqCst);
                let guard = CancelGuard(fixture);
                Box::pin(async_stream::stream! {
                    let _guard = guard;
                    yield Ok(Message { data: b"ready".to_vec() });
                    futures::future::pending::<()>().await;
                })
            } else {
                Box::pin(async_stream::stream! {
                    yield Ok(Message { data: data.clone() });
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    yield Ok(Message { data });
                })
            };
            Ok(tonic::Response::new(stream))
        })
    }
}
impl tonic::server::StreamingService<Message> for Fixture {
    type Response = Message;
    type ResponseStream = BoxStream<Message>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, Status>;
    fn call(&mut self, request: tonic::Request<tonic::Streaming<Message>>) -> Self::Future {
        Box::pin(async move {
            let stream: BoxStream<Message> = Box::pin(request.into_inner().map(|message| {
                message.map(|mut message| {
                    message.data.reverse();
                    message
                })
            }));
            Ok(tonic::Response::new(stream))
        })
    }
}
pub async fn serve(
    request: Request<hyper::body::Incoming>,
    fixture: Fixture,
) -> Result<Response<Body>, Infallible> {
    let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::<Message, Message>::default());
    let response = match request.uri().path() {
        "/echo.Echo/Unary" => grpc.unary(fixture, request).await,
        "/echo.Echo/Client" => grpc.client_streaming(fixture, request).await,
        "/echo.Echo/Server" => grpc.server_streaming(fixture, request).await,
        "/echo.Echo/Bidi" => grpc.streaming(fixture, request).await,
        _ => Response::builder()
            .status(404)
            .body(tonic::body::Body::empty())
            .unwrap(),
    };
    Ok(response.map(Body::new))
}
