//! Observe streamed bytes and finish accounting before yielding the terminal frame.
use axum::body::{Body, Bytes};
use futures_util::{future::BoxFuture, Stream};
use hyper::body::Frame;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

type Completion =
    Box<dyn FnOnce(u64, Vec<u8>) -> BoxFuture<'static, Result<(), axum::Error>> + Send>;
pub struct ObservedBody {
    stream: Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, axum::Error>> + Send>>,
    total: u64,
    preview: Vec<u8>,
    preview_limit: usize,
    complete: Option<Completion>,
    completion: Option<BoxFuture<'static, Result<(), axum::Error>>>,
    terminal_error: Option<axum::Error>,
    terminal_frame: Option<Frame<Bytes>>,
    finished: bool,
}
impl ObservedBody {
    pub fn wrap(
        body: Body,
        preview_limit: usize,
        complete: impl FnOnce(u64, Vec<u8>) + Send + 'static,
    ) -> Body {
        Self::wrap_async(body, preview_limit, |bytes, preview| async move {
            complete(bytes, preview);
            Ok(())
        })
    }
    pub fn wrap_async<F: Future<Output = Result<(), axum::Error>> + Send + 'static>(
        body: Body,
        preview_limit: usize,
        complete: impl FnOnce(u64, Vec<u8>) -> F + Send + 'static,
    ) -> Body {
        Body::new(http_body_util::StreamBody::new(Self {
            stream: Box::pin(http_body_util::BodyStream::new(body)),
            total: 0,
            preview: Vec::new(),
            preview_limit,
            complete: Some(Box::new(|bytes, preview| {
                Box::pin(complete(bytes, preview))
            })),
            completion: None,
            terminal_error: None,
            terminal_frame: None,
            finished: false,
        }))
    }
    fn finish(&mut self) {
        if let Some(complete) = self.complete.take() {
            self.completion = Some(complete(self.total, std::mem::take(&mut self.preview)));
        }
    }
    fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        if let Some(task) = self.completion.as_mut() {
            match task.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => self.terminal_error = Some(error),
                Poll::Ready(Ok(())) => {}
            }
        }
        self.completion = None;
        self.finished = true;
        Poll::Ready(
            self.terminal_error
                .take()
                .map(Err)
                .or_else(|| self.terminal_frame.take().map(Ok)),
        )
    }
}
impl Stream for ObservedBody {
    type Item = Result<Frame<Bytes>, axum::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if self.completion.is_some() {
            return self.poll_completion(cx);
        }
        match self.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    self.total = self.total.saturating_add(bytes.len() as u64);
                    let retain = bytes
                        .len()
                        .min(self.preview_limit.saturating_sub(self.preview.len()));
                    self.preview.extend_from_slice(&bytes[..retain]);
                    Poll::Ready(Some(Ok(frame)))
                } else {
                    self.terminal_frame = Some(frame);
                    self.finish();
                    self.poll_completion(cx)
                }
            }
            Poll::Ready(value) => {
                self.terminal_error = value.and_then(Result::err);
                self.finish();
                self.poll_completion(cx)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for ObservedBody {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finish();
        // A canceled response cannot await its completion. Preserve the observed
        // partial usage while the runtime is alive; a process kill before commit
        // remains outside the durable-observation guarantee.
        if let (Some(task), Ok(runtime)) = (
            self.completion.take(),
            tokio::runtime::Handle::try_current(),
        ) {
            runtime.spawn(async move {
                if let Err(error) = task.await {
                    tracing::error!(%error, "canceled response accounting failed");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    #[tokio::test]
    async fn streams_full_bytes_with_bounded_capture_and_completes_once_on_drop() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = ObservedBody::wrap(
            Body::from(vec![b'x'; 100_000]),
            17,
            move |bytes, preview| {
                let _ = tx.send((bytes, preview));
            },
        );
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 100_000);
        let (bytes, preview) = rx.await.unwrap();
        assert_eq!(bytes, 100_000);
        assert_eq!(preview.len(), 17);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = ObservedBody::wrap(Body::empty(), 17, move |bytes, _| {
            let _ = tx.send(bytes);
        });
        drop(body);
        assert_eq!(rx.await.unwrap(), 0);
    }
    #[tokio::test]
    async fn terminal_frame_waits_for_accounting_and_propagates_failure() {
        use futures_util::StreamExt;
        let (complete, gate) = tokio::sync::oneshot::channel();
        let body = ObservedBody::wrap_async(Body::from("abc"), 0, move |bytes, _| async move {
            assert_eq!(bytes, 3);
            gate.await.unwrap();
            Err(axum::Error::new(std::io::Error::other("disk full")))
        });
        let mut stream = body.into_data_stream();
        assert_eq!(stream.next().await.unwrap().unwrap(), "abc");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stream.next())
                .await
                .is_err()
        );
        complete.send(()).unwrap();
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
    }
    #[tokio::test]
    async fn cancellation_commits_partial_bytes_once_while_runtime_is_alive() {
        use futures_util::StreamExt;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let chunks = futures_util::stream::iter([Ok::<_, axum::Error>(Bytes::from_static(b"abc"))])
            .chain(futures_util::stream::pending());
        let body = ObservedBody::wrap_async(
            Body::from_stream(chunks),
            2,
            move |bytes, preview| async move {
                tokio::task::yield_now().await;
                tx.send((bytes, preview)).unwrap();
                Ok(())
            },
        );
        let mut stream = body.into_data_stream();
        stream.next().await.unwrap().unwrap();
        drop(stream);
        assert_eq!(rx.await.unwrap(), (3, b"ab".to_vec()));
    }
    #[tokio::test]
    async fn preserves_trailers_and_finishes_accounting_before_they_arrive() {
        let (done, finished) = tokio::sync::oneshot::channel();
        let frames = [
            Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::trailers(
                [(
                    axum::http::HeaderName::from_static("grpc-status"),
                    "0".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            )),
        ];
        let mut body = ObservedBody::wrap(
            Body::new(http_body_util::StreamBody::new(futures_util::stream::iter(
                frames,
            ))),
            0,
            |bytes, _| {
                done.send(bytes).unwrap();
            },
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "abc"
        );
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap()["grpc-status"],
            "0"
        );
        assert_eq!(finished.await.unwrap(), 3);
        assert!(body.frame().await.is_none());
    }
}
