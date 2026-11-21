//! Streaming capture: pass a body through untouched while recording its size
//! and the first [`MAX_BODY_TEXT`] bytes for the UI.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

/// Cap on body text sent to the UI (same as Node's `MAX_INTERCEPT_BODY`).
pub const MAX_BODY_TEXT: usize = 512 * 1024;

/// What was seen of a body.
#[derive(Default, Debug)]
pub struct Captured {
    pub size: u64,
    head: Vec<u8>,
}

impl Captured {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut c = Self::default();
        c.push(bytes);
        c
    }

    fn push(&mut self, chunk: &[u8]) {
        self.size += chunk.len() as u64;
        let room = MAX_BODY_TEXT.saturating_sub(self.head.len());
        self.head.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    /// Body text as Node's `Buffer#toString('utf8')` would give it, or `None`
    /// for an empty body (the field is then left out, as in Node).
    pub fn text(&self) -> Option<String> {
        (!self.head.is_empty()).then(|| String::from_utf8_lossy(&self.head).into_owned())
    }
}

pub enum Outcome {
    /// The body was delivered in full.
    Complete(Captured),
    /// The body stopped early (client went away or the upstream failed).
    Aborted,
}

type OnEnd = Box<dyn FnOnce(Outcome) + Send>;

pub struct CaptureBody<B: Body<Data = Bytes> + Unpin> {
    inner: B,
    captured: Captured,
    on_end: Option<OnEnd>,
}

impl<B: Body<Data = Bytes> + Unpin> CaptureBody<B> {
    pub fn new(inner: B, on_end: impl FnOnce(Outcome) + Send + 'static) -> Self {
        Self {
            inner,
            captured: Captured::default(),
            on_end: Some(Box::new(on_end)),
        }
    }

    fn finish(&mut self, complete: bool) {
        if let Some(on_end) = self.on_end.take() {
            on_end(if complete {
                Outcome::Complete(std::mem::take(&mut self.captured))
            } else {
                Outcome::Aborted
            });
        }
    }
}

impl<B> Body for CaptureBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.captured.push(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish(false);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finish(true);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B: Body<Data = Bytes> + Unpin> Drop for CaptureBody<B> {
    fn drop(&mut self) {
        // hyper may stop polling once the body reports it has ended, so a drop
        // is only an abort if the body really hadn't finished.
        if self.on_end.is_some() {
            let complete = self.inner.is_end_stream();
            self.finish(complete);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_text_but_counts_everything() {
        let big = vec![b'a'; MAX_BODY_TEXT + 10];
        let c = Captured::from_bytes(&big);
        assert_eq!(c.size, (MAX_BODY_TEXT + 10) as u64);
        assert_eq!(c.text().unwrap().len(), MAX_BODY_TEXT);
        assert!(Captured::from_bytes(b"").text().is_none());
    }
}
