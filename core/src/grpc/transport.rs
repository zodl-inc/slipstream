// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL Slipstream.
//
// ZODL Slipstream is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL Slipstream is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! Connection-owned provenance for local OHTTP errors, before tonic decodes wire metadata.

use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body::Frame;
use tonic::{Status, body::Body, transport::Channel};
use tower_service::Service;

use crate::{
    error::SlipstreamError,
    ohttp::{OHTTP_OUTCOME_HEADER, OUTCOME_POLICY_DENIED, OUTCOME_RATE_LIMITED, OUTCOME_TOO_LARGE},
};

const OBSOLETE_AUTH_HEADER: &str = "x-ohttp-outcome-auth";

/// Lightwalletd transport. Converting an ordinary Channel always preserves remote origin.
/// Only Slipstream's connectors can attach local OHTTP provenance.
#[derive(Clone, Debug)]
pub struct LwdTransport {
    channel: Channel,
    local_bridge: bool,
}

impl From<Channel> for LwdTransport {
    fn from(channel: Channel) -> Self {
        Self {
            channel,
            local_bridge: false,
        }
    }
}

impl LwdTransport {
    pub(crate) fn local_bridge(channel: Channel) -> Self {
        Self {
            channel,
            local_bridge: true,
        }
    }
}

// This private Rust object never crosses HTTP/2, so peer metadata or error text cannot
// recreate it. tonic retains the source when forwarding service/body Status errors.
#[derive(Clone, Copy, Debug)]
enum LocalOhttpOutcome {
    PolicyDenied,
    RateLimited,
    TooLarge,
}

impl fmt::Display for LocalOhttpOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PolicyDenied => OUTCOME_POLICY_DENIED,
            Self::RateLimited => OUTCOME_RATE_LIMITED,
            Self::TooLarge => OUTCOME_TOO_LARGE,
        })
    }
}
impl Error for LocalOhttpOutcome {}

/// Strip all reserved fields, including on remote channels. Only our actual local bridge
/// channel can turn a valid error into typed provenance; OK/malformed statuses cannot.
fn local_status(headers: &mut HeaderMap, local_bridge: bool) -> Option<Status> {
    let outcome = headers.remove(OHTTP_OUTCOME_HEADER);
    headers.remove(OBSOLETE_AUTH_HEADER);
    if !local_bridge {
        return None;
    }
    let outcome = match outcome?.to_str().ok()? {
        OUTCOME_POLICY_DENIED => LocalOhttpOutcome::PolicyDenied,
        OUTCOME_RATE_LIMITED => LocalOhttpOutcome::RateLimited,
        OUTCOME_TOO_LARGE => LocalOhttpOutcome::TooLarge,
        _ => return None,
    };
    let code = headers.get("grpc-status")?.to_str().ok()?;
    let number = code.parse::<u8>().ok()?;
    if !(1..=16).contains(&number) || number.to_string() != code {
        return None;
    }
    let mut status = Status::from_header_map(headers)?;
    status.set_source(Arc::new(outcome));
    Some(status)
}

impl Service<Request<Body>> for LwdTransport {
    type Response = Response<Body>;
    type Error = Status;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Status>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Status>> {
        self.channel
            .poll_ready(cx)
            .map_err(|error| Status::from_error(Box::new(error)))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // Call the exact service whose readiness was reserved, before moving into the future.
        let response = self.channel.call(request);
        let local_bridge = self.local_bridge;
        Box::pin(async move {
            let mut response = response
                .await
                .map_err(|error| Status::from_error(Box::new(error)))?;
            if let Some(status) = local_status(response.headers_mut(), local_bridge) {
                return Err(status);
            }
            Ok(response.map(|body| {
                Body::new(OutcomeBody {
                    body,
                    local_bridge,
                    done: false,
                })
            }))
        })
    }
}

struct OutcomeBody {
    body: Body,
    local_bridge: bool,
    done: bool,
}

impl http_body::Body for OutcomeBody {
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if self.done {
            return Poll::Ready(None);
        }
        let frame = match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
            Some(Ok(frame)) => frame,
            other => {
                self.done = true;
                return Poll::Ready(other);
            }
        };
        let frame = match frame.into_trailers() {
            Ok(mut trailers) => {
                self.done = true;
                if let Some(status) = local_status(&mut trailers, self.local_bridge) {
                    return Poll::Ready(Some(Err(status)));
                }
                Frame::trailers(trailers)
            }
            Err(frame) => frame,
        };
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

pub(super) fn status_err(context: &str, status: Status) -> SlipstreamError {
    let outcome = status
        .source()
        .and_then(|source| source.downcast_ref::<LocalOhttpOutcome>());
    match outcome {
        Some(LocalOhttpOutcome::PolicyDenied) => {
            SlipstreamError::PolicyDenied(format!("{context}: {status}"))
        }
        Some(LocalOhttpOutcome::RateLimited) => {
            SlipstreamError::RateLimited(format!("{context}: {status}"))
        }
        Some(LocalOhttpOutcome::TooLarge) => {
            SlipstreamError::RequestTooLarge(format!("{context}: {status}"))
        }
        None => SlipstreamError::Transport(format!("{context}: {status}")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        error::SlipstreamError,
        grpc::{LwdClient, TrackedConnection},
        ohttp::{
            OHTTP_OUTCOME_HEADER, OUTCOME_POLICY_DENIED, OUTCOME_RATE_LIMITED, OUTCOME_TOO_LARGE,
        },
    };
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use http_body::Frame;
    use http_body_util::StreamBody;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };
    use tokio::io::DuplexStream;
    use zcash_client_backend::proto::service::Empty;

    pub(crate) fn bridge_outcome_status(headers: &mut HeaderMap) -> Status {
        local_status(headers, true).unwrap()
    }

    struct Pipe(Option<DuplexStream>);
    impl Service<http::Uri> for Pipe {
        type Response = TokioIo<DuplexStream>;
        type Error = std::io::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: http::Uri) -> Self::Future {
            std::future::ready(Ok(TokioIo::new(self.0.take().unwrap())))
        }
    }

    async fn client(response: Response<Body>, local: bool) -> LwdClient {
        let (send, receive) = tokio::io::duplex(64 * 1024);
        let response = Arc::new(Mutex::new(Some(response)));
        tokio::spawn(async move {
            let handler = hyper::service::service_fn(move |_| {
                let response = response.lock().unwrap().take().unwrap();
                async move { Ok::<_, Infallible>(response) }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(receive), handler)
                .await;
        });
        let channel = tonic::transport::Endpoint::from_static("http://local-fixture.invalid")
            .connect_with_connector(Pipe(Some(send)))
            .await
            .unwrap();
        LwdClient::new(if local {
            LwdTransport::local_bridge(channel)
        } else {
            channel.into()
        })
    }

    fn fields(code: &str, outcome: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", HeaderValue::from_str(code).unwrap());
        headers.insert(
            OHTTP_OUTCOME_HEADER,
            HeaderValue::from_str(outcome).unwrap(),
        );
        headers.insert(
            "x-ohttp-outcome-auth",
            HeaderValue::from_static("invented-or-replayed-authentication"),
        );
        headers
    }

    fn assert_outcome(status: Status, local: bool, outcome: &str) {
        let error = crate::grpc::status_err(
            "transport fixture",
            status,
            crate::grpc::StatusOrigin::LocalOhttpBridge,
        );
        assert!(
            matches!(
                (local, outcome, &error),
                (false, _, SlipstreamError::Transport(_))
                    | (
                        true,
                        OUTCOME_POLICY_DENIED,
                        SlipstreamError::PolicyDenied(_)
                    )
                    | (true, OUTCOME_RATE_LIMITED, SlipstreamError::RateLimited(_))
                    | (true, OUTCOME_TOO_LARGE, SlipstreamError::RequestTooLarge(_))
            ),
            "{local} / {outcome}: {error:?}"
        );
    }

    #[tokio::test]
    async fn initial_outcomes_require_connection_owned_provenance() {
        for local in [false, true] {
            for outcome in [
                OUTCOME_POLICY_DENIED,
                OUTCOME_RATE_LIMITED,
                OUTCOME_TOO_LARGE,
            ] {
                let mut response = Response::new(Body::empty());
                *response.headers_mut() = fields("14", outcome);
                response
                    .headers_mut()
                    .insert("content-type", HeaderValue::from_static("application/grpc"));
                let status = client(response, local)
                    .await
                    .get_mempool_stream(Empty {})
                    .await
                    .unwrap_err();
                assert!(
                    !format!("{status:?}").contains("x-ohttp-outcome"),
                    "reserved metadata remained after transport conversion"
                );
                assert_outcome(status, local, outcome);
            }
        }
    }

    #[tokio::test]
    async fn streamed_outcomes_keep_data_order_and_survive_scope_exit() {
        use futures_util::StreamExt;
        for local in [false, true] {
            for outcome in [
                OUTCOME_POLICY_DENIED,
                OUTCOME_RATE_LIMITED,
                OUTCOME_TOO_LARGE,
            ] {
                let release = Arc::new(tokio::sync::Notify::new());
                let wait = release.clone();
                let data = futures_util::stream::once(async {
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0])))
                });
                let trailer = futures_util::stream::once(async move {
                    wait.notified().await;
                    Ok::<_, Infallible>(Frame::trailers(fields("14", outcome)))
                });
                let mut response =
                    Response::new(Body::new(StreamBody::new(Box::pin(data.chain(trailer)))));
                response
                    .headers_mut()
                    .insert("content-type", HeaderValue::from_static("application/grpc"));
                let connection = TrackedConnection::plain(client(response, local).await);
                let mut stream = connection
                    .call(async |client| {
                        Ok(client
                            .get_mempool_stream(Empty {})
                            .await
                            .unwrap()
                            .into_inner())
                    })
                    .await
                    .unwrap();
                drop(connection);
                assert!(
                    stream.message().await.unwrap().is_some(),
                    "data before the error must arrive first"
                );
                release.notify_one();
                let status = stream.message().await.unwrap_err();
                assert!(
                    !format!("{status:?}").contains("x-ohttp-outcome"),
                    "reserved metadata remained after stream conversion"
                );
                assert_outcome(status, local, outcome);
            }
        }
    }

    #[tokio::test]
    async fn outcome_body_emits_one_error_and_no_following_frames() {
        use http_body_util::BodyExt;
        let frames = futures_util::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"before"))),
            Ok(Frame::trailers(fields("14", OUTCOME_RATE_LIMITED))),
            Ok(Frame::data(Bytes::from_static(b"after"))),
        ]);
        let mut body = OutcomeBody {
            body: Body::new(StreamBody::new(frames)),
            local_bridge: true,
            done: false,
        };
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"before")
        );
        assert_outcome(
            body.frame().await.unwrap().unwrap_err(),
            true,
            OUTCOME_RATE_LIMITED,
        );
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn remote_replay_of_formatted_local_status_cannot_supply_provenance() {
        let mut local = Response::new(Body::empty());
        *local.headers_mut() = fields("14", OUTCOME_RATE_LIMITED);
        local
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/grpc"));
        let status = client(local, true)
            .await
            .get_mempool_stream(Empty {})
            .await
            .unwrap_err();
        let observed = format!("{status} {status:?}");
        assert!(!observed.contains("x-ohttp-outcome"));
        assert_outcome(status, true, OUTCOME_RATE_LIMITED);
        let mut replay = Response::new(Body::empty());
        *replay.headers_mut() = fields("14", OUTCOME_RATE_LIMITED);
        replay
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/grpc"));
        replay
            .headers_mut()
            .insert("grpc-message", HeaderValue::from_str(&observed).unwrap());
        let status = client(replay, false)
            .await
            .get_mempool_stream(Empty {})
            .await
            .unwrap_err();
        assert_outcome(status, false, OUTCOME_RATE_LIMITED);
    }

    #[tokio::test]
    async fn streamed_malformed_or_ok_status_cannot_mint_local_outcomes() {
        for (code, outcome) in [
            ("0", OUTCOME_RATE_LIMITED),
            ("bogus", OUTCOME_RATE_LIMITED),
            ("17", OUTCOME_RATE_LIMITED),
            ("01", OUTCOME_RATE_LIMITED),
            ("+1", OUTCOME_RATE_LIMITED),
            ("14", "unknown-outcome"),
        ] {
            let frames = futures_util::stream::iter([
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0]))),
                Ok(Frame::trailers(fields(code, outcome))),
            ]);
            let mut response = Response::new(Body::new(StreamBody::new(frames)));
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/grpc"));
            let mut stream = client(response, true)
                .await
                .get_mempool_stream(Empty {})
                .await
                .unwrap()
                .into_inner();
            assert!(stream.message().await.unwrap().is_some());
            if let Err(status) = stream.message().await {
                assert!(!format!("{status:?}").contains("x-ohttp-outcome"));
                assert!(
                    matches!(
                        crate::grpc::status_err(
                            "invalid trailer",
                            status,
                            crate::grpc::StatusOrigin::LocalOhttpBridge
                        ),
                        SlipstreamError::Transport(_)
                    ),
                    "{code} / {outcome}"
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_or_ok_status_cannot_mint_local_outcomes() {
        for (code, outcome) in [
            ("0", OUTCOME_RATE_LIMITED),
            ("bogus", OUTCOME_RATE_LIMITED),
            ("17", OUTCOME_RATE_LIMITED),
            ("01", OUTCOME_RATE_LIMITED),
            ("+1", OUTCOME_RATE_LIMITED),
            ("14", "unknown-outcome"),
        ] {
            let mut response = Response::new(Body::empty());
            *response.headers_mut() = fields(code, outcome);
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/grpc"));
            let result = client(response, true)
                .await
                .get_mempool_stream(Empty {})
                .await;
            if let Err(status) = result {
                assert!(
                    matches!(
                        crate::grpc::status_err(
                            "invalid status",
                            status,
                            crate::grpc::StatusOrigin::LocalOhttpBridge
                        ),
                        SlipstreamError::Transport(_)
                    ),
                    "{code}"
                );
            }
        }
    }
}
