//! WebSocket passthrough.
//!
//! The upgrade request goes to the origin first; the client then receives the
//! origin's real response (status, subprotocol, extensions — untouched), and
//! the two upgraded connections are joined byte for byte. Nothing about the
//! handshake is synthesized, so subprotocols and compression keep working.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::sync::watch;

use crate::forward::{
    BoxError, ResBody, Target, empty, error_response, node_error_text, status_message,
    text_response,
};
use crate::headers::node_headers;
use crate::{ProxyEvent, Shared, new_id, now_ms};

pub(crate) fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

pub(crate) async fn passthrough(
    shared: Arc<Shared>,
    mut req: Request<Incoming>,
    scheme: &'static str,
    fallback: Option<&str>,
    shutdown: watch::Receiver<bool>,
) -> Response<ResBody> {
    let client_upgrade = hyper::upgrade::on(&mut req);
    let (mut parts, _) = req.into_parts();
    parts.headers.remove("proxy-connection");
    let Some(target) = Target::resolve(&parts, scheme, fallback) else {
        return text_response(StatusCode::BAD_REQUEST, "Bad request: no target host");
    };
    let secure = scheme == "https";
    let ws_scheme = if secure { "wss" } else { "ws" };
    let id = new_id();

    shared.emit(ProxyEvent::Flow(json!({
        "id": id,
        "method": if secure { "WSS" } else { "WS" },
        "protocol": ws_scheme,
        "host": target.host_field,
        "path": target.path,
        "url": format!("{ws_scheme}://{}{}", target.host_field, target.path),
        "requestHeaders": node_headers(&parts.headers),
        "startedAt": now_ms(),
        "ws": true,
        "wsState": "connecting",
    })));

    parts.uri = match format!("{scheme}://{}{}", target.authority, target.path).parse() {
        Ok(uri) => uri,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "Bad request: invalid URL"),
    };
    parts.version = Version::HTTP_11;
    let upstream_req = Request::from_parts(parts, Full::default());

    let mut res = match shared.clients().h1_ws.request(upstream_req).await {
        Ok(res) => res,
        Err(e) => {
            return error_response(
                &shared,
                &id,
                StatusCode::BAD_GATEWAY,
                "Error communicating with upstream server",
                node_error_text(&e),
            );
        }
    };

    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Rejected handshake: pass the origin's answer through as-is.
        let (parts, body) = res.into_parts();
        return Response::from_parts(
            parts,
            body.map_err(|e| Box::new(e) as BoxError).boxed_unsync(),
        );
    }

    let server_upgrade = hyper::upgrade::on(&mut res);
    let (parts, _) = res.into_parts();
    shared.emit(ProxyEvent::FlowUpdate(json!({
        "id": id,
        "statusCode": parts.status.as_u16(),
        "statusMessage": status_message(&parts),
        "responseHeaders": node_headers(&parts.headers),
        "ws": true,
        "wsState": "open",
    })));

    let pipe_shared = shared.clone();
    let mut stop = shutdown;
    tokio::spawn(async move {
        let joined = async {
            let (client, server) = tokio::try_join!(client_upgrade, server_upgrade).ok()?;
            let mut client = TokioIo::new(client);
            let mut server = TokioIo::new(server);
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            Some(())
        };
        tokio::select! {
            _ = joined => {}
            _ = stop.wait_for(|stopped| *stopped) => {}
        }
        pipe_shared.emit(ProxyEvent::FlowUpdate(json!({
            "id": id,
            "ws": true,
            "wsState": "closed",
            "completedAt": now_ms(),
        })));
    });

    Response::from_parts(parts, empty())
}
