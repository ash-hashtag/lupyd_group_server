#![feature(map_try_insert)]
#![feature(assert_matches)]

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{stream::SplitSink, SinkExt, StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming, service::service_fn, upgrade::Upgraded, Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{error, info, warn};
use mls::client_mls::normal_test;
use mls::custom_client::{test_custom_client, test_server_client};
use mls::group_server_mls::GroupServerMLS;
use serde_json::json;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use tokio::sync::{mpsc::Receiver, RwLock};

mod mls;
mod test_client;
mod types;

use crate::types::*;

#[tokio::main]
async fn main() {
    use std::io::Write;
    env_logger::builder()
        .format(|buf, record| {
            writeln!(
                buf,
                "{:<5} [{}:{}] - {}",
                record.level(),
                // File name with padding of 30 characters
                format!("{:30}", record.file().unwrap_or("unknown")),
                // Line number with padding of 4 characters
                format!("{:4}", record.line().unwrap_or(0)),
                record.args()
            )
        })
        .init();
    // if let Ok(username) = std::env::var("LG_USER") {
    //     info!("Connecting as {}", username);
    //     test_main(username).await.unwrap();
    // } else {
    //     run().await;
    // }
    // test_custom_client().unwrap();
    // test_server_client().unwrap();
    normal_test().unwrap();
}

async fn run() {
    let port = std::env::var("PORT").unwrap_or("9797".to_string());
    let port = port.parse().unwrap();
    info!("Starting Server at {port}");
    let group = GroupServer::new("MyGroup");
    http_serve(port, Arc::new(RwLock::new(group))).await;
}

async fn http_serve(port: u16, sd: Arc<RwLock<GroupServer>>) {
    let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let active_connections = ActiveConnections::new();

    while let Ok((stream, addr)) = listener.accept().await {
        let sd = sd.clone();
        let ac = active_connections.clone();
        let _ = tokio::spawn(async move {
            let sd = sd.clone();
            let io = TokioIo::new(stream);
            let executor = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let conn = executor.serve_connection_with_upgrades(
                io,
                service_fn(|req| request_handler(req, sd.clone(), ac.clone())),
            );

            if let Err(err) = conn.await {
                error!("Connection Error {}: {}", addr, err);
            }
        });
    }
}

async fn request_handler(
    mut request: Request<Incoming>,
    sd: Arc<RwLock<GroupServer>>,
    ac: ActiveConnections,
) -> hyper::http::Result<Response<Full<Bytes>>> {
    let username = request.uri().path()[1..].to_string();
    if hyper_tungstenite::is_upgrade_request(&request) {
        match hyper_tungstenite::upgrade(&mut request, None) {
            Ok((response, websocket)) => {
                tokio::spawn(serve_websocket(username, websocket, ac));
                return Ok(response);
            }
            Err(err) => {
                error!("Connection Upgrade failed {}", err);
                return Ok(Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
        };
    }
    let result = match request.method().clone() {
        Method::GET => get_handler(request, sd).await,
        Method::PUT => put_handler(request, sd, ac).await,
        Method::DELETE => delete_handler(request, sd).await,
        _ => return Ok(Response::new(Full::new(Bytes::from_static(b"Hello")))),
    };

    match result {
        Ok(response) => Ok(response),
        Err(err) => {
            error!("{err}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
    }
}

async fn get_handler(
    request: Request<Incoming>,
    sd: Arc<RwLock<GroupServer>>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let uri = request.uri();
    let path = uri.path();
    if path == "/" {
        let group = sd.read().await;
        let data = json!({
            "name": group.get_name(),
            "channels": group.get_channels().keys().collect::<Vec<_>>(),
            "members": group.get_members().keys().collect::<Vec<_>>(),
        });

        let body = serde_json::to_vec(&data)?;

        return Ok(Response::new(Full::new(Bytes::from(body))));
    } else if path.starts_with("/channel/") {
        let channel_name = &path["/channel/".len()..];
        let group = sd.read().await;
        if let Some(channel) = group.get_channel(channel_name) {
            let body = serde_json::to_vec(channel)?;
            return Ok(Response::new(Full::new(Bytes::from(body))));
        } else {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    } else if path.starts_with("/user/") {
        let username = &path["/user/".len()..];
        if let Some(pkg) = sd.read().await.get_member_key(username) {
            return Ok(Response::new(Full::new(Bytes::from(pkg))));
        } else {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    } else if path.starts_with("/welcome/") {
        let username = &path["/welcome/".len()..];
        if let Some(welcome) = sd.read().await.invites.get(username).cloned() {
            return Ok(Response::new(Full::new(Bytes::from(welcome))));
        } else {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    } else if path.starts_with("/messages") {
        let g = sd.read().await;
        let Some(gm) = &g.mls_group else {
            return Err(anyhow::anyhow!("Group is Missing"));
        };
        let mut offset = 0;
        if let Some(q) = uri.query() {
            for part in q.split('&') {
                let (key, val) = part.split_once('=').context("Query Pair invalid")?;
                if key == "offset" {
                    offset = val.parse()?;
                }
            }
        }
        let messages = gm.download_messages(offset);
        let body = bincode::serialize(messages)?;
        return Ok(Response::new(Full::new(Bytes::from(body))));
    }

    return Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::new()))
        .unwrap());
}

async fn put_handler(
    request: Request<Incoming>,
    sd: Arc<RwLock<GroupServer>>,
    ac: ActiveConnections,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let (parts, body) = request.into_parts();
    let uri = parts.uri;
    let path = uri.path();

    if path.starts_with("/channel/") {
        let channel_name = &path["/channel/".len()..];

        let body = body.collect().await?.to_bytes();
        let channel: GroupChannel = serde_json::from_slice(&body)?;

        let mut group = sd.write().await;
        group.add_channel(channel_name, channel);

        return Ok(Response::new(Full::new(Bytes::new())));
    } else if path.starts_with("/user/") {
        let username = &path["/user/".len()..];
        let body = body.collect().await?.to_bytes();
        let mut group = sd.write().await;
        group.add_member(username.to_string(), AddMemberWith::Key(body.to_vec()));
        return Ok(Response::new(Full::new(Bytes::new())));
        // }
    } else if path.starts_with("/welcome/") {
        let username = &path["/welcome/".len()..];
        let body = body.collect().await?.to_bytes();
        sd.write()
            .await
            .invites
            .insert(username.to_string(), body.to_vec());
        return Ok(Response::new(Full::new(Bytes::new())));
    } else if path.starts_with("/proposal") {
        let body = body.collect().await?.to_bytes();
        let mut g = sd.write().await;
        if let Some(gmls) = g.mls_group.as_mut() {
            gmls.upload_proposal(body.to_vec())?;
        } else {
            error!("MLS Group is Missing");
        }
        return Ok(Response::new(Full::new(Bytes::new())));
    } else if path.starts_with("/commit") {
        let body = body.collect().await?.to_bytes();
        let mut g = sd.write().await;
        if let Some(gmls) = g.mls_group.as_mut() {
            gmls.upload_commit(body.to_vec())?;
        } else {
            error!("MLS Group is Missing");
        }
        return Ok(Response::new(Full::new(Bytes::new())));
    } else if path.starts_with("/group/") {
        let body = body.collect().await?.to_bytes();
        let group = GroupServerMLS::new(&body)?;
        sd.write().await.mls_group = Some(group);
        return Ok(Response::new(Full::new(Bytes::new())));
    }
    return Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::new()))
        .unwrap());
}

async fn delete_handler(
    request: Request<Incoming>,
    sd: Arc<RwLock<GroupServer>>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let uri = request.uri();
    let path = uri.path();
    if path.starts_with("/channel/") {
        let channel_name = &path["/channel/".len()..];
        let mut group = sd.write().await;
        group.remove_channel(channel_name);

        return Ok(Response::new(Full::new(Bytes::new())));
    } else if path.starts_with("/user/") {
        let username = &path["/user/".len()..];

        if let Some(query_string) = uri.query() {
            let mut group = sd.write().await;
            for pair in query_string.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    if key == "channel" {
                        group.remove_member(username, Some(value));
                    }
                }
            }
            return Ok(Response::new(Full::new(Bytes::new())));
        } else {
            let mut group = sd.write().await;
            group.remove_member(username, None);
            return Ok(Response::new(Full::new(Bytes::new())));
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::new()))
        .unwrap());
}

async fn serve_websocket(
    username: String,
    websocket: hyper_tungstenite::HyperWebsocket,
    active_connections: ActiveConnections,
) -> anyhow::Result<()> {
    let (write, mut read) = websocket.await?.split();
    let (tx, rx) = tokio::sync::mpsc::channel::<Message>(64);

    active_connections.add_peer(username.clone(), tx).await;

    info!("New WebSocket connection: {}", username);

    let handle = tokio::spawn(handle_sending_messages(write, rx));

    while let Ok(Some(msg)) = read.try_next().await {
        let data = match msg {
            Message::Text(val) => val.into_bytes(),
            Message::Binary(val) => val,
            _ => {
                warn!("UNHANDLED MESSAGE TYPE");
                continue;
            }
        };

        let _ = active_connections
            .broadcast(Message::Binary(data), Some(username.clone()))
            .await;
    }

    active_connections.remove_peer(&username).await;
    let _ = handle.await;
    info!("Websocket Connection Closed {}", username);
    Ok(())
}

async fn handle_sending_messages(
    mut sink: SplitSink<WebSocketStream<TokioIo<Upgraded>>, Message>,
    mut rx: Receiver<Message>,
) {
    while let Some(msg) = rx.recv().await {
        if sink.send(msg).await.is_err() {
            break;
        }
    }
}
