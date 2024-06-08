use std::{
    io::stdin,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures::{executor::block_on, stream::SplitSink, AsyncReadExt, SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use log::{error, info, warn};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::mls::client_mls::GroupClientMLS;
const REST_URL: &str = "http://127.0.0.1:9797";

pub async fn test_main(username: String) -> anyhow::Result<()> {
    let client = GroupClientMLS::new(
        username.clone().into_bytes(),
        Path::new(&format!("/tmp/{username}.sqlite")),
    )?;

    let client = Arc::new(Mutex::new(client));

    let (stream, _) = connect_async(format!("ws://127.0.0.1:9797/{username}")).await?;

    let (write, mut read) = stream.split();

    let client_cloned = client.clone();

    let rest_client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build_http::<Full<Bytes>>();

    let _ = rest_client
        .request(
            Request::builder()
                .uri(format!("{REST_URL}/user/{username}"))
                .method(Method::PUT)
                .body(Full::new(Bytes::from(
                    client.lock().unwrap().key_package()?,
                )))?,
        )
        .await?;

    tokio::spawn(async move {
        while let Some(Ok(msg)) = read.next().await {
            info!("Received Message {}", msg.len());
            let data = match msg {
                Message::Text(val) => val.into_bytes(),
                Message::Binary(val) => val,
                _ => {
                    warn!("Unhandled message type");
                    continue;
                }
            };

            if let Err(err) = client_cloned.lock().unwrap().process_message(&data) {
                error!("{err}");
            }
        }
    });

    let handle = tokio::task::spawn_blocking(move || {
        if let Err(err) = interact(rest_client.clone(), client.clone(), write, username.clone()) {
            error!("{err}");
        }
    });
    let _ = handle.await?;

    Ok(())
}

fn interact(
    rest_client: Client<HttpConnector, Full<Bytes>>,
    client: Arc<Mutex<GroupClientMLS>>,
    mut write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    username: String,
) -> anyhow::Result<()> {
    let mut offset = 0;
    for line in stdin().lines() {
        if let Ok(l) = line {
            let line = l.trim();
            if line.starts_with("add") {
                let proposal = line.starts_with("add p");
                let (_, member) = line.split_once(' ').unwrap();
                let resp = block_on(
                    rest_client.get(Uri::from_str(&format!("{REST_URL}/user/{member}"))?),
                )?;
                info!("KPKG GET: STATUS={}", resp.status());
                if resp.status().is_success() {
                    let kpkg = block_on(resp.into_body().collect())?.to_bytes();
                    if proposal {
                        let welcome_msg = client.lock().unwrap().propose_add_member(&kpkg)?;
                        let welcome = Bytes::from(welcome_msg);
                        let request = Request::builder()
                            .uri(format!("{REST_URL}/proposal/{member}"))
                            .method(Method::PUT)
                            .body(Full::new(welcome.clone()))?;

                        let resp = block_on(rest_client.request(request))?;
                        info!("PROPOSAL: STATUS={}", resp.status());
                    } else {
                        let (commit_msg, welcome_msg) =
                            client.lock().unwrap().commit_add_member(&kpkg)?;
                        let welcome = Bytes::from(welcome_msg);
                        let request = Request::builder()
                            .uri(format!("{REST_URL}/welcome/{member}"))
                            .method(Method::PUT)
                            .body(Full::new(welcome.clone()))?;

                        let resp = block_on(rest_client.request(request))?;
                        info!("ADD: STATUS={}", resp.status());
                    }
                }
            } else if line.starts_with("join") {
                let resp = block_on(
                    rest_client.get(Uri::from_str(&format!("{REST_URL}/welcome/{username}"))?),
                )?;
                info!("JOIN: STATUS={}", resp.status());
                if resp.status().is_success() {
                    let welcome = block_on(resp.into_body().collect())?.to_bytes();
                    client.lock().unwrap().join_group(welcome.to_vec())?;
                }
            } else if line.starts_with("create") {
                let body = client.lock().unwrap().create_group()?;
                let request = Request::builder()
                    .method(Method::PUT)
                    .uri(format!("{REST_URL}/group/{username}"))
                    .body(Full::new(Bytes::from(body)))?;
                let resp = block_on(rest_client.request(request))?;
                info!("CREATE: STATUS={}", resp.status());
            } else if line.starts_with("sync") {
                let resp = block_on(rest_client.get(Uri::from_str(&format!(
                    "{REST_URL}/messages?offset={offset}"
                ))?))?;
                info!("MESSAGES : STATUS={}", resp.status());

                if resp.status().is_success() {
                    let body = block_on(resp.into_body().collect())?.to_bytes();
                    let msgs: Vec<Vec<u8>> = bincode::deserialize(body.as_ref())?;

                    for msg in msgs.iter() {
                        if let Err(err) = client.lock().unwrap().process_message(&msg) {
                            error!("{err}");
                        }
                    }

                    offset += msgs.len();
                    info!("SYNCED OFFSET: {offset}");
                }
            } else if line.starts_with("send") {
                let (_, umsg) = line.split_once(' ').unwrap();
                let msg = client.lock().unwrap().encrypt_message(umsg.as_bytes())?;
                block_on(write.send(Message::Binary(msg)))?;
                info!("Sent {umsg}");
            } else if line.starts_with("commit") {
                let body = Bytes::from(client.lock().unwrap().commit()?);
                let request = Request::builder()
                    .method(Method::PUT)
                    .uri(format!("{REST_URL}/commit/{username}"))
                    .body(Full::new(Bytes::from(body)))?;
                let resp = block_on(rest_client.request(request))?;
                info!("COMMIT: STATUS={}", resp.status());
            } else {
                error!("Invalid Command {}", line);
            }
        } else {
            break;
        }
    }
    Ok(())
}
