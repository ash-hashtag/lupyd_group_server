use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use log::info;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{error::SendError, Sender},
    RwLock,
};
use tokio_tungstenite::tungstenite::Message;

use crate::mls::group_server_mls::GroupServerMLS;

pub type Tx = Sender<Message>;

#[derive(Serialize, Deserialize)]
pub enum GroupChannelType {
    Text,
    Voice,
    Video,
}

#[derive(Serialize, Deserialize)]
pub struct GroupChannel {
    channel_type: GroupChannelType,
    members: BTreeSet<String>,
}

impl GroupChannel {
    pub fn add_member(&mut self, username: String) -> bool {
        self.members.insert(username)
    }

    pub fn remove_member(&mut self, username: &str) -> bool {
        self.members.remove(username)
    }
}

pub struct GroupServer {
    name: String,
    channels: BTreeMap<String, GroupChannel>,
    members: BTreeMap<String, Vec<u8>>,
    pub invites: BTreeMap<String, Vec<u8>>,
    pub mls_group: Option<GroupServerMLS>,
}

pub enum AddMemberWith {
    Channel(String),
    Key(Vec<u8>),
}

impl GroupServer {
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_member_key(&self, username: &str) -> Option<Vec<u8>> {
        self.members.get(username).cloned()
    }

    pub fn add_member(&mut self, username: String, with: AddMemberWith) {
        match with {
            AddMemberWith::Channel(channel_name) => {
                if let Some(channel) = self.channels.get_mut(&channel_name) {
                    channel.add_member(username);
                }
            }
            AddMemberWith::Key(pkg) => {
                self.members.insert(username, pkg);
            }
        }
    }

    pub fn remove_member(&mut self, username: &str, channel_name: Option<&str>) {
        if let Some(channel_name) = channel_name {
            if let Some(channel) = self.channels.get_mut(channel_name) {
                channel.remove_member(username);
            }
        } else {
            self.members.remove(username);
            for channel in self.channels.values_mut() {
                channel.remove_member(username);
            }
        }
    }

    pub fn add_channel(&mut self, channel_name: impl Into<String>, channel: GroupChannel) -> bool {
        self.channels
            .try_insert(channel_name.into(), channel)
            .is_ok()
    }

    pub fn remove_channel(&mut self, channel_name: &str) -> bool {
        self.channels.remove(channel_name).is_some()
    }

    pub fn get_channel(&self, channel_name: &str) -> Option<&GroupChannel> {
        self.channels.get(channel_name)
    }

    pub fn get_channels(&self) -> &BTreeMap<String, GroupChannel> {
        &self.channels
    }

    pub fn get_members(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.members
    }

    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            channels: BTreeMap::new(),
            members: BTreeMap::new(),
            invites: BTreeMap::new(),
            mls_group: None,
        }
    }
}

#[derive(Clone)]
pub struct ActiveConnections {
    map: Arc<RwLock<HashMap<String, Tx>>>,
}

impl ActiveConnections {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn broadcast(
        &self,
        msg: Message,
        except: Option<String>,
    ) -> Vec<Result<(), SendError<Message>>> {
        let gaurd = self.map.read().await;
        let values = gaurd.values();
        if let Some(except) = except {
            let r = futures::future::join_all(gaurd.iter().map(|(k, tx)| async {
                let k = k.clone();
                if k != except {
                    info!("Sending {} bytes to {k}", msg.len());
                    tx.send(msg.clone()).await?;
                }
                Ok(())
            }))
            .await;

            r
        } else {
            let f = values.map(|tx| tx.send(msg.clone()));
            let r = futures::future::join_all(f).await;
            r
        }
    }

    pub async fn add_peer(&self, id: String, tx: Tx) -> Option<Tx> {
        self.map.write().await.insert(id, tx)
    }

    pub async fn remove_peer(&self, id: &str) -> Option<Tx> {
        self.map.write().await.remove(id)
    }

    pub async fn send(&self, id: &str, msg: Message) -> Option<Result<(), SendError<Message>>> {
        let gaurd = self.map.read().await;
        let tx = gaurd.get(id)?;
        Some(tx.send(msg).await)
    }
}
