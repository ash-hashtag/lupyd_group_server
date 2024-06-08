use std::path::Path;

use log::{info, warn};
use mls_rs::{
    client_builder::{
        BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
        WithKeyPackageRepo, WithPskStore,
    },
    crypto::SignatureSecretKey,
    error::MlsError,
    group::{CommitMessageDescription, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    mls_rules::{CommitOptions, DefaultMlsRules},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_provider_sqlite::{
    connection_strategy::FileConnectionStrategy, SqLiteDataStorageEngine,
};

use mls_rs_provider_sqlite::storage::{
    SqLiteGroupStateStorage, SqLiteKeyPackageStorage, SqLitePreSharedKeyStorage,
};
type MlsClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<
        OpensslCryptoProvider,
        // WithPskStore<
        //     SqLitePreSharedKeyStorage,
        //     WithGroupStateStorage<
        //         SqLiteGroupStateStorage,
        //         WithKeyPackageRepo<SqLiteKeyPackageStorage, BaseConfig>,
        //     >,
        // >,
        BaseConfig,
    >,
>;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

fn cipher_suite_provider() -> impl CipherSuiteProvider {
    OpensslCryptoProvider::new()
        .cipher_suite_provider(CIPHERSUITE)
        .unwrap()
}

pub struct GroupClientMLS {
    id: Vec<u8>,
    client: Client<MlsClientConfig>,
    group: Option<Group<MlsClientConfig>>,
}

fn make_client(id: &[u8], sqlite_path: &Path) -> anyhow::Result<Client<MlsClientConfig>> {
    let (secret, signing_identity) = make_identity(id);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(OpensslCryptoProvider::new())
        .mls_rules(
            DefaultMlsRules::new()
                .with_commit_options(CommitOptions::new().with_single_welcome_message(false)),
        )
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build())
}

fn make_identity(id: &[u8]) -> (SignatureSecretKey, SigningIdentity) {
    let cipher_suite = cipher_suite_provider();
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    let basic_identity = BasicCredential::new(id.to_vec());
    let identity = SigningIdentity::new(basic_identity.into_credential(), public);

    (secret, identity)
}

impl GroupClientMLS {
    pub fn new(id: Vec<u8>, sqlite_path: &Path) -> anyhow::Result<Self> {
        let client = make_client(&id, sqlite_path)?;
        let group = None;
        Ok(Self { id, client, group })
    }

    pub fn create_group(&mut self) -> Result<Vec<u8>, MlsError> {
        let group = self.client.create_group(ExtensionList::default())?;
        info!("CREATED GROUp");
        let res = group.group_info_message(true)?.to_bytes();
        self.group = Some(group);
        res
    }

    pub fn join_group(&mut self, welcome: Vec<u8>) -> anyhow::Result<()> {
        let (group, mem) = self
            .client
            .join_group(None, &MlsMessage::from_bytes(&welcome)?)?;
        info!("JOINED {:?}", mem);
        self.group = Some(group);
        Ok(())
    }

    pub fn key_package(&self) -> Result<Vec<u8>, MlsError> {
        let msg = self.client.generate_key_package_message()?;
        msg.to_bytes()
    }

    pub fn commit_add_member(
        &mut self,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), MlsError> {
        let key_pkg = MlsMessage::from_bytes(key_package)?;
        let g = self.group.as_mut().unwrap();

        let commit = g.commit_builder().add_member(key_pkg)?.build()?;

        let commit_message = commit.commit_message.to_bytes()?;
        let welcome_message = commit.welcome_messages[0].to_bytes()?;

        Ok((commit_message, welcome_message))
    }

    pub fn propose_add_member(&mut self, key_package: &[u8]) -> Result<Vec<u8>, MlsError> {
        let key_pkg = MlsMessage::from_bytes(key_package)?;
        let g = self.group.as_mut().unwrap();

        g.propose_add(key_pkg, Vec::new())?.to_bytes()
    }

    pub fn apply_pending_commits(&mut self) -> Result<CommitMessageDescription, MlsError> {
        self.group.as_mut().unwrap().apply_pending_commit()
    }

    pub fn commit(&mut self) -> Result<Vec<u8>, MlsError> {
        self.group
            .as_mut()
            .unwrap()
            .commit(Vec::new())?
            .commit_message
            .to_bytes()
    }

    pub fn process_messages(&mut self, messages: Vec<Vec<u8>>) -> anyhow::Result<()> {
        for msg in messages {
            self.process_message(&msg)?;
        }
        Ok(())
    }

    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, MlsError> {
        let msg = self
            .group
            .as_mut()
            .unwrap()
            .encrypt_application_message(message, Vec::new())?;
        msg.to_bytes()
    }

    pub fn process_message(&mut self, msg: &[u8]) -> anyhow::Result<()> {
        let message = MlsMessage::from_bytes(&msg)?;
        if let Some(group) = self.group.as_mut() {
            let res = group.process_incoming_message(message)?;
            match res {
                ReceivedMessage::ApplicationMessage(msg) => {
                    let s = std::str::from_utf8(msg.data())?;
                    let sender_id = msg.sender_index;
                    info!("Sender #{sender_id}:{s}");
                }
                ReceivedMessage::GroupInfo(group_info) => {
                    info!("Group Info: {:?}", group_info)
                }
                _ => {
                    warn!("UNHANDLED RECEIVED MESSAGE: {:?}", res);
                }
            };
        } else {
            warn!("Group is missing");
        }
        Ok(())
    }
}

pub fn normal_test() -> anyhow::Result<()> {
    let client = make_client(b"hello", std::path::Path::new(""))?;
    let alice = make_client(b"alice", std::path::Path::new(""))?;
    let bob = make_client(b"bob", std::path::Path::new(""))?;
    let charles = make_client(b"charles", std::path::Path::new(""))?;
    let dave = make_client(b"dave", std::path::Path::new(""))?;
    let mut group = client.create_group(ExtensionList::default())?;

    let key_alice = alice.generate_key_package_message()?;
    let key_bob = bob.generate_key_package_message()?;
    let key_charles = charles.generate_key_package_message()?;
    let key_dave = dave.generate_key_package_message()?;

    let commit = group
        .commit_builder()
        .add_member(key_alice.clone())?
        .add_member(key_bob.clone())?
        .add_member(key_charles.clone())?
        .add_member(key_dave.clone())?
        .build()?;
    for msg in commit.welcome_messages {
        info!("WELCOME: {:?}", msg);
        for r1 in msg.welcome_key_package_references() {
            let r2 = key_dave
                .key_package_reference(&cipher_suite_provider())?
                .unwrap();
            if r1 == &r2 {
                println!("Belongs to Dave");
            }
            let r2 = key_alice
                .key_package_reference(&cipher_suite_provider())?
                .unwrap();
            if r1 == &r2 {
                println!("Belongs to Alice");
            }
            let r2 = key_charles
                .key_package_reference(&cipher_suite_provider())?
                .unwrap();
            if r1 == &r2 {
                println!("Belongs to Charles");
            }
            let r2 = key_bob
                .key_package_reference(&cipher_suite_provider())?
                .unwrap();
            if r1 == &r2 {
                println!("Belongs to Bob");
            }
        }
    }

    Ok(())
}
