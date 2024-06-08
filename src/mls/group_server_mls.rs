use anyhow::anyhow;
use mls_rs::{
    external_client::{
        builder::{ExternalBaseConfig, WithCryptoProvider, WithIdentityProvider},
        ExternalClient, ExternalReceivedMessage, ExternalSnapshot,
    },
    group::CachedProposal,
    identity::basic::BasicIdentityProvider,
    mls_rules::DefaultMlsRules,
    MlsMessage,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

type ExternalMlsConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, ExternalBaseConfig>,
>;

pub struct GroupServerMLS {
    group_state: Vec<u8>,
    cached_proposals: Vec<Vec<u8>>,
    message_queue: Vec<Vec<u8>>,
}

pub fn make_server() -> ExternalClient<ExternalMlsConfig> {
    let crypto_provider = OpensslCryptoProvider::new();
    ExternalClient::builder()
        .crypto_provider(crypto_provider)
        .identity_provider(BasicIdentityProvider::new())
        .mls_rules(DefaultMlsRules::new())
        .build()
}

impl GroupServerMLS {
    pub fn new(group_info: &[u8]) -> anyhow::Result<Self> {
        let group_info = MlsMessage::from_bytes(group_info)?;

        let server = make_server();
        let group = server.observe_group(group_info, None)?;
        let group_state = group.snapshot().to_bytes()?;
        let cached_proposals = Vec::new();
        let message_queue = Vec::new();

        Ok(Self {
            group_state,
            cached_proposals,
            message_queue,
        })
    }

    pub fn upload_proposal(&mut self, proposal: Vec<u8>) -> anyhow::Result<()> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state)?;

        let proposal_msg = MlsMessage::from_bytes(&proposal)?;

        let res = group.process_incoming_message(proposal_msg)?;

        let ExternalReceivedMessage::Proposal(proposal_desc) = res else {
            return Err(anyhow!("Expected Proposal Message"));
        };

        self.cached_proposals
            .push(proposal_desc.cached_proposal().to_bytes()?);
        self.message_queue.push(proposal);
        Ok(())
    }

    pub fn upload_commit(&mut self, commit: Vec<u8>) -> anyhow::Result<()> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state)?;
        for p in &self.cached_proposals {
            group.insert_proposal(CachedProposal::from_bytes(p)?);
        }

        let commit_msg = MlsMessage::from_bytes(&commit)?;
        let res = group.process_incoming_message(commit_msg)?;

        let ExternalReceivedMessage::Commit(_) = res else {
            return Err(anyhow!("Expected Commit Message"));
        };

        self.cached_proposals.clear();
        self.group_state = group.snapshot().to_bytes()?;
        self.message_queue.push(commit);

        Ok(())
    }

    pub fn download_messages(&self, offset: usize) -> &[Vec<u8>] {
        &self.message_queue[offset..]
    }
}
