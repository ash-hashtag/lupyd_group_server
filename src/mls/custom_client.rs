use anyhow::anyhow;
use anyhow::Context;
use log::error;
use log::info;
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::MlsExtension;
use mls_rs::external_client::builder::MlsConfig as ExternalMlsConfig;
use mls_rs::external_client::ExternalClient;
use mls_rs::external_client::ExternalReceivedMessage;
use mls_rs::external_client::ExternalSnapshot;
use mls_rs::group::CachedProposal;
use mls_rs::group::GroupContext;
use mls_rs::group::ProposalSender;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::CustomCredential;
use mls_rs::identity::MlsCredential;
use mls_rs::mls_rules::CommitSource;
use mls_rs::Client;
use mls_rs::MlsMessage;
use std::assert_matches::assert_matches;
use std::fmt::Display;

use mls_rs::{
    crypto::{SignaturePublicKey, SignatureSecretKey},
    error::{ExtensionError, IntoAnyError, MlsError},
    extension::{ExtensionType, MlsCodecExtension},
    group::{
        proposal::{MlsCustomProposal, Proposal, ProposalType},
        Sender,
    },
    identity::{Credential, CredentialType, SigningIdentity},
    mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize},
    mls_rules::{CommitOptions, EncryptionOptions, ProposalSource},
    time::MlsTime,
    CipherSuite, CipherSuiteProvider, CryptoProvider, ExtensionList, IdentityProvider, MlsRules,
};

const CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

const ROSTER_EXTENSION_V1: ExtensionType = ExtensionType::new(65000);
const ADD_USER_PROPOSAL_V1: ProposalType = ProposalType::new(65001);
const REMOVE_USER_PROPOSAL_V1: ProposalType = ProposalType::new(65002);
const CREDENTIAL_V1: CredentialType = CredentialType::new(65002);

fn crypto() -> impl CryptoProvider + Clone {
    mls_rs_crypto_openssl::OpensslCryptoProvider::new()
}

fn cipher_suite() -> impl CipherSuiteProvider {
    crypto().cipher_suite_provider(CIPHER_SUITE).unwrap()
}

#[derive(MlsSize, MlsDecode, MlsEncode)]
#[repr(u8)]
enum UserRole {
    Regular = 1u8,
    Moderator = 2u8,
}

#[derive(MlsSize, MlsDecode, MlsEncode)]
struct UserCredential {
    name: String,
    role: UserRole,
    public_key: SignaturePublicKey,
}

#[derive(MlsSize, MlsDecode, MlsEncode)]
struct MemberCredential {
    name: String,
    user_public_key: SignaturePublicKey, // Identifies the user
    signature: Vec<u8>,
}

#[derive(MlsSize, MlsEncode)]
struct MemberCredentialTBS<'a> {
    name: &'a str,
    user_public_key: &'a SignaturePublicKey,
    public_key: &'a SignaturePublicKey,
}

/// The roster will be stored in the custom RosterExtension, an extension in the MLS GroupContext
#[derive(MlsSize, MlsDecode, MlsEncode)]
struct RosterExtension {
    roster: Vec<UserCredential>,
}

impl MlsCodecExtension for RosterExtension {
    fn extension_type() -> ExtensionType {
        ROSTER_EXTENSION_V1
    }
}

/// The custom AddUser proposal will be used to update the RosterExtension
#[derive(MlsSize, MlsDecode, MlsEncode)]
struct AddUserProposal {
    new_user: UserCredential,
}

impl MlsCustomProposal for AddUserProposal {
    fn proposal_type() -> ProposalType {
        ADD_USER_PROPOSAL_V1
    }
}
#[derive(MlsSize, MlsDecode, MlsEncode)]
struct RemoveUserProposal {
    username: UserCredential,
}

impl MlsCustomProposal for RemoveUserProposal {
    fn proposal_type() -> ProposalType {
        REMOVE_USER_PROPOSAL_V1
    }
}

/// MlsRules tell MLS how to handle our custom proposal
#[derive(Debug, Clone, Copy)]
struct CustomMlsRules;

#[derive(Debug, thiserror::Error)]
struct CustomError;

impl IntoAnyError for CustomError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Custom Error")
    }
}

impl From<MlsError> for CustomError {
    fn from(_: MlsError) -> Self {
        Self
    }
}

impl From<mls_rs_codec::Error> for CustomError {
    fn from(_: mls_rs_codec::Error) -> Self {
        Self
    }
}

impl From<ExtensionError> for CustomError {
    fn from(_: ExtensionError) -> Self {
        Self
    }
}

impl MlsRules for CustomMlsRules {
    type Error = CustomError;

    fn filter_proposals(
        &self,
        _direction: mls_rs::mls_rules::CommitDirection,
        source: mls_rs::mls_rules::CommitSource,
        _current_roster: &mls_rs::group::Roster,
        extension_list: &mls_rs::ExtensionList,
        mut proposals: mls_rs::mls_rules::ProposalBundle,
    ) -> Result<mls_rs::mls_rules::ProposalBundle, Self::Error> {
        let CommitSource::ExistingMember(member) = source else {
            return Err(CustomError);
        };

        let mut roster: RosterExtension =
            extension_list.get_as().ok().flatten().ok_or(CustomError)?;
        let Credential::Custom(custom) = member.signing_identity.credential else {
            return Err(CustomError);
        };

        if custom.credential_type != CREDENTIAL_V1 {
            return Err(CustomError);
        }

        let member = MemberCredential::mls_decode(&mut &*custom.data)?;
        info!("Committer Source: {}", member.name);
        let committer = roster
            .roster
            .iter()
            .find(|u| u.public_key == member.user_public_key)
            .ok_or(CustomError)?;
        if !matches!(committer.role, UserRole::Moderator) {
            error!("Regular User {} tried to commit", committer.name);
            return Err(CustomError);
        }

        let add_user_proposals = proposals
            .custom_proposals()
            .iter()
            .filter(|p| p.proposal.proposal_type() == ADD_USER_PROPOSAL_V1);

        for add_user_info in add_user_proposals {
            let add_user = AddUserProposal::from_custom_proposal(&add_user_info.proposal)?;

            roster.roster.push(add_user.new_user);
        }

        // Issue GroupContextExtensions proposal to modify our roster (eventually we don't have to do this if there were no AddUser proposals)
        let mut new_extensions = extension_list.clone();
        new_extensions.set_from(roster)?;
        let gce_proposal = Proposal::GroupContextExtensions(new_extensions);
        proposals.add(gce_proposal, Sender::Member(0), ProposalSource::Local);

        Ok(proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &mls_rs::group::Roster,
        _new_extension_list: &mls_rs::ExtensionList,
        _proposals: &mls_rs::mls_rules::ProposalBundle,
    ) -> Result<mls_rs::mls_rules::CommitOptions, Self::Error> {
        Ok(CommitOptions::new())
    }

    fn encryption_options(
        &self,
        _current_roster: &mls_rs::group::Roster,
        _current_extension_list: &mls_rs::ExtensionList,
    ) -> Result<mls_rs::mls_rules::EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::new(
            false,
            mls_rs::client_builder::PaddingMode::None,
        ))
    }
}

// The IdentityProvider will tell MLS how to validate members' identities. We will use custom identity
// type to store our User structs.
impl MlsCredential for MemberCredential {
    type Error = CustomError;

    fn credential_type() -> CredentialType {
        CREDENTIAL_V1
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        Ok(Credential::Custom(CustomCredential::new(
            Self::credential_type(),
            self.mls_encode_to_vec()?,
        )))
    }
}

#[derive(Debug, Clone, Copy)]
struct CustomIdentityProvider;

impl IdentityProvider for CustomIdentityProvider {
    type Error = CustomError;

    fn validate_member(
        &self,
        signing_identity: &mls_rs::identity::SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        extensions: Option<&mls_rs::ExtensionList>,
    ) -> Result<(), Self::Error> {
        let Some(extensions) = extensions else {
            return Ok(());
        };

        let roster = extensions
            .get_as::<RosterExtension>()
            .ok()
            .flatten()
            .ok_or(CustomError)?;

        let Credential::Custom(custom) = &signing_identity.credential else {
            return Err(CustomError);
        };

        if custom.credential_type != CREDENTIAL_V1 {
            return Err(CustomError);
        }

        let member = MemberCredential::mls_decode(&mut &*custom.data)?;

        // validate the member credential

        let tbs = MemberCredentialTBS {
            name: &member.name,
            user_public_key: &member.user_public_key,
            public_key: &signing_identity.signature_key,
        }
        .mls_encode_to_vec()?;

        cipher_suite()
            .verify(&member.user_public_key, &member.signature, &tbs)
            .map_err(|_| CustomError)?;

        let user_in_roster = roster
            .roster
            .iter()
            .any(|u| u.public_key == member.user_public_key);

        if !user_in_roster {
            return Err(CustomError);
        }

        Ok(())
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(signing_identity.mls_encode_to_vec()?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CREDENTIAL_V1]
    }

    fn valid_successor(
        &self,
        _: &SigningIdentity,
        _: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn validate_external_sender(
        &self,
        _: &SigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Convenience structs to create users and members

struct User {
    credential: UserCredential,
    signer: SignatureSecretKey,
}

impl User {
    fn new(name: &str, role: UserRole) -> Result<Self, CustomError> {
        let (signer, public_key) = cipher_suite()
            .signature_key_generate()
            .map_err(|_| CustomError)?;

        let credential = UserCredential {
            name: name.into(),
            role,
            public_key,
        };

        Ok(Self { credential, signer })
    }
}

struct Member {
    credential: MemberCredential,
    public_key: SignaturePublicKey,
    signer: SignatureSecretKey,
}

impl Member {
    fn new(name: &str, user: &User) -> Result<Self, CustomError> {
        let (signer, public_key) = cipher_suite()
            .signature_key_generate()
            .map_err(|_| CustomError)?;

        let tbs = MemberCredentialTBS {
            name,
            user_public_key: &user.credential.public_key,
            public_key: &public_key,
        }
        .mls_encode_to_vec()?;

        let signature = cipher_suite()
            .sign(&user.signer, &tbs)
            .map_err(|_| CustomError)?;

        let credential = MemberCredential {
            name: name.into(),
            user_public_key: user.credential.public_key.clone(),
            signature,
        };

        Ok(Self {
            credential,
            signer,
            public_key,
        })
    }
}

// Set up Client to use our custom providers
fn make_client(member: Member) -> Result<Client<impl MlsConfig>, CustomError> {
    let mls_credential = member.credential.into_credential()?;
    let signing_identity = SigningIdentity::new(mls_credential, member.public_key);

    Ok(Client::builder()
        .identity_provider(CustomIdentityProvider)
        .mls_rules(CustomMlsRules)
        .custom_proposal_type(ADD_USER_PROPOSAL_V1)
        .extension_type(ROSTER_EXTENSION_V1)
        .crypto_provider(crypto())
        .signing_identity(signing_identity, member.signer, CIPHER_SUITE)
        .build())
}

struct BasicServer {
    group_state: Vec<u8>,
    cached_proposals: Vec<Vec<u8>>,
    message_queue: Vec<Vec<u8>>,
}

impl BasicServer {
    pub fn new(group_info: &[u8]) -> Result<Self, MlsError> {
        let server = make_server();
        let group_info = MlsMessage::from_bytes(group_info)?;

        let group = server.observe_group(group_info, None)?;

        Ok(Self {
            group_state: group.snapshot().to_bytes()?,
            cached_proposals: Vec::new(),
            message_queue: Vec::new(),
        })
    }

    // Client uploads a proposal. This doesn't change the server's group state, so clients can
    // upload prposals without synchronization (`cached_proposals` and `message_queue` collect
    // all proposals in any order).
    pub fn upload_proposal(&mut self, proposal: Vec<u8>) -> Result<(), MlsError> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state)?;

        let proposal_msg = MlsMessage::from_bytes(&proposal)?;
        let res = group.process_incoming_message(proposal_msg)?;

        let ExternalReceivedMessage::Proposal(proposal_desc) = res else {
            panic!("expected proposal message!")
        };

        if let ProposalSender::Member(member) = proposal_desc.sender {
            info!("Proposal by {}", member);
        }

        self.cached_proposals
            .push(proposal_desc.cached_proposal().to_bytes()?);

        self.message_queue.push(proposal);

        Ok(())
    }

    // Client uploads a commit. This changes the server's group state, so in a real application,
    // it must be synchronized. That is, only one `upload_commit` operation can succeed.
    fn upload_commit(&mut self, commit: Vec<u8>) -> Result<(), MlsError> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state)?;

        for p in &self.cached_proposals {
            group.insert_proposal(CachedProposal::from_bytes(p)?);
        }

        let commit_msg = MlsMessage::from_bytes(&commit)?;
        let res = group.process_incoming_message(commit_msg)?;

        let ExternalReceivedMessage::Commit(_commit_desc) = res else {
            panic!("expected commit message!")
        };

        self.cached_proposals = Vec::new();
        self.group_state = group.snapshot().to_bytes()?;
        self.message_queue.push(commit);

        Ok(())
    }

    pub fn download_messages(&self, i: usize) -> &[Vec<u8>] {
        &self.message_queue[i..]
    }
}

fn make_server() -> ExternalClient<impl ExternalMlsConfig> {
    ExternalClient::builder()
        .identity_provider(CustomIdentityProvider)
        .mls_rules(CustomMlsRules)
        .extension_type(ROSTER_EXTENSION_V1)
        .custom_proposal_type(ADD_USER_PROPOSAL_V1)
        .crypto_provider(crypto())
        .build()
}

pub fn test_custom_client() -> anyhow::Result<()> {
    let alice = User::new("alice", UserRole::Moderator)?;
    let bob = User::new("bob", UserRole::Regular)?;
    let charles = User::new("charles", UserRole::Regular)?;

    let alice_tablet = Member::new("alice tablet", &alice)?;
    let alice_pc = Member::new("alice pc", &alice)?;
    let bob_tablet = Member::new("bob tablet", &bob)?;
    let charles_tablet = Member::new("charles tablet", &charles)?;

    let mut context_extensions = ExtensionList::new();
    let roster = vec![alice.credential];
    context_extensions.set_from(RosterExtension { roster })?;

    let alice_tablet_client = make_client(alice_tablet)?;
    let mut alice_tablet_group = alice_tablet_client.create_group(context_extensions)?;
    let alice_pc_client = make_client(alice_pc)?;
    let bob_tablet_client = make_client(bob_tablet)?;
    let charles_tablet_client = make_client(charles_tablet)?;

    let key_package = alice_pc_client.generate_key_package_message()?;
    let commit = alice_tablet_group
        .commit_builder()
        .add_member(key_package)?
        .build()?;

    info!("COMMIT: {:?}", commit);

    let committed = alice_tablet_group.apply_pending_commit()?;
    info!("COMMITED: {:?}", committed);

    let (mut alice_pc_group, mem_info) =
        alice_pc_client.join_group(None, &commit.welcome_messages[0])?;

    info!("NEW_MEM: {:?}", mem_info);

    let key_package = bob_tablet_client.generate_key_package_message()?;

    let commit = alice_tablet_group
        .commit_builder()
        .add_member(key_package.clone())?
        .build();

    assert_matches!(commit, Err(MlsError::IdentityProviderError(_)));
    info!("COMMIT: {:?}", commit);

    let add_bob = AddUserProposal {
        new_user: bob.credential,
    };

    let commit = alice_tablet_group
        .commit_builder()
        .custom_proposal(add_bob.to_custom_proposal()?)
        .add_member(key_package)?
        .build()?;

    info!("COMMIT: {:?}", commit);

    let (mut bob_tablet_group, mem_info) =
        bob_tablet_client.join_group(None, &commit.welcome_messages[0])?;

    info!("NEW_MEM: {:?}", mem_info);
    let commited = alice_tablet_group.apply_pending_commit()?;

    info!("COMMITED: {:?}", commited);

    alice_pc_group.process_incoming_message(commit.commit_message.clone())?;

    let msg = alice_pc_group.encrypt_application_message(b"Hello World", Vec::new())?;

    let ReceivedMessage::ApplicationMessage(data) =
        bob_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("BOB RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("BOB RECV: {} {}", data.sender_index, s);
    let ReceivedMessage::ApplicationMessage(data) =
        alice_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_TABLET RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_TABLET RECV: {} {}", data.sender_index, s);

    let sender = bob_tablet_group
        .member_at_index(data.sender_index)
        .context("Missing Sender")?;

    let Credential::Custom(custom) = sender.signing_identity.credential else {
        return Err(anyhow!("NOT CUSTOM IDENTITY"));
    };

    if custom.credential_type != CREDENTIAL_V1 {
        return Err(anyhow!("Not Valid Credential Type"));
    }

    let member = MemberCredential::mls_decode(&mut &*custom.data)?;
    info!(
        "Sender Member Public Key: {:?}",
        member.user_public_key.as_bytes()
    );

    let add_charles = AddUserProposal {
        new_user: charles.credential,
    };

    let commit = bob_tablet_group
        .commit_builder()
        .custom_proposal(add_charles.to_custom_proposal()?)
        .add_member(charles_tablet_client.generate_key_package_message()?)?
        .build()?;
    info!("COMMIT: {:?}", commit);
    alice_pc_group.process_incoming_message(commit.commit_message.clone())?;
    alice_tablet_group.process_incoming_message(commit.commit_message.clone())?;

    bob_tablet_group.apply_pending_commit()?;

    let (mut charles_tablet_group, _) =
        charles_tablet_client.join_group(None, &commit.welcome_messages[0])?;

    let msg =
        charles_tablet_group.encrypt_application_message(b"Hello From Charles", Vec::new())?;

    let ReceivedMessage::ApplicationMessage(data) =
        bob_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("BOB RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("BOB RECV: {} {}", data.sender_index, s);
    let ReceivedMessage::ApplicationMessage(data) =
        alice_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_TABLET RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_TABLET RECV: {} {}", data.sender_index, s);

    let ReceivedMessage::ApplicationMessage(data) =
        alice_pc_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_PC RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_PC RECV: {} {}", data.sender_index, s);

    let sender = alice_tablet_group
        .member_at_index(data.sender_index)
        .context("Missing Sender")?;

    let Credential::Custom(custom) = sender.signing_identity.credential else {
        return Err(anyhow!("NOT CUSTOM IDENTITY"));
    };

    if custom.credential_type != CREDENTIAL_V1 {
        return Err(anyhow!("Not Valid Credential Type"));
    }

    let member = MemberCredential::mls_decode(&mut &*custom.data)?;
    info!(
        "Sender Member Public Key: {:?}",
        member.user_public_key.as_bytes()
    );

    let extension = charles_tablet_group
        .context()
        .extensions()
        .get(ROSTER_EXTENSION_V1)
        .context("Missing Roster Extension")?;

    let roster = RosterExtension::from_extension(&extension)?;
    for user in roster.roster {
        info!(
            "User: Name: {}, Role: {} KEY: {:?}",
            user.name,
            user.role as u8,
            user.public_key.as_bytes()
        );
    }
    Ok(())
}

pub fn test_server_client() -> anyhow::Result<()> {
    let alice = User::new("alice", UserRole::Moderator)?;
    let bob = User::new("bob", UserRole::Regular)?;
    let charles = User::new("charles", UserRole::Regular)?;

    let alice_tablet = Member::new("alice tablet", &alice)?;
    let alice_pc = Member::new("alice pc", &alice)?;
    let bob_tablet = Member::new("bob tablet", &bob)?;
    let charles_tablet = Member::new("charles tablet", &charles)?;

    let mut context_extensions = ExtensionList::new();
    let roster = vec![alice.credential];
    context_extensions.set_from(RosterExtension { roster })?;

    let alice_tablet_client = make_client(alice_tablet)?;
    let mut alice_tablet_group = alice_tablet_client.create_group(context_extensions)?;

    let alice_pc_client = make_client(alice_pc)?;
    let bob_tablet_client = make_client(bob_tablet)?;
    let charles_tablet_client = make_client(charles_tablet)?;

    let key_package = alice_pc_client.generate_key_package_message()?;
    let commit = alice_tablet_group
        .commit_builder()
        .add_member(key_package)?
        .build()?;

    info!("COMMIT: {:?}", commit);

    let committed = alice_tablet_group.apply_pending_commit()?;
    info!("COMMITED: {:?}", committed);

    let (mut alice_pc_group, mem_info) =
        alice_pc_client.join_group(None, &commit.welcome_messages[0])?;

    info!("NEW_MEM: {:?}", mem_info);

    let key_package = bob_tablet_client.generate_key_package_message()?;
    let mut server = BasicServer::new(&alice_tablet_group.group_info_message(true)?.to_bytes()?)?;

    // let commit = alice_tablet_group
    //     .commit_builder()
    //     .add_member(key_package.clone())?
    //     .build();

    // assert_matches!(commit, Err(MlsError::IdentityProviderError(_)));
    // info!("COMMIT: {:?}", commit);
    for m in server.download_messages(0) {
        let msg = alice_tablet_group.process_incoming_message(MlsMessage::from_bytes(m)?)?;
        info!("ALICE_TABLET DOWNLOADED MESSAGE: {:?}", msg);
    }

    let add_bob = AddUserProposal {
        new_user: bob.credential,
    };
    let proposal = alice_tablet_group.propose_custom(add_bob.to_custom_proposal()?, Vec::new())?;
    server.upload_proposal(proposal.to_bytes()?)?;
    let proposal = alice_tablet_group.propose_add(key_package.clone(), Vec::new())?;
    server.upload_proposal(proposal.to_bytes()?)?;

    // let commit = alice_tablet_group
    //     .commit_builder()
    //     .custom_proposal(add_bob.to_custom_proposal()?)
    //     .add_member(key_package)?
    //     .build()?;
    info!(
        "Alice Tablet Has Pending Commits? {}",
        alice_tablet_group.has_pending_commit()
    );
    let commit = alice_tablet_group.commit(Vec::new())?;

    info!("COMMIT: {:?}", commit);
    let commit_in_bytes = commit.commit_message.to_bytes()?;
    server.upload_commit(commit_in_bytes)?;

    let commited = alice_tablet_group.apply_pending_commit()?;

    info!("COMMITED: {:?}", commited);

    let (mut bob_tablet_group, mem_info) =
        bob_tablet_client.join_group(None, &commit.welcome_messages[0])?;

    info!("NEW_MEM: {:?}", mem_info);
    for m in server.download_messages(0) {
        let msg = alice_pc_group.process_incoming_message(MlsMessage::from_bytes(m)?)?;
        info!("ALICE_PC DOWNLOADED MESSAGE: {:?}", msg);
    }

    let msg = bob_tablet_group.encrypt_application_message(b"Hello World From Bob", Vec::new())?;

    let ReceivedMessage::ApplicationMessage(data) =
        alice_pc_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_PC RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_PC RECV: {} {}", data.sender_index, s);
    let ReceivedMessage::ApplicationMessage(data) =
        alice_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_TABLET RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_TABLET RECV: {} {}", data.sender_index, s);

    let sender = alice_pc_group
        .member_at_index(data.sender_index)
        .context("Missing Sender")?;

    let Credential::Custom(custom) = sender.signing_identity.credential else {
        return Err(anyhow!("NOT CUSTOM IDENTITY"));
    };

    if custom.credential_type != CREDENTIAL_V1 {
        return Err(anyhow!("Not Valid Credential Type"));
    }

    let member = MemberCredential::mls_decode(&mut &*custom.data)?;
    info!(
        "Sender Member Public Key: {:?}",
        member.user_public_key.as_bytes()
    );

    // let commit = bob_tablet_group
    //     .commit_builder()
    //     .custom_proposal(add_charles.to_custom_proposal()?)
    //     .add_member(charles_tablet_client.generate_key_package_message()?)?
    //     .build()?;
    // info!("COMMIT: {:?}", commit);
    // alice_pc_group.process_incoming_message(commit.commit_message.clone())?;
    // alice_tablet_group.process_incoming_message(commit.commit_message.clone())?;

    // bob_tablet_group.apply_pending_commit()?;

    // let (mut charles_tablet_group, _) =
    //     charles_tablet_client.join_group(None, &commit.welcome_messages[0])?;

    // let msg =
    //     charles_tablet_group.encrypt_application_message(b"Hello From Charles", Vec::new())?;

    // let ReceivedMessage::ApplicationMessage(data) =
    //     bob_tablet_group.process_incoming_message(msg.clone())?
    // else {
    //     error!("BOB RECEIVED INVALID MSG TYPE");
    //     return Ok(());
    // };
    // let s = std::str::from_utf8(data.data())?;
    // info!("BOB RECV: {} {}", data.sender_index, s);
    // let ReceivedMessage::ApplicationMessage(data) =
    //     alice_tablet_group.process_incoming_message(msg.clone())?
    // else {
    //     error!("ALICE_TABLET RECEIVED INVALID MSG TYPE");
    //     return Ok(());
    // };
    // let s = std::str::from_utf8(data.data())?;
    // info!("ALICE_TABLET RECV: {} {}", data.sender_index, s);

    // let ReceivedMessage::ApplicationMessage(data) =
    //     alice_pc_group.process_incoming_message(msg.clone())?
    // else {
    //     error!("ALICE_PC RECEIVED INVALID MSG TYPE");
    //     return Ok(());
    // };
    // let s = std::str::from_utf8(data.data())?;
    // info!("ALICE_PC RECV: {} {}", data.sender_index, s);

    let sender = alice_tablet_group
        .member_at_index(data.sender_index)
        .context("Missing Sender")?;

    let Credential::Custom(custom) = sender.signing_identity.credential else {
        return Err(anyhow!("NOT CUSTOM IDENTITY"));
    };

    if custom.credential_type != CREDENTIAL_V1 {
        return Err(anyhow!("Not Valid Credential Type"));
    }

    let member = MemberCredential::mls_decode(&mut &*custom.data)?;
    info!(
        "Sender Member Public Key: {:?}",
        member.user_public_key.as_bytes()
    );

    let extension = alice_pc_group
        .context()
        .extensions()
        .get(ROSTER_EXTENSION_V1)
        .context("Missing Roster Extension")?;

    let roster = RosterExtension::from_extension(&extension)?;
    for user in roster.roster {
        info!(
            "User: Name: {}, Role: {} KEY: {:?}",
            user.name,
            user.role as u8,
            user.public_key.as_bytes()
        );
    }

    info!("ALICE PC EPOCH: {}", alice_pc_group.current_epoch());
    info!("ALICE TABLET EPOCH: {}", alice_tablet_group.current_epoch());
    info!("BOB TABLET EPOCH: {}", bob_tablet_group.current_epoch());

    let add_charles = AddUserProposal {
        new_user: charles.credential,
    };

    let messages_offset = server.message_queue.len();

    let proposal =
        bob_tablet_group.propose_custom(add_charles.to_custom_proposal()?, Vec::new())?;
    server.upload_proposal(proposal.to_bytes()?)?;
    let proposal = bob_tablet_group.propose_add(
        charles_tablet_client.generate_key_package_message()?,
        Vec::new(),
    )?;
    server.upload_proposal(proposal.to_bytes()?)?;

    // Bob tries to commit as regular user
    let commit = bob_tablet_group.commit(Vec::new())?;

    server.upload_commit(commit.commit_message.to_bytes()?)?;
    let _ = bob_tablet_group.apply_pending_commit()?;

    // for m in server.download_messages(messages_offset) {
    //     alice_pc_group.process_incoming_message(MlsMessage::from_bytes(m)?)?;
    // }

    // let bob_messages_offset = server.message_queue.len();

    // let commit = alice_pc_group.commit(Vec::new())?;

    // server.upload_commit(commit.commit_message.to_bytes()?)?;

    // let _ = alice_pc_group.apply_pending_commit()?;

    for m in server.download_messages(messages_offset) {
        let msg = MlsMessage::from_bytes(m)?;
        alice_tablet_group.process_incoming_message(msg.clone())?;
        alice_pc_group.process_incoming_message(msg.clone())?;
    }
    // for m in server.download_messages(bob_messages_offset) {
    //     let msg = MlsMessage::from_bytes(m)?;
    //     bob_tablet_group.process_incoming_message(msg)?;
    // }

    // for m in server.download_messages(messages_offset) {
    //         alice_pc_group.process_incoming_message(MlsMessage::from_bytes(m)?)?;
    //     }

    //     let bob_messages_offset = server.message_queue.len();

    //     let commit = alice_pc_group.commit(Vec::new())?;

    //     server.upload_commit(commit.commit_message.to_bytes()?)?;

    //     let _ = alice_pc_group.apply_pending_commit()?;

    //     for m in server.download_messages(messages_offset) {
    //         let msg = MlsMessage::from_bytes(m)?;
    //         alice_tablet_group.process_incoming_message(msg)?;
    //     }
    //     for m in server.download_messages(bob_messages_offset) {
    //         let msg = MlsMessage::from_bytes(m)?;
    //         bob_tablet_group.process_incoming_message(msg)?;
    //     }

    let (mut charles_tablet_group, mem_info) =
        charles_tablet_client.join_group(None, &commit.welcome_messages[0])?;
    info!("CHARLES MEM INFO {:?}", mem_info);

    let msg =
        charles_tablet_group.encrypt_application_message(b"Hello From Charles", Vec::new())?;

    let ReceivedMessage::ApplicationMessage(data) =
        bob_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("BOB RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("BOB RECV: {} {}", data.sender_index, s);
    let ReceivedMessage::ApplicationMessage(data) =
        alice_tablet_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_TABLET RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_TABLET RECV: {} {}", data.sender_index, s);

    let ReceivedMessage::ApplicationMessage(data) =
        alice_pc_group.process_incoming_message(msg.clone())?
    else {
        error!("ALICE_PC RECEIVED INVALID MSG TYPE");
        return Ok(());
    };
    let s = std::str::from_utf8(data.data())?;
    info!("ALICE_PC RECV: {} {}", data.sender_index, s);

    Ok(())
}
