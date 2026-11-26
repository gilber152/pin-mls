use std::io::Cursor;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::{random_bytes, CoreError};

/// RFC 9420 ciphersuite 0x0003: X25519 + ChaCha20Poly1305 + SHA-256 (kp_ref 32B) + Ed25519.
pub const PIN_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
pub const PIN_MLS_CIPHERSUITE_ID: u16 = 3;
pub const KEY_PACKAGE_LIFETIME_SEC: u64 = 30 * 24 * 3600;

/// Provider OpenMLS con almacenamiento en memoria serializable (apto para IndexedDB y SQLCipher).
pub struct PinMlsProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl PinMlsProvider {
    pub fn new_empty() -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
        }
    }

    pub fn from_json(json_str: &str) -> Result<Self, CoreError> {
        if json_str.trim().is_empty() {
            return Ok(Self::new_empty());
        }
        let mut cursor = Cursor::new(json_str.as_bytes());
        let storage = MemoryStorage::load_from_file(&mut cursor)
            .map_err(|e| CoreError::Mls(format!("fallo cargando estado OpenMLS: {e}")))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }

    pub fn to_json(&self) -> Result<String, CoreError> {
        let mut buf = Vec::new();
        self.storage
            .save_to_file(&mut buf)
            .map_err(|e| CoreError::Mls(format!("fallo serializando estado OpenMLS: {e}")))?;
        String::from_utf8(buf)
            .map_err(|e| CoreError::Mls(format!("estado OpenMLS no es UTF-8: {e}")))
    }
}

impl OpenMlsProvider for PinMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedMlsKeyPackage {
    pub kp_ref: [u8; 32],
    pub kp_raw: Vec<u8>,
    pub is_last_resort: bool,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct CreatedMlsGroup {
    pub group_id: [u8; 32],
    pub base_epoch: u64,
    pub commit_raw: Vec<u8>,
    pub welcome_raw: Vec<u8>,
    pub added_device_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct JoinedMlsGroup {
    pub group_id: [u8; 32],
    pub peer_pin: String,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedMlsCommit {
    pub skipped: bool,
    pub base_epoch: u64,
    pub commit_raw: Vec<u8>,
    pub welcome_raw: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct EncryptedMlsMessage {
    pub epoch: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ProcessedMlsOutcome {
    Application {
        epoch: u64,
        sender_pin: String,
        sender_device_id: String,
        plaintext: Vec<u8>,
    },
    Commit {
        epoch: u64,
        active: bool,
        sender_pin: String,
        sender_device_id: String,
    },
    Proposal {
        epoch: u64,
        sender_pin: String,
        sender_device_id: String,
    },
}

pub fn format_leaf_identity(pin: &str, device_id: &str) -> Vec<u8> {
    format!("{}:{}", pin.to_uppercase(), device_id.to_lowercase()).into_bytes()
}

pub fn parse_leaf_identity(identity: &[u8]) -> Option<(String, String)> {
    let txt = std::str::from_utf8(identity).ok()?;
    let (pin, dev) = txt.split_once(':')?;
    Some((pin.to_string(), dev.to_string()))
}

fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(PIN_MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(4)
        .build()
}

fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(4)
        .build()
}

pub fn create_and_store_mls_signer(provider: &PinMlsProvider) -> Result<Vec<u8>, CoreError> {
    let signer = SignatureKeyPair::new(PIN_MLS_CIPHERSUITE.signature_algorithm())
        .map_err(|e| CoreError::Mls(format!("fallo generando SignatureKeyPair: {e:?}")))?;
    let pk = signer.public().to_vec();
    signer
        .store(provider.storage())
        .map_err(|e| CoreError::Mls(format!("fallo guardando SignatureKeyPair: {e:?}")))?;
    Ok(pk)
}

pub fn load_mls_signer(provider: &PinMlsProvider, pk: &[u8]) -> Result<SignatureKeyPair, CoreError> {
    SignatureKeyPair::read(
        provider.storage(),
        pk,
        PIN_MLS_CIPHERSUITE.signature_algorithm(),
    )
    .ok_or_else(|| CoreError::Mls("SignatureKeyPair MLS no encontrado en el almacenamiento".into()))
}

pub fn build_credential_with_key(pin: &str, device_id: &str, pk: &[u8]) -> CredentialWithKey {
    let basic = BasicCredential::new(format_leaf_identity(pin, device_id));
    CredentialWithKey {
        credential: basic.into(),
        signature_key: pk.to_vec().into(),
    }
}

fn load_group(provider: &PinMlsProvider, group_id_32: &[u8; 32]) -> Result<MlsGroup, CoreError> {
    let gid = GroupId::from_slice(group_id_32);
    MlsGroup::load(provider.storage(), &gid)
        .map_err(|e| CoreError::Mls(format!("fallo leyendo grupo MLS: {e:?}")))?
        .ok_or_else(|| CoreError::Mls("grupo MLS no encontrado en almacenamiento local".into()))
}

fn parse_and_validate_kp(provider: &PinMlsProvider, kp_raw: &[u8]) -> Result<KeyPackage, CoreError> {
    let kp_in = KeyPackageIn::tls_deserialize_exact(kp_raw)
        .map_err(|e| CoreError::Mls(format!("KeyPackage TLS malformado: {e:?}")))?;
    kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| CoreError::Mls(format!("KeyPackage inválido o expirado: {e:?}")))
}

fn extract_sender_identity(cred: &Credential) -> (String, String) {
    BasicCredential::try_from(cred.clone())
        .ok()
        .and_then(|bc| parse_leaf_identity(bc.identity()))
        .unwrap_or_else(|| ("UNKNOWN".to_string(), "unknown".to_string()))
}

pub fn generate_mls_key_package(
    provider: &PinMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    is_last_resort: bool,
    now_unix_sec: u64,
) -> Result<GeneratedMlsKeyPackage, CoreError> {
    let lifetime = Lifetime::new(KEY_PACKAGE_LIFETIME_SEC);
    let mut builder = KeyPackage::builder()
        .lifetime(lifetime)
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[PIN_MLS_CIPHERSUITE]),
            Some(&[ExtensionType::LastResort]),
            None,
            None,
        ));

    if is_last_resort {
        builder = builder.mark_as_last_resort();
    }

    let bundle = builder
        .build(PIN_MLS_CIPHERSUITE, provider, signer, credential_with_key)
        .map_err(|e| CoreError::Mls(format!("fallo creando KeyPackage MLS: {e:?}")))?;

    let kp = bundle.key_package();
    let kp_ref_obj = kp
        .hash_ref(provider.crypto())
        .map_err(|e| CoreError::Mls(format!("fallo calculando hash_ref: {e:?}")))?;
    let kp_ref: [u8; 32] = kp_ref_obj
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Mls("KeyPackageRef no mide 32 bytes".into()))?;
    let kp_raw = kp
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando KeyPackage: {e:?}")))?;

    Ok(GeneratedMlsKeyPackage {
        kp_ref,
        kp_raw,
        is_last_resort,
        expires_at: now_unix_sec + KEY_PACKAGE_LIFETIME_SEC,
    })
}

/// Crea un grupo MLS en época 0 y genera el Commit + Welcome RFC 9420 para añadir 1..N KeyPackages.
/// IMPORTANTE: el Commit queda pendiente hasta llamar `confirm_pending_commit` tras HTTP 200.
pub fn create_group_and_add_members(
    provider: &PinMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    peer_kps_raw: &[Vec<u8>],
) -> Result<CreatedMlsGroup, CoreError> {
    if peer_kps_raw.is_empty() {
        return Err(CoreError::Mls("se requiere al menos un KeyPackage para crear el grupo".into()));
    }

    let mut validated_kps = Vec::with_capacity(peer_kps_raw.len());
    let mut added_device_ids = Vec::with_capacity(peer_kps_raw.len());
    for raw in peer_kps_raw {
        let kp = parse_and_validate_kp(provider, raw)?;
        let (_pin, dev_id) = extract_sender_identity(kp.leaf_node().credential());
        added_device_ids.push(dev_id);
        validated_kps.push(kp);
    }

    let group_id = random_bytes::<32>()?;
    let mut group = MlsGroup::new_with_group_id(
        provider,
        signer,
        &group_create_config(),
        GroupId::from_slice(&group_id),
        credential_with_key,
    )
    .map_err(|e| CoreError::Mls(format!("fallo creando MlsGroup: {e:?}")))?;

    let base_epoch = group.epoch().as_u64();
    let (commit_out, welcome_out, _group_info) = group
        .add_members(provider, signer, &validated_kps)
        .map_err(|e| CoreError::Mls(format!("fallo ejecutando add_members inicial: {e:?}")))?;

    let commit_raw = commit_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando Commit: {e:?}")))?;
    let welcome_raw = welcome_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando Welcome: {e:?}")))?;

    Ok(CreatedMlsGroup {
        group_id,
        base_epoch,
        commit_raw,
        welcome_raw,
        added_device_ids,
    })
}

pub fn confirm_pending_commit(
    provider: &PinMlsProvider,
    group_id_32: &[u8; 32],
) -> Result<u64, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    group
        .merge_pending_commit(provider)
        .map_err(|e| CoreError::Mls(format!("fallo en merge_pending_commit: {e:?}")))?;
    Ok(group.epoch().as_u64())
}

pub fn clear_pending_commit(
    provider: &PinMlsProvider,
    group_id_32: &[u8; 32],
) -> Result<u64, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    group
        .clear_pending_commit(provider.storage())
        .map_err(|e| CoreError::Mls(format!("fallo en clear_pending_commit: {e:?}")))?;
    Ok(group.epoch().as_u64())
}

pub fn join_group_from_welcome(
    provider: &PinMlsProvider,
    my_pin: &str,
    welcome_raw: &[u8],
) -> Result<JoinedMlsGroup, CoreError> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(welcome_raw)
        .map_err(|e| CoreError::Mls(format!("Welcome TLS malformado: {e:?}")))?;
    let welcome = match msg_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(CoreError::Mls("el payload recibido no es un MLS Welcome".into())),
    };

    let staged = StagedWelcome::new_from_welcome(provider, &group_join_config(), welcome, None)
        .map_err(|e| CoreError::Mls(format!("fallo abriendo StagedWelcome: {e:?}")))?;
    let group = staged
        .into_group(provider)
        .map_err(|e| CoreError::Mls(format!("fallo activando MlsGroup desde Welcome: {e:?}")))?;

    let group_id: [u8; 32] = group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Mls("group_id en Welcome no mide 32 bytes".into()))?;

    let mut peer_pin = my_pin.to_uppercase();
    for m in group.members() {
        let (pin, _dev) = extract_sender_identity(&m.credential);
        if pin != "UNKNOWN" && !pin.eq_ignore_ascii_case(my_pin) {
            peer_pin = pin;
            break;
        }
    }

    Ok(JoinedMlsGroup {
        group_id,
        peer_pin,
        epoch: group.epoch().as_u64(),
    })
}

pub fn prepare_add_member_commit(
    provider: &PinMlsProvider,
    signer: &SignatureKeyPair,
    group_id_32: &[u8; 32],
    target_kp_raw: &[u8],
) -> Result<PreparedMlsCommit, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    let kp = parse_and_validate_kp(provider, target_kp_raw)?;
    let base_epoch = group.epoch().as_u64();

    let (commit_out, welcome_out, _group_info) = group
        .add_members(provider, signer, &[kp])
        .map_err(|e| CoreError::Mls(format!("fallo en add_members: {e:?}")))?;

    let commit_raw = commit_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando Commit add: {e:?}")))?;
    let welcome_raw = welcome_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando Welcome add: {e:?}")))?;

    Ok(PreparedMlsCommit {
        skipped: false,
        base_epoch,
        commit_raw,
        welcome_raw: Some(welcome_raw),
    })
}

/// Genera un Commit TreeKEM `remove_members` para expulsar un `device_id` revocado (PCS real).
pub fn prepare_remove_device_commit(
    provider: &PinMlsProvider,
    signer: &SignatureKeyPair,
    group_id_32: &[u8; 32],
    target_device_id: &str,
) -> Result<PreparedMlsCommit, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    let base_epoch = group.epoch().as_u64();

    let target_indices: Vec<LeafNodeIndex> = group
        .members()
        .filter_map(|m| {
            let (_pin, dev_id) = extract_sender_identity(&m.credential);
            if dev_id.eq_ignore_ascii_case(target_device_id) {
                Some(m.index)
            } else {
                None
            }
        })
        .collect();

    if target_indices.is_empty() {
        return Ok(PreparedMlsCommit {
            skipped: true,
            base_epoch,
            commit_raw: Vec::new(),
            welcome_raw: None,
        });
    }

    let (commit_out, _welcome_opt, _group_info) = group
        .remove_members(provider, signer, &target_indices)
        .map_err(|e| CoreError::Mls(format!("fallo en remove_members: {e:?}")))?;

    let commit_raw = commit_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando Commit remove: {e:?}")))?;

    Ok(PreparedMlsCommit {
        skipped: false,
        base_epoch,
        commit_raw,
        welcome_raw: None,
    })
}

pub fn encrypt_application_message(
    provider: &PinMlsProvider,
    signer: &SignatureKeyPair,
    group_id_32: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedMlsMessage, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    let epoch = group.epoch().as_u64();
    let msg_out = group
        .create_message(provider, signer, plaintext)
        .map_err(|e| CoreError::Mls(format!("fallo cifrando mensaje MLS: {e:?}")))?;
    let ciphertext = msg_out
        .tls_serialize_detached()
        .map_err(|e| CoreError::Mls(format!("fallo serializando PrivateMessage: {e:?}")))?;

    Ok(EncryptedMlsMessage { epoch, ciphertext })
}

pub fn process_incoming_envelope(
    provider: &PinMlsProvider,
    group_id_32: &[u8; 32],
    envelope_raw: &[u8],
) -> Result<ProcessedMlsOutcome, CoreError> {
    let mut group = load_group(provider, group_id_32)?;
    let msg_in = MlsMessageIn::tls_deserialize_exact(envelope_raw)
        .map_err(|e| CoreError::Mls(format!("sobre MLS malformado: {e:?}")))?;

    let protocol_msg: ProtocolMessage = match msg_in.extract() {
        MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
        MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
        _ => return Err(CoreError::Mls("sobre MLS no es ProtocolMessage".into())),
    };

    let processed = group
        .process_message(provider, protocol_msg)
        .map_err(|e| CoreError::Mls(format!("fallo procesando sobre MLS: {e:?}")))?;

    let (sender_pin, sender_device_id) = extract_sender_identity(processed.credential());

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(ProcessedMlsOutcome::Application {
            epoch: group.epoch().as_u64(),
            sender_pin,
            sender_device_id,
            plaintext: app.into_bytes(),
        }),
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(provider, *staged_commit)
                .map_err(|e| CoreError::Mls(format!("fallo en merge_staged_commit: {e:?}")))?;
            Ok(ProcessedMlsOutcome::Commit {
                epoch: group.epoch().as_u64(),
                active: group.is_active(),
                sender_pin,
                sender_device_id,
            })
        }
        ProcessedMessageContent::ProposalMessage(queued_proposal) => {
            group
                .store_pending_proposal(provider.storage(), *queued_proposal)
                .map_err(|e| CoreError::Mls(format!("fallo guardando Proposal: {e:?}")))?;
            Ok(ProcessedMlsOutcome::Proposal {
                epoch: group.epoch().as_u64(),
                sender_pin,
                sender_device_id,
            })
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(queued_proposal) => {
            group
                .store_pending_proposal(provider.storage(), *queued_proposal)
                .map_err(|e| CoreError::Mls(format!("fallo guardando ExternalJoinProposal: {e:?}")))?;
            Ok(ProcessedMlsOutcome::Proposal {
                epoch: group.epoch().as_u64(),
                sender_pin,
                sender_device_id,
            })
        }
    }
}
