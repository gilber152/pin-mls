mod vault;

use std::sync::Mutex;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use pin_core::auth::sign_canonical_http;
use pin_core::cert::{
    build_and_sign_device_cert, build_and_sign_keypackage_grant,
    build_and_sign_revocation_manifest,
};
use pin_core::identity::{
    derive_root_from_mnemonic, generate_device_keypair, generate_mnemonic_12_words,
    validate_crockford_pin, verify_invite_key_binding,
};
use pin_core::invite::{open_invite_box, seal_invite_box};
use pin_core::mls_engine::{
    build_credential_with_key, clear_pending_commit, confirm_pending_commit,
    create_and_store_mls_signer, create_group_and_add_members, encrypt_application_message,
    generate_mls_key_package, join_group_from_welcome, load_mls_signer, prepare_add_member_commit,
    prepare_remove_device_commit, process_incoming_envelope, PinMlsProvider, ProcessedMlsOutcome,
    PIN_MLS_CIPHERSUITE_ID,
};
use pin_core::pow::solve_argon2id;
use pin_core::qr::{
    derive_link_session_id, encode_link_qr, generate_link_ephemeral_keypair, open_link_bundle,
    parse_link_qr, LinkQr,
};
use pin_core::random_bytes;
use pin_core::CoreError;

use crate::vault::{
    get_group, insert_message, kv_get, kv_set, list_groups, list_messages, load_account,
    open_sqlcipher_db, save_account, upsert_group, wipe_all_tables, AccountMeta, LocalGroupRow,
    LocalMessageRow,
};

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum MobileFfiError {
    #[error("error core: {0}")]
    Core(String),
    #[error("error bóveda SQLCipher: {0}")]
    Vault(String),
    #[error("cuenta no inicializada en la bóveda local")]
    NotInitialized,
    #[error("entrada inválida: {0}")]
    InvalidInput(String),
}

impl From<CoreError> for MobileFfiError {
    fn from(value: CoreError) -> Self {
        MobileFfiError::Core(value.to_string())
    }
}

struct ClientInner {
    conn: Connection,
    account: Option<AccountMeta>,
    provider: PinMlsProvider,
}

impl ClientInner {
    fn persist_mls(&self) -> Result<(), MobileFfiError> {
        let json = self.provider.to_json()?;
        kv_set(&self.conn, "mls_storage_json", &json)
    }

    fn require_account(&self) -> Result<&AccountMeta, MobileFfiError> {
        self.account.as_ref().ok_or(MobileFfiError::NotInitialized)
    }
}

fn decode_hex_32(s: &str, name: &str) -> Result<[u8; 32], MobileFfiError> {
    let bytes = hex::decode(s).map_err(|_| MobileFfiError::InvalidInput(format!("{name} hex inválido")))?;
    bytes
        .try_into()
        .map_err(|_| MobileFfiError::InvalidInput(format!("{name} debe medir 32 bytes")))
}

fn decode_b64_32(s: &str, name: &str) -> Result<[u8; 32], MobileFfiError> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|_| MobileFfiError::InvalidInput(format!("{name} base64 inválido")))?;
    bytes
        .try_into()
        .map_err(|_| MobileFfiError::InvalidInput(format!("{name} debe medir 32 bytes")))
}

fn decode_b64url_arr<const N: usize>(s: &str, name: &str) -> Result<[u8; N], MobileFfiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| MobileFfiError::InvalidInput(format!("{name} base64url inválido")))?;
    bytes
        .try_into()
        .map_err(|_| MobileFfiError::InvalidInput(format!("{name} debe medir {N} bytes")))
}

// ============================================================================
// FUNCIONES TOP-LEVEL (SIN BÓVEDA ABIERTA)
// ============================================================================

#[uniffi::export]
pub fn mobile_generate_mnemonic_12_words() -> Result<String, MobileFfiError> {
    Ok(generate_mnemonic_12_words()?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityRegistrationDto {
    pk_root_b64_url: String,
    pk_invite_b64_url: String,
    sig_invite_b64_url: String,
    proof_of_possession_b64_url: String,
    pk_root_hex: String,
    sk_invite_hex: String,
    pk_invite_hex: String,
}

#[uniffi::export]
pub fn mobile_derive_identity_registration_json(mnemonic_12_words: String) -> Result<String, MobileFfiError> {
    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str())?;
    phrase.zeroize();

    let dto = IdentityRegistrationDto {
        pk_root_b64_url: URL_SAFE_NO_PAD.encode(root.pk_root),
        pk_invite_b64_url: URL_SAFE_NO_PAD.encode(root.pk_invite),
        sig_invite_b64_url: URL_SAFE_NO_PAD.encode(root.sig_invite),
        proof_of_possession_b64_url: URL_SAFE_NO_PAD.encode(root.proof_of_possession),
        pk_root_hex: hex::encode(root.pk_root),
        sk_invite_hex: hex::encode(root.sk_invite),
        pk_invite_hex: hex::encode(root.pk_invite),
    };
    serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
}

#[uniffi::export]
pub fn mobile_solve_pow_nonce(
    challenge_payload_raw: Vec<u8>,
    challenge_id_16: Vec<u8>,
    subject_bytes: Vec<u8>,
    difficulty_bits: u8,
) -> Result<Vec<u8>, MobileFfiError> {
    let ch_id: [u8; 16] = challenge_id_16
        .try_into()
        .map_err(|_| MobileFfiError::InvalidInput("challenge_id_16 debe medir 16 bytes".into()))?;
    let sol = solve_argon2id(&challenge_payload_raw, &ch_id, &subject_bytes, difficulty_bits)?;
    Ok(sol.nonce.to_vec())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RootHttpHeadersDto {
    x_pin: String,
    x_timestamp: String,
    x_nonce: String,
    x_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceEnrollmentDto {
    device_id: String,
    sk_dev_hex: String,
    pk_dev_hex: String,
    device_cert_b64: String,
    enroll_headers: RootHttpHeadersDto,
}

#[uniffi::export]
pub fn mobile_prepare_device_enrollment_json(
    mnemonic_12_words: String,
    pin: String,
    now_unix_sec: u64,
) -> Result<String, MobileFfiError> {
    validate_crockford_pin(&pin)?;
    let exp_sec = now_unix_sec + 180 * 24 * 3600;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str())?;
    phrase.zeroize();

    let device_uuid = Uuid::new_v4();
    let dev_kp = generate_device_keypair()?;
    let cert_raw = build_and_sign_device_cert(
        &pin,
        &root.pk_root,
        device_uuid.as_bytes(),
        &dev_kp.pk_dev,
        now_unix_sec,
        exp_sec,
        &root.sk_root,
    )?;

    let http_nonce = Uuid::new_v4().to_string();
    let http_sig = sign_canonical_http(
        &root.sk_root,
        "POST",
        "/v1/devices/enroll",
        now_unix_sec,
        &http_nonce,
        &cert_raw,
    );

    let dto = DeviceEnrollmentDto {
        device_id: device_uuid.to_string(),
        sk_dev_hex: hex::encode(dev_kp.sk_dev),
        pk_dev_hex: hex::encode(dev_kp.pk_dev),
        device_cert_b64: STANDARD.encode(cert_raw),
        enroll_headers: RootHttpHeadersDto {
            x_pin: pin,
            x_timestamp: now_unix_sec.to_string(),
            x_nonce: http_nonce,
            x_signature: URL_SAFE_NO_PAD.encode(http_sig),
        },
    };
    serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedLinkSessionDto {
    device_id: String,
    sk_dev_hex: String,
    pk_dev_hex: String,
    sk_link_eph_hex: String,
    pk_link_eph_hex: String,
    read_secret_b64_url: String,
    session_id_hex: String,
    link_qr_uri: String,
}

#[uniffi::export]
pub fn mobile_start_link_session_json() -> Result<String, MobileFfiError> {
    let device_uuid = Uuid::new_v4();
    let dev_kp = generate_device_keypair()?;
    let (sk_link_eph, pk_link_eph) = generate_link_ephemeral_keypair()?;
    let read_secret = random_bytes::<32>()?;
    let session_id = derive_link_session_id(&read_secret);

    let qr = LinkQr {
        session_id_32: session_id,
        device_id: *device_uuid.as_bytes(),
        pk_dev_32: dev_kp.pk_dev,
        pk_link_eph_32: pk_link_eph,
    };

    let dto = StartedLinkSessionDto {
        device_id: device_uuid.to_string(),
        sk_dev_hex: hex::encode(dev_kp.sk_dev),
        pk_dev_hex: hex::encode(dev_kp.pk_dev),
        sk_link_eph_hex: hex::encode(sk_link_eph),
        pk_link_eph_hex: hex::encode(pk_link_eph),
        read_secret_b64_url: URL_SAFE_NO_PAD.encode(read_secret),
        session_id_hex: hex::encode(session_id),
        link_qr_uri: encode_link_qr(&qr),
    };
    serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
}

#[uniffi::export]
pub fn mobile_open_link_bundle_json(
    sk_link_eph_hex: String,
    session_id_hex: String,
    device_id: String,
    bundle_wire: Vec<u8>,
) -> Result<String, MobileFfiError> {
    let mut sk_eph = decode_hex_32(&sk_link_eph_hex, "sk_link_eph_hex")?;
    let session_id = decode_hex_32(&session_id_hex, "session_id_hex")?;
    let dev_uuid = Uuid::parse_str(&device_id)
        .map_err(|e| MobileFfiError::InvalidInput(format!("device_id inválido: {e}")))?;

    let plain = open_link_bundle(&sk_eph, &session_id, dev_uuid.as_bytes(), &bundle_wire)?;
    sk_eph.zeroize();
    String::from_utf8(plain).map_err(|e| MobileFfiError::Core(e.to_string()))
}

// ============================================================================
// OBJETO PRINCIPAL UNIFFI: PINMOBILECLIENT (SQLCIPHER + OPENMLS 0.9.2)
// ============================================================================

#[derive(uniffi::Object)]
pub struct PinMobileClient {
    inner: Mutex<ClientInner>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountSummaryDto {
    initialized: bool,
    pin: Option<String>,
    device_id: Option<String>,
    safe_backup_revision: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceHttpHeadersDto {
    x_device_id: String,
    x_timestamp: String,
    x_nonce: String,
    x_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedKpItemDto {
    kp_ref: String,
    kp_raw: String,
    is_last_resort: bool,
    expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedGroupDto {
    group_id_b64: String,
    group_id_b64_url: String,
    cipher_suite: u16,
    base_epoch: u64,
    commit_raw_b64: String,
    welcome_raw_b64: String,
    added_device_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedMsgDto {
    epoch: u64,
    ciphertext_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatTextPayload {
    text: String,
    sent_at_ms: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessedEnvelopeDto {
    kind: String,
    epoch: u64,
    active: bool,
    sender_pin: String,
    sender_device_id: String,
    text: Option<String>,
}

#[uniffi::export]
impl PinMobileClient {
    #[uniffi::constructor]
    pub fn open(db_path: String, db_key_hex: String) -> Result<Self, MobileFfiError> {
        let conn = open_sqlcipher_db(&db_path, &db_key_hex)?;
        let account = load_account(&conn)?;
        let mls_json = kv_get(&conn, "mls_storage_json")?.unwrap_or_default();
        let provider = PinMlsProvider::from_json(&mls_json)?;

        Ok(Self {
            inner: Mutex::new(ClientInner {
                conn,
                account,
                provider,
            }),
        })
    }

    pub fn get_account_summary_json(&self) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let dto = match &guard.account {
            Some(a) => AccountSummaryDto {
                initialized: true,
                pin: Some(a.pin.clone()),
                device_id: Some(a.device_id.clone()),
                safe_backup_revision: a.safe_backup_revision,
            },
            None => AccountSummaryDto {
                initialized: false,
                pin: None,
                device_id: None,
                safe_backup_revision: 0,
            },
        };
        serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn init_local_account(
        &self,
        pin: String,
        device_id: String,
        pk_root_hex: String,
        sk_invite_hex: String,
        pk_invite_hex: String,
        sk_dev_hex: String,
        pk_dev_hex: String,
    ) -> Result<(), MobileFfiError> {
        validate_crockford_pin(&pin)?;
        let _ = Uuid::parse_str(&device_id)
            .map_err(|e| MobileFfiError::InvalidInput(format!("device_id inválido: {e}")))?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;

        let provider = PinMlsProvider::new_empty();
        let sig_pk = create_and_store_mls_signer(&provider)?;

        let acc = AccountMeta {
            pin: pin.to_uppercase(),
            device_id: device_id.to_lowercase(),
            pk_root_hex,
            sk_invite_hex,
            pk_invite_hex,
            sk_dev_hex,
            pk_dev_hex,
            mls_sig_pk_b64: STANDARD.encode(sig_pk),
            safe_backup_revision: 0,
        };

        save_account(&guard.conn, &acc)?;
        guard.provider = provider;
        guard.account = Some(acc);
        guard.persist_mls()?;
        Ok(())
    }

    pub fn sign_device_http_json(
        &self,
        method: String,
        path_with_query: String,
        raw_body: Vec<u8>,
        now_unix_sec: u64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let mut sk_dev = decode_hex_32(&acc.sk_dev_hex, "sk_dev_hex")?;
        let nonce = Uuid::new_v4().to_string();
        let sig = sign_canonical_http(
            &sk_dev,
            &method,
            &path_with_query,
            now_unix_sec,
            &nonce,
            &raw_body,
        );
        sk_dev.zeroize();

        let dto = DeviceHttpHeadersDto {
            x_device_id: acc.device_id.clone(),
            x_timestamp: now_unix_sec.to_string(),
            x_nonce: nonce,
            x_signature: URL_SAFE_NO_PAD.encode(sig),
        };
        serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn generate_key_packages_json(
        &self,
        count: u32,
        include_last_resort: bool,
        now_unix_sec: u64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let sig_pk = STANDARD
            .decode(&acc.mls_sig_pk_b64)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let signer = load_mls_signer(&guard.provider, &sig_pk)?;

        let total = count as usize + usize::from(include_last_resort);
        let mut out = Vec::with_capacity(total);
        for i in 0..total {
            let is_lr = include_last_resort && i == total - 1;
            let cred = build_credential_with_key(&acc.pin, &acc.device_id, &sig_pk);
            let kp = generate_mls_key_package(&guard.provider, &signer, cred, is_lr, now_unix_sec)?;
            out.push(GeneratedKpItemDto {
                kp_ref: STANDARD.encode(kp.kp_ref),
                kp_raw: STANDARD.encode(kp.kp_raw),
                is_last_resort: kp.is_last_resort,
                expires_at: kp.expires_at,
            });
        }
        guard.persist_mls()?;
        serde_json::to_string(&out).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn seal_invite_json(
        &self,
        target_pin: String,
        target_pk_root_b64_url: String,
        target_pk_invite_b64_url: String,
        target_sig_invite_b64_url: String,
        note: String,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        validate_crockford_pin(&target_pin)?;

        let pk_root = decode_b64url_arr::<32>(&target_pk_root_b64_url, "pkRoot")?;
        let pk_invite = decode_b64url_arr::<32>(&target_pk_invite_b64_url, "pkInvite")?;
        let sig_invite = decode_b64url_arr::<64>(&target_sig_invite_b64_url, "sigInvite")?;
        verify_invite_key_binding(&pk_root, &pk_invite, &sig_invite)?;

        let inner = serde_json::json!({ "senderPin": acc.pin, "note": note });
        let sealed = seal_invite_box(&pk_invite, &target_pin, inner.to_string().as_bytes())?;
        Ok(STANDARD.encode(sealed))
    }

    pub fn open_invite_json(&self, ciphertext_b64: String) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let mut sk_inv = decode_hex_32(&acc.sk_invite_hex, "sk_invite_hex")?;
        let pk_inv = decode_hex_32(&acc.pk_invite_hex, "pk_invite_hex")?;
        let wire = STANDARD
            .decode(&ciphertext_b64)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
        let plain = open_invite_box(&sk_inv, &pk_inv, &acc.pin, &wire)?;
        sk_inv.zeroize();
        String::from_utf8(plain).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn build_keypackage_grant_b64_url(
        &self,
        requester_pin: String,
        now_unix_sec: u64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let grant_uuid = Uuid::new_v4();
        let signer_uuid = Uuid::parse_str(&acc.device_id)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let mut sk_dev = decode_hex_32(&acc.sk_dev_hex, "sk_dev_hex")?;
        let raw = build_and_sign_keypackage_grant(
            grant_uuid.as_bytes(),
            &acc.pin,
            &requester_pin,
            signer_uuid.as_bytes(),
            now_unix_sec + 7 * 24 * 3600,
            &sk_dev,
        )?;
        sk_dev.zeroize();
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn create_group_and_add_members_json(
        &self,
        peer_pin: String,
        peer_kps_raw_b64_json: String,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let sig_pk = STANDARD
            .decode(&acc.mls_sig_pk_b64)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let signer = load_mls_signer(&guard.provider, &sig_pk)?;
        let cred = build_credential_with_key(&acc.pin, &acc.device_id, &sig_pk);

        let kps_b64: Vec<String> = serde_json::from_str(&peer_kps_raw_b64_json)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
        let mut kps_raw = Vec::with_capacity(kps_b64.len());
        for s in &kps_b64 {
            kps_raw.push(
                STANDARD
                    .decode(s)
                    .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?,
            );
        }

        let created = create_group_and_add_members(&guard.provider, &signer, cred, &kps_raw)?;
        let group_id_b64 = STANDARD.encode(created.group_id);
        let group_id_b64_url = URL_SAFE_NO_PAD.encode(created.group_id);

        upsert_group(
            &guard.conn,
            &LocalGroupRow {
                group_id_b64: group_id_b64.clone(),
                group_id_b64_url: group_id_b64_url.clone(),
                peer_pin: peer_pin.to_uppercase(),
                cipher_suite: PIN_MLS_CIPHERSUITE_ID,
                epoch: created.base_epoch,
                active: true,
                last_seq: 0,
            },
        )?;
        guard.persist_mls()?;

        let dto = CreatedGroupDto {
            group_id_b64,
            group_id_b64_url,
            cipher_suite: PIN_MLS_CIPHERSUITE_ID,
            base_epoch: created.base_epoch,
            commit_raw_b64: STANDARD.encode(created.commit_raw),
            welcome_raw_b64: STANDARD.encode(created.welcome_raw),
            added_device_ids: created.added_device_ids,
        };
        serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn confirm_pending_commit(
        &self,
        group_id_b64: String,
        confirmed_seq: u64,
    ) -> Result<u64, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let new_epoch = confirm_pending_commit(&guard.provider, &group_id)?;
        if let Some(mut grp) = get_group(&guard.conn, &group_id_b64)? {
            grp.epoch = new_epoch;
            grp.last_seq = grp.last_seq.max(confirmed_seq);
            upsert_group(&guard.conn, &grp)?;
        }
        guard.persist_mls()?;
        Ok(new_epoch)
    }

    pub fn clear_pending_commit(&self, group_id_b64: String) -> Result<u64, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let epoch = clear_pending_commit(&guard.provider, &group_id)?;
        guard.persist_mls()?;
        Ok(epoch)
    }

    pub fn join_from_welcome_json(
        &self,
        welcome_raw_b64: String,
        commit_seq: u64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let welcome_raw = STANDARD
            .decode(&welcome_raw_b64)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
        let joined = join_group_from_welcome(&guard.provider, &acc.pin, &welcome_raw)?;

        let row = LocalGroupRow {
            group_id_b64: STANDARD.encode(joined.group_id),
            group_id_b64_url: URL_SAFE_NO_PAD.encode(joined.group_id),
            peer_pin: joined.peer_pin,
            cipher_suite: PIN_MLS_CIPHERSUITE_ID,
            epoch: joined.epoch,
            active: true,
            last_seq: commit_seq,
        };
        upsert_group(&guard.conn, &row)?;
        guard.persist_mls()?;
        serde_json::to_string(&row).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn encrypt_message_json(
        &self,
        group_id_b64: String,
        text: String,
        sent_at_ms: i64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let sig_pk = STANDARD
            .decode(&acc.mls_sig_pk_b64)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let signer = load_mls_signer(&guard.provider, &sig_pk)?;

        let payload = serde_json::to_vec(&ChatTextPayload { text, sent_at_ms })
            .map_err(|e| MobileFfiError::Core(e.to_string()))?;
        let enc = encrypt_application_message(&guard.provider, &signer, &group_id, &payload)?;
        guard.persist_mls()?;

        let dto = EncryptedMsgDto {
            epoch: enc.epoch,
            ciphertext_b64: STANDARD.encode(enc.ciphertext),
        };
        serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn record_sent_message(
        &self,
        group_id_b64: String,
        group_seq: u64,
        text: String,
        sent_at_ms: i64,
    ) -> Result<(), MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        insert_message(
            &guard.conn,
            &LocalMessageRow {
                group_id_b64: group_id_b64.clone(),
                group_seq,
                sender_pin: acc.pin.clone(),
                sender_device_id: acc.device_id.clone(),
                text,
                sent_at_ms,
                mine: true,
            },
        )?;
        if let Some(mut grp) = get_group(&guard.conn, &group_id_b64)? {
            grp.last_seq = grp.last_seq.max(group_seq);
            upsert_group(&guard.conn, &grp)?;
        }
        Ok(())
    }

    pub fn process_envelope_json(
        &self,
        group_id_b64: String,
        group_seq: u64,
        envelope_raw_b64: String,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let env_raw = STANDARD
            .decode(&envelope_raw_b64)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;

        let outcome = process_incoming_envelope(&guard.provider, &group_id, &env_raw)?;
        guard.persist_mls()?;

        let dto = match outcome {
            ProcessedMlsOutcome::Application {
                epoch,
                sender_pin,
                sender_device_id,
                plaintext,
            } => {
                let parsed: ChatTextPayload = serde_json::from_slice(&plaintext)
                    .map_err(|e| MobileFfiError::Core(e.to_string()))?;
                insert_message(
                    &guard.conn,
                    &LocalMessageRow {
                        group_id_b64: group_id_b64.clone(),
                        group_seq,
                        sender_pin: sender_pin.clone(),
                        sender_device_id: sender_device_id.clone(),
                        text: parsed.text.clone(),
                        sent_at_ms: parsed.sent_at_ms,
                        mine: sender_pin.eq_ignore_ascii_case(&acc.pin),
                    },
                )?;
                if let Some(mut grp) = get_group(&guard.conn, &group_id_b64)? {
                    grp.epoch = epoch;
                    grp.last_seq = grp.last_seq.max(group_seq);
                    upsert_group(&guard.conn, &grp)?;
                }
                ProcessedEnvelopeDto {
                    kind: "application".into(),
                    epoch,
                    active: true,
                    sender_pin,
                    sender_device_id,
                    text: Some(parsed.text),
                }
            }
            ProcessedMlsOutcome::Commit {
                epoch,
                active,
                sender_pin,
                sender_device_id,
            } => {
                if let Some(mut grp) = get_group(&guard.conn, &group_id_b64)? {
                    grp.epoch = epoch;
                    grp.active = active;
                    grp.last_seq = grp.last_seq.max(group_seq);
                    upsert_group(&guard.conn, &grp)?;
                }
                ProcessedEnvelopeDto {
                    kind: "commit".into(),
                    epoch,
                    active,
                    sender_pin,
                    sender_device_id,
                    text: None,
                }
            }
            ProcessedMlsOutcome::Proposal {
                epoch,
                sender_pin,
                sender_device_id,
            } => ProcessedEnvelopeDto {
                kind: "proposal".into(),
                epoch,
                active: true,
                sender_pin,
                sender_device_id,
                text: None,
            },
        };

        serde_json::to_string(&dto).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn prepare_remove_device_json(
        &self,
        group_id_b64: String,
        target_device_id: String,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let sig_pk = STANDARD
            .decode(&acc.mls_sig_pk_b64)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let signer = load_mls_signer(&guard.provider, &sig_pk)?;

        let prep = prepare_remove_device_commit(&guard.provider, &signer, &group_id, &target_device_id)?;
        guard.persist_mls()?;

        let out = serde_json::json!({
            "skipped": prep.skipped,
            "baseEpoch": prep.base_epoch,
            "commitRawB64": STANDARD.encode(prep.commit_raw),
        });
        Ok(out.to_string())
    }

    pub fn prepare_add_member_json(
        &self,
        group_id_b64: String,
        target_kp_raw_b64: String,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;
        let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
        let kp_raw = STANDARD
            .decode(&target_kp_raw_b64)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
        let sig_pk = STANDARD
            .decode(&acc.mls_sig_pk_b64)
            .map_err(|e| MobileFfiError::Vault(e.to_string()))?;
        let signer = load_mls_signer(&guard.provider, &sig_pk)?;

        let prep = prepare_add_member_commit(&guard.provider, &signer, &group_id, &kp_raw)?;
        guard.persist_mls()?;

        let out = serde_json::json!({
            "skipped": prep.skipped,
            "baseEpoch": prep.base_epoch,
            "commitRawB64": STANDARD.encode(prep.commit_raw),
            "welcomeRawB64": prep.welcome_raw.map(|w| STANDARD.encode(w)),
        });
        Ok(out.to_string())
    }

    pub fn prepare_revocation_manifest_json(
        &self,
        mnemonic_12_words: String,
        next_seq_num: u64,
        revoked_device_ids_json: String,
        now_unix_sec: u64,
    ) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let acc = guard.require_account()?;

        let mut phrase = Zeroizing::new(mnemonic_12_words);
        let root = derive_root_from_mnemonic(phrase.as_str())?;
        phrase.zeroize();

        if hex::encode(root.pk_root) != acc.pk_root_hex.to_lowercase() {
            return Err(MobileFfiError::InvalidInput(
                "Las 12 palabras no coinciden con la clave raíz de este PIN".into(),
            ));
        }

        let ids_str: Vec<String> = serde_json::from_str(&revoked_device_ids_json)
            .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
        let mut id_bytes = Vec::with_capacity(ids_str.len());
        for s in ids_str {
            let u = Uuid::parse_str(&s)
                .map_err(|e| MobileFfiError::InvalidInput(e.to_string()))?;
            id_bytes.push(*u.as_bytes());
        }

        let signed = build_and_sign_revocation_manifest(&acc.pin, next_seq_num, &id_bytes, &root.sk_root)?;
        let http_nonce = Uuid::new_v4().to_string();
        let http_sig = sign_canonical_http(
            &root.sk_root,
            "POST",
            "/v1/identities/revoke",
            now_unix_sec,
            &http_nonce,
            &signed.wire_bytes,
        );

        let out = serde_json::json!({
            "seqNum": next_seq_num,
            "wireB64": STANDARD.encode(&signed.wire_bytes),
            "revokeHeaders": {
                "xPin": acc.pin,
                "xTimestamp": now_unix_sec.to_string(),
                "xNonce": http_nonce,
                "xSignature": URL_SAFE_NO_PAD.encode(http_sig),
            }
        });
        Ok(out.to_string())
    }

    pub fn list_groups_json(&self) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let groups = list_groups(&guard.conn)?;
        serde_json::to_string(&groups).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn list_messages_json(&self, group_id_b64: String) -> Result<String, MobileFfiError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        let msgs = list_messages(&guard.conn, &group_id_b64)?;
        serde_json::to_string(&msgs).map_err(|e| MobileFfiError::Core(e.to_string()))
    }

    pub fn wipe_vault(&self) -> Result<(), MobileFfiError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| MobileFfiError::Vault("mutex envenenado".into()))?;
        wipe_all_tables(&guard.conn)?;
        guard.account = None;
        guard.provider = PinMlsProvider::new_empty();
        Ok(())
    }
}
