use std::cell::RefCell;
use std::collections::HashMap;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
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
    parse_link_qr, seal_link_bundle, LinkQr,
};
use pin_core::random_bytes;
use pin_core::safe::{
    derive_safe_keys_from_mnemonic, open_safe_backup, seal_safe_backup, sign_safe_http_request,
};

struct MlsRuntime {
    provider: PinMlsProvider,
    pin: String,
    device_id: String,
    sig_pk: Vec<u8>,
}

thread_local! {
    static MLS_RT: RefCell<Option<MlsRuntime>> = const { RefCell::new(None) };
}

fn js_err(msg: impl ToString) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

fn to_u64(v: f64, name: &str) -> Result<u64, JsValue> {
    if !v.is_finite() || v < 0.0 || v > 9_007_199_254_740_991.0 {
        return Err(js_err(format!("{name} fuera de rango entero seguro")));
    }
    Ok(v as u64)
}

fn decode_hex_32(s: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes = hex::decode(s).map_err(|_| js_err(format!("{name} hex inválido")))?;
    bytes
        .try_into()
        .map_err(|_| js_err(format!("{name} debe medir 32 bytes")))
}

fn decode_b64_32(s: &str, name: &str) -> Result<[u8; 32], JsValue> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|_| js_err(format!("{name} base64 inválido")))?;
    bytes
        .try_into()
        .map_err(|_| js_err(format!("{name} debe medir 32 bytes")))
}

fn decode_b64url_arr<const N: usize>(s: &str, name: &str) -> Result<[u8; N], JsValue> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| js_err(format!("{name} base64url inválido")))?;
    bytes
        .try_into()
        .map_err(|_| js_err(format!("{name} debe medir {N} bytes")))
}

fn with_mls_rt<T>(f: impl FnOnce(&MlsRuntime) -> Result<T, JsValue>) -> Result<T, JsValue> {
    MLS_RT.with(|cell| {
        let borrow = cell.borrow();
        let rt = borrow
            .as_ref()
            .ok_or_else(|| js_err("Runtime OpenMLS no inicializado; llama a mlsInitRuntime primero"))?;
        f(rt)
    })
}

#[wasm_bindgen(start)]
pub fn wasm_init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// IDENTIDAD, POW Y AUTENTICACIÓN HTTP
// ============================================================================

#[wasm_bindgen(js_name = generateMnemonic12Words)]
pub fn wasm_generate_mnemonic() -> Result<String, JsValue> {
    generate_mnemonic_12_words().map_err(js_err)
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

#[wasm_bindgen(js_name = deriveIdentityRegistrationJson)]
pub fn wasm_derive_identity_registration(mnemonic_12_words: String) -> Result<String, JsValue> {
    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str()).map_err(js_err)?;
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
    serde_json::to_string(&dto).map_err(js_err)
}

#[wasm_bindgen(js_name = solvePowNonce)]
pub fn wasm_solve_pow_nonce(
    challenge_payload_raw: &[u8],
    challenge_id_16: &[u8],
    subject_bytes: &[u8],
    difficulty_bits: u8,
) -> Result<Vec<u8>, JsValue> {
    let ch_id: [u8; 16] = challenge_id_16
        .try_into()
        .map_err(|_| js_err("challenge_id_16 debe medir 16 bytes"))?;
    let sol = solve_argon2id(challenge_payload_raw, &ch_id, subject_bytes, difficulty_bits)
        .map_err(js_err)?;
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

#[wasm_bindgen(js_name = prepareDeviceEnrollmentJson)]
pub fn wasm_prepare_device_enrollment(
    mnemonic_12_words: String,
    pin: String,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    validate_crockford_pin(&pin).map_err(js_err)?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;
    let exp_sec = now_sec + 180 * 24 * 3600;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    let device_uuid = Uuid::new_v4();
    let dev_kp = generate_device_keypair().map_err(js_err)?;

    let cert_raw = build_and_sign_device_cert(
        &pin,
        &root.pk_root,
        device_uuid.as_bytes(),
        &dev_kp.pk_dev,
        now_sec,
        exp_sec,
        &root.sk_root,
    )
    .map_err(js_err)?;

    let http_nonce = Uuid::new_v4().to_string();
    let http_sig = sign_canonical_http(
        &root.sk_root,
        "POST",
        "/v1/devices/enroll",
        now_sec,
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
            x_timestamp: now_sec.to_string(),
            x_nonce: http_nonce,
            x_signature: URL_SAFE_NO_PAD.encode(http_sig),
        },
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceHttpHeadersDto {
    x_device_id: String,
    x_timestamp: String,
    x_nonce: String,
    x_signature: String,
}

#[wasm_bindgen(js_name = signDeviceHttpJson)]
pub fn wasm_sign_device_http(
    sk_dev_hex: String,
    device_id: String,
    method: String,
    path_with_query: String,
    raw_body: &[u8],
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    let mut sk_dev = decode_hex_32(&sk_dev_hex, "sk_dev_hex")?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_canonical_http(&sk_dev, &method, &path_with_query, now_sec, &nonce, raw_body);
    sk_dev.zeroize();

    let dto = DeviceHttpHeadersDto {
        x_device_id: device_id,
        x_timestamp: now_sec.to_string(),
        x_nonce: nonce,
        x_signature: URL_SAFE_NO_PAD.encode(sig),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

// ============================================================================
// INVITACIONES Y KEYPACKAGE GRANTS
// ============================================================================

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteInnerPayload {
    sender_pin: String,
    note: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedInviteDto {
    ciphertext_b64: String,
    verified_pk_root_b64: String,
}

#[wasm_bindgen(js_name = sealInviteJson)]
pub fn wasm_seal_invite(
    sender_pin: String,
    target_pin: String,
    target_pk_root_b64_url: String,
    target_pk_invite_b64_url: String,
    target_sig_invite_b64_url: String,
    note: String,
) -> Result<String, JsValue> {
    validate_crockford_pin(&sender_pin).map_err(js_err)?;
    validate_crockford_pin(&target_pin).map_err(js_err)?;

    let pk_root = decode_b64url_arr::<32>(&target_pk_root_b64_url, "pkRoot")?;
    let pk_invite = decode_b64url_arr::<32>(&target_pk_invite_b64_url, "pkInvite")?;
    let sig_invite = decode_b64url_arr::<64>(&target_sig_invite_b64_url, "sigInvite")?;

    verify_invite_key_binding(&pk_root, &pk_invite, &sig_invite).map_err(js_err)?;

    let inner = serde_json::to_vec(&InviteInnerPayload { sender_pin, note }).map_err(js_err)?;
    let sealed = seal_invite_box(&pk_invite, &target_pin, &inner).map_err(js_err)?;

    let dto = SealedInviteDto {
        ciphertext_b64: STANDARD.encode(sealed),
        verified_pk_root_b64: STANDARD.encode(pk_root),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[wasm_bindgen(js_name = openInviteJson)]
pub fn wasm_open_invite(
    sk_invite_hex: String,
    pk_invite_hex: String,
    my_pin: String,
    ciphertext_b64: String,
) -> Result<String, JsValue> {
    let mut sk_inv = decode_hex_32(&sk_invite_hex, "sk_invite_hex")?;
    let pk_inv = decode_hex_32(&pk_invite_hex, "pk_invite_hex")?;
    let wire = STANDARD.decode(&ciphertext_b64).map_err(js_err)?;
    let plain = open_invite_box(&sk_inv, &pk_inv, &my_pin, &wire).map_err(js_err)?;
    sk_inv.zeroize();
    String::from_utf8(plain).map_err(js_err)
}

#[wasm_bindgen(js_name = buildKeyPackageGrantB64Url)]
pub fn wasm_build_kp_grant(
    target_pin: String,
    requester_pin: String,
    signer_device_id: String,
    sk_dev_hex: String,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    let grant_uuid = Uuid::new_v4();
    let signer_uuid = Uuid::parse_str(&signer_device_id).map_err(js_err)?;
    let mut sk_dev = decode_hex_32(&sk_dev_hex, "sk_dev_hex")?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;
    let exp_sec = now_sec + 7 * 24 * 3600;

    let raw = build_and_sign_keypackage_grant(
        grant_uuid.as_bytes(),
        &target_pin,
        &requester_pin,
        signer_uuid.as_bytes(),
        exp_sec,
        &sk_dev,
    )
    .map_err(js_err)?;
    sk_dev.zeroize();
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

// ============================================================================
// BLOQUE 2B: MOTOR OPENMLS 0.9 REAL (RFC 9420 · TREEKEM)
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsRuntimeInitDto {
    sig_pk_b64: String,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsInitRuntimeJson)]
pub fn wasm_mls_init_runtime(
    storage_json: String,
    pin: String,
    device_id: String,
    sig_pk_b64: String,
) -> Result<String, JsValue> {
    validate_crockford_pin(&pin).map_err(js_err)?;
    let _ = Uuid::parse_str(&device_id).map_err(js_err)?;

    let provider = PinMlsProvider::from_json(&storage_json).map_err(js_err)?;
    let sig_pk = if sig_pk_b64.trim().is_empty() {
        create_and_store_mls_signer(&provider).map_err(js_err)?
    } else {
        let pk = STANDARD.decode(sig_pk_b64.trim()).map_err(js_err)?;
        let _ = load_mls_signer(&provider, &pk).map_err(js_err)?;
        pk
    };

    let exported_json = provider.to_json().map_err(js_err)?;
    let sig_pk_out = STANDARD.encode(&sig_pk);

    MLS_RT.with(|cell| {
        *cell.borrow_mut() = Some(MlsRuntime {
            provider,
            pin: pin.to_uppercase(),
            device_id: device_id.to_lowercase(),
            sig_pk,
        });
    });

    let dto = MlsRuntimeInitDto {
        sig_pk_b64: sig_pk_out,
        storage_json: exported_json,
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsGeneratedKpItemDto {
    kp_ref: String,
    kp_raw: String,
    is_last_resort: bool,
    expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsGeneratedKpsDto {
    key_packages: Vec<MlsGeneratedKpItemDto>,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsGenerateKeyPackagesJson)]
pub fn wasm_mls_generate_key_packages(
    count: u32,
    include_last_resort: bool,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;
    with_mls_rt(|rt| {
        let signer = load_mls_signer(&rt.provider, &rt.sig_pk).map_err(js_err)?;
        let total = count as usize + usize::from(include_last_resort);
        let mut items = Vec::with_capacity(total);

        for i in 0..total {
            let is_last_resort = include_last_resort && i == total - 1;
            let cred = build_credential_with_key(&rt.pin, &rt.device_id, &rt.sig_pk);
            let kp = generate_mls_key_package(&rt.provider, &signer, cred, is_last_resort, now_sec)
                .map_err(js_err)?;
            items.push(MlsGeneratedKpItemDto {
                kp_ref: STANDARD.encode(kp.kp_ref),
                kp_raw: STANDARD.encode(kp.kp_raw),
                is_last_resort: kp.is_last_resort,
                expires_at: kp.expires_at,
            });
        }

        let dto = MlsGeneratedKpsDto {
            key_packages: items,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsCreatedGroupDto {
    group_id_b64: String,
    group_id_b64_url: String,
    cipher_suite: u16,
    base_epoch: u64,
    commit_raw_b64: String,
    welcome_raw_b64: String,
    added_device_ids: Vec<String>,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsCreateGroupAndAddMembersJson)]
pub fn wasm_mls_create_group_and_add_members(
    peer_kps_raw_b64_json: String,
) -> Result<String, JsValue> {
    let kps_b64: Vec<String> = serde_json::from_str(&peer_kps_raw_b64_json).map_err(js_err)?;
    let mut kps_raw = Vec::with_capacity(kps_b64.len());
    for s in &kps_b64 {
        kps_raw.push(STANDARD.decode(s).map_err(js_err)?);
    }

    with_mls_rt(|rt| {
        let signer = load_mls_signer(&rt.provider, &rt.sig_pk).map_err(js_err)?;
        let cred = build_credential_with_key(&rt.pin, &rt.device_id, &rt.sig_pk);
        let created =
            create_group_and_add_members(&rt.provider, &signer, cred, &kps_raw).map_err(js_err)?;

        let dto = MlsCreatedGroupDto {
            group_id_b64: STANDARD.encode(created.group_id),
            group_id_b64_url: URL_SAFE_NO_PAD.encode(created.group_id),
            cipher_suite: PIN_MLS_CIPHERSUITE_ID,
            base_epoch: created.base_epoch,
            commit_raw_b64: STANDARD.encode(created.commit_raw),
            welcome_raw_b64: STANDARD.encode(created.welcome_raw),
            added_device_ids: created.added_device_ids,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsEpochStateDto {
    epoch: u64,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsConfirmPendingCommitJson)]
pub fn wasm_mls_confirm_pending_commit(group_id_b64: String) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    with_mls_rt(|rt| {
        let epoch = confirm_pending_commit(&rt.provider, &group_id).map_err(js_err)?;
        let dto = MlsEpochStateDto {
            epoch,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[wasm_bindgen(js_name = mlsClearPendingCommitJson)]
pub fn wasm_mls_clear_pending_commit(group_id_b64: String) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    with_mls_rt(|rt| {
        let epoch = clear_pending_commit(&rt.provider, &group_id).map_err(js_err)?;
        let dto = MlsEpochStateDto {
            epoch,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsJoinedGroupDto {
    group_id_b64: String,
    group_id_b64_url: String,
    peer_pin: String,
    epoch: u64,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsJoinFromWelcomeJson)]
pub fn wasm_mls_join_from_welcome(welcome_raw_b64: String) -> Result<String, JsValue> {
    let welcome_raw = STANDARD.decode(&welcome_raw_b64).map_err(js_err)?;
    with_mls_rt(|rt| {
        let joined = join_group_from_welcome(&rt.provider, &rt.pin, &welcome_raw).map_err(js_err)?;
        let dto = MlsJoinedGroupDto {
            group_id_b64: STANDARD.encode(joined.group_id),
            group_id_b64_url: URL_SAFE_NO_PAD.encode(joined.group_id),
            peer_pin: joined.peer_pin,
            epoch: joined.epoch,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsPreparedCommitDto {
    skipped: bool,
    base_epoch: u64,
    commit_raw_b64: String,
    welcome_raw_b64: Option<String>,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsPrepareAddMemberJson)]
pub fn wasm_mls_prepare_add_member(
    group_id_b64: String,
    target_kp_raw_b64: String,
) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    let kp_raw = STANDARD.decode(&target_kp_raw_b64).map_err(js_err)?;
    with_mls_rt(|rt| {
        let signer = load_mls_signer(&rt.provider, &rt.sig_pk).map_err(js_err)?;
        let prep =
            prepare_add_member_commit(&rt.provider, &signer, &group_id, &kp_raw).map_err(js_err)?;
        let dto = MlsPreparedCommitDto {
            skipped: prep.skipped,
            base_epoch: prep.base_epoch,
            commit_raw_b64: STANDARD.encode(prep.commit_raw),
            welcome_raw_b64: prep.welcome_raw.map(|w| STANDARD.encode(w)),
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[wasm_bindgen(js_name = mlsPrepareRemoveDeviceJson)]
pub fn wasm_mls_prepare_remove_device(
    group_id_b64: String,
    target_device_id: String,
) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    with_mls_rt(|rt| {
        let signer = load_mls_signer(&rt.provider, &rt.sig_pk).map_err(js_err)?;
        let prep = prepare_remove_device_commit(&rt.provider, &signer, &group_id, &target_device_id)
            .map_err(js_err)?;
        let dto = MlsPreparedCommitDto {
            skipped: prep.skipped,
            base_epoch: prep.base_epoch,
            commit_raw_b64: STANDARD.encode(prep.commit_raw),
            welcome_raw_b64: None,
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsEncryptedMsgDto {
    epoch: u64,
    ciphertext_b64: String,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsEncryptMessageJson)]
pub fn wasm_mls_encrypt_message(
    group_id_b64: String,
    plaintext_json: String,
) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    with_mls_rt(|rt| {
        let signer = load_mls_signer(&rt.provider, &rt.sig_pk).map_err(js_err)?;
        let enc = encrypt_application_message(
            &rt.provider,
            &signer,
            &group_id,
            plaintext_json.as_bytes(),
        )
        .map_err(js_err)?;
        let dto = MlsEncryptedMsgDto {
            epoch: enc.epoch,
            ciphertext_b64: STANDARD.encode(enc.ciphertext),
            storage_json: rt.provider.to_json().map_err(js_err)?,
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MlsProcessedEnvelopeDto {
    kind: String,
    epoch: u64,
    active: bool,
    sender_pin: String,
    sender_device_id: String,
    plaintext_json: Option<String>,
    storage_json: String,
}

#[wasm_bindgen(js_name = mlsProcessEnvelopeJson)]
pub fn wasm_mls_process_envelope(
    group_id_b64: String,
    envelope_raw_b64: String,
) -> Result<String, JsValue> {
    let group_id = decode_b64_32(&group_id_b64, "group_id_b64")?;
    let envelope_raw = STANDARD.decode(&envelope_raw_b64).map_err(js_err)?;
    with_mls_rt(|rt| {
        let outcome =
            process_incoming_envelope(&rt.provider, &group_id, &envelope_raw).map_err(js_err)?;
        let storage_json = rt.provider.to_json().map_err(js_err)?;

        let dto = match outcome {
            ProcessedMlsOutcome::Application {
                epoch,
                sender_pin,
                sender_device_id,
                plaintext,
            } => MlsProcessedEnvelopeDto {
                kind: "application".to_string(),
                epoch,
                active: true,
                sender_pin,
                sender_device_id,
                plaintext_json: Some(String::from_utf8(plaintext).map_err(js_err)?),
                storage_json,
            },
            ProcessedMlsOutcome::Commit {
                epoch,
                active,
                sender_pin,
                sender_device_id,
            } => MlsProcessedEnvelopeDto {
                kind: "commit".to_string(),
                epoch,
                active,
                sender_pin,
                sender_device_id,
                plaintext_json: None,
                storage_json,
            },
            ProcessedMlsOutcome::Proposal {
                epoch,
                sender_pin,
                sender_device_id,
            } => MlsProcessedEnvelopeDto {
                kind: "proposal".to_string(),
                epoch,
                active: true,
                sender_pin,
                sender_device_id,
                plaintext_json: None,
                storage_json,
            },
        };
        serde_json::to_string(&dto).map_err(js_err)
    })
}

// ============================================================================
// MULTIDISPOSITIVO (LinkQr + LinkBundle) & REVOCACIÓN (revmanifest-v1)
// ============================================================================

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

#[wasm_bindgen(js_name = startLinkSessionJson)]
pub fn wasm_start_link_session() -> Result<String, JsValue> {
    let device_uuid = Uuid::new_v4();
    let dev_kp = generate_device_keypair().map_err(js_err)?;
    let (sk_link_eph, pk_link_eph) = generate_link_ephemeral_keypair().map_err(js_err)?;
    let read_secret = random_bytes::<32>().map_err(js_err)?;
    let session_id = derive_link_session_id(&read_secret);

    let qr = LinkQr {
        session_id_32: session_id,
        device_id: *device_uuid.as_bytes(),
        pk_dev_32: dev_kp.pk_dev,
        pk_link_eph_32: pk_link_eph,
    };
    let link_qr_uri = encode_link_qr(&qr);

    let dto = StartedLinkSessionDto {
        device_id: device_uuid.to_string(),
        sk_dev_hex: hex::encode(dev_kp.sk_dev),
        pk_dev_hex: hex::encode(dev_kp.pk_dev),
        sk_link_eph_hex: hex::encode(sk_link_eph),
        pk_link_eph_hex: hex::encode(pk_link_eph),
        read_secret_b64_url: URL_SAFE_NO_PAD.encode(read_secret),
        session_id_hex: hex::encode(session_id),
        link_qr_uri,
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParsedLinkQrDto {
    session_id_hex: String,
    device_id: String,
    pk_dev_hex: String,
    pk_link_eph_hex: String,
}

#[wasm_bindgen(js_name = parseLinkQrJson)]
pub fn wasm_parse_link_qr(uri: String) -> Result<String, JsValue> {
    let qr = parse_link_qr(&uri).map_err(js_err)?;
    let dto = ParsedLinkQrDto {
        session_id_hex: hex::encode(qr.session_id_32),
        device_id: Uuid::from_bytes(qr.device_id).to_string(),
        pk_dev_hex: hex::encode(qr.pk_dev_32),
        pk_link_eph_hex: hex::encode(qr.pk_link_eph_32),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkAuthorizationDto {
    session_id_hex: String,
    target_device_id: String,
    device_cert_b64: String,
    enroll_headers: RootHttpHeadersDto,
    sealed_bundle_b64: String,
}

#[wasm_bindgen(js_name = prepareLinkAuthorizationJson)]
pub fn wasm_prepare_link_authorization(
    mnemonic_12_words: String,
    my_pin: String,
    expected_pk_root_hex: String,
    link_qr_uri: String,
    bundle_payload_json: String,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    validate_crockford_pin(&my_pin).map_err(js_err)?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;
    let exp_sec = now_sec + 180 * 24 * 3600;
    let qr = parse_link_qr(&link_qr_uri).map_err(js_err)?;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    if hex::encode(root.pk_root) != expected_pk_root_hex.to_lowercase() {
        return Err(js_err("Las 12 palabras no coinciden con la clave raíz de este PIN"));
    }

    let cert_raw = build_and_sign_device_cert(
        &my_pin,
        &root.pk_root,
        &qr.device_id,
        &qr.pk_dev_32,
        now_sec,
        exp_sec,
        &root.sk_root,
    )
    .map_err(js_err)?;

    let http_nonce = Uuid::new_v4().to_string();
    let http_sig = sign_canonical_http(
        &root.sk_root,
        "POST",
        "/v1/devices/enroll",
        now_sec,
        &http_nonce,
        &cert_raw,
    );

    let sealed_bundle = seal_link_bundle(
        &qr.pk_link_eph_32,
        &qr.session_id_32,
        &qr.device_id,
        bundle_payload_json.as_bytes(),
    )
    .map_err(js_err)?;

    let dto = LinkAuthorizationDto {
        session_id_hex: hex::encode(qr.session_id_32),
        target_device_id: Uuid::from_bytes(qr.device_id).to_string(),
        device_cert_b64: STANDARD.encode(cert_raw),
        enroll_headers: RootHttpHeadersDto {
            x_pin: my_pin,
            x_timestamp: now_sec.to_string(),
            x_nonce: http_nonce,
            x_signature: URL_SAFE_NO_PAD.encode(http_sig),
        },
        sealed_bundle_b64: STANDARD.encode(sealed_bundle),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[wasm_bindgen(js_name = openLinkBundleJson)]
pub fn wasm_open_link_bundle(
    sk_link_eph_hex: String,
    session_id_hex: String,
    device_id: String,
    bundle_wire: &[u8],
) -> Result<String, JsValue> {
    let mut sk_eph = decode_hex_32(&sk_link_eph_hex, "sk_link_eph_hex")?;
    let session_id = decode_hex_32(&session_id_hex, "session_id_hex")?;
    let dev_uuid = Uuid::parse_str(&device_id).map_err(js_err)?;

    let plain = open_link_bundle(&sk_eph, &session_id, dev_uuid.as_bytes(), bundle_wire)
        .map_err(js_err)?;
    sk_eph.zeroize();
    String::from_utf8(plain).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedRevocationDto {
    seq_num: u64,
    wire_b64: String,
    revoke_headers: RootHttpHeadersDto,
}

#[wasm_bindgen(js_name = prepareRevocationManifestJson)]
pub fn wasm_prepare_revocation_manifest(
    mnemonic_12_words: String,
    my_pin: String,
    expected_pk_root_hex: String,
    next_seq_num: f64,
    revoked_device_ids_json: String,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    validate_crockford_pin(&my_pin).map_err(js_err)?;
    let seq_num = to_u64(next_seq_num, "next_seq_num")?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let root = derive_root_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    if hex::encode(root.pk_root) != expected_pk_root_hex.to_lowercase() {
        return Err(js_err("Las 12 palabras no coinciden con la clave raíz de este PIN"));
    }

    let ids_str: Vec<String> = serde_json::from_str(&revoked_device_ids_json).map_err(js_err)?;
    let mut id_bytes: Vec<[u8; 16]> = Vec::with_capacity(ids_str.len());
    for s in ids_str {
        let u = Uuid::parse_str(&s).map_err(js_err)?;
        id_bytes.push(*u.as_bytes());
    }

    let signed = build_and_sign_revocation_manifest(&my_pin, seq_num, &id_bytes, &root.sk_root)
        .map_err(js_err)?;

    let http_nonce = Uuid::new_v4().to_string();
    let http_sig = sign_canonical_http(
        &root.sk_root,
        "POST",
        "/v1/identities/revoke",
        now_sec,
        &http_nonce,
        &signed.wire_bytes,
    );

    let dto = PreparedRevocationDto {
        seq_num,
        wire_b64: STANDARD.encode(&signed.wire_bytes),
        revoke_headers: RootHttpHeadersDto {
            x_pin: my_pin,
            x_timestamp: now_sec.to_string(),
            x_nonce: http_nonce,
            x_signature: URL_SAFE_NO_PAD.encode(http_sig),
        },
    };
    serde_json::to_string(&dto).map_err(js_err)
}

// ============================================================================
// SAFE BACKUP
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SafeSnapshotContact {
    pin: String,
    pk_root_b64: String,
    trust_state: String,
    alias_local: Option<String>,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SafeSnapshotV1 {
    version: u8,
    pin: String,
    exported_at: u64,
    contacts: Vec<SafeSnapshotContact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeIdentityDto {
    backup_id_hex: String,
    safe_path: String,
    pk_safe_auth_b64_url: String,
}

#[wasm_bindgen(js_name = deriveSafeIdentityJson)]
pub fn wasm_derive_safe_identity(mnemonic_12_words: String) -> Result<String, JsValue> {
    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let keys = derive_safe_keys_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    let backup_id_hex = hex::encode(keys.backup_id);
    let dto = SafeIdentityDto {
        safe_path: format!("/v1/safe/{backup_id_hex}"),
        backup_id_hex,
        pk_safe_auth_b64_url: URL_SAFE_NO_PAD.encode(keys.pk_safe_auth),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportedSafeDto {
    backup_id_hex: String,
    safe_path: String,
    revision: u64,
    contacts_count: u32,
    wire_blob_b64: String,
}

#[wasm_bindgen(js_name = exportSafeBackupJson)]
pub fn wasm_export_safe_backup(
    mnemonic_12_words: String,
    pin: String,
    contacts_json: String,
    target_revision: f64,
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    validate_crockford_pin(&pin).map_err(js_err)?;
    let rev = to_u64(target_revision, "target_revision")?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let keys = derive_safe_keys_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    let contacts: Vec<SafeSnapshotContact> =
        serde_json::from_str(&contacts_json).map_err(js_err)?;
    let snapshot = SafeSnapshotV1 {
        version: 1,
        pin,
        exported_at: now_sec,
        contacts,
    };
    let plain = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(js_err)?);
    let wire = seal_safe_backup(&keys, rev, &plain).map_err(js_err)?;

    let backup_id_hex = hex::encode(keys.backup_id);
    let dto = ExportedSafeDto {
        safe_path: format!("/v1/safe/{backup_id_hex}"),
        backup_id_hex,
        revision: rev,
        contacts_count: snapshot.contacts.len() as u32,
        wire_blob_b64: STANDARD.encode(wire),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeHttpHeadersDto {
    x_safe_pubkey: String,
    x_safe_revision: String,
    x_timestamp: String,
    x_nonce: String,
    x_safe_signature: String,
}

#[wasm_bindgen(js_name = signSafeHttpJson)]
pub fn wasm_sign_safe_http(
    mnemonic_12_words: String,
    method: String,
    path_with_query: String,
    revision: f64,
    raw_body: &[u8],
    now_unix_sec: f64,
) -> Result<String, JsValue> {
    let rev = to_u64(revision, "revision")?;
    let now_sec = to_u64(now_unix_sec, "now_unix_sec")?;

    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let keys = derive_safe_keys_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    let nonce = Uuid::new_v4().to_string();
    let sig = sign_safe_http_request(&keys, &method, &path_with_query, rev, now_sec, &nonce, raw_body);

    let dto = SafeHttpHeadersDto {
        x_safe_pubkey: URL_SAFE_NO_PAD.encode(keys.pk_safe_auth),
        x_safe_revision: rev.to_string(),
        x_timestamp: now_sec.to_string(),
        x_nonce: nonce,
        x_safe_signature: URL_SAFE_NO_PAD.encode(sig),
    };
    serde_json::to_string(&dto).map_err(js_err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoredSafeDto {
    restored_pin: String,
    restored_revision: u64,
    contacts_imported: u32,
    contacts_updated: u32,
    conflicting_pins: Vec<String>,
    merged_contacts: Vec<SafeSnapshotContact>,
}

#[wasm_bindgen(js_name = restoreSafeBackupJson)]
pub fn wasm_restore_safe_backup(
    mnemonic_12_words: String,
    server_revision: f64,
    wire_blob: &[u8],
    existing_pin: String,
    existing_contacts_json: String,
) -> Result<String, JsValue> {
    let rev = to_u64(server_revision, "server_revision")?;
    let mut phrase = Zeroizing::new(mnemonic_12_words);
    let keys = derive_safe_keys_from_mnemonic(phrase.as_str()).map_err(js_err)?;
    phrase.zeroize();

    let plain = Zeroizing::new(open_safe_backup(&keys, rev, wire_blob).map_err(js_err)?);
    let snapshot: SafeSnapshotV1 = serde_json::from_slice(&plain).map_err(js_err)?;
    if snapshot.version != 1 {
        return Err(js_err("versión de SafeSnapshot no soportada"));
    }
    validate_crockford_pin(&snapshot.pin).map_err(js_err)?;

    if !existing_pin.is_empty() && existing_pin != snapshot.pin {
        return Err(js_err(format!(
            "IDENTITY_MISMATCH: respaldo pertenece a {} y este navegador usa {}",
            snapshot.pin, existing_pin
        )));
    }

    let existing: Vec<SafeSnapshotContact> =
        serde_json::from_str(&existing_contacts_json).map_err(js_err)?;
    let mut map: HashMap<String, SafeSnapshotContact> =
        existing.into_iter().map(|c| (c.pin.clone(), c)).collect();

    let mut imported = 0u32;
    let mut updated = 0u32;
    let mut conflicting_pins = Vec::new();

    for c in snapshot.contacts {
        match map.get_mut(&c.pin) {
            None => {
                map.insert(c.pin.clone(), c);
                imported += 1;
            }
            Some(ex) => {
                if ex.pk_root_b64 != c.pk_root_b64 {
                    conflicting_pins.push(c.pin);
                    continue;
                }
                let trust = if ex.trust_state == "verified" || c.trust_state == "verified" {
                    "verified".to_string()
                } else {
                    "tofu".to_string()
                };
                let alias = ex.alias_local.clone().or(c.alias_local);
                if trust != ex.trust_state || alias != ex.alias_local {
                    ex.trust_state = trust;
                    ex.alias_local = alias;
                    ex.updated_at = ex.updated_at.max(c.updated_at);
                    updated += 1;
                }
            }
        }
    }

    let mut merged: Vec<SafeSnapshotContact> = map.into_values().collect();
    merged.sort_by(|a, b| a.pin.cmp(&b.pin));

    let dto = RestoredSafeDto {
        restored_pin: snapshot.pin,
        restored_revision: rev,
        contacts_imported: imported,
        contacts_updated: updated,
        conflicting_pins,
        merged_contacts: merged,
    };
    serde_json::to_string(&dto).map_err(js_err)
}
