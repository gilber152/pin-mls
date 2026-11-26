use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use uuid::Uuid;

use pin_core::auth::sign_canonical_http;
use pin_core::cert::{
    build_and_sign_device_cert, build_and_sign_keypackage_grant,
    build_and_sign_revocation_manifest, parse_and_verify_revocation_manifest,
};
use pin_core::identity::derive_root_from_mnemonic;
use pin_core::pow::argon2id_pow_hash;
use pin_core::qr::{derive_link_session_id, encode_link_qr, parse_link_qr, LinkQr};
use pin_core::safe::{
    derive_safe_keys_from_mnemonic, open_safe_backup, seal_safe_backup, sign_safe_http_request,
};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn sign_raw_manifest_for_negative_test(manifest_raw: &[u8], sk_root: &[u8; 32]) -> Vec<u8> {
    let mut signed_msg = Vec::with_capacity(14 + manifest_raw.len());
    signed_msg.extend_from_slice(b"revmanifest-v1");
    signed_msg.extend_from_slice(manifest_raw);
    let sig = SigningKey::from_bytes(sk_root).sign(&signed_msg).to_bytes();

    let mut wire = Vec::with_capacity(manifest_raw.len() + 64);
    wire.extend_from_slice(manifest_raw);
    wire.extend_from_slice(&sig);
    wire
}

fn build_revocation_manifest_vector() -> Value {
    const PIN: &str = "7F3A9C1B";
    const SEQ_NUM: u64 = 4_294_967_338; // > 2^32 para probar uint64 BE completo

    let root = derive_root_from_mnemonic(TEST_MNEMONIC).unwrap();

    let uuid_high = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let uuid_low = Uuid::parse_str("110e8400-e29b-41d4-a716-446655440000").unwrap();
    let uuid_mid = Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap();

    let signed = build_and_sign_revocation_manifest(
        PIN,
        SEQ_NUM,
        &[
            *uuid_high.as_bytes(),
            *uuid_low.as_bytes(),
            *uuid_mid.as_bytes(),
            *uuid_low.as_bytes(),
        ],
        &root.sk_root,
    )
    .unwrap();

    let verified =
        parse_and_verify_revocation_manifest(&signed.wire_bytes, PIN, &root.pk_root).unwrap();
    assert_eq!(verified.seq_num, SEQ_NUM);
    assert_eq!(
        verified.revoked_device_ids,
        vec![
            uuid_low.to_string(),
            uuid_mid.to_string(),
            uuid_high.to_string(),
        ]
    );

    let http_ts: u64 = 1_795_000_123;
    let http_nonce = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d";
    let http_sig = sign_canonical_http(
        &root.sk_root,
        "POST",
        "/v1/identities/revoke",
        http_ts,
        http_nonce,
        &signed.wire_bytes,
    );

    let mut tampered = signed.wire_bytes.clone();
    tampered[16] ^= 0x01;

    let mut unsorted_raw = Vec::new();
    unsorted_raw.push(1u8);
    unsorted_raw.extend_from_slice(PIN.as_bytes());
    unsorted_raw.extend_from_slice(&SEQ_NUM.to_be_bytes());
    unsorted_raw.extend_from_slice(&2u16.to_be_bytes());
    unsorted_raw.extend_from_slice(uuid_high.as_bytes());
    unsorted_raw.extend_from_slice(uuid_low.as_bytes());
    let unsorted_wire = sign_raw_manifest_for_negative_test(&unsorted_raw, &root.sk_root);

    let mut dup_raw = Vec::new();
    dup_raw.push(1u8);
    dup_raw.extend_from_slice(PIN.as_bytes());
    dup_raw.extend_from_slice(&SEQ_NUM.to_be_bytes());
    dup_raw.extend_from_slice(&2u16.to_be_bytes());
    dup_raw.extend_from_slice(uuid_low.as_bytes());
    dup_raw.extend_from_slice(uuid_low.as_bytes());
    let duplicate_wire = sign_raw_manifest_for_negative_test(&dup_raw, &root.sk_root);

    let mut zero_seq_raw = Vec::new();
    zero_seq_raw.push(1u8);
    zero_seq_raw.extend_from_slice(PIN.as_bytes());
    zero_seq_raw.extend_from_slice(&0u64.to_be_bytes());
    zero_seq_raw.extend_from_slice(&1u16.to_be_bytes());
    zero_seq_raw.extend_from_slice(uuid_low.as_bytes());
    let zero_seq_wire = sign_raw_manifest_for_negative_test(&zero_seq_raw, &root.sk_root);

    json!({
        "pin": PIN,
        "pkRootHex": hex::encode(root.pk_root),
        "seqNum": SEQ_NUM.to_string(),
        "expectedSortedDeviceIds": verified.revoked_device_ids,
        "manifestRawHex": hex::encode(&signed.manifest_raw),
        "sigRootHex": hex::encode(signed.sig_root),
        "wireHex": hex::encode(&signed.wire_bytes),
        "httpRevoke": {
            "method": "POST",
            "path": "/v1/identities/revoke",
            "timestamp": http_ts.to_string(),
            "nonce": http_nonce,
            "signatureB64Url": URL_SAFE_NO_PAD.encode(http_sig)
        },
        "negativeVectors": {
            "tamperedWireHex": hex::encode(tampered),
            "unsortedValidSigWireHex": hex::encode(unsorted_wire),
            "duplicateValidSigWireHex": hex::encode(duplicate_wire),
            "zeroSeqValidSigWireHex": hex::encode(zero_seq_wire)
        }
    })
}

fn build_link_session_vector() -> Value {
    let read_secret_32: [u8; 32] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    ];
    let session_id_32 = derive_link_session_id(&read_secret_32);
    let device_uuid = Uuid::parse_str("3fa85f64-5717-4562-b3fc-2c963f66afa6").unwrap();
    let pk_dev_32 = [0x42u8; 32];
    let pk_link_eph_32 = [0x7au8; 32];

    let link_qr = LinkQr {
        session_id_32,
        device_id: *device_uuid.as_bytes(),
        pk_dev_32,
        pk_link_eph_32,
    };
    let link_qr_uri = encode_link_qr(&link_qr);
    assert_eq!(parse_link_qr(&link_qr_uri).unwrap(), link_qr);

    let mut wrong_secret = read_secret_32;
    wrong_secret[31] ^= 0x01;

    let non_v4_uuid = Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
    let non_v4_qr = encode_link_qr(&LinkQr {
        session_id_32,
        device_id: *non_v4_uuid.as_bytes(),
        pk_dev_32,
        pk_link_eph_32,
    });
    assert!(parse_link_qr(&non_v4_qr).is_err());

    let wrong_prefix_qr = link_qr_uri.replace("pinapp://v1/link?", "https://example.com/link?");
    let missing_ek_qr = format!(
        "pinapp://v1/link?s={}&d={}&pk={}",
        URL_SAFE_NO_PAD.encode(session_id_32),
        URL_SAFE_NO_PAD.encode(device_uuid.as_bytes()),
        URL_SAFE_NO_PAD.encode(pk_dev_32),
    );
    let session_id_hex = hex::encode(session_id_32);

    json!({
        "readSecretHex": hex::encode(read_secret_32),
        "readSecretB64Url": URL_SAFE_NO_PAD.encode(read_secret_32),
        "sessionIdHex": session_id_hex,
        "linkPath": format!("/v1/link-sessions/{session_id_hex}"),
        "deviceIdUuid": device_uuid.to_string(),
        "pkDevHex": hex::encode(pk_dev_32),
        "pkLinkEphHex": hex::encode(pk_link_eph_32),
        "linkQrUri": link_qr_uri,
        "negativeVectors": {
            "wrongSecretB64Url": URL_SAFE_NO_PAD.encode(wrong_secret),
            "shortSecretB64Url": URL_SAFE_NO_PAD.encode(&read_secret_32[..31]),
            "nonUuidV4QrUri": non_v4_qr,
            "wrongPrefixQrUri": wrong_prefix_qr,
            "missingEkQrUri": missing_ek_qr
        }
    })
}

#[test]
fn generate_rust_node_interop_vectors() {
    let root = derive_root_from_mnemonic(TEST_MNEMONIC).unwrap();
    let dev_sk = [0x55u8; 32];
    let dev_pk = SigningKey::from_bytes(&dev_sk).verifying_key().to_bytes();
    let dev_uuid = Uuid::parse_str("110e8400-e29b-41d4-a716-446655440000").unwrap();
    let grant_uuid = Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap();
    let now_sec: u64 = 1_795_000_000;
    let exp_sec: u64 = now_sec + 86_400;

    // 1. DeviceCert (169B)
    let cert_raw = build_and_sign_device_cert(
        "7F3A9C1B",
        &root.pk_root,
        dev_uuid.as_bytes(),
        &dev_pk,
        now_sec,
        exp_sec,
        &root.sk_root,
    )
    .unwrap();

    // 2. KeyPackageGrant (121B)
    let grant_raw = build_and_sign_keypackage_grant(
        grant_uuid.as_bytes(),
        "7F3A9C1B",
        "9K2M4P8Q",
        dev_uuid.as_bytes(),
        exp_sec,
        &dev_sk,
    )
    .unwrap();

    // 3. Safe Backup (seal + open + safe-http-v1)
    let safe_keys = derive_safe_keys_from_mnemonic(TEST_MNEMONIC).unwrap();
    let safe_plain = br#"{"version":1,"pin":"7F3A9C1B","contacts":[]}"#;
    let safe_blob = seal_safe_backup(&safe_keys, 1, safe_plain).unwrap();
    assert_eq!(open_safe_backup(&safe_keys, 1, &safe_blob).unwrap(), safe_plain);

    let safe_path = format!("/v1/safe/{}", hex::encode(safe_keys.backup_id));
    let safe_nonce = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d";
    let safe_sig = sign_safe_http_request(
        &safe_keys,
        "PUT",
        &safe_path,
        1,
        now_sec,
        safe_nonce,
        &safe_blob,
    );

    // 4. Argon2id PoW exact hash parity (m=16384, t=2, p=1, len=32)
    let pow_payload = [0x11u8; 35];
    let pow_salt = [0x22u8; 16];
    let pow_subject = [0x33u8; 32];
    let pow_nonce = 42u64.to_be_bytes();
    let pow_hash = argon2id_pow_hash(&pow_payload, &pow_salt, &pow_subject, &pow_nonce).unwrap();

    let root_json = json!({
        "deviceCert": {
            "pin": "7F3A9C1B",
            "pkRootHex": hex::encode(root.pk_root),
            "deviceId": dev_uuid.to_string(),
            "pkDevHex": hex::encode(dev_pk),
            "nowSec": now_sec,
            "certHex": hex::encode(cert_raw)
        },
        "keyPackageGrant": {
            "grantId": grant_uuid.to_string(),
            "targetPin": "7F3A9C1B",
            "requesterPin": "9K2M4P8Q",
            "signerDeviceId": dev_uuid.to_string(),
            "signerPkDevHex": hex::encode(dev_pk),
            "nowSec": now_sec,
            "grantHex": hex::encode(grant_raw)
        },
        "safeBackup": {
            "backupIdHex": hex::encode(safe_keys.backup_id),
            "pkSafeAuthHex": hex::encode(safe_keys.pk_safe_auth),
            "safePath": safe_path,
            "revision": "1",
            "timestamp": now_sec.to_string(),
            "nonce": safe_nonce,
            "blobLen": safe_blob.len(),
            "blobHex": hex::encode(&safe_blob),
            "signatureB64Url": URL_SAFE_NO_PAD.encode(safe_sig)
        },
        "argon2Pow": {
            "payloadHex": hex::encode(pow_payload),
            "saltHex": hex::encode(pow_salt),
            "subjectHex": hex::encode(pow_subject),
            "nonceHex": hex::encode(pow_nonce),
            "expectedHashHex": hex::encode(pow_hash)
        },
        "revocationManifest": build_revocation_manifest_vector(),
        "linkSession": build_link_session_vector()
    });

    // Escribir siempre en <workspace_root>/target/interop_vectors.json
    let out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/interop_vectors.json");
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&out_path, serde_json::to_string_pretty(&root_json).unwrap()).unwrap();
    println!("Wrote interop vectors to {}", out_path.display());
}
