use serde_json::Value;
use uuid::Uuid;

use pin_mobile_ffi::{
    mobile_derive_identity_registration_json, mobile_generate_mnemonic_12_words,
    mobile_prepare_device_enrollment_json, PinMobileClient,
};

fn temp_db_path(label: &str) -> String {
    std::env::temp_dir()
        .join(format!("pin_mls_ffi_{label}_{}.db", Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

fn init_test_client(db_path: &str, key_hex: &str, pin: &str) -> PinMobileClient {
    let client = PinMobileClient::open(db_path.to_string(), key_hex.to_string()).unwrap();
    let mnemonic = mobile_generate_mnemonic_12_words().unwrap();
    let reg: Value =
        serde_json::from_str(&mobile_derive_identity_registration_json(mnemonic.clone()).unwrap())
            .unwrap();
    let enr: Value = serde_json::from_str(
        &mobile_prepare_device_enrollment_json(mnemonic, pin.to_string(), 1_795_000_000).unwrap(),
    )
    .unwrap();

    client
        .init_local_account(
            pin.to_string(),
            enr["deviceId"].as_str().unwrap().to_string(),
            reg["pkRootHex"].as_str().unwrap().to_string(),
            reg["skInviteHex"].as_str().unwrap().to_string(),
            reg["pkInviteHex"].as_str().unwrap().to_string(),
            enr["skDevHex"].as_str().unwrap().to_string(),
            enr["pkDevHex"].as_str().unwrap().to_string(),
        )
        .unwrap();
    client
}

#[test]
fn sqlcipher_rejects_wrong_key_and_persists_openmls_messaging() {
    let alice_db = temp_db_path("alice");
    let bob_db = temp_db_path("bob");
    let alice_key = "11".repeat(32);
    let bob_key = "22".repeat(32);
    let wrong_key = "99".repeat(32);

    let alice = init_test_client(&alice_db, &alice_key, "7F3A9C1B");
    let bob = init_test_client(&bob_db, &bob_key, "9K2M4P8Q");

    // 1. Verificar que abrir con clave incorrecta falla (cifrado SQLCipher AES-256 real)
    assert!(
        PinMobileClient::open(alice_db.clone(), wrong_key).is_err(),
        "SQLCipher debe rechazar una clave incorrecta"
    );

    // 2. Bob genera KeyPackage OpenMLS y Alice crea el grupo
    let bob_kps: Value =
        serde_json::from_str(&bob.generate_key_packages_json(1, false, 1_795_000_000).unwrap())
            .unwrap();
    let bob_kp_raw = bob_kps[0]["kpRaw"].as_str().unwrap().to_string();

    let created: Value = serde_json::from_str(
        &alice
            .create_group_and_add_members_json(
                "9K2M4P8Q".to_string(),
                serde_json::to_string(&vec![bob_kp_raw]).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let gid = created["groupIdB64"].as_str().unwrap().to_string();
    let welcome_b64 = created["welcomeRawB64"].as_str().unwrap().to_string();
    assert_eq!(alice.confirm_pending_commit(gid.clone(), 1).unwrap(), 1);

    // 3. Bob se une desde el Welcome
    let joined: Value =
        serde_json::from_str(&bob.join_from_welcome_json(welcome_b64, 1).unwrap()).unwrap();
    assert_eq!(joined["groupIdB64"].as_str().unwrap(), gid);
    assert_eq!(joined["epoch"].as_u64().unwrap(), 1);

    // 4. Cerrar ambos clientes y reabrir desde disco (persistencia SQLCipher + OpenMLS)
    drop(alice);
    drop(bob);

    let alice2 = PinMobileClient::open(alice_db.clone(), alice_key).unwrap();
    let bob2 = PinMobileClient::open(bob_db.clone(), bob_key).unwrap();

    // 5. Alice cifra un mensaje y Bob lo descifra y lo guarda en local_messages
    let enc: Value = serde_json::from_str(
        &alice2
            .encrypt_message_json(gid.clone(), "Hola desde Android FFI!".into(), 1_795_000_123_000)
            .unwrap(),
    )
    .unwrap();
    let ct_b64 = enc["ciphertextB64"].as_str().unwrap().to_string();

    let dec: Value = serde_json::from_str(
        &bob2
            .process_envelope_json(gid.clone(), 2, ct_b64)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dec["kind"].as_str().unwrap(), "application");
    assert_eq!(dec["text"].as_str().unwrap(), "Hola desde Android FFI!");

    let bob_msgs: Value = serde_json::from_str(&bob2.list_messages_json(gid).unwrap()).unwrap();
    assert_eq!(bob_msgs.as_array().unwrap().len(), 1);
    assert_eq!(bob_msgs[0]["text"].as_str().unwrap(), "Hola desde Android FFI!");

    let _ = std::fs::remove_file(&alice_db);
    let _ = std::fs::remove_file(&bob_db);
}
