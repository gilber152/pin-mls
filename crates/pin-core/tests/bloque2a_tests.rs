use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use pin_core::group_e2ee::{
    decrypt_group_commit, encrypt_group_commit, generate_signed_key_package, open_group_welcome,
    parse_and_verify_key_package, seal_group_welcome_multi, CommitPayload, WelcomePayload,
};
use pin_core::identity::generate_device_keypair;
use pin_core::qr::{derive_link_session_id, open_link_bundle, seal_link_bundle};
use pin_core::random_bytes;

#[test]
fn link_bundle_roundtrip_and_aad_binding() {
    let read_secret = random_bytes::<32>().unwrap();
    let session_id = derive_link_session_id(&read_secret);
    let dev_uuid = *Uuid::new_v4().as_bytes();
    let sk_eph = random_bytes::<32>().unwrap();
    let pk_eph = X25519PublicKey::from(&X25519Secret::from(sk_eph)).to_bytes();

    let payload = br#"{"pin":"7F3A9C1B","contacts":[]}"#;
    let wire = seal_link_bundle(&pk_eph, &session_id, &dev_uuid, payload).unwrap();
    assert!(wire.len() >= 48);

    let opened = open_link_bundle(&sk_eph, &session_id, &dev_uuid, &wire).unwrap();
    assert_eq!(opened, payload);

    let mut wrong_session = session_id;
    wrong_session[0] ^= 0xff;
    assert!(open_link_bundle(&sk_eph, &wrong_session, &dev_uuid, &wire).is_err());
}

#[test]
fn multi_recipient_welcome_and_commit_rotation() {
    let group_id = random_bytes::<32>().unwrap();
    let epoch_secret_1 = random_bytes::<32>().unwrap();

    let dev_a1 = *Uuid::new_v4().as_bytes();
    let kp_a1_keys = generate_device_keypair().unwrap();
    let kp_a1 = generate_signed_key_package(&dev_a1, &kp_a1_keys.pk_dev, &kp_a1_keys.sk_dev).unwrap();

    let dev_a2 = *Uuid::new_v4().as_bytes();
    let kp_a2_keys = generate_device_keypair().unwrap();
    let kp_a2 = generate_signed_key_package(&dev_a2, &kp_a2_keys.pk_dev, &kp_a2_keys.sk_dev).unwrap();

    let p1 = parse_and_verify_key_package(&kp_a1.kp_raw).unwrap();
    let p2 = parse_and_verify_key_package(&kp_a2.kp_raw).unwrap();

    let w = WelcomePayload {
        group_id_b64: "test".into(),
        epoch: 1,
        epoch_secret_hex: hex::encode(epoch_secret_1),
        creator_pin: "9K2M4P8Q".into(),
        peer_pin: "7F3A9C1B".into(),
    };
    let wire = seal_group_welcome_multi(&[p1.pk_kp_x25519, p2.pk_kp_x25519], &group_id, &w).unwrap();

    let o1 = open_group_welcome(&kp_a1.sk_kp_x25519, &group_id, &wire).unwrap();
    let o2 = open_group_welcome(&kp_a2.sk_kp_x25519, &group_id, &wire).unwrap();
    assert_eq!(o1.epoch_secret_hex, o2.epoch_secret_hex);

    // Epoch 1 -> 2 commit rotation
    let epoch_secret_2 = random_bytes::<32>().unwrap();
    let commit = CommitPayload {
        new_epoch: 2,
        new_epoch_secret_hex: hex::encode(epoch_secret_2),
        action: "rekey".into(),
        target_device_id: Some(Uuid::from_bytes(dev_a2).to_string()),
    };
    let c_wire = encrypt_group_commit(&epoch_secret_1, &group_id, 1, &commit).unwrap();
    let opened_c = decrypt_group_commit(&epoch_secret_1, &group_id, 1, &c_wire).unwrap();
    assert_eq!(opened_c.new_epoch, 2);
    assert_eq!(opened_c.new_epoch_secret_hex, hex::encode(epoch_secret_2));
}
