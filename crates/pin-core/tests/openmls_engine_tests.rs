use uuid::Uuid;

use pin_core::mls_engine::{
    build_credential_with_key, clear_pending_commit, confirm_pending_commit,
    create_and_store_mls_signer, create_group_and_add_members, encrypt_application_message,
    generate_mls_key_package, join_group_from_welcome, load_mls_signer, prepare_add_member_commit,
    prepare_remove_device_commit, process_incoming_envelope, PinMlsProvider, ProcessedMlsOutcome,
};

struct TestDevice {
    pin: String,
    device_id: String,
    provider: PinMlsProvider,
    sig_pk: Vec<u8>,
}

impl TestDevice {
    fn new(pin: &str) -> Self {
        let provider = PinMlsProvider::new_empty();
        let sig_pk = create_and_store_mls_signer(&provider).unwrap();
        Self {
            pin: pin.to_string(),
            device_id: Uuid::new_v4().to_string(),
            provider,
            sig_pk,
        }
    }

    fn reload_from_json(&mut self) {
        let json = self.provider.to_json().unwrap();
        self.provider = PinMlsProvider::from_json(&json).unwrap();
    }

    fn gen_kp(&self, last_resort: bool) -> Vec<u8> {
        let signer = load_mls_signer(&self.provider, &self.sig_pk).unwrap();
        let cred = build_credential_with_key(&self.pin, &self.device_id, &self.sig_pk);
        generate_mls_key_package(&self.provider, &signer, cred, last_resort, 1_795_000_000)
            .unwrap()
            .kp_raw
    }
}

#[test]
fn openmls_two_party_handshake_persistence_and_messaging() {
    let mut alice = TestDevice::new("7F3A9C1B");
    let mut bob = TestDevice::new("9K2M4P8Q");

    let bob_kp = bob.gen_kp(false);

    // 1. Alice crea grupo y añade a Bob
    let alice_signer = load_mls_signer(&alice.provider, &alice.sig_pk).unwrap();
    let alice_cred = build_credential_with_key(&alice.pin, &alice.device_id, &alice.sig_pk);
    let created = create_group_and_add_members(&alice.provider, &alice_signer, alice_cred, &[bob_kp]).unwrap();
    assert_eq!(created.base_epoch, 0);
    let alice_epoch = confirm_pending_commit(&alice.provider, &created.group_id).unwrap();
    assert_eq!(alice_epoch, 1);

    // 2. Bob se une desde el Welcome
    let joined = join_group_from_welcome(&bob.provider, &bob.pin, &created.welcome_raw).unwrap();
    assert_eq!(joined.group_id, created.group_id);
    assert_eq!(joined.peer_pin, alice.pin);
    assert_eq!(joined.epoch, 1);

    // 3. Simular recarga completa de navegador (serializar y restaurar MemoryStorage JSON)
    alice.reload_from_json();
    bob.reload_from_json();

    // 4. Mensajería bidireccional cifrada RFC 9420
    let a_signer = load_mls_signer(&alice.provider, &alice.sig_pk).unwrap();
    let enc1 = encrypt_application_message(&alice.provider, &a_signer, &created.group_id, b"Hola desde OpenMLS!").unwrap();
    assert_eq!(enc1.epoch, 1);

    match process_incoming_envelope(&bob.provider, &created.group_id, &enc1.ciphertext).unwrap() {
        ProcessedMlsOutcome::Application { sender_pin, sender_device_id, plaintext, .. } => {
            assert_eq!(sender_pin, alice.pin);
            assert_eq!(sender_device_id, alice.device_id);
            assert_eq!(plaintext, b"Hola desde OpenMLS!");
        }
        other => panic!("esperaba Application, recibí {other:?}"),
    }

    let b_signer = load_mls_signer(&bob.provider, &bob.sig_pk).unwrap();
    let enc2 = encrypt_application_message(&bob.provider, &b_signer, &created.group_id, b"Recibido con TreeKEM").unwrap();
    match process_incoming_envelope(&alice.provider, &created.group_id, &enc2.ciphertext).unwrap() {
        ProcessedMlsOutcome::Application { sender_pin, plaintext, .. } => {
            assert_eq!(sender_pin, bob.pin);
            assert_eq!(plaintext, b"Recibido con TreeKEM");
        }
        other => panic!("esperaba Application, recibí {other:?}"),
    }
}

#[test]
fn openmls_multidevice_add_and_revocation_pcs() {
    let alice1 = TestDevice::new("7F3A9C1B");
    let alice2 = TestDevice::new("7F3A9C1B");
    let bob = TestDevice::new("9K2M4P8Q");

    let bob_kp = bob.gen_kp(false);
    let a1_signer = load_mls_signer(&alice1.provider, &alice1.sig_pk).unwrap();
    let a1_cred = build_credential_with_key(&alice1.pin, &alice1.device_id, &alice1.sig_pk);
    let created = create_group_and_add_members(&alice1.provider, &a1_signer, a1_cred, &[bob_kp]).unwrap();
    confirm_pending_commit(&alice1.provider, &created.group_id).unwrap();
    join_group_from_welcome(&bob.provider, &bob.pin, &created.welcome_raw).unwrap();

    // Añadir Alice2 al grupo (época 1 -> 2)
    let a2_kp = alice2.gen_kp(false);
    let add_commit = prepare_add_member_commit(&alice1.provider, &a1_signer, &created.group_id, &a2_kp).unwrap();
    assert_eq!(add_commit.base_epoch, 1);
    assert_eq!(confirm_pending_commit(&alice1.provider, &created.group_id).unwrap(), 2);

    // Bob procesa el Commit de adición
    match process_incoming_envelope(&bob.provider, &created.group_id, &add_commit.commit_raw).unwrap() {
        ProcessedMlsOutcome::Commit { epoch, active, .. } => {
            assert_eq!(epoch, 2);
            assert!(active);
        }
        other => panic!("esperaba Commit, recibí {other:?}"),
    }

    // Alice2 entra por Welcome en época 2
    let joined_a2 = join_group_from_welcome(&alice2.provider, &alice2.pin, add_commit.welcome_raw.as_ref().unwrap()).unwrap();
    assert_eq!(joined_a2.epoch, 2);
    assert_eq!(joined_a2.peer_pin, bob.pin);

    // Alice2 envía mensaje y tanto Alice1 como Bob lo descifran
    let a2_signer = load_mls_signer(&alice2.provider, &alice2.sig_pk).unwrap();
    let msg_a2 = encrypt_application_message(&alice2.provider, &a2_signer, &created.group_id, b"Desde disp 2").unwrap();
    match process_incoming_envelope(&bob.provider, &created.group_id, &msg_a2.ciphertext).unwrap() {
        ProcessedMlsOutcome::Application { sender_device_id, plaintext, .. } => {
            assert_eq!(sender_device_id, alice2.device_id);
            assert_eq!(plaintext, b"Desde disp 2");
        }
        other => panic!("esperaba Application, recibí {other:?}"),
    }

    // Revocar Alice2 con TreeKEM remove_members (época 2 -> 3)
    let rem_commit = prepare_remove_device_commit(&alice1.provider, &a1_signer, &created.group_id, &alice2.device_id).unwrap();
    assert!(!rem_commit.skipped);
    assert_eq!(confirm_pending_commit(&alice1.provider, &created.group_id).unwrap(), 3);

    match process_incoming_envelope(&bob.provider, &created.group_id, &rem_commit.commit_raw).unwrap() {
        ProcessedMlsOutcome::Commit { epoch, active, .. } => {
            assert_eq!(epoch, 3);
            assert!(active);
        }
        other => panic!("esperaba Commit, recibí {other:?}"),
    }

    // Post-Compromise Security: mensaje de época 3 es legible por Bob, pero IMPOSIBLE para Alice2
    let secret_msg = encrypt_application_message(&alice1.provider, &a1_signer, &created.group_id, b"Secreto post-revocacion").unwrap();
    assert_eq!(secret_msg.epoch, 3);

    match process_incoming_envelope(&bob.provider, &created.group_id, &secret_msg.ciphertext).unwrap() {
        ProcessedMlsOutcome::Application { plaintext, .. } => {
            assert_eq!(plaintext, b"Secreto post-revocacion");
        }
        other => panic!("esperaba Application, recibí {other:?}"),
    }

    assert!(
        process_incoming_envelope(&alice2.provider, &created.group_id, &secret_msg.ciphertext).is_err(),
        "Alice2 revocado NO debe poder descifrar mensajes de la época 3"
    );
}

#[test]
fn openmls_epoch_conflict_clear_and_catchup() {
    let alice = TestDevice::new("7F3A9C1B");
    let bob = TestDevice::new("9K2M4P8Q");
    let charlie = TestDevice::new("2B4C6D8E");
    let dave = TestDevice::new("3C5D7E9F");

    let bob_kp = bob.gen_kp(false);
    let a_signer = load_mls_signer(&alice.provider, &alice.sig_pk).unwrap();
    let a_cred = build_credential_with_key(&alice.pin, &alice.device_id, &alice.sig_pk);
    let created = create_group_and_add_members(&alice.provider, &a_signer, a_cred, &[bob_kp]).unwrap();
    confirm_pending_commit(&alice.provider, &created.group_id).unwrap();
    join_group_from_welcome(&bob.provider, &bob.pin, &created.welcome_raw).unwrap();

    // Alice prepara un Commit para añadir a Charlie (sin hacer merge todavía)
    let charlie_kp = charlie.gen_kp(false);
    let _alice_conflict_commit = prepare_add_member_commit(&alice.provider, &a_signer, &created.group_id, &charlie_kp).unwrap();

    // Bob gana la carrera en el servidor (añade a Dave y avanza a época 2)
    let b_signer = load_mls_signer(&bob.provider, &bob.sig_pk).unwrap();
    let dave_kp = dave.gen_kp(false);
    let bob_winning_commit = prepare_add_member_commit(&bob.provider, &b_signer, &created.group_id, &dave_kp).unwrap();
    assert_eq!(confirm_pending_commit(&bob.provider, &created.group_id).unwrap(), 2);

    // Alice recibe 409: limpia su pending_commit, aplica el Commit ganador de Bob y reintenta
    assert_eq!(clear_pending_commit(&alice.provider, &created.group_id).unwrap(), 1);
    match process_incoming_envelope(&alice.provider, &created.group_id, &bob_winning_commit.commit_raw).unwrap() {
        ProcessedMlsOutcome::Commit { epoch, active, .. } => {
            assert_eq!(epoch, 2);
            assert!(active);
        }
        other => panic!("esperaba Commit, recibí {other:?}"),
    }

    let charlie_kp2 = charlie.gen_kp(false);
    let retry_commit = prepare_add_member_commit(&alice.provider, &a_signer, &created.group_id, &charlie_kp2).unwrap();
    assert_eq!(retry_commit.base_epoch, 2);
    assert_eq!(confirm_pending_commit(&alice.provider, &created.group_id).unwrap(), 3);
}
