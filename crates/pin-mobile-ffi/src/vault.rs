use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::MobileFfiError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountMeta {
    pub pin: String,
    pub device_id: String,
    pub pk_root_hex: String,
    pub sk_invite_hex: String,
    pub pk_invite_hex: String,
    pub sk_dev_hex: String,
    pub pk_dev_hex: String,
    pub mls_sig_pk_b64: String,
    pub safe_backup_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalGroupRow {
    pub group_id_b64: String,
    pub group_id_b64_url: String,
    pub peer_pin: String,
    pub cipher_suite: u16,
    pub epoch: u64,
    pub active: bool,
    pub last_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMessageRow {
    pub group_id_b64: String,
    pub group_seq: u64,
    pub sender_pin: String,
    pub sender_device_id: String,
    pub text: String,
    pub sent_at_ms: i64,
    pub mine: bool,
}

pub fn open_sqlcipher_db(db_path: &str, db_key_hex: &str) -> Result<Connection, MobileFfiError> {
    let key_bytes = hex::decode(db_key_hex.trim())
        .map_err(|_| MobileFfiError::Vault("db_key_hex no es hexadecimal válido".into()))?;
    if key_bytes.len() != 32 {
        return Err(MobileFfiError::Vault(
            "db_key_hex debe medir exactamente 32 bytes (64 hex chars)".into(),
        ));
    }

    let conn = Connection::open(db_path)
        .map_err(|e| MobileFfiError::Vault(format!("error abriendo SQLCipher: {e}")))?;

    let pragma_key = format!("PRAGMA key = \"x'{}'\";", hex::encode(&key_bytes));
    conn.execute_batch(&format!(
        "{pragma_key}
        PRAGMA cipher_compatibility = 4;
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;"
    ))
    .map_err(|e| MobileFfiError::Vault(format!("clave SQLCipher inválida o DB corrupta: {e}")))?;

    // Validar que la DB es legible con esta clave
    conn.query_row("SELECT count(*) FROM sqlite_master;", [], |r| r.get::<_, i64>(0))
        .map_err(|e| MobileFfiError::Vault(format!("fallo verificando clave SQLCipher: {e}")))?;

    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> Result<(), MobileFfiError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_kv (
            k TEXT PRIMARY KEY NOT NULL,
            v TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS local_groups (
            group_id_b64 TEXT PRIMARY KEY NOT NULL,
            group_id_b64_url TEXT NOT NULL,
            peer_pin TEXT NOT NULL,
            cipher_suite INTEGER NOT NULL,
            epoch INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            last_seq INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS local_messages (
            group_id_b64 TEXT NOT NULL,
            group_seq INTEGER NOT NULL,
            sender_pin TEXT NOT NULL,
            sender_device_id TEXT NOT NULL,
            body_text TEXT NOT NULL,
            sent_at_ms INTEGER NOT NULL,
            mine INTEGER NOT NULL,
            PRIMARY KEY (group_id_b64, group_seq)
        );",
    )
    .map_err(|e| MobileFfiError::Vault(format!("error creando esquema SQLCipher: {e}")))
}

pub fn kv_set(conn: &Connection, key: &str, val: &str) -> Result<(), MobileFfiError> {
    conn.execute(
        "INSERT INTO vault_kv (k, v) VALUES (?1, ?2)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![key, val],
    )
    .map_err(|e| MobileFfiError::Vault(format!("error guardando {key}: {e}")))?;
    Ok(())
}

pub fn kv_get(conn: &Connection, key: &str) -> Result<Option<String>, MobileFfiError> {
    conn.query_row("SELECT v FROM vault_kv WHERE k = ?1", params![key], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .map_err(|e| MobileFfiError::Vault(format!("error leyendo {key}: {e}")))
}

pub fn save_account(conn: &Connection, acc: &AccountMeta) -> Result<(), MobileFfiError> {
    let json = serde_json::to_string(acc)
        .map_err(|e| MobileFfiError::Vault(format!("error serializando cuenta: {e}")))?;
    kv_set(conn, "account_meta", &json)
}

pub fn load_account(conn: &Connection) -> Result<Option<AccountMeta>, MobileFfiError> {
    match kv_get(conn, "account_meta")? {
        None => Ok(None),
        Some(raw) => {
            let acc = serde_json::from_str(&raw)
                .map_err(|e| MobileFfiError::Vault(format!("cuenta corrupta: {e}")))?;
            Ok(Some(acc))
        }
    }
}

pub fn upsert_group(conn: &Connection, grp: &LocalGroupRow) -> Result<(), MobileFfiError> {
    conn.execute(
        "INSERT INTO local_groups (group_id_b64, group_id_b64_url, peer_pin, cipher_suite, epoch, active, last_seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(group_id_b64) DO UPDATE SET
           epoch = excluded.epoch,
           active = excluded.active,
           last_seq = MAX(local_groups.last_seq, excluded.last_seq)",
        params![
            grp.group_id_b64,
            grp.group_id_b64_url,
            grp.peer_pin,
            grp.cipher_suite as i64,
            grp.epoch as i64,
            if grp.active { 1i64 } else { 0i64 },
            grp.last_seq as i64,
        ],
    )
    .map_err(|e| MobileFfiError::Vault(format!("error guardando grupo: {e}")))?;
    Ok(())
}

pub fn get_group(conn: &Connection, group_id_b64: &str) -> Result<Option<LocalGroupRow>, MobileFfiError> {
    conn.query_row(
        "SELECT group_id_b64, group_id_b64_url, peer_pin, cipher_suite, epoch, active, last_seq
         FROM local_groups WHERE group_id_b64 = ?1",
        params![group_id_b64],
        |r| {
            Ok(LocalGroupRow {
                group_id_b64: r.get(0)?,
                group_id_b64_url: r.get(1)?,
                peer_pin: r.get(2)?,
                cipher_suite: r.get::<_, i64>(3)? as u16,
                epoch: r.get::<_, i64>(4)? as u64,
                active: r.get::<_, i64>(5)? != 0,
                last_seq: r.get::<_, i64>(6)? as u64,
            })
        },
    )
    .optional()
    .map_err(|e| MobileFfiError::Vault(format!("error leyendo grupo: {e}")))
}

pub fn list_groups(conn: &Connection) -> Result<Vec<LocalGroupRow>, MobileFfiError> {
    let mut stmt = conn
        .prepare(
            "SELECT group_id_b64, group_id_b64_url, peer_pin, cipher_suite, epoch, active, last_seq
             FROM local_groups ORDER BY last_seq DESC",
        )
        .map_err(|e| MobileFfiError::Vault(e.to_string()))?;

    let rows = stmt
        .query_map([], |r| {
            Ok(LocalGroupRow {
                group_id_b64: r.get(0)?,
                group_id_b64_url: r.get(1)?,
                peer_pin: r.get(2)?,
                cipher_suite: r.get::<_, i64>(3)? as u16,
                epoch: r.get::<_, i64>(4)? as u64,
                active: r.get::<_, i64>(5)? != 0,
                last_seq: r.get::<_, i64>(6)? as u64,
            })
        })
        .map_err(|e| MobileFfiError::Vault(e.to_string()))?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|e| MobileFfiError::Vault(e.to_string()))?);
    }
    Ok(out)
}

pub fn insert_message(conn: &Connection, msg: &LocalMessageRow) -> Result<(), MobileFfiError> {
    conn.execute(
        "INSERT OR IGNORE INTO local_messages
         (group_id_b64, group_seq, sender_pin, sender_device_id, body_text, sent_at_ms, mine)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            msg.group_id_b64,
            msg.group_seq as i64,
            msg.sender_pin,
            msg.sender_device_id,
            msg.text,
            msg.sent_at_ms,
            if msg.mine { 1i64 } else { 0i64 },
        ],
    )
    .map_err(|e| MobileFfiError::Vault(format!("error guardando mensaje: {e}")))?;
    Ok(())
}

pub fn list_messages(conn: &Connection, group_id_b64: &str) -> Result<Vec<LocalMessageRow>, MobileFfiError> {
    let mut stmt = conn
        .prepare(
            "SELECT group_id_b64, group_seq, sender_pin, sender_device_id, body_text, sent_at_ms, mine
             FROM local_messages WHERE group_id_b64 = ?1 ORDER BY group_seq ASC",
        )
        .map_err(|e| MobileFfiError::Vault(e.to_string()))?;

    let rows = stmt
        .query_map(params![group_id_b64], |r| {
            Ok(LocalMessageRow {
                group_id_b64: r.get(0)?,
                group_seq: r.get::<_, i64>(1)? as u64,
                sender_pin: r.get(2)?,
                sender_device_id: r.get(3)?,
                text: r.get(4)?,
                sent_at_ms: r.get(5)?,
                mine: r.get::<_, i64>(6)? != 0,
            })
        })
        .map_err(|e| MobileFfiError::Vault(e.to_string()))?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|e| MobileFfiError::Vault(e.to_string()))?);
    }
    Ok(out)
}

pub fn wipe_all_tables(conn: &Connection) -> Result<(), MobileFfiError> {
    conn.execute_batch(
        "DELETE FROM local_messages;
         DELETE FROM local_groups;
         DELETE FROM vault_kv;
         VACUUM;",
    )
    .map_err(|e| MobileFfiError::Vault(format!("error limpiando bóveda: {e}")))
}
