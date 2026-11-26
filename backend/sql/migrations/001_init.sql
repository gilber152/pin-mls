-- PIN-MLS Delivery Service Schema v1 (Zero-Archive + OpenMLS + Safe Backup)

CREATE TABLE IF NOT EXISTS identities (
  pin           CHAR(8) PRIMARY KEY,
  pk_root       BYTEA NOT NULL UNIQUE,
  pk_invite     BYTEA NOT NULL,
  sig_invite    BYTEA NOT NULL,
  invite_policy TEXT NOT NULL DEFAULT 'open' CHECK (invite_policy IN ('open', 'qr_only')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(pk_root) = 32),
  CHECK (octet_length(pk_invite) = 32),
  CHECK (octet_length(sig_invite) = 64)
);

CREATE TABLE IF NOT EXISTS devices (
  device_id       UUID PRIMARY KEY,
  pin             CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  pk_dev          BYTEA NOT NULL,
  device_cert_raw BYTEA NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  cert_issued_at  TIMESTAMPTZ NOT NULL,
  cert_expires_at TIMESTAMPTZ NOT NULL,
  push_platform   TEXT CHECK (push_platform IN ('fcm', 'apns')),
  push_token      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(pk_dev) = 32),
  CHECK (octet_length(device_cert_raw) = 169)
);
CREATE INDEX IF NOT EXISTS idx_devices_pin_status ON devices (pin, status);

CREATE TABLE IF NOT EXISTS revocation_manifests (
  pin                CHAR(8) PRIMARY KEY REFERENCES identities(pin) ON DELETE CASCADE,
  seq_num            BIGINT NOT NULL CHECK (seq_num > 0),
  manifest_raw       BYTEA NOT NULL,
  sig_root           BYTEA NOT NULL,
  revoked_device_ids UUID[] NOT NULL,
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(sig_root) = 64)
);

CREATE TABLE IF NOT EXISTS key_packages (
  kp_ref         BYTEA PRIMARY KEY,
  device_id      UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  pin            CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  kp_raw         BYTEA NOT NULL,
  is_last_resort BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(kp_ref) = 32)
);
CREATE INDEX IF NOT EXISTS idx_kp_device_pick
  ON key_packages (device_id, is_last_resort, expires_at ASC, created_at ASC);

CREATE TABLE IF NOT EXISTS contact_requests (
  request_id UUID PRIMARY KEY,
  sender_pin CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  target_pin CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  ciphertext BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_requests_target ON contact_requests (target_pin, expires_at);

CREATE TABLE IF NOT EXISTS reject_cooldowns (
  pair_hash  BYTEA PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (octet_length(pair_hash) = 32)
);

CREATE TABLE IF NOT EXISTS pending_keypackage_grants (
  grant_id      UUID PRIMARY KEY,
  requester_pin CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  target_pin    CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  grant_raw     BYTEA NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL,
  CHECK (octet_length(grant_raw) = 121)
);
CREATE INDEX IF NOT EXISTS idx_pending_grants_requester ON pending_keypackage_grants (requester_pin, expires_at);

CREATE TABLE IF NOT EXISTS consumed_grants (
  grant_id    UUID PRIMARY KEY,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mls_groups (
  group_id      BYTEA PRIMARY KEY,
  cipher_suite  SMALLINT NOT NULL DEFAULT 1,
  current_epoch BIGINT NOT NULL DEFAULT 0,
  last_seq      BIGINT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(group_id) = 32)
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id       BYTEA NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
  device_id      UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  pin            CHAR(8) NOT NULL REFERENCES identities(pin) ON DELETE CASCADE,
  joined_epoch   BIGINT NOT NULL DEFAULT 0,
  last_acked_seq BIGINT NOT NULL DEFAULT 0,
  joined_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (group_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_device ON group_members (device_id);

CREATE TABLE IF NOT EXISTS mls_envelopes (
  group_id         BYTEA NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
  group_seq        BIGINT NOT NULL CHECK (group_seq > 0),
  msg_type         TEXT NOT NULL CHECK (msg_type IN ('application', 'commit', 'proposal')),
  epoch            BIGINT NOT NULL CHECK (epoch >= 0),
  sender_device_id UUID NOT NULL,
  client_msg_id    UUID,
  ciphertext       BYTEA NOT NULL,
  server_timestamp BIGINT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (group_id, group_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mls_envelopes_idempotency
  ON mls_envelopes (group_id, sender_device_id, client_msg_id)
  WHERE client_msg_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mls_envelopes_group_type_epoch
  ON mls_envelopes (group_id, msg_type, epoch);

CREATE TABLE IF NOT EXISTS welcome_deliveries (
  welcome_blob_id UUID PRIMARY KEY,
  group_id        BYTEA NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
  device_id       UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  target_epoch    BIGINT NOT NULL,
  commit_seq      BIGINT NOT NULL,
  kp_ref          BYTEA NOT NULL,
  welcome_raw     BYTEA NOT NULL,
  acked_at        TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(kp_ref) = 32)
);
CREATE INDEX IF NOT EXISTS idx_welcome_deliveries_pending
  ON welcome_deliveries (device_id) WHERE acked_at IS NULL;

CREATE TABLE IF NOT EXISTS safe_backups (
  backup_id    BYTEA PRIMARY KEY,
  pk_safe_auth BYTEA NOT NULL,
  revision     BIGINT NOT NULL CHECK (revision > 0),
  blob         BYTEA NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (octet_length(backup_id) = 32),
  CHECK (octet_length(pk_safe_auth) = 32)
);
