import { randomUUID } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { env } from '../../config/env.js';
import { pool } from '../db.js';

let supabaseClient: SupabaseClient | null = null;
let mediaTableReady: Promise<void> | null = null;
let lastCleanupAtMs = 0;

const CLEANUP_INTERVAL_MS = 30 * 60 * 1000;

export function isMediaStorageEnabled(): boolean {
  return Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY && env.SUPABASE_MEDIA_BUCKET);
}

function getSupabaseAdmin(): SupabaseClient {
  if (!isMediaStorageEnabled()) {
    throw new Error('MEDIA_STORAGE_NOT_CONFIGURED');
  }
  if (!supabaseClient) {
    supabaseClient = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    });
  }
  return supabaseClient;
}

function normalizeSignedUrl(rawUrl: string): string {
  if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
    return rawUrl;
  }
  const base = env.SUPABASE_URL.replace(/\/+$/, '');
  const path = rawUrl.startsWith('/') ? rawUrl : `/${rawUrl}`;
  return path.startsWith('/storage/v1') ? `${base}${path}` : `${base}/storage/v1${path}`;
}

export async function ensureMediaObjectsTable(): Promise<void> {
  if (!mediaTableReady) {
    mediaTableReady = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS media_objects (
          media_id           TEXT PRIMARY KEY,
          group_id           BYTEA NOT NULL,
          object_path        TEXT NOT NULL,
          uploader_device_id TEXT NOT NULL,
          cipher_bytes       INTEGER NOT NULL,
          created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          expires_at         TIMESTAMPTZ NOT NULL
        );
      `);
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_media_objects_expires ON media_objects (expires_at);`,
      );
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_media_objects_group ON media_objects (group_id);`,
      );
    })().catch((err) => {
      mediaTableReady = null;
      throw err;
    });
  }
  await mediaTableReady;
}

async function cleanupExpiredMediaIfDue(): Promise<void> {
  const now = Date.now();
  if (now - lastCleanupAtMs < CLEANUP_INTERVAL_MS) return;
  lastCleanupAtMs = now;

  if (!isMediaStorageEnabled()) return;
  try {
    await ensureMediaObjectsTable();
    const expired = await pool.query<{ media_id: string; object_path: string }>(
      `SELECT media_id, object_path
       FROM media_objects
       WHERE expires_at <= NOW()
       ORDER BY expires_at ASC
       LIMIT 50`,
    );
    if (expired.rows.length === 0) return;

    const paths = expired.rows.map((r) => r.object_path);
    const ids = expired.rows.map((r) => r.media_id);
    const supabase = getSupabaseAdmin();
    await supabase.storage.from(env.SUPABASE_MEDIA_BUCKET).remove(paths);
    await pool.query(`DELETE FROM media_objects WHERE media_id = ANY($1::text[])`, [ids]);
  } catch (err) {
    console.warn('[media] Error limpiando adjuntos expirados:', (err as Error).message);
  }
}

export async function createSignedMediaUpload(params: {
  groupId: Buffer;
  deviceId: string;
  cipherBytes: number;
}): Promise<{
  mediaId: string;
  signedUrl: string;
  token: string;
  expiresAt: string;
}> {
  await ensureMediaObjectsTable();
  const supabase = getSupabaseAdmin();

  const mediaId = randomUUID();
  const groupPrefix = params.groupId.toString('hex').slice(0, 16);
  const objectPath = `${groupPrefix}/${mediaId}.enc`;

  const { data, error } = await supabase.storage
    .from(env.SUPABASE_MEDIA_BUCKET)
    .createSignedUploadUrl(objectPath);

  if (error || !data?.signedUrl) {
    throw new Error(`SUPABASE_UPLOAD_SIGN_FAILED: ${error?.message ?? 'empty response'}`);
  }

  const ttlMs = env.MEDIA_TTL_DAYS * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(Date.now() + ttlMs);

  await pool.query(
    `INSERT INTO media_objects (media_id, group_id, object_path, uploader_device_id, cipher_bytes, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [mediaId, params.groupId, objectPath, params.deviceId, params.cipherBytes, expiresAt.toISOString()],
  );

  void cleanupExpiredMediaIfDue();

  return {
    mediaId,
    signedUrl: normalizeSignedUrl(data.signedUrl),
    token: data.token ?? '',
    expiresAt: expiresAt.toISOString(),
  };
}

export async function createSignedMediaDownload(params: {
  mediaId: string;
  deviceId: string;
}): Promise<
  | { status: 'ok'; signedUrl: string; cipherBytes: number; expiresInSec: number }
  | { status: 'not_found' | 'forbidden' | 'expired' }
> {
  await ensureMediaObjectsTable();
  const rowRes = await pool.query<{
    group_id: Buffer;
    object_path: string;
    cipher_bytes: number;
    expires_at: Date;
  }>(
    `SELECT group_id, object_path, cipher_bytes, expires_at
     FROM media_objects
     WHERE media_id = $1`,
    [params.mediaId],
  );

  if (rowRes.rows.length === 0) {
    return { status: 'not_found' };
  }

  const row = rowRes.rows[0];
  const memRes = await pool.query(
    `SELECT 1 FROM group_members WHERE group_id = $1 AND device_id::text = $2`,
    [row.group_id, params.deviceId],
  );
  if (memRes.rows.length === 0) {
    return { status: 'forbidden' };
  }

  if (row.expires_at.getTime() <= Date.now()) {
    return { status: 'expired' };
  }

  const supabase = getSupabaseAdmin();
  const expiresInSec = 300;
  const { data, error } = await supabase.storage
    .from(env.SUPABASE_MEDIA_BUCKET)
    .createSignedUrl(row.object_path, expiresInSec);

  if (error || !data?.signedUrl) {
    throw new Error(`SUPABASE_DOWNLOAD_SIGN_FAILED: ${error?.message ?? 'empty response'}`);
  }

  return {
    status: 'ok',
    signedUrl: normalizeSignedUrl(data.signedUrl),
    cipherBytes: row.cipher_bytes,
    expiresInSec,
  };
}
