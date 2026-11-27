import webpush from 'web-push';
import { env } from '../../config/env.js';
import { pool } from '../db.js';

export interface StoredPushSubscription {
  endpoint: string;
  p256dh: string;
  auth: string;
}

let vapidConfigured = false;
let tableReadyPromise: Promise<void> | null = null;

export function isWebPushEnabled(): boolean {
  return Boolean(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY);
}

function configureVapidOnce(): boolean {
  if (!isWebPushEnabled()) return false;
  if (!vapidConfigured) {
    webpush.setVapidDetails(env.VAPID_SUBJECT, env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
    vapidConfigured = true;
  }
  return true;
}

export async function ensureWebPushTable(): Promise<void> {
  if (!tableReadyPromise) {
    tableReadyPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS web_push_subscriptions (
          endpoint   TEXT PRIMARY KEY,
          device_id  TEXT NOT NULL,
          pin        TEXT NOT NULL,
          p256dh     TEXT NOT NULL,
          auth       TEXT NOT NULL,
          user_agent TEXT,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_web_push_device ON web_push_subscriptions (device_id);`,
      );
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_web_push_pin ON web_push_subscriptions (pin);`,
      );
    })().catch((err) => {
      tableReadyPromise = null;
      throw err;
    });
  }
  await tableReadyPromise;
}

export async function saveWebPushSubscription(params: {
  deviceId: string;
  pin: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  userAgent?: string;
}): Promise<void> {
  await ensureWebPushTable();
  await pool.query(
    `INSERT INTO web_push_subscriptions (endpoint, device_id, pin, p256dh, auth, user_agent, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (endpoint) DO UPDATE SET
       device_id = EXCLUDED.device_id,
       pin = EXCLUDED.pin,
       p256dh = EXCLUDED.p256dh,
       auth = EXCLUDED.auth,
       user_agent = EXCLUDED.user_agent,
       updated_at = NOW()`,
    [
      params.endpoint,
      params.deviceId,
      params.pin,
      params.p256dh,
      params.auth,
      params.userAgent ?? null,
    ],
  );
}

export async function removeWebPushSubscription(params: {
  deviceId: string;
  endpoint?: string;
}): Promise<void> {
  await ensureWebPushTable();
  if (params.endpoint) {
    await pool.query(
      `DELETE FROM web_push_subscriptions WHERE device_id = $1 AND endpoint = $2`,
      [params.deviceId, params.endpoint],
    );
  } else {
    await pool.query(`DELETE FROM web_push_subscriptions WHERE device_id = $1`, [params.deviceId]);
  }
}

async function sendToSubscriptions(
  subs: StoredPushSubscription[],
  payloadObj: Record<string, unknown>,
): Promise<void> {
  if (!configureVapidOnce() || subs.length === 0) return;

  const payload = JSON.stringify(payloadObj);
  await Promise.allSettled(
    subs.map(async (sub) => {
      try {
        await webpush.sendNotification(
          {
            endpoint: sub.endpoint,
            keys: { p256dh: sub.p256dh, auth: sub.auth },
          },
          payload,
          { TTL: 86400, urgency: 'high' },
        );
      } catch (err) {
        const statusCode = (err as { statusCode?: number }).statusCode;
        if (statusCode === 404 || statusCode === 410) {
          await pool
            .query(`DELETE FROM web_push_subscriptions WHERE endpoint = $1`, [sub.endpoint])
            .catch(() => undefined);
        }
      }
    }),
  );
}

export async function notifyGroupMembersWebPush(
  groupId: Buffer,
  senderDeviceId: string,
  senderPin: string,
  groupIdB64: string,
): Promise<void> {
  if (!isWebPushEnabled()) return;
  try {
    await ensureWebPushTable();
    const res = await pool.query<StoredPushSubscription>(
      `SELECT DISTINCT s.endpoint, s.p256dh, s.auth
       FROM web_push_subscriptions s
       INNER JOIN group_members gm ON gm.device_id::text = s.device_id
       WHERE gm.group_id = $1
         AND s.device_id <> $2
         AND s.pin <> $3`,
      [groupId, senderDeviceId, senderPin],
    );
    await sendToSubscriptions(res.rows, {
      kind: 'message',
      groupIdB64,
      ts: Date.now(),
    });
  } catch (err) {
    console.warn('[web-push] Error enviando notificación de grupo:', (err as Error).message);
  }
}

export async function notifyDeviceWebPush(
  deviceId: string,
  kind: 'message' | 'invite',
): Promise<void> {
  if (!isWebPushEnabled()) return;
  try {
    await ensureWebPushTable();
    const res = await pool.query<StoredPushSubscription>(
      `SELECT endpoint, p256dh, auth FROM web_push_subscriptions WHERE device_id = $1`,
      [deviceId],
    );
    await sendToSubscriptions(res.rows, {
      kind,
      ts: Date.now(),
    });
  } catch (err) {
    console.warn('[web-push] Error enviando notificación a dispositivo:', (err as Error).message);
  }
}
