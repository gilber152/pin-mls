import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { env } from '../../config/env.js';
import { pool } from '../../infra/db.js';
import { hmacSha256 } from '../../infra/crypto.js';
import { cmdRedis } from '../../infra/redis.js';
import { verifyAndBurnPowSolution } from '../../infra/pow.js';
import {
  KeyPackageGrantError,
  parseKeyPackageGrant,
  verifyKeyPackageGrantSignature,
} from '../../infra/keyPackageGrant.js';
import { enqueueDelayedPush } from '../../infra/push/queue.js';
import { deviceChannel, presenceKey } from '../ws/presence.js';

const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INVITE_TTL_SEC = 14 * 24 * 3600;
const REJECT_COOLDOWN_SEC = 30 * 24 * 3600;

interface CreateInviteBody {
  targetPin?: unknown;
  ciphertext?: unknown;
  powPayload?: unknown;
  powMac?: unknown;
  powNonce?: unknown;
}

interface RespondInviteBody {
  decision?: unknown;
  grantRaw?: unknown;
}

function pairCooldownHash(senderPin: string, targetPin: string): Buffer {
  return hmacSha256(env.COOLDOWN_PEPPER, Buffer.from(`${senderPin}:${targetPin}`, 'ascii'));
}

async function notifyPinDevices(pin: string, wsFrame: Record<string, unknown>, pushKind: 'sync' | 'invite'): Promise<void> {
  const { rows } = await pool.query<{ device_id: string }>(
    `SELECT device_id FROM devices WHERE pin = $1 AND status = 'active' AND cert_expires_at > NOW()`,
    [pin],
  );
  const raw = JSON.stringify(wsFrame);
  for (const row of rows) {
    const online = (await cmdRedis.exists(presenceKey(row.device_id))) === 1;
    if (online) {
      await cmdRedis.spublish(deviceChannel(row.device_id), raw);
    } else {
      await enqueueDelayedPush({ deviceId: row.device_id, kind: pushKind }, 1000);
    }
  }
}

export async function registerInviteRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. POST /v1/invites — Enviar solicitud HPKE cifrada con PoW action=2
  fastify.post<{ Body: CreateInviteBody }>(
    '/v1/invites',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const senderPin = req.auth!.pin;
      const b = req.body;
      if (
        typeof b?.targetPin !== 'string' ||
        typeof b?.ciphertext !== 'string' ||
        typeof b?.powPayload !== 'string' ||
        typeof b?.powMac !== 'string' ||
        typeof b?.powNonce !== 'string'
      ) {
        return reply.code(400).send({ error: 'MISSING_INVITE_FIELDS' });
      }

      const targetPin = b.targetPin.trim().toUpperCase();
      if (!PIN_CROCKFORD_RE.test(targetPin) || targetPin === senderPin) {
        return reply.code(400).send({ error: 'INVALID_TARGET_PIN' });
      }

      const ct = Buffer.from(b.ciphertext, 'base64');
      if (ct.length < 32 || ct.length > 4096) {
        return reply.code(400).send({ error: 'INVALID_INVITE_CIPHERTEXT' });
      }

      const pow = await verifyAndBurnPowSolution({
        expectedAction: 2,
        subjectBytes: Buffer.from(targetPin, 'ascii'),
        powPayloadB64Url: b.powPayload,
        powMacB64Url: b.powMac,
        powNonceB64Url: b.powNonce,
      });
      if (!pow.ok) {
        return reply.code(400).send({ error: pow.error });
      }

      // Verificar que targetPin existe
      const targetExists = await pool.query(`SELECT 1 FROM identities WHERE pin = $1`, [targetPin]);
      if (targetExists.rows.length === 0) {
        return reply.code(404).send({ error: 'TARGET_IDENTITY_NOT_FOUND' });
      }

      // Comprobar cooldown de rechazo (30 días)
      const pairHash = pairCooldownHash(senderPin, targetPin);
      const cdRes = await pool.query(
        `SELECT 1 FROM reject_cooldowns WHERE pair_hash = $1 AND expires_at > NOW()`,
        [pairHash],
      );
      if (cdRes.rows.length > 0) {
        return reply.code(429).send({ error: 'INVITE_COOLDOWN_ACTIVE' });
      }

      const requestId = randomUUID();
      await pool.query(
        `INSERT INTO contact_requests (request_id, sender_pin, target_pin, ciphertext, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + make_interval(secs => $5))`,
        [requestId, senderPin, targetPin, ct, INVITE_TTL_SEC],
      );

      await notifyPinDevices(
        targetPin,
        {
          type: 'contact_request',
          request_id: requestId,
          sender_pin: senderPin,
          ciphertext: b.ciphertext,
        },
        'invite',
      );

      return reply.code(201).send({ requestId });
    },
  );

  // 2. POST /v1/invites/:requestId/respond — Aceptar (con grantRaw 121B) o rechazar (cooldown 30d)
  fastify.post<{ Params: { requestId: string }; Body: RespondInviteBody }>(
    '/v1/invites/:requestId/respond',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const targetPin = req.auth!.pin;
      const responderDeviceId = req.auth!.deviceId!;
      const requestId = req.params.requestId.toLowerCase();
      if (!UUID_V4_RE.test(requestId)) {
        return reply.code(400).send({ error: 'INVALID_REQUEST_ID' });
      }

      const decision = req.body?.decision;
      if (decision !== 'accept' && decision !== 'reject') {
        return reply.code(400).send({ error: 'INVALID_DECISION' });
      }

      const reqRow = await pool.query<{ sender_pin: string }>(
        `SELECT sender_pin FROM contact_requests
         WHERE request_id = $1 AND target_pin = $2 AND expires_at > NOW()`,
        [requestId, targetPin],
      );
      if (reqRow.rows.length === 0) {
        return reply.code(404).send({ error: 'CONTACT_REQUEST_NOT_FOUND' });
      }
      const senderPin = reqRow.rows[0].sender_pin;

      if (decision === 'reject') {
        const pairHash = pairCooldownHash(senderPin, targetPin);
        await pool.query(
          `INSERT INTO reject_cooldowns (pair_hash, expires_at)
           VALUES ($1, NOW() + make_interval(secs => $2))
           ON CONFLICT (pair_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
          [pairHash, REJECT_COOLDOWN_SEC],
        );
        await pool.query(`DELETE FROM contact_requests WHERE request_id = $1`, [requestId]);
        return reply.code(200).send({ ok: true, decision: 'reject' });
      }

      const grantRawB64Url = req.body?.grantRaw;
      if (typeof grantRawB64Url !== 'string') {
        return reply.code(400).send({ error: 'MISSING_GRANT_RAW' });
      }

      const grantBytes = Buffer.from(grantRawB64Url, 'base64url');
      const nowSec = Math.floor(Date.now() / 1000);
      let grant;
      try {
        grant = parseKeyPackageGrant(grantBytes, nowSec);
      } catch (err) {
        if (err instanceof KeyPackageGrantError) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        throw err;
      }

      if (
        grant.targetPin !== targetPin ||
        grant.requesterPin !== senderPin ||
        grant.signerDeviceId !== responderDeviceId
      ) {
        return reply.code(403).send({ error: 'GRANT_CLAIMS_MISMATCH' });
      }

      const devRes = await pool.query<{ pk_dev: Buffer }>(
        `SELECT pk_dev FROM devices WHERE device_id = $1 AND status = 'active'`,
        [responderDeviceId],
      );
      if (devRes.rows.length === 0 || !verifyKeyPackageGrantSignature(grant, devRes.rows[0].pk_dev)) {
        return reply.code(400).send({ error: 'INVALID_GRANT_SIGNATURE' });
      }

      await pool.query(
        `INSERT INTO pending_keypackage_grants (grant_id, requester_pin, target_pin, grant_raw, expires_at)
         VALUES ($1, $2, $3, $4, to_timestamp($5))
         ON CONFLICT (grant_id) DO NOTHING`,
        [grant.grantId, senderPin, targetPin, grantBytes, grant.expiresAtSec],
      );
      await pool.query(`DELETE FROM contact_requests WHERE request_id = $1`, [requestId]);

      await notifyPinDevices(
        senderPin,
        {
          type: 'keypackage_grant',
          grant_id: grant.grantId,
          target_pin: targetPin,
          grant_raw: grantRawB64Url,
        },
        'sync',
      );

      return reply.code(200).send({ ok: true, decision: 'accept', grantId: grant.grantId });
    },
  );
}
