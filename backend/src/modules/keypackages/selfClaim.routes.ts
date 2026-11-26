import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { deviceChannel, presenceKey } from '../ws/presence.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SELF_CLAIM_RL_MAX = 60;
const SELF_CLAIM_RL_WINDOW_SEC = 300;
const KP_LOW_THRESHOLD = 20;

interface SelfClaimBody {
  targetDeviceId?: unknown;
}

interface ClaimedKpRow {
  kp_ref: Buffer;
  kp_raw: Buffer;
  is_last_resort: boolean;
  expires_at: Date;
}

export async function registerSelfClaimKeyPackageRoutes(
  fastify: FastifyInstance,
): Promise<void> {
  fastify.post<{ Body: SelfClaimBody }>(
    '/v1/keypackages/self-claim',
    { preHandler: [fastify.verifyEd25519({ keyType: 'device' })] },
    async (req, reply) => {
      const requesterPin = req.auth!.pin;
      const requesterDeviceId = req.auth!.deviceId!.toLowerCase();

      const rawTarget = req.body?.targetDeviceId;
      if (typeof rawTarget !== 'string' || !UUID_V4_RE.test(rawTarget.trim())) {
        return reply.code(400).send({ error: 'INVALID_TARGET_DEVICE_ID' });
      }
      const targetDeviceId = rawTarget.trim().toLowerCase();

      if (targetDeviceId === requesterDeviceId) {
        return reply.code(400).send({ error: 'CANNOT_SELF_CLAIM_SAME_DEVICE' });
      }

      const rlKey = `rl:kp_self_claim:${requesterDeviceId}`;
      const hits = await cmdRedis.incr(rlKey);
      if (hits === 1) await cmdRedis.expire(rlKey, SELF_CLAIM_RL_WINDOW_SEC);
      if (hits > SELF_CLAIM_RL_MAX) {
        return reply
          .code(429)
          .header('Retry-After', String(SELF_CLAIM_RL_WINDOW_SEC))
          .send({ error: 'SELF_CLAIM_RATE_LIMITED' });
      }

      const pgClient = await pool.connect();
      let claimed: ClaimedKpRow | null = null;
      let remainingOneTime = 0;

      try {
        await pgClient.query('BEGIN');

        const devCheck = await pgClient.query<{ device_id: string }>(
          `SELECT device_id FROM devices
           WHERE device_id = $1 AND pin = $2 AND status = 'active' AND cert_expires_at > NOW()`,
          [targetDeviceId, requesterPin],
        );
        if (devCheck.rows.length === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(404).send({ error: 'TARGET_DEVICE_NOT_FOUND' });
        }

        const oneTimeRes = await pgClient.query<ClaimedKpRow>(
          `WITH picked AS (
             SELECT kp_ref FROM key_packages
             WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()
             ORDER BY expires_at ASC, created_at ASC
             LIMIT 1
             FOR UPDATE SKIP LOCKED
           )
           DELETE FROM key_packages kp
           USING picked
           WHERE kp.kp_ref = picked.kp_ref
           RETURNING kp.kp_ref, kp.kp_raw, kp.is_last_resort, kp.expires_at`,
          [targetDeviceId],
        );

        if (oneTimeRes.rows.length > 0) {
          claimed = oneTimeRes.rows[0];
        } else {
          const lastResortRes = await pgClient.query<ClaimedKpRow>(
            `SELECT kp_ref, kp_raw, is_last_resort, expires_at
             FROM key_packages
             WHERE device_id = $1 AND is_last_resort = TRUE AND expires_at > NOW()
             ORDER BY expires_at DESC LIMIT 1`,
            [targetDeviceId],
          );
          if (lastResortRes.rows.length > 0) claimed = lastResortRes.rows[0];
        }

        if (!claimed) {
          await pgClient.query('ROLLBACK');
          return reply.code(404).send({ error: 'NO_KEYPACKAGES_AVAILABLE' });
        }

        const countRes = await pgClient.query<{ cnt: string }>(
          `SELECT COUNT(*) AS cnt FROM key_packages
           WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()`,
          [targetDeviceId],
        );
        remainingOneTime = Number(countRes.rows[0]?.cnt ?? '0');

        await pgClient.query('COMMIT');
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }

      if (remainingOneTime < KP_LOW_THRESHOLD) {
        if ((await cmdRedis.exists(presenceKey(targetDeviceId))) === 1) {
          void cmdRedis
            .spublish(
              deviceChannel(targetDeviceId),
              JSON.stringify({ type: 'kp_replenish', kp_remaining: remainingOneTime }),
            )
            .catch(() => {});
        }
      }

      return reply.code(200).header('Cache-Control', 'no-store').send({
        targetPin: requesterPin,
        targetDeviceId,
        kpRef: claimed.kp_ref.toString('base64'),
        kpRaw: claimed.kp_raw.toString('base64'),
        usedLastResort: claimed.is_last_resort,
        expiresAt: Math.floor(claimed.expires_at.getTime() / 1000),
      });
    },
  );
}
