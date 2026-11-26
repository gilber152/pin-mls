import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import {
  KeyPackageGrantError,
  parseKeyPackageGrant,
  verifyKeyPackageGrantSignature,
} from '../../infra/keyPackageGrant.js';
import { deviceChannel, presenceKey } from '../ws/presence.js';

const KP_LOW_THRESHOLD = 20;

interface KpUploadItem {
  kpRef?: unknown;
  kpRaw?: unknown;
  isLastResort?: unknown;
  expiresAt?: unknown;
}

interface UploadKpsBody {
  keyPackages?: unknown;
}

interface ClaimKpsBody {
  grantRaw?: unknown;
}

export async function registerKeyPackageRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. POST /v1/keypackages — Subir lote de KeyPackages (Nivel 2 SK_dev)
  fastify.post<{ Body: UploadKpsBody }>(
    '/v1/keypackages',
    { preHandler: [fastify.verifyEd25519({ keyType: 'device' })] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;

      const list = req.body?.keyPackages;
      if (!Array.isArray(list) || list.length === 0 || list.length > 100) {
        return reply.code(400).send({ error: 'INVALID_KEYPACKAGES_BATCH' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const parsed: Array<{ kpRef: Buffer; kpRaw: Buffer; isLastResort: boolean; expiresAtSec: number }> = [];

      for (const item of list as KpUploadItem[]) {
        if (
          typeof item?.kpRef !== 'string' ||
          typeof item?.kpRaw !== 'string' ||
          typeof item?.isLastResort !== 'boolean' ||
          typeof item?.expiresAt !== 'number'
        ) {
          return reply.code(400).send({ error: 'INVALID_KEYPACKAGE_ITEM' });
        }

        const kpRef = Buffer.from(item.kpRef, 'base64');
        const kpRaw = Buffer.from(item.kpRaw, 'base64');
        if (kpRef.length !== 32 || kpRaw.length < 32 || kpRaw.length > 16384) {
          return reply.code(400).send({ error: 'INVALID_KEYPACKAGE_BYTES' });
        }
        if (!Number.isSafeInteger(item.expiresAt) || item.expiresAt <= nowSec) {
          return reply.code(400).send({ error: 'EXPIRED_KEYPACKAGE_UPLOAD' });
        }
        parsed.push({
          kpRef,
          kpRaw,
          isLastResort: item.isLastResort,
          expiresAtSec: item.expiresAt,
        });
      }

      const pgClient = await pool.connect();
      try {
        await pgClient.query('BEGIN');
        for (const kp of parsed) {
          await pgClient.query(
            `INSERT INTO key_packages (kp_ref, device_id, pin, kp_raw, is_last_resort, expires_at)
             VALUES ($1, $2, $3, $4, $5, to_timestamp($6))
             ON CONFLICT (kp_ref) DO NOTHING`,
            [kp.kpRef, deviceId, pin, kp.kpRaw, kp.isLastResort, kp.expiresAtSec],
          );
        }
        const cntRes = await pgClient.query<{ cnt: string }>(
          `SELECT COUNT(*) AS cnt FROM key_packages
           WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()`,
          [deviceId],
        );
        await pgClient.query('COMMIT');

        return reply.code(200).send({
          ok: true,
          uploaded: parsed.length,
          kpRemaining: Number(cntRes.rows[0]?.cnt ?? '0'),
        });
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }
    },
  );

  // 2. POST /v1/keypackages/claim — Canjear KeyPackageGrant (121B) firmado por SK_dev destino
  fastify.post<{ Body: ClaimKpsBody }>(
    '/v1/keypackages/claim',
    { preHandler: [fastify.verifyEd25519({ keyType: 'device' })] },
    async (req, reply) => {
      const requesterPin = req.auth!.pin;
      const grantRawB64Url = req.body?.grantRaw;
      if (typeof grantRawB64Url !== 'string' || grantRawB64Url.length < 100) {
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

      if (grant.requesterPin !== requesterPin) {
        return reply.code(403).send({ error: 'GRANT_REQUESTER_MISMATCH' });
      }

      const pgClient = await pool.connect();
      const claimedItems: Array<{
        deviceId: string;
        kpRef: string;
        kpRaw: string;
        usedLastResort: boolean;
      }> = [];
      const lowStockDevices: Array<{ deviceId: string; remaining: number }> = [];

      try {
        await pgClient.query('BEGIN');

        // 1. Verificar que el dispositivo firmante pertenece a targetPin y sigue activo
        const signerRes = await pgClient.query<{ pk_dev: Buffer }>(
          `SELECT pk_dev FROM devices
           WHERE device_id = $1 AND pin = $2 AND status = 'active' AND cert_expires_at > NOW()`,
          [grant.signerDeviceId, grant.targetPin],
        );
        if (signerRes.rows.length === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(403).send({ error: 'GRANT_SIGNER_NOT_ACTIVE' });
        }

        if (!verifyKeyPackageGrantSignature(grant, signerRes.rows[0].pk_dev)) {
          await pgClient.query('ROLLBACK');
          return reply.code(400).send({ error: 'INVALID_GRANT_SIGNATURE' });
        }

        // 2. Quemar grant_id atómicamente (single-use)
        const burnRes = await pgClient.query(
          `INSERT INTO consumed_grants (grant_id) VALUES ($1) ON CONFLICT (grant_id) DO NOTHING`,
          [grant.grantId],
        );
        if (burnRes.rowCount === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(409).send({ error: 'GRANT_ALREADY_CONSUMED' });
        }

        // Limpiar el grant pendiente si estaba en buzón
        await pgClient.query(`DELETE FROM pending_keypackage_grants WHERE grant_id = $1`, [grant.grantId]);

        // 3. Reclamar 1 KeyPackage por cada dispositivo activo de targetPin
        const targetDevices = await pgClient.query<{ device_id: string }>(
          `SELECT device_id FROM devices
           WHERE pin = $1 AND status = 'active' AND cert_expires_at > NOW()`,
          [grant.targetPin],
        );

        for (const dev of targetDevices.rows) {
          const picked = await pgClient.query<{ kp_ref: Buffer; kp_raw: Buffer; is_last_resort: boolean }>(
            `WITH pick AS (
               SELECT kp_ref FROM key_packages
               WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()
               ORDER BY expires_at ASC, created_at ASC
               LIMIT 1
               FOR UPDATE SKIP LOCKED
             )
             DELETE FROM key_packages kp
             USING pick
             WHERE kp.kp_ref = pick.kp_ref
             RETURNING kp.kp_ref, kp.kp_raw, kp.is_last_resort`,
            [dev.device_id],
          );

          let row = picked.rows[0];
          if (!row) {
            const fallback = await pgClient.query<{ kp_ref: Buffer; kp_raw: Buffer; is_last_resort: boolean }>(
              `SELECT kp_ref, kp_raw, is_last_resort FROM key_packages
               WHERE device_id = $1 AND is_last_resort = TRUE AND expires_at > NOW()
               ORDER BY expires_at DESC LIMIT 1`,
              [dev.device_id],
            );
            row = fallback.rows[0];
          }

          if (row) {
            claimedItems.push({
              deviceId: dev.device_id,
              kpRef: row.kp_ref.toString('base64'),
              kpRaw: row.kp_raw.toString('base64'),
              usedLastResort: row.is_last_resort,
            });
          }

          const remRes = await pgClient.query<{ cnt: string }>(
            `SELECT COUNT(*) AS cnt FROM key_packages
             WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()`,
            [dev.device_id],
          );
          const remaining = Number(remRes.rows[0]?.cnt ?? '0');
          if (remaining < KP_LOW_THRESHOLD) {
            lowStockDevices.push({ deviceId: dev.device_id, remaining });
          }
        }

        await pgClient.query('COMMIT');
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }

      if (claimedItems.length === 0) {
        return reply.code(404).send({ error: 'NO_ACTIVE_KEYPACKAGES' });
      }

      for (const item of lowStockDevices) {
        if ((await cmdRedis.exists(presenceKey(item.deviceId))) === 1) {
          void cmdRedis
            .spublish(
              deviceChannel(item.deviceId),
              JSON.stringify({ type: 'kp_replenish', kp_remaining: item.remaining }),
            )
            .catch(() => {});
        }
      }

      return reply.code(200).header('Cache-Control', 'no-store').send({
        targetPin: grant.targetPin,
        keyPackages: claimedItems,
      });
    },
  );
}
