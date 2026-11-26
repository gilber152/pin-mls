import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import {
  parseAndVerifyRevocationManifest,
  RevocationManifestError,
} from '../../infra/revocationManifest.js';
import { publishDeviceKick } from '../ws/presence.js';

const REVOKED_DEV_REDIS_TTL_SEC = 1800; // > JWT TTL (900s)

export async function registerRevokeRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.post(
    '/v1/identities/revoke',
    { preHandler: [fastify.verifyEd25519({ keyType: 'root' })] },
    async (req, reply) => {
      const pin = req.auth!.pin;
      const rawWire = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);

      const idRes = await pool.query<{ pk_root: Buffer }>(
        `SELECT pk_root FROM identities WHERE pin = $1`,
        [pin],
      );
      if (idRes.rows.length === 0) {
        return reply.code(404).send({ error: 'IDENTITY_NOT_FOUND' });
      }

      let parsed;
      try {
        parsed = parseAndVerifyRevocationManifest(rawWire, pin, idRes.rows[0].pk_root);
      } catch (err) {
        if (err instanceof RevocationManifestError) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        throw err;
      }

      const pgClient = await pool.connect();
      try {
        await pgClient.query('BEGIN');

        const curRes = await pgClient.query<{ seq_num: string }>(
          `SELECT seq_num FROM revocation_manifests WHERE pin = $1 FOR UPDATE`,
          [pin],
        );
        const currentSeq = curRes.rows.length > 0 ? BigInt(curRes.rows[0].seq_num) : 0n;
        if (parsed.seqNum <= currentSeq) {
          await pgClient.query('ROLLBACK');
          return reply.code(409).send({
            error: 'STALE_REVOCATION_SEQ',
            currentSeqNum: currentSeq.toString(),
          });
        }

        await pgClient.query(
          `INSERT INTO revocation_manifests (pin, seq_num, manifest_raw, sig_root, revoked_device_ids, updated_at)
           VALUES ($1, $2, $3, $4, $5::uuid[], NOW())
           ON CONFLICT (pin) DO UPDATE
             SET seq_num = EXCLUDED.seq_num,
                 manifest_raw = EXCLUDED.manifest_raw,
                 sig_root = EXCLUDED.sig_root,
                 revoked_device_ids = EXCLUDED.revoked_device_ids,
                 updated_at = NOW()`,
          [pin, parsed.seqNum.toString(), parsed.manifestRaw, parsed.sigRoot, parsed.revokedDeviceIds],
        );

        await pgClient.query(
          `UPDATE devices
           SET status = 'revoked', push_token = NULL
           WHERE pin = $1 AND device_id = ANY($2::uuid[])`,
          [pin, parsed.revokedDeviceIds],
        );

        // Purgar KeyPackages, membresías de grupo y Welcomes pendientes (evita bloquear GC Zero-Archive)
        await pgClient.query(
          `DELETE FROM key_packages WHERE pin = $1 AND device_id = ANY($2::uuid[])`,
          [pin, parsed.revokedDeviceIds],
        );
        await pgClient.query(
          `DELETE FROM group_members WHERE pin = $1 AND device_id = ANY($2::uuid[])`,
          [pin, parsed.revokedDeviceIds],
        );
        await pgClient.query(
          `DELETE FROM welcome_deliveries WHERE device_id = ANY($1::uuid[])`,
          [parsed.revokedDeviceIds],
        );

        await pgClient.query('COMMIT');
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }

      // Invalidación inmediata en Redis + expulsión WS 4001
      for (const devId of parsed.revokedDeviceIds) {
        await cmdRedis.del(`pk:device:${devId}`);
        await cmdRedis.set(`revoked:dev:${devId}`, '1', 'EX', REVOKED_DEV_REDIS_TTL_SEC);
        await publishDeviceKick(cmdRedis, devId, 'DEVICE_REVOKED');
      }

      return reply.code(200).send({
        ok: true,
        pin,
        seqNum: parsed.seqNum.toString(),
        revokedCount: parsed.revokedDeviceIds.length,
      });
    },
  );
}
