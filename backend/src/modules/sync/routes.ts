import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { handleWsAck } from '../ws/ack.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SYNC_ENVELOPE_LIMIT = 200;

interface SyncQuery {
  group_id?: string;
  after?: string;
}

interface AcksBody {
  welcomeBlobIds?: unknown;
  groupCursors?: unknown;
}

export async function registerSyncRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. GET /v1/sync — Descarga consolidada de Welcomes, Invites, Grants y Envelopes pendientes
  fastify.get<{ Querystring: SyncQuery }>(
    '/v1/sync',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;

      const filterGroupId = req.query.group_id
        ? Buffer.from(req.query.group_id, 'base64url')
        : null;
      if (filterGroupId && filterGroupId.length !== 32) {
        return reply.code(400).send({ error: 'INVALID_GROUP_ID_FILTER' });
      }
      const afterSeq = req.query.after ? Number.parseInt(req.query.after, 10) : null;

      const [kpRes, welcomesRes, invitesRes, grantsRes, envRes] = await Promise.all([
        pool.query<{ cnt: string }>(
          `SELECT COUNT(*) AS cnt FROM key_packages
           WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()`,
          [deviceId],
        ),
        pool.query<{
          welcome_blob_id: string;
          group_id: Buffer;
          target_epoch: string;
          commit_seq: string;
          kp_ref: Buffer;
          welcome_raw: Buffer;
        }>(
          `SELECT welcome_blob_id, group_id, target_epoch, commit_seq, kp_ref, welcome_raw
           FROM welcome_deliveries
           WHERE device_id = $1 AND acked_at IS NULL
           ORDER BY created_at ASC`,
          [deviceId],
        ),
        pool.query<{
          request_id: string;
          sender_pin: string;
          ciphertext: Buffer;
          created_at: Date;
        }>(
          `SELECT request_id, sender_pin, ciphertext, created_at
           FROM contact_requests
           WHERE target_pin = $1 AND expires_at > NOW()
           ORDER BY created_at ASC`,
          [pin],
        ),
        pool.query<{
          grant_id: string;
          target_pin: string;
          grant_raw: Buffer;
          expires_at: Date;
        }>(
          `SELECT grant_id, target_pin, grant_raw, expires_at
           FROM pending_keypackage_grants
           WHERE requester_pin = $1 AND expires_at > NOW()
           ORDER BY created_at ASC`,
          [pin],
        ),
        filterGroupId
          ? pool.query<{
              group_id: Buffer;
              group_seq: string;
              msg_type: string;
              epoch: string;
              ciphertext: Buffer;
              server_timestamp: string;
            }>(
              `SELECT env.group_id, env.group_seq, env.msg_type, env.epoch, env.ciphertext, env.server_timestamp
               FROM group_members gm
               JOIN mls_envelopes env ON env.group_id = gm.group_id
               WHERE gm.device_id = $1
                 AND gm.group_id = $2
                 AND env.group_seq > COALESCE($3::bigint, gm.last_acked_seq)
               ORDER BY env.group_seq ASC
               LIMIT $4`,
              [deviceId, filterGroupId, afterSeq !== null && Number.isFinite(afterSeq) ? String(afterSeq) : null, SYNC_ENVELOPE_LIMIT + 1],
            )
          : pool.query<{
              group_id: Buffer;
              group_seq: string;
              msg_type: string;
              epoch: string;
              ciphertext: Buffer;
              server_timestamp: string;
            }>(
              `SELECT env.group_id, env.group_seq, env.msg_type, env.epoch, env.ciphertext, env.server_timestamp
               FROM group_members gm
               JOIN mls_envelopes env
                 ON env.group_id = gm.group_id
                AND env.group_seq > gm.last_acked_seq
               WHERE gm.device_id = $1
               ORDER BY env.server_timestamp ASC, env.group_seq ASC
               LIMIT $2`,
              [deviceId, SYNC_ENVELOPE_LIMIT + 1],
            ),
      ]);

      const hasMoreEnvelopes = envRes.rows.length > SYNC_ENVELOPE_LIMIT;
      const sliceEnvelopes = hasMoreEnvelopes ? envRes.rows.slice(0, SYNC_ENVELOPE_LIMIT) : envRes.rows;

      return reply.code(200).header('Cache-Control', 'no-store').send({
        kpRemaining: Number(kpRes.rows[0]?.cnt ?? '0'),
        welcomes: welcomesRes.rows.map((w) => ({
          welcomeBlobId: w.welcome_blob_id,
          groupId: w.group_id.toString('base64'),
          targetEpoch: Number(w.target_epoch),
          commitSeq: Number(w.commit_seq),
          kpRef: w.kp_ref.toString('base64'),
          welcomeRaw: w.welcome_raw.toString('base64'),
        })),
        contactRequests: invitesRes.rows.map((r) => ({
          requestId: r.request_id,
          senderPin: r.sender_pin,
          ciphertext: r.ciphertext.toString('base64'),
          createdAt: r.created_at.toISOString(),
        })),
        pendingGrants: grantsRes.rows.map((g) => ({
          grantId: g.grant_id,
          targetPin: g.target_pin,
          grantRaw: g.grant_raw.toString('base64url'),
          expiresAt: g.expires_at.toISOString(),
        })),
        envelopes: sliceEnvelopes.map((e) => ({
          groupId: e.group_id.toString('base64'),
          groupSeq: Number(e.group_seq),
          msgType: e.msg_type,
          epoch: Number(e.epoch),
          ciphertext: e.ciphertext.toString('base64'),
          serverTimestamp: Number(e.server_timestamp),
        })),
        hasMoreEnvelopes,
      });
    },
  );

  // 2. POST /v1/acks — Confirmar Welcomes y cursores de grupos tras COMMIT local
  fastify.post<{ Body: AcksBody }>(
    '/v1/acks',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const welcomeBlobIds = Array.isArray(req.body?.welcomeBlobIds)
        ? (req.body.welcomeBlobIds as unknown[]).filter(
            (x): x is string => typeof x === 'string' && UUID_V4_RE.test(x),
          )
        : [];

      if (welcomeBlobIds.length > 0) {
        await pool.query(
          `UPDATE welcome_deliveries
           SET acked_at = NOW()
           WHERE device_id = $1 AND welcome_blob_id = ANY($2::uuid[]) AND acked_at IS NULL`,
          [deviceId, welcomeBlobIds],
        );
      }

      const cursors = Array.isArray(req.body?.groupCursors) ? req.body.groupCursors : [];
      for (const c of cursors as Array<{ groupId?: unknown; lastSeq?: unknown }>) {
        if (typeof c?.groupId === 'string' && typeof c?.lastSeq === 'number') {
          await handleWsAck(deviceId, c.groupId, c.lastSeq);
        }
      }

      return reply.code(204).send();
    },
  );
}
