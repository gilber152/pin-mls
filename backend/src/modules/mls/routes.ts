import { notifyGroupMembersWebPush } from '../../infra/push/webPushService.js';
import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { enqueueDelayedPush } from '../../infra/push/queue.js';
import { deviceChannel, presenceKey } from '../ws/presence.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function decodeGroupId32(raw: string, encoding: 'base64' | 'base64url'): Buffer | null {
  try {
    const buf = Buffer.from(raw, encoding);
    return buf.length === 32 ? buf : null;
  } catch {
    return null;
  }
}

async function fanoutGroupEvent(
  groupId: Buffer,
  excludeDeviceId: string,
  wsFrame: Record<string, unknown>,
  groupSeq: number,
): Promise<void> {
  const { rows } = await pool.query<{ device_id: string }>(
    `SELECT device_id FROM group_members WHERE group_id = $1 AND device_id <> $2`,
    [groupId, excludeDeviceId],
  );
  const groupIdB64 = groupId.toString('base64');
  const payloadStr = JSON.stringify(wsFrame);

  for (const r of rows) {
    const online = (await cmdRedis.exists(presenceKey(r.device_id))) === 1;
    if (online) {
      await cmdRedis.spublish(deviceChannel(r.device_id), payloadStr);
    }
    // Push diferido de 6s (si el cliente confirma por WS ack antes, el worker lo omite)
    await enqueueDelayedPush(
      { deviceId: r.device_id, kind: 'sync', groupIdB64, minGroupSeq: groupSeq },
      online ? 6000 : 1000,
    );
  }
}

interface CreateGroupBody {
  groupId?: unknown;
  cipherSuite?: unknown;
}

interface CommitBody {
  expectedBaseEpoch?: unknown;
  clientMsgId?: unknown;
  commitRaw?: unknown;
  welcomeRaw?: unknown;
  addedDevices?: unknown;
  addedKpRefs?: unknown;
  removedDevices?: unknown;
}

interface MessageBody {
  msgType?: unknown;
  epoch?: unknown;
  clientMsgId?: unknown;
  ciphertext?: unknown;
}

export async function registerMlsRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. POST /v1/groups — Crear grupo MLS en época 0
  fastify.post<{ Body: CreateGroupBody }>(
    '/v1/groups',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;

      if (typeof req.body?.groupId !== 'string') {
        return reply.code(400).send({ error: 'MISSING_GROUP_ID' });
      }
      const groupId = decodeGroupId32(req.body.groupId, 'base64');
      if (!groupId) return reply.code(400).send({ error: 'INVALID_GROUP_ID' });

      const cipherSuite = typeof req.body.cipherSuite === 'number' ? req.body.cipherSuite : 1;

      const pgClient = await pool.connect();
      try {
        await pgClient.query('BEGIN');
        const ins = await pgClient.query(
          `INSERT INTO mls_groups (group_id, cipher_suite, current_epoch, last_seq)
           VALUES ($1, $2, 0, 0)
           ON CONFLICT (group_id) DO NOTHING`,
          [groupId, cipherSuite],
        );
        if (ins.rowCount === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(409).send({ error: 'GROUP_ALREADY_EXISTS' });
        }

        await pgClient.query(
          `INSERT INTO group_members (group_id, device_id, pin, joined_epoch, last_acked_seq)
           VALUES ($1, $2, $3, 0, 0)`,
          [groupId, deviceId, pin],
        );
        await pgClient.query('COMMIT');
        return reply.code(201).send({ ok: true, groupId: groupId.toString('base64'), epoch: 0 });
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }
    },
  );

  // 2. POST /v1/groups/:groupId/commits — Ordenación atómica de Commits + Welcomes con 409 catch-up
  fastify.post<{ Params: { groupId: string }; Body: CommitBody }>(
    '/v1/groups/:groupId/commits',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const senderDeviceId = req.auth!.deviceId!;
      const groupId = decodeGroupId32(req.params.groupId, 'base64url');
      if (!groupId) return reply.code(400).send({ error: 'INVALID_GROUP_ID' });

      const b = req.body;
      if (
        typeof b?.expectedBaseEpoch !== 'number' ||
        !Number.isSafeInteger(b.expectedBaseEpoch) ||
        b.expectedBaseEpoch < 0 ||
        typeof b?.clientMsgId !== 'string' ||
        !UUID_V4_RE.test(b.clientMsgId) ||
        typeof b?.commitRaw !== 'string'
      ) {
        return reply.code(400).send({ error: 'INVALID_COMMIT_PAYLOAD' });
      }

      const commitRaw = Buffer.from(b.commitRaw, 'base64');
      if (commitRaw.length === 0 || commitRaw.length > 5 * 1024 * 1024) {
        return reply.code(400).send({ error: 'INVALID_COMMIT_SIZE' });
      }

      const welcomeRaw = typeof b.welcomeRaw === 'string' && b.welcomeRaw.length > 0
        ? Buffer.from(b.welcomeRaw, 'base64')
        : null;
      const addedDevices = Array.isArray(b.addedDevices) ? (b.addedDevices as string[]) : [];
      const addedKpRefs = Array.isArray(b.addedKpRefs) ? (b.addedKpRefs as string[]) : [];
      const removedDevices = Array.isArray(b.removedDevices) ? (b.removedDevices as string[]) : [];

      if (addedDevices.length > 0 && (!welcomeRaw || addedKpRefs.length !== addedDevices.length)) {
        return reply.code(400).send({ error: 'WELCOME_AND_KP_REFS_REQUIRED' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const pgClient = await pool.connect();

      let confirmedCommitSeq = 0;
      let newEpoch = 0;
      const welcomeNotifications: Array<{ deviceId: string; welcomeBlobId: string }> = [];

      try {
        await pgClient.query('BEGIN');

        // Verificar pertenencia y bloquear fila del grupo para serializar épocas
        const memCheck = await pgClient.query(
          `SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2`,
          [groupId, senderDeviceId],
        );
        if (memCheck.rows.length === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(403).send({ error: 'NOT_A_GROUP_MEMBER' });
        }

        const grpRes = await pgClient.query<{ current_epoch: string; last_seq: string }>(
          `SELECT current_epoch, last_seq FROM mls_groups WHERE group_id = $1 FOR UPDATE`,
          [groupId],
        );
        const currentEpoch = Number(grpRes.rows[0].current_epoch);
        const lastSeq = Number(grpRes.rows[0].last_seq);

        // Idempotencia por clientMsgId
        const existingCommit = await pgClient.query<{ group_seq: string; epoch: string }>(
          `SELECT group_seq, epoch FROM mls_envelopes
           WHERE group_id = $1 AND sender_device_id = $2 AND client_msg_id = $3`,
          [groupId, senderDeviceId, b.clientMsgId.toLowerCase()],
        );
        if (existingCommit.rows.length > 0) {
          await pgClient.query('COMMIT');
          return reply.code(200).send({
            confirmedCommitSeq: Number(existingCommit.rows[0].group_seq),
            newEpoch: Number(existingCommit.rows[0].epoch) + 1,
          });
        }

        // Conflicto optimista de época -> devolver missingCommits para catch-up inmediato
        if (currentEpoch !== b.expectedBaseEpoch) {
          const missingRes = await pgClient.query<{
            group_seq: string;
            epoch: string;
            ciphertext: Buffer;
            server_timestamp: string;
          }>(
            `SELECT group_seq, epoch, ciphertext, server_timestamp
             FROM mls_envelopes
             WHERE group_id = $1 AND msg_type = 'commit' AND epoch >= $2
             ORDER BY group_seq ASC`,
            [groupId, b.expectedBaseEpoch],
          );
          await pgClient.query('ROLLBACK');
          return reply.code(409).send({
            error: 'EPOCH_CONFLICT',
            currentEpoch,
            missingCommits: missingRes.rows.map((r) => ({
              groupSeq: Number(r.group_seq),
              epoch: Number(r.epoch),
              ciphertext: r.ciphertext.toString('base64'),
              serverTimestamp: Number(r.server_timestamp),
            })),
          });
        }

        confirmedCommitSeq = lastSeq + 1;
        newEpoch = currentEpoch + 1;

        await pgClient.query(
          `UPDATE mls_groups SET current_epoch = $2, last_seq = $3 WHERE group_id = $1`,
          [groupId, newEpoch, confirmedCommitSeq],
        );

        await pgClient.query(
          `INSERT INTO mls_envelopes (
             group_id, group_seq, msg_type, epoch, sender_device_id, client_msg_id, ciphertext, server_timestamp
           ) VALUES ($1, $2, 'commit', $3, $4, $5, $6, $7)`,
          [groupId, confirmedCommitSeq, currentEpoch, senderDeviceId, b.clientMsgId.toLowerCase(), commitRaw, nowSec],
        );

        // Avanzar cursor del emisor (ya aplicó su propio Commit)
        await pgClient.query(
          `UPDATE group_members SET last_acked_seq = GREATEST(last_acked_seq, $3)
           WHERE group_id = $1 AND device_id = $2`,
          [groupId, senderDeviceId, confirmedCommitSeq],
        );

        // Remover dispositivos si corresponde
        if (removedDevices.length > 0) {
          await pgClient.query(
            `DELETE FROM group_members WHERE group_id = $1 AND device_id = ANY($2::uuid[])`,
            [groupId, removedDevices],
          );
        }

        // Añadir nuevos dispositivos + encolar Welcome para cada uno
        for (let i = 0; i < addedDevices.length; i += 1) {
          const addedDevId = addedDevices[i].toLowerCase();
          const kpRef = Buffer.from(addedKpRefs[i], 'base64');
          if (!UUID_V4_RE.test(addedDevId) || kpRef.length !== 32) {
            await pgClient.query('ROLLBACK');
            return reply.code(400).send({ error: 'INVALID_ADDED_DEVICE_OR_KPREF' });
          }

          const devPinRes = await pgClient.query<{ pin: string }>(
            `SELECT pin FROM devices WHERE device_id = $1 AND status = 'active'`,
            [addedDevId],
          );
          if (devPinRes.rows.length === 0) {
            await pgClient.query('ROLLBACK');
            return reply.code(400).send({ error: 'ADDED_DEVICE_NOT_ACTIVE', deviceId: addedDevId });
          }

          await pgClient.query(
            `INSERT INTO group_members (group_id, device_id, pin, joined_epoch, last_acked_seq)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (group_id, device_id) DO UPDATE
               SET joined_epoch = EXCLUDED.joined_epoch, last_acked_seq = EXCLUDED.last_acked_seq`,
            [groupId, addedDevId, devPinRes.rows[0].pin, newEpoch, confirmedCommitSeq],
          );

          const welcomeBlobId = randomUUID();
          await pgClient.query(
            `INSERT INTO welcome_deliveries (
               welcome_blob_id, group_id, device_id, target_epoch, commit_seq, kp_ref, welcome_raw
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [welcomeBlobId, groupId, addedDevId, newEpoch, confirmedCommitSeq, kpRef, welcomeRaw!],
          );
          welcomeNotifications.push({ deviceId: addedDevId, welcomeBlobId });
        }

        await pgClient.query('COMMIT');
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }

      // Notificar Commit a miembros previos
      await fanoutGroupEvent(
        groupId,
        senderDeviceId,
        {
          type: 'mls_event',
          group_id: groupId.toString('base64'),
          group_seq: confirmedCommitSeq,
          msg_type: 'commit',
          epoch: newEpoch - 1,
        },
        confirmedCommitSeq,
      );

      // Notificar Welcome a nuevos dispositivos
      for (const w of welcomeNotifications) {
        const online = (await cmdRedis.exists(presenceKey(w.deviceId))) === 1;
        if (online) {
          await cmdRedis.spublish(
            deviceChannel(w.deviceId),
            JSON.stringify({
              type: 'mls_welcome',
              welcome_blob_id: w.welcomeBlobId,
              group_id: groupId.toString('base64'),
              target_epoch: newEpoch,
            }),
          );
        } else {
          await enqueueDelayedPush({ deviceId: w.deviceId, kind: 'sync' }, 1000);
        }
      }

      return reply.code(200).send({ confirmedCommitSeq, newEpoch });
    },
  );

  // 3. POST /v1/groups/:groupId/messages — Enviar ApplicationMessage o Proposal idempotente
  fastify.post<{ Params: { groupId: string }; Body: MessageBody }>(
    '/v1/groups/:groupId/messages',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const senderDeviceId = req.auth!.deviceId!;
      const groupId = decodeGroupId32(req.params.groupId, 'base64url');
      if (!groupId) return reply.code(400).send({ error: 'INVALID_GROUP_ID' });

      const b = req.body;
      const msgType = b?.msgType === 'proposal' ? 'proposal' : 'application';
      if (
        typeof b?.epoch !== 'number' ||
        !Number.isSafeInteger(b.epoch) ||
        b.epoch < 0 ||
        typeof b?.clientMsgId !== 'string' ||
        !UUID_V4_RE.test(b.clientMsgId) ||
        typeof b?.ciphertext !== 'string'
      ) {
        return reply.code(400).send({ error: 'INVALID_MESSAGE_PAYLOAD' });
      }

      const ct = Buffer.from(b.ciphertext, 'base64');
      if (ct.length === 0 || ct.length > 512 * 1024) {
        return reply.code(400).send({ error: 'INVALID_CIPHERTEXT_SIZE' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const pgClient = await pool.connect();
      let groupSeq = 0;

      try {
        await pgClient.query('BEGIN');

        const memCheck = await pgClient.query(
          `SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2`,
          [groupId, senderDeviceId],
        );
        if (memCheck.rows.length === 0) {
          await pgClient.query('ROLLBACK');
          return reply.code(403).send({ error: 'NOT_A_GROUP_MEMBER' });
        }

        const grpRes = await pgClient.query<{ current_epoch: string; last_seq: string }>(
          `SELECT current_epoch, last_seq FROM mls_groups WHERE group_id = $1 FOR UPDATE`,
          [groupId],
        );
        const currentEpoch = Number(grpRes.rows[0].current_epoch);
        const lastSeq = Number(grpRes.rows[0].last_seq);

        // Idempotencia ante reintento con mismo clientMsgId
        const existing = await pgClient.query<{ group_seq: string }>(
          `SELECT group_seq FROM mls_envelopes
           WHERE group_id = $1 AND sender_device_id = $2 AND client_msg_id = $3`,
          [groupId, senderDeviceId, b.clientMsgId.toLowerCase()],
        );
        if (existing.rows.length > 0) {
          await pgClient.query('COMMIT');
          return reply.code(200).send({ groupSeq: Number(existing.rows[0].group_seq) });
        }

        // Ventana tolerante: época actual o inmediatamente anterior (para mensajes en vuelo durante Commit)
        if (b.epoch > currentEpoch || b.epoch + 1 < currentEpoch) {
          await pgClient.query('ROLLBACK');
          return reply.code(409).send({ error: 'EPOCH_OUT_OF_WINDOW', currentEpoch });
        }

        groupSeq = lastSeq + 1;
        await pgClient.query(`UPDATE mls_groups SET last_seq = $2 WHERE group_id = $1`, [groupId, groupSeq]);
        await pgClient.query(
          `INSERT INTO mls_envelopes (
             group_id, group_seq, msg_type, epoch, sender_device_id, client_msg_id, ciphertext, server_timestamp
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [groupId, groupSeq, msgType, b.epoch, senderDeviceId, b.clientMsgId.toLowerCase(), ct, nowSec],
        );
        await pgClient.query(
          `UPDATE group_members SET last_acked_seq = GREATEST(last_acked_seq, $3)
           WHERE group_id = $1 AND device_id = $2`,
          [groupId, senderDeviceId, groupSeq],
        );

        await pgClient.query('COMMIT');
      } catch (err) {
        await pgClient.query('ROLLBACK');
        throw err;
      } finally {
        pgClient.release();
      }

      await fanoutGroupEvent(
        groupId,
        senderDeviceId,
        {
          type: 'mls_event',
          group_id: groupId.toString('base64'),
          group_seq: groupSeq,
          msg_type: msgType,
          epoch: b.epoch,
        },
        groupSeq,
      );

      if (msgType === 'application') {
        void notifyGroupMembersWebPush(groupId, senderDeviceId, req.auth!.pin, groupId.toString('base64'));
      }

      return reply.code(200).send({ groupSeq });
    },
  );
}
