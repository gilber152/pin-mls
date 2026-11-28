import type { FastifyInstance } from 'fastify';
import { env } from '../../config/env.js';
import { pool } from '../../infra/db.js';
import {
  createSignedMediaDownload,
  createSignedMediaUpload,
  ensureMediaObjectsTable,
  isMediaStorageEnabled,
} from '../../infra/media/supabaseMediaService.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function decodeGroupId32Flex(raw: string): Buffer | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  for (const enc of ['base64', 'base64url'] as const) {
    try {
      const buf = Buffer.from(trimmed, enc);
      if (buf.length === 32) return buf;
    } catch {
      // Probar siguiente codificación
    }
  }
  return null;
}

interface UploadUrlBody {
  groupIdB64?: unknown;
  cipherBytes?: unknown;
}

export async function registerMediaRoutes(fastify: FastifyInstance): Promise<void> {
  await ensureMediaObjectsTable().catch((err) => {
    fastify.log.warn({ err }, 'No se pudo inicializar media_objects al arrancar');
  });

  fastify.get(
    '/v1/media/status',
    { preHandler: [fastify.verifyJwt] },
    async (_req, reply) => {
      return reply.code(200).send({
        enabled: isMediaStorageEnabled(),
        maxBytes: env.MEDIA_MAX_BYTES,
        ttlDays: env.MEDIA_TTL_DAYS,
      });
    },
  );

  fastify.post<{ Body: UploadUrlBody }>(
    '/v1/media/upload-url',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      if (!isMediaStorageEnabled()) {
        return reply.code(503).send({ error: 'MEDIA_STORAGE_NOT_CONFIGURED' });
      }

      const deviceId = req.auth!.deviceId!;
      const rawGid = typeof req.body?.groupIdB64 === 'string' ? req.body.groupIdB64 : '';
      const cipherBytes = typeof req.body?.cipherBytes === 'number' ? req.body.cipherBytes : 0;

      const groupId = decodeGroupId32Flex(rawGid);
      if (!groupId) {
        return reply.code(400).send({ error: 'INVALID_GROUP_ID' });
      }

      if (!Number.isSafeInteger(cipherBytes) || cipherBytes <= 0 || cipherBytes > env.MEDIA_MAX_BYTES) {
        return reply.code(400).send({
          error: 'INVALID_MEDIA_SIZE',
          maxBytes: env.MEDIA_MAX_BYTES,
        });
      }

      const memCheck = await pool.query(
        `SELECT 1 FROM group_members WHERE group_id = $1 AND device_id::text = $2`,
        [groupId, deviceId],
      );
      if (memCheck.rows.length === 0) {
        return reply.code(403).send({ error: 'NOT_A_GROUP_MEMBER' });
      }

      try {
        const signed = await createSignedMediaUpload({ groupId, deviceId, cipherBytes });
        return reply.code(200).send(signed);
      } catch (err) {
        req.log.error({ err }, 'Error generando URL firmada de subida en Supabase');
        return reply.code(502).send({ error: 'MEDIA_UPLOAD_SIGN_ERROR' });
      }
    },
  );

  fastify.get<{ Params: { mediaId: string } }>(
    '/v1/media/:mediaId/download-url',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      if (!isMediaStorageEnabled()) {
        return reply.code(503).send({ error: 'MEDIA_STORAGE_NOT_CONFIGURED' });
      }

      const mediaId = (req.params.mediaId ?? '').trim().toLowerCase();
      if (!UUID_RE.test(mediaId)) {
        return reply.code(400).send({ error: 'INVALID_MEDIA_ID' });
      }

      try {
        const res = await createSignedMediaDownload({
          mediaId,
          deviceId: req.auth!.deviceId!,
        });
        if (res.status !== 'ok') {
          if (res.status === 'not_found') return reply.code(404).send({ error: 'MEDIA_NOT_FOUND' });
          if (res.status === 'forbidden') return reply.code(403).send({ error: 'NOT_A_GROUP_MEMBER' });
          return reply.code(410).send({ error: 'MEDIA_EXPIRED' });
        }

        return reply.code(200).send({
          signedUrl: res.signedUrl,
          cipherBytes: res.cipherBytes,
          expiresInSec: res.expiresInSec,
        });
      } catch (err) {
        req.log.error({ err }, 'Error generando URL firmada de descarga en Supabase');
        return reply.code(502).send({ error: 'MEDIA_DOWNLOAD_SIGN_ERROR' });
      }
    },
  );
}
