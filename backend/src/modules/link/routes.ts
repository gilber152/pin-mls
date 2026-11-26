import type { FastifyInstance, FastifyRequest } from 'fastify';
import { cmdRedis } from '../../infra/redis.js';
import { SESSION_ID_HEX_RE, verifyLinkReadSecret } from '../../infra/linkSession.js';

const LINK_SESSION_TTL_SEC = 180;
const LINK_MIN_BUNDLE_BYTES = 48;
const LINK_MAX_BUNDLE_BYTES = 512 * 1024;
const PUT_RL_MAX = 10;
const PUT_RL_WINDOW_SEC = 600;
const GET_RL_MAX = 120;
const GET_RL_WINDOW_SEC = 180;

function getSingleHeader(req: FastifyRequest, name: string): string | null {
  const val = req.headers[name];
  if (typeof val !== 'string') return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function extractRawBuffer(req: FastifyRequest): Buffer {
  if (Buffer.isBuffer(req.rawBody)) return req.rawBody;
  if (Buffer.isBuffer(req.body)) return req.body;
  return Buffer.alloc(0);
}

export async function registerLinkRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.put<{ Params: { sessionId: string } }>(
    '/v1/link-sessions/:sessionId',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const sessionId = req.params.sessionId.toLowerCase();
      if (!SESSION_ID_HEX_RE.test(sessionId)) {
        return reply.code(400).send({ error: 'INVALID_LINK_SESSION_ID' });
      }

      const contentType = getSingleHeader(req, 'content-type') ?? '';
      if (!contentType.toLowerCase().startsWith('application/octet-stream')) {
        return reply.code(415).send({ error: 'UNSUPPORTED_MEDIA_TYPE' });
      }

      const deviceId = req.auth!.deviceId!;
      const rlKey = `rl:link_put:${deviceId}`;
      const hits = await cmdRedis.incr(rlKey);
      if (hits === 1) await cmdRedis.expire(rlKey, PUT_RL_WINDOW_SEC);
      if (hits > PUT_RL_MAX) {
        return reply
          .code(429)
          .header('Retry-After', String(PUT_RL_WINDOW_SEC))
          .send({ error: 'LINK_PUT_RATE_LIMITED' });
      }

      const bundle = extractRawBuffer(req);
      if (bundle.length < LINK_MIN_BUNDLE_BYTES || bundle.length > LINK_MAX_BUNDLE_BYTES) {
        return reply.code(400).send({ error: 'INVALID_LINK_BUNDLE_SIZE' });
      }

      const consumedKey = `link:consumed:${sessionId}`;
      if ((await cmdRedis.exists(consumedKey)) === 1) {
        return reply.code(409).send({ error: 'LINK_SESSION_ALREADY_CONSUMED' });
      }

      const stored = await cmdRedis.set(
        `link:session:${sessionId}`,
        bundle.toString('base64'),
        'EX',
        LINK_SESSION_TTL_SEC,
        'NX',
      );
      if (stored !== 'OK') {
        return reply.code(409).send({ error: 'LINK_SESSION_ALREADY_EXISTS' });
      }

      return reply.code(201).header('Cache-Control', 'no-store').send({
        ok: true,
        sessionId,
        expiresInSec: LINK_SESSION_TTL_SEC,
      });
    },
  );

  fastify.get<{ Params: { sessionId: string } }>(
    '/v1/link-sessions/:sessionId',
    async (req, reply) => {
      const sessionId = req.params.sessionId.toLowerCase();
      if (!SESSION_ID_HEX_RE.test(sessionId)) {
        return reply.code(400).send({ error: 'INVALID_LINK_SESSION_ID' });
      }

      const secretB64Url = getSingleHeader(req, 'x-link-read-secret');
      if (!secretB64Url || !verifyLinkReadSecret(sessionId, secretB64Url)) {
        return reply.code(401).send({ error: 'LINK_SECRET_REJECTED' });
      }

      const rlKey = `rl:link_get:${sessionId}`;
      const hits = await cmdRedis.incr(rlKey);
      if (hits === 1) await cmdRedis.expire(rlKey, GET_RL_WINDOW_SEC);
      if (hits > GET_RL_MAX) {
        return reply.code(429).header('Retry-After', '5').send({ error: 'LINK_POLL_RATE_LIMITED' });
      }

      const consumedKey = `link:consumed:${sessionId}`;
      if ((await cmdRedis.exists(consumedKey)) === 1) {
        return reply.code(410).send({ error: 'LINK_SESSION_EXPIRED' });
      }

      const rawB64 = await cmdRedis.getdel(`link:session:${sessionId}`);
      if (!rawB64) {
        return reply.code(204).header('Cache-Control', 'no-store').send();
      }

      await cmdRedis.set(consumedKey, '1', 'EX', LINK_SESSION_TTL_SEC);
      const bundle = Buffer.from(rawB64, 'base64');

      return reply
        .code(200)
        .header('Content-Type', 'application/octet-stream')
        .header('Cache-Control', 'no-store')
        .send(bundle);
    },
  );
}
