import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { env } from './config/env.js';
import { checkDbReady } from './infra/db.js';
import { checkRedisReady } from './infra/redis.js';
import rawBodyPlugin from './plugins/rawBody.js';
import jwtAuthPlugin from './plugins/jwtAuth.js';
import ed25519AuthPlugin from './plugins/ed25519Auth.js';
import { registerPowRoutes } from './modules/pow/routes.js';
import { registerAuthRoutes } from './modules/auth/routes.js';
import { registerIdentityRoutes } from './modules/identities/routes.js';
import { registerRevokeRoutes } from './modules/identities/revoke.routes.js';
import { registerKeyPackageRoutes } from './modules/keypackages/routes.js';
import { registerSelfClaimKeyPackageRoutes } from './modules/keypackages/selfClaim.routes.js';
import { registerInviteRoutes } from './modules/invites/routes.js';
import { registerMlsRoutes } from './modules/mls/routes.js';
import { registerSyncRoutes } from './modules/sync/routes.js';
import { registerLinkRoutes } from './modules/link/routes.js';
import { registerSafeRoutes } from './modules/safe/routes.js';
import { attachWsGateway } from './modules/ws/gateway.js';

export async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    bodyLimit: 7 * 1024 * 1024, // 7 MiB para Commits + Welcomes Base64
    trustProxy: ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    logger: {
      level: env.LOG_LEVEL,
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers["x-signature"]',
          'req.headers["x-safe-signature"]',
          'req.headers["x-link-read-secret"]',
        ],
        censor: '[REDACTED]',
      },
    },
  });

  await app.register(cors, {
    origin: env.ALLOWED_WEB_ORIGINS,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Pin',
      'X-Device-Id',
      'X-Timestamp',
      'X-Nonce',
      'X-Signature',
      'X-Safe-PubKey',
      'X-Safe-Revision',
      'X-Safe-Signature',
      'X-Pow-Payload',
      'X-Pow-Mac',
      'X-Pow-Nonce',
      'X-Link-Read-Secret',
    ],
    exposedHeaders: ['X-Safe-Revision'],
  });

  await app.register(rawBodyPlugin);
  await app.register(jwtAuthPlugin);
  await app.register(ed25519AuthPlugin);

  app.get('/healthz', async () => ({ ok: true }));

  app.get('/readyz', async (_req, reply) => {
    const [dbOk, redisOk] = await Promise.all([checkDbReady(), checkRedisReady()]);
    if (!dbOk || !redisOk) {
      return reply.code(503).send({ ok: false, db: dbOk, redis: redisOk });
    }
    return reply.code(200).send({ ok: true, db: true, redis: true });
  });

  await registerPowRoutes(app);
  await registerAuthRoutes(app);
  await registerIdentityRoutes(app);
  await registerRevokeRoutes(app);
  await registerKeyPackageRoutes(app);
  await registerSelfClaimKeyPackageRoutes(app);
  await registerInviteRoutes(app);
  await registerMlsRoutes(app);
  await registerSyncRoutes(app);
  await registerLinkRoutes(app);
  await registerSafeRoutes(app);

  await attachWsGateway(app);

  return app;
}
