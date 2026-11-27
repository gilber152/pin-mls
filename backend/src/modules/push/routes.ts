import type { FastifyInstance } from 'fastify';
import { env } from '../../config/env.js';
import {
  ensureWebPushTable,
  isWebPushEnabled,
  removeWebPushSubscription,
  saveWebPushSubscription,
} from '../../infra/push/webPushService.js';

interface SubscribeBody {
  endpoint?: unknown;
  keys?: {
    p256dh?: unknown;
    auth?: unknown;
  };
}

interface UnsubscribeBody {
  endpoint?: unknown;
}

export async function registerPushRoutes(fastify: FastifyInstance): Promise<void> {
  await ensureWebPushTable().catch((err) => {
    fastify.log.warn({ err }, 'No se pudo inicializar web_push_subscriptions al arrancar');
  });

  fastify.get('/v1/push/vapid-public-key', async (_req, reply) => {
    const enabled = isWebPushEnabled();
    return reply.code(200).send({
      enabled,
      publicKey: enabled ? env.VAPID_PUBLIC_KEY : null,
    });
  });

  fastify.post<{ Body: SubscribeBody }>(
    '/v1/push/subscribe',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const pin = req.auth!.pin;
      const b = req.body;

      const endpoint = typeof b?.endpoint === 'string' ? b.endpoint.trim() : '';
      const p256dh = typeof b?.keys?.p256dh === 'string' ? b.keys.p256dh.trim() : '';
      const auth = typeof b?.keys?.auth === 'string' ? b.keys.auth.trim() : '';

      if (!endpoint.startsWith('https://') || !p256dh || !auth) {
        return reply.code(400).send({ error: 'INVALID_PUSH_SUBSCRIPTION' });
      }

      const uaHeader = req.headers['user-agent'];
      await saveWebPushSubscription({
        deviceId,
        pin,
        endpoint,
        p256dh,
        auth,
        ...(typeof uaHeader === 'string' ? { userAgent: uaHeader.slice(0, 240) } : {}),
      });

      return reply.code(200).send({ ok: true, pushEnabled: isWebPushEnabled() });
    },
  );

  fastify.delete<{ Body: UnsubscribeBody }>(
    '/v1/push/subscribe',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const endpoint =
        typeof req.body?.endpoint === 'string' && req.body.endpoint.trim()
          ? req.body.endpoint.trim()
          : undefined;

      await removeWebPushSubscription({
        deviceId,
        ...(endpoint ? { endpoint } : {}),
      });

      return reply.code(200).send({ ok: true });
    },
  );
}
