import fp from 'fastify-plugin';
import { importSPKI, jwtVerify, type KeyLike } from 'jose';
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { env } from '../config/env.js';
import { cmdRedis } from '../infra/redis.js';
import './authTypes.js';

const JWT_ISSUER = 'pin-mls-ds';
const JWT_AUDIENCE = 'pin-mls-client';
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

export interface VerifiedJwtClaims {
  deviceId: string;
  pin: string;
  exp: number;
}

export async function verifyAccessJwt(
  token: string,
  publicKey: KeyLike,
): Promise<VerifiedJwtClaims | null> {
  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      clockTolerance: 5,
    });

    const deviceId = typeof payload.sub === 'string' ? payload.sub : '';
    const pin = typeof payload.pin === 'string' ? payload.pin : '';
    const exp = typeof payload.exp === 'number' ? payload.exp : 0;

    if (!UUID_V4_RE.test(deviceId) || !PIN_CROCKFORD_RE.test(pin) || exp <= 0) {
      return null;
    }

    const isRevoked = await cmdRedis.exists(`revoked:dev:${deviceId}`);
    if (isRevoked === 1) {
      return null;
    }

    return { deviceId, pin, exp };
  } catch {
    return null;
  }
}

function extractBearerToken(req: FastifyRequest): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;

  const spaceIdx = header.indexOf(' ');
  if (spaceIdx === -1) return null;

  const scheme = header.slice(0, spaceIdx);
  const token = header.slice(spaceIdx + 1).trim();
  if (scheme.toLowerCase() !== 'bearer' || token.length < 20) {
    return null;
  }
  return token;
}

const jwtAuthPlugin: FastifyPluginAsync = async (fastify) => {
  const jwtPublicKey: KeyLike = await importSPKI(env.JWT_PUBLIC_KEY_PEM, 'EdDSA');

  if (!fastify.hasRequestDecorator('auth')) {
    fastify.decorateRequest('auth', undefined);
  }

  async function verifyJwtHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const token = extractBearerToken(req);
    if (!token) {
      return reply.code(401).send({ error: 'MISSING_OR_INVALID_BEARER_TOKEN' });
    }

    const claims = await verifyAccessJwt(token, jwtPublicKey);
    if (!claims) {
      return reply.code(401).send({ error: 'INVALID_OR_REVOKED_JWT' });
    }

    req.auth = {
      authType: 'jwt',
      pin: claims.pin,
      deviceId: claims.deviceId,
    };
  }

  fastify.decorate('verifyJwt', verifyJwtHandler);
};

export default fp(jwtAuthPlugin, {
  name: 'pin-jwt-auth',
  fastify: '5.x',
});
