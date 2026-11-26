import type { preHandlerHookHandler } from 'fastify';

export type AuthContext =
  | { authType: 'jwt'; pin: string; deviceId: string }
  | { authType: 'ed25519_device'; pin: string; deviceId: string }
  | { authType: 'ed25519_root'; pin: string; deviceId?: undefined };

export interface VerifyEd25519Options {
  keyType: 'device' | 'root';
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
    rawBody?: Buffer;
  }

  interface FastifyInstance {
    verifyJwt: preHandlerHookHandler;
    verifyEd25519: (opts: VerifyEd25519Options) => preHandlerHookHandler;
  }
}
