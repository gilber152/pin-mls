import { Redis } from 'ioredis';
import { env } from '../config/env.js';

export const cmdRedis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
});

export function parseBullConnection(redisUrl: string): {
  host: string;
  port: number;
  username?: string;
  password?: string;
  db?: number;
  family?: number;
  tls?: Record<string, never>;
  maxRetriesPerRequest: null;
} {
  const u = new URL(redisUrl);
  const dbNum = u.pathname && u.pathname.length > 1 ? Number.parseInt(u.pathname.slice(1), 10) : 0;
  const familyParam = u.searchParams.get('family');
  const familyNum = familyParam !== null ? Number.parseInt(familyParam, 10) : undefined;
  return {
    host: u.hostname,
    port: u.port ? Number.parseInt(u.port, 10) : 6379,
    ...(u.username ? { username: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    db: Number.isFinite(dbNum) ? dbNum : 0,
    ...(familyNum !== undefined && Number.isFinite(familyNum) ? { family: familyNum } : {}),
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
    maxRetriesPerRequest: null,
  };
}

export async function checkRedisReady(): Promise<boolean> {
  try {
    return (await cmdRedis.ping()) === 'PONG';
  } catch {
    return false;
  }
}
