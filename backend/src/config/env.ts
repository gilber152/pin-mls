import 'dotenv/config';
import { readFileSync } from 'node:fs';

function readSecretOrEnv(pathVar: string, inlineVar: string): string {
  const filePath = process.env[pathVar];
  if (filePath && filePath.trim().length > 0) {
    return readFileSync(filePath.trim(), 'utf8').trim();
  }
  return (process.env[inlineVar] ?? '').trim().replace(/^["']|["']$/g, '').replace(/\\n/g, '\n').trim();
}

function requiredEnv(name: string): string {
  const val = process.env[name]?.trim();
  if (!val) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return val;
}

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseOrigins(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const jwtPrivatePem = readSecretOrEnv('JWT_PRIVATE_KEY_PATH', 'JWT_PRIVATE_KEY_PEM');
const jwtPublicPem = readSecretOrEnv('JWT_PUBLIC_KEY_PATH', 'JWT_PUBLIC_KEY_PEM');
if (!jwtPrivatePem || !jwtPublicPem) {
  throw new Error('JWT_PRIVATE_KEY_PEM/PATH and JWT_PUBLIC_KEY_PEM/PATH are required');
}

const powSecretHex = requiredEnv('POW_HMAC_SECRET_HEX');
const cooldownPepperHex = requiredEnv('COOLDOWN_PEPPER_HEX');

export const env = {
  NODE_ENV: process.env.NODE_ENV ?? 'development',
  HOST: process.env.HOST ?? '0.0.0.0',
  PORT: intEnv('PORT', 3000),
  LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
  DATABASE_URL: requiredEnv('DATABASE_URL'),
  REDIS_URL: requiredEnv('REDIS_URL'),
  ALLOWED_WEB_ORIGINS: parseOrigins(
    process.env.ALLOWED_WEB_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173',
  ),
  JWT_KEY_ID: process.env.JWT_KEY_ID ?? 'dev-ed25519-1',
  JWT_PRIVATE_KEY_PEM: jwtPrivatePem,
  JWT_PUBLIC_KEY_PEM: jwtPublicPem,
  POW_HMAC_SECRET: Buffer.from(powSecretHex, 'hex'),
  COOLDOWN_PEPPER: Buffer.from(cooldownPepperHex, 'hex'),
  POW_DIFFICULTY_REGISTER: intEnv('POW_DIFFICULTY_REGISTER', 10),
  POW_DIFFICULTY_INVITE: intEnv('POW_DIFFICULTY_INVITE', 10),
  POW_DIFFICULTY_SAFE: intEnv('POW_DIFFICULTY_SAFE', 10),
  PUSH_MODE: (process.env.PUSH_MODE ?? 'mock') as 'mock' | 'live',
};
