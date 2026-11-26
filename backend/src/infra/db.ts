import { Pool } from 'pg';
import { env } from '../config/env.js';

function resolvePgSsl(url: string): { rejectUnauthorized: false } | undefined {
  const explicit = process.env.DATABASE_SSL?.trim().toLowerCase();
  if (explicit === 'true' || explicit === '1') return { rejectUnauthorized: false };
  if (explicit === 'false' || explicit === '0') return undefined;
  if (
    url.includes('sslmode=require') ||
    url.includes('.supabase.co') ||
    url.includes('.supabase.com') ||
    url.includes('.render.com') ||
    url.includes('.neon.tech')
  ) {
    return { rejectUnauthorized: false };
  }
  return undefined;
}

const poolMax = Number.parseInt(process.env.PG_POOL_MAX ?? '10', 10);

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: Number.isFinite(poolMax) && poolMax > 0 ? poolMax : 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: resolvePgSsl(env.DATABASE_URL),
});

export async function checkDbReady(): Promise<boolean> {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}
