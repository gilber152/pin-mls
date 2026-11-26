import 'dotenv/config';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';

async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required for migrations');
  }

  const explicitSsl = process.env.DATABASE_SSL?.trim().toLowerCase();
  const useSsl =
    explicitSsl === 'true' ||
    explicitSsl === '1' ||
    (explicitSsl !== 'false' &&
      explicitSsl !== '0' &&
      (databaseUrl.includes('sslmode=require') ||
        databaseUrl.includes('.supabase.co') ||
        databaseUrl.includes('.supabase.com') ||
        databaseUrl.includes('.render.com') ||
        databaseUrl.includes('.neon.tech')));

  const pool = new Pool({
    connectionString: databaseUrl,
    ...(useSsl ? { ssl: { rejectUnauthorized: false } } : {}),
  });
  const currentDir = fileURLToPath(new URL('.', import.meta.url));
  const migrationsDir = resolve(currentDir, '../../sql/migrations');

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        filename TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const exists = await pool.query(
        'SELECT 1 FROM schema_migrations WHERE filename = $1',
        [file],
      );
      if (exists.rowCount && exists.rowCount > 0) {
        console.log(`[migrator] already applied: ${file}`);
        continue;
      }

      const sql = readFileSync(join(migrationsDir, file), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[migrator] applied: ${file}`);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    }
    console.log('[migrator] all migrations up to date.');
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[migrator] fatal error:', err);
  process.exit(1);
});
