import { env } from './config/env.js';
import { pool } from './infra/db.js';
import { cmdRedis } from './infra/redis.js';
import { pushQueue } from './infra/push/queue.js';
import { buildApp } from './app.js';

async function main(): Promise<void> {
  const app = await buildApp();

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'Shutting down API server...');
    await app.close();
    await pushQueue.close().catch(() => undefined);
    await cmdRedis.quit().catch(() => undefined);
    await pool.end().catch(() => undefined);
    process.exit(0);
  };

  process.on('SIGINT', () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });

  await app.listen({ host: env.HOST, port: env.PORT });
  app.log.info(`PIN-MLS API listening on http://${env.HOST}:${env.PORT}`);
}

main().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
