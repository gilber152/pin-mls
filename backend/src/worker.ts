import { Worker } from 'bullmq';
import { env } from './config/env.js';
import { pool } from './infra/db.js';
import { parseBullConnection } from './infra/redis.js';
import { PUSH_QUEUE_NAME, type DelayedPushJob } from './infra/push/queue.js';

const GC_INTERVAL_MS = 10 * 60 * 1000; // 10 minutos

async function shouldDeliverPush(job: DelayedPushJob): Promise<boolean> {
  if (job.kind === 'invite') {
    const res = await pool.query(
      `SELECT 1 FROM devices d
       JOIN contact_requests cr ON cr.target_pin = d.pin
       WHERE d.device_id = $1 AND d.status = 'active' AND cr.expires_at > NOW()
       LIMIT 1`,
      [job.deviceId],
    );
    return res.rows.length > 0;
  }

  if (job.groupIdB64 && typeof job.minGroupSeq === 'number') {
    const gid = Buffer.from(job.groupIdB64, 'base64');
    const res = await pool.query<{ last_acked_seq: string }>(
      `SELECT last_acked_seq FROM group_members WHERE group_id = $1 AND device_id = $2`,
      [gid, job.deviceId],
    );
    if (res.rows.length === 0) return false;
    // Si el cliente ya confirmó vía WS ack antes de los 6s, suprimir Push
    if (Number(res.rows[0].last_acked_seq) >= job.minGroupSeq) return false;
  }
  return true;
}

async function runZeroArchiveGc(): Promise<void> {
  try {
    await pool.query(`DELETE FROM key_packages WHERE expires_at <= NOW()`);
    await pool.query(`DELETE FROM contact_requests WHERE expires_at <= NOW()`);
    await pool.query(`DELETE FROM reject_cooldowns WHERE expires_at <= NOW()`);
    await pool.query(`DELETE FROM pending_keypackage_grants WHERE expires_at <= NOW()`);
    await pool.query(`DELETE FROM welcome_deliveries WHERE acked_at IS NOT NULL AND acked_at < NOW() - INTERVAL '1 hour'`);
    // Zero-Archive: eliminar sobres ya confirmados por TODOS los miembros actuales del grupo
    await pool.query(`
      DELETE FROM mls_envelopes env
      USING (
        SELECT group_id, MIN(last_acked_seq) AS min_acked
        FROM group_members
        GROUP BY group_id
      ) agg
      WHERE env.group_id = agg.group_id
        AND env.group_seq <= agg.min_acked
    `);
  } catch (err) {
    console.error('[worker-gc] error:', err);
  }
}

async function main(): Promise<void> {
  const worker = new Worker<DelayedPushJob>(
    PUSH_QUEUE_NAME,
    async (job) => {
      const needed = await shouldDeliverPush(job.data);
      if (!needed) return;

      const devRes = await pool.query<{ push_platform: string | null; push_token: string | null }>(
        `SELECT push_platform, push_token FROM devices WHERE device_id = $1 AND status = 'active'`,
        [job.data.deviceId],
      );
      const dev = devRes.rows[0];
      if (!dev || !dev.push_platform || !dev.push_token) return;

      if (env.PUSH_MODE === 'mock') {
        console.log(
          `[push-mock] -> device=${job.data.deviceId} platform=${dev.push_platform} kind=${job.data.kind}`,
        );
        return;
      }

      console.log(
        `[push-live] dispatcher hook ready for device=${job.data.deviceId} platform=${dev.push_platform}`,
      );
    },
    { connection: parseBullConnection(env.REDIS_URL), concurrency: 8 },
  );

  worker.on('failed', (job, err) => {
    console.error(`[worker-push] failed job=${job?.id}:`, err.message);
  });

  const gcTimer = setInterval(() => { void runZeroArchiveGc(); }, GC_INTERVAL_MS);
  gcTimer.unref();

  const shutdown = async () => {
    clearInterval(gcTimer);
    await worker.close();
    await pool.end();
    process.exit(0);
  };

  process.on('SIGINT', () => { void shutdown(); });
  process.on('SIGTERM', () => { void shutdown(); });

  console.log(`[worker] started (PUSH_MODE=${env.PUSH_MODE})`);
}

main().catch((err) => {
  console.error('Fatal worker startup error:', err);
  process.exit(1);
});
