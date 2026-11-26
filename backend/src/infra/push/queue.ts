import { Queue } from 'bullmq';
import { env } from '../../config/env.js';
import { parseBullConnection } from '../redis.js';

export interface DelayedPushJob {
  deviceId: string;
  kind: 'sync' | 'invite';
  groupIdB64?: string;
  minGroupSeq?: number;
}

export const PUSH_QUEUE_NAME = 'pin-delayed-push';

export const pushQueue = new Queue<DelayedPushJob>(PUSH_QUEUE_NAME, {
  connection: parseBullConnection(env.REDIS_URL),
  defaultJobOptions: {
    removeOnComplete: true,
    removeOnFail: 100,
    attempts: 2,
    backoff: { type: 'fixed', delay: 3000 },
  },
});

export async function enqueueDelayedPush(job: DelayedPushJob, delayMs = 6000): Promise<void> {
  const jobId = `push_${job.deviceId}_${job.kind}`;
  try {
    await pushQueue.add('notify', job, { delay: delayMs, jobId });
  } catch {
    // Job deduplicado ya en cola para este dispositivo
  }
}
