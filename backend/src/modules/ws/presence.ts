import type { Redis } from 'ioredis';

export const PRESENCE_TTL_SEC = 65;

export type DeviceKickReason = 'DEVICE_REVOKED' | 'SESSION_REPLACED';

export interface ControlKickFrame {
  type: 'control_kick';
  reason: DeviceKickReason;
  targetConnId?: string;
}

export function presenceKey(deviceId: string): string {
  return `ws:presence:${deviceId.toLowerCase()}`;
}

export function deviceChannel(deviceId: string): string {
  return `ws:dev:${deviceId.toLowerCase()}`;
}

function presenceOwnerValue(nodeId: string, connId: string): string {
  return `${nodeId}:${connId}`;
}

const REFRESH_IF_OWNER_LUA = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("EXPIRE", KEYS[1], tonumber(ARGV[2]))
end
return 0
`;

const RELEASE_IF_OWNER_LUA = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`;

export async function claimPresence(
  redis: Redis,
  deviceId: string,
  nodeId: string,
  connId: string,
): Promise<{ replacedPrevious: boolean }> {
  const key = presenceKey(deviceId);
  const nextOwner = presenceOwnerValue(nodeId, connId);
  const prevOwner = await redis.set(key, nextOwner, 'EX', PRESENCE_TTL_SEC, 'GET');

  if (prevOwner && prevOwner !== nextOwner) {
    const sepIdx = prevOwner.lastIndexOf(':');
    const prevConnId = sepIdx !== -1 ? prevOwner.slice(sepIdx + 1) : undefined;
    await publishDeviceKick(redis, deviceId, 'SESSION_REPLACED', prevConnId);
    return { replacedPrevious: true };
  }

  return { replacedPrevious: false };
}

export async function refreshPresence(
  redis: Redis,
  deviceId: string,
  nodeId: string,
  connId: string,
): Promise<boolean> {
  const res = await redis.eval(
    REFRESH_IF_OWNER_LUA,
    1,
    presenceKey(deviceId),
    presenceOwnerValue(nodeId, connId),
    String(PRESENCE_TTL_SEC),
  );
  return Number(res) === 1;
}

export async function releasePresence(
  redis: Redis,
  deviceId: string,
  nodeId: string,
  connId: string,
): Promise<boolean> {
  const res = await redis.eval(
    RELEASE_IF_OWNER_LUA,
    1,
    presenceKey(deviceId),
    presenceOwnerValue(nodeId, connId),
  );
  return Number(res) === 1;
}

export async function publishDeviceKick(
  redis: Redis,
  deviceId: string,
  reason: DeviceKickReason,
  targetConnId?: string,
): Promise<void> {
  const frame: ControlKickFrame = {
    type: 'control_kick',
    reason,
    ...(targetConnId ? { targetConnId } : {}),
  };

  if (reason === 'DEVICE_REVOKED') {
    await redis.del(presenceKey(deviceId));
  }

  await redis.spublish(deviceChannel(deviceId), JSON.stringify(frame));
}
