import { randomBytes, timingSafeEqual } from 'node:crypto';
import argon2 from 'argon2';
import { env } from '../config/env.js';
import { hmacSha256 } from './crypto.js';
import { cmdRedis } from './redis.js';

export type PowAction = 1 | 2 | 3;

const POW_CHALLENGE_VERSION = 1;
const POW_CHALLENGE_LEN = 35; // 1B ver + 1B action + 1B diff + 8B issued + 8B expires + 16B id
const POW_TTL_SEC = 180;
const POW_MAC_DOMAIN = Buffer.from('pow-challenge-v1', 'ascii');

export interface IssuedPowChallenge {
  challengeId: string;
  challengePayload: string;
  challengeMac: string;
  difficultyBits: number;
  expiresAtSec: number;
}

export function getDifficultyForAction(action: PowAction): number {
  switch (action) {
    case 1:
      return env.POW_DIFFICULTY_REGISTER;
    case 2:
      return env.POW_DIFFICULTY_INVITE;
    case 3:
      return env.POW_DIFFICULTY_SAFE;
  }
}

export function issuePowChallenge(action: PowAction): IssuedPowChallenge {
  const difficultyBits = getDifficultyForAction(action);
  const nowSec = Math.floor(Date.now() / 1000);
  const expiresAtSec = nowSec + POW_TTL_SEC;
  const challengeIdBuf = randomBytes(16);

  const payload = Buffer.alloc(POW_CHALLENGE_LEN);
  payload[0] = POW_CHALLENGE_VERSION;
  payload[1] = action;
  payload[2] = difficultyBits;
  payload.writeBigUInt64BE(BigInt(nowSec), 3);
  payload.writeBigUInt64BE(BigInt(expiresAtSec), 11);
  challengeIdBuf.copy(payload, 19);

  const mac = hmacSha256(env.POW_HMAC_SECRET, Buffer.concat([POW_MAC_DOMAIN, payload]));

  return {
    challengeId: challengeIdBuf.toString('base64url'),
    challengePayload: payload.toString('base64url'),
    challengeMac: mac.toString('base64url'),
    difficultyBits,
    expiresAtSec,
  };
}

export function countLeadingZeroBits(buf: Uint8Array): number {
  let zeros = 0;
  for (const byte of buf) {
    if (byte === 0) {
      zeros += 8;
    } else {
      zeros += Math.clz32(byte) - 24;
      break;
    }
  }
  return zeros;
}

export async function verifyAndBurnPowSolution(params: {
  expectedAction: PowAction;
  subjectBytes: Uint8Array;
  powPayloadB64Url: string;
  powMacB64Url: string;
  powNonceB64Url: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const payload = Buffer.from(params.powPayloadB64Url, 'base64url');
  const suppliedMac = Buffer.from(params.powMacB64Url, 'base64url');
  const nonce8 = Buffer.from(params.powNonceB64Url, 'base64url');

  if (payload.length !== POW_CHALLENGE_LEN || suppliedMac.length !== 32 || nonce8.length !== 8) {
    return { ok: false, error: 'INVALID_POW_FORMAT' };
  }

  const expectedMac = hmacSha256(env.POW_HMAC_SECRET, Buffer.concat([POW_MAC_DOMAIN, payload]));
  if (!timingSafeEqual(expectedMac, suppliedMac)) {
    return { ok: false, error: 'INVALID_POW_MAC' };
  }

  const version = payload[0];
  const action = payload[1];
  const difficultyBits = payload[2];
  const expiresAtSec = Number(payload.readBigUInt64BE(11));
  const challengeId16 = payload.subarray(19, 35);

  if (version !== POW_CHALLENGE_VERSION || action !== params.expectedAction) {
    return { ok: false, error: 'POW_ACTION_MISMATCH' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (expiresAtSec <= nowSec) {
    return { ok: false, error: 'POW_CHALLENGE_EXPIRED' };
  }

  // Argon2id v19: m=16 MiB (16384 KiB), t=1, p=1, len=32, salt=challengeId16
  const input = Buffer.concat([payload, Buffer.from(params.subjectBytes), nonce8]);
  const hash = await argon2.hash(input, {
    type: argon2.argon2id,
    memoryCost: 16384,
    timeCost: 2,
    parallelism: 1,
    hashLength: 32,
    salt: challengeId16,
    raw: true,
  });

  if (countLeadingZeroBits(hash) < difficultyBits) {
    return { ok: false, error: 'POW_INSUFFICIENT_WORK' };
  }

  // Quemar challengeId SOLO tras verificar que el trabajo es válido
  const burnTtl = Math.max(30, expiresAtSec - nowSec + 30);
  const burnKey = `pow:used:${challengeId16.toString('hex')}`;
  const claimed = await cmdRedis.set(burnKey, '1', 'EX', burnTtl, 'NX');
  if (claimed !== 'OK') {
    return { ok: false, error: 'POW_CHALLENGE_REPLAYED' };
  }

  return { ok: true };
}
