import type { FastifyInstance, FastifyRequest } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { sha256Hex, verifyEd25519 } from '../../infra/crypto.js';
import { verifyAndBurnPowSolution } from '../../infra/pow.js';

const BACKUP_ID_HEX_RE = /^[0-9a-f]{64}$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_CLOCK_SKEW_SEC = 60;
const SAFE_NONCE_TTL_SEC = 180;
const SAFE_NONCE_HEADER_LEN = 24;
const SAFE_BUCKET_BYTES = 16_384;
const SAFE_MAX_BLOB_BYTES = SAFE_NONCE_HEADER_LEN + 512 * 1024; // 512 KiB max

function getSingleHeader(req: FastifyRequest, name: string): string | null {
  const val = req.headers[name];
  if (typeof val !== 'string') return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

interface VerifiedSafeAuth {
  backupIdBuf: Buffer;
  backupIdHex: string;
  pkSafeAuth32: Buffer;
  revision: bigint;
}

async function verifySafeHttpHeaders(
  req: FastifyRequest,
  backupIdHex: string,
  requirePositiveRevision: boolean,
): Promise<{ ok: true; auth: VerifiedSafeAuth } | { ok: false; status: number; error: string }> {
  if (!BACKUP_ID_HEX_RE.test(backupIdHex)) {
    return { ok: false, status: 400, error: 'INVALID_BACKUP_ID' };
  }

  const pkB64Url = getSingleHeader(req, 'x-safe-pubkey');
  const revStr = getSingleHeader(req, 'x-safe-revision');
  const tsStr = getSingleHeader(req, 'x-timestamp');
  const nonce = getSingleHeader(req, 'x-nonce');
  const sigB64Url = getSingleHeader(req, 'x-safe-signature');

  if (!pkB64Url || !revStr || !tsStr || !nonce || !sigB64Url) {
    return { ok: false, status: 401, error: 'MISSING_SAFE_AUTH_HEADERS' };
  }
  if (!/^\d{1,18}$/.test(revStr) || !/^\d{10,12}$/.test(tsStr) || !UUID_V4_RE.test(nonce)) {
    return { ok: false, status: 401, error: 'INVALID_SAFE_HEADER_FORMAT' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const reqTs = Number.parseInt(tsStr, 10);
  if (Math.abs(nowSec - reqTs) > MAX_CLOCK_SKEW_SEC) {
    return { ok: false, status: 401, error: 'TIMESTAMP_OUT_OF_WINDOW' };
  }

  const revision = BigInt(revStr);
  if (requirePositiveRevision && revision <= 0n) {
    return { ok: false, status: 400, error: 'SAFE_REVISION_MUST_BE_POSITIVE' };
  }
  if (!requirePositiveRevision && revision !== 0n) {
    return { ok: false, status: 400, error: 'SAFE_REVISION_MUST_BE_ZERO' };
  }

  const pkSafeAuth32 = Buffer.from(pkB64Url, 'base64url');
  const sig64 = Buffer.from(sigB64Url, 'base64url');
  if (pkSafeAuth32.length !== 32 || sig64.length !== 64) {
    return { ok: false, status: 401, error: 'INVALID_SAFE_KEY_OR_SIGNATURE' };
  }

  const rawBody = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);
  const canonical = Buffer.from(
    `safe-http-v1\n${req.method.toUpperCase()}\n${req.url}\n${revStr}\n${tsStr}\n${nonce}\n${sha256Hex(rawBody)}`,
    'utf8',
  );

  if (!verifyEd25519(pkSafeAuth32, canonical, sig64)) {
    return { ok: false, status: 401, error: 'INVALID_SAFE_SIGNATURE' };
  }

  const nonceKey = `nonce:safe:${backupIdHex}:${nonce.toLowerCase()}`;
  const claimed = await cmdRedis.set(nonceKey, '1', 'EX', SAFE_NONCE_TTL_SEC, 'NX');
  if (claimed !== 'OK') {
    return { ok: false, status: 401, error: 'REPLAYED_SAFE_NONCE' };
  }

  return {
    ok: true,
    auth: {
      backupIdBuf: Buffer.from(backupIdHex, 'hex'),
      backupIdHex,
      pkSafeAuth32,
      revision,
    },
  };
}

export async function registerSafeRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. PUT /v1/safe/:backupId — Subir/actualizar respaldo cifrado (428 PoW al crear, 409 en conflicto)
  fastify.put<{ Params: { backupId: string } }>('/v1/safe/:backupId', async (req, reply) => {
    const backupIdHex = req.params.backupId.toLowerCase();
    const verified = await verifySafeHttpHeaders(req, backupIdHex, true);
    if (!verified.ok) {
      return reply.code(verified.status).send({ error: verified.error });
    }
    const { backupIdBuf, pkSafeAuth32, revision } = verified.auth;

    const blob = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);
    if (
      blob.length < SAFE_NONCE_HEADER_LEN + SAFE_BUCKET_BYTES ||
      blob.length > SAFE_MAX_BLOB_BYTES ||
      (blob.length - SAFE_NONCE_HEADER_LEN) % SAFE_BUCKET_BYTES !== 0
    ) {
      return reply.code(400).send({ error: 'INVALID_SAFE_BUCKET_SIZE' });
    }

    const pgClient = await pool.connect();
    try {
      await pgClient.query('BEGIN');

      const existing = await pgClient.query<{ pk_safe_auth: Buffer; revision: string }>(
        `SELECT pk_safe_auth, revision FROM safe_backups WHERE backup_id = $1 FOR UPDATE`,
        [backupIdBuf],
      );

      if (existing.rows.length === 0) {
        // Primer PUT -> exigir PoW Argon2id action=3 (HTTP 428 Precondition Required si falta)
        const powPayload = getSingleHeader(req, 'x-pow-payload');
        const powMac = getSingleHeader(req, 'x-pow-mac');
        const powNonce = getSingleHeader(req, 'x-pow-nonce');

        if (!powPayload || !powMac || !powNonce) {
          await pgClient.query('ROLLBACK');
          return reply.code(428).send({
            error: 'SAFE_BACKUP_POW_REQUIRED',
            requiredAction: 3,
          });
        }

        const pow = await verifyAndBurnPowSolution({
          expectedAction: 3,
          subjectBytes: backupIdBuf,
          powPayloadB64Url: powPayload,
          powMacB64Url: powMac,
          powNonceB64Url: powNonce,
        });
        if (!pow.ok) {
          await pgClient.query('ROLLBACK');
          return reply.code(400).send({ error: pow.error });
        }

        await pgClient.query(
          `INSERT INTO safe_backups (backup_id, pk_safe_auth, revision, blob, updated_at)
           VALUES ($1, $2, $3, $4, NOW())`,
          [backupIdBuf, pkSafeAuth32, revision.toString(), blob],
        );
        await pgClient.query('COMMIT');
        return reply.code(200).send({ ok: true, revision: revision.toString() });
      }

      // Ya existe -> validar propietario pk_safe_auth y monotonicidad estricta de revisión
      const cur = existing.rows[0];
      if (Buffer.compare(cur.pk_safe_auth, pkSafeAuth32) !== 0) {
        await pgClient.query('ROLLBACK');
        return reply.code(403).send({ error: 'SAFE_PUBKEY_MISMATCH' });
      }

      const currentRev = BigInt(cur.revision);
      if (revision <= currentRev) {
        await pgClient.query('ROLLBACK');
        return reply.code(409).send({
          error: 'SAFE_REVISION_CONFLICT',
          currentRevision: currentRev.toString(),
        });
      }

      await pgClient.query(
        `UPDATE safe_backups SET revision = $2, blob = $3, updated_at = NOW() WHERE backup_id = $1`,
        [backupIdBuf, revision.toString(), blob],
      );
      await pgClient.query('COMMIT');
      return reply.code(200).send({ ok: true, revision: revision.toString() });
    } catch (err) {
      await pgClient.query('ROLLBACK');
      throw err;
    } finally {
      pgClient.release();
    }
  });

  // 2. GET /v1/safe/:backupId — Descargar blob cifrado + cabecera X-Safe-Revision
  fastify.get<{ Params: { backupId: string } }>('/v1/safe/:backupId', async (req, reply) => {
    const backupIdHex = req.params.backupId.toLowerCase();
    const verified = await verifySafeHttpHeaders(req, backupIdHex, false);
    if (!verified.ok) {
      return reply.code(verified.status).send({ error: verified.error });
    }
    const { backupIdBuf, pkSafeAuth32 } = verified.auth;

    const { rows } = await pool.query<{ pk_safe_auth: Buffer; revision: string; blob: Buffer }>(
      `SELECT pk_safe_auth, revision, blob FROM safe_backups WHERE backup_id = $1`,
      [backupIdBuf],
    );
    if (rows.length === 0) {
      return reply.code(404).send({ error: 'SAFE_BACKUP_NOT_FOUND' });
    }
    if (Buffer.compare(rows[0].pk_safe_auth, pkSafeAuth32) !== 0) {
      return reply.code(403).send({ error: 'SAFE_PUBKEY_MISMATCH' });
    }

    return reply
      .code(200)
      .header('Content-Type', 'application/octet-stream')
      .header('X-Safe-Revision', rows[0].revision)
      .header('Cache-Control', 'no-store')
      .send(rows[0].blob);
  });

  // 3. DELETE /v1/safe/:backupId — Eliminar respaldo cifrado
  fastify.delete<{ Params: { backupId: string } }>('/v1/safe/:backupId', async (req, reply) => {
    const backupIdHex = req.params.backupId.toLowerCase();
    const verified = await verifySafeHttpHeaders(req, backupIdHex, false);
    if (!verified.ok) {
      return reply.code(verified.status).send({ error: verified.error });
    }
    const { backupIdBuf, pkSafeAuth32 } = verified.auth;

    const del = await pool.query(
      `DELETE FROM safe_backups WHERE backup_id = $1 AND pk_safe_auth = $2`,
      [backupIdBuf, pkSafeAuth32],
    );
    if (del.rowCount === 0) {
      return reply.code(404).send({ error: 'SAFE_BACKUP_NOT_FOUND' });
    }
    return reply.code(204).send();
  });
}
