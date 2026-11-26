import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { verifyEd25519 } from '../../infra/crypto.js';
import { DeviceCertError, parseAndVerifyDeviceCert } from '../../infra/deviceCert.js';
import { verifyAndBurnPowSolution } from '../../infra/pow.js';
import { presenceKey } from '../ws/presence.js';

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PIN_CROCKFORD_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;
const APNS_HEX_TOKEN_RE = /^[0-9a-f]{64,256}$/i;
const FCM_TOKEN_RE = /^[A-Za-z0-9:_-]{20,4096}$/;

const DOMAIN_INVITE_KEY = Buffer.from('pin-invite-key-v1', 'ascii');
const DOMAIN_POP = Buffer.from('pin-register-pop-v1', 'ascii');

function generateRandomCrockfordPin(): string {
  const bytes = randomBytes(8);
  let out = '';
  for (let i = 0; i < 8; i += 1) {
    out += CROCKFORD_ALPHABET[bytes[i] & 31];
  }
  return out;
}

interface RegisterIdentityBody {
  pkRoot?: unknown;
  pkInvite?: unknown;
  sigInvite?: unknown;
  proofOfPossession?: unknown;
  powPayload?: unknown;
  powMac?: unknown;
  powNonce?: unknown;
}

interface PushTokenBody {
  platform?: unknown;
  pushToken?: unknown;
}

export async function registerIdentityRoutes(fastify: FastifyInstance): Promise<void> {
  // 1. POST /v1/identities — Registro de identidad con PoW Argon2id (action=1)
  fastify.post<{ Body: RegisterIdentityBody }>('/v1/identities', async (req, reply) => {
    const b = req.body;
    if (
      typeof b?.pkRoot !== 'string' ||
      typeof b?.pkInvite !== 'string' ||
      typeof b?.sigInvite !== 'string' ||
      typeof b?.proofOfPossession !== 'string' ||
      typeof b?.powPayload !== 'string' ||
      typeof b?.powMac !== 'string' ||
      typeof b?.powNonce !== 'string'
    ) {
      return reply.code(400).send({ error: 'MISSING_IDENTITY_FIELDS' });
    }

    const pkRoot = Buffer.from(b.pkRoot, 'base64url');
    const pkInvite = Buffer.from(b.pkInvite, 'base64url');
    const sigInvite = Buffer.from(b.sigInvite, 'base64url');
    const popSig = Buffer.from(b.proofOfPossession, 'base64url');

    if (pkRoot.length !== 32 || pkInvite.length !== 32 || sigInvite.length !== 64 || popSig.length !== 64) {
      return reply.code(400).send({ error: 'INVALID_KEY_OR_SIGNATURE_LENGTH' });
    }

    if (!verifyEd25519(pkRoot, Buffer.concat([DOMAIN_INVITE_KEY, pkInvite]), sigInvite)) {
      return reply.code(400).send({ error: 'INVALID_SIG_INVITE' });
    }

    if (!verifyEd25519(pkRoot, Buffer.concat([DOMAIN_POP, pkRoot, pkInvite]), popSig)) {
      return reply.code(400).send({ error: 'INVALID_PROOF_OF_POSSESSION' });
    }

    const pow = await verifyAndBurnPowSolution({
      expectedAction: 1,
      subjectBytes: pkRoot,
      powPayloadB64Url: b.powPayload,
      powMacB64Url: b.powMac,
      powNonceB64Url: b.powNonce,
    });
    if (!pow.ok) {
      return reply.code(400).send({ error: pow.error });
    }

    const existing = await pool.query<{ pin: string }>(
      `SELECT pin FROM identities WHERE pk_root = $1`,
      [pkRoot],
    );
    if (existing.rows.length > 0) {
      return reply.code(409).send({ error: 'PK_ROOT_ALREADY_REGISTERED', pin: existing.rows[0].pin });
    }

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidatePin = generateRandomCrockfordPin();
      try {
        await pool.query(
          `INSERT INTO identities (pin, pk_root, pk_invite, sig_invite)
           VALUES ($1, $2, $3, $4)`,
          [candidatePin, pkRoot, pkInvite, sigInvite],
        );
        return reply.code(201).send({ pin: candidatePin });
      } catch (err: unknown) {
        const pgErr = err as { code?: string };
        if (pgErr.code === '23505') continue;
        throw err;
      }
    }

    return reply.code(503).send({ error: 'PIN_ALLOCATION_EXHAUSTED' });
  });

  // 2. POST /v1/devices/enroll — Enrolar dispositivo con firma SK_root + DeviceCert 169B
  fastify.post(
    '/v1/devices/enroll',
    { preHandler: [fastify.verifyEd25519({ keyType: 'root' })] },
    async (req, reply) => {
      const pin = req.auth!.pin;
      const rawCert = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);

      const idRes = await pool.query<{ pk_root: Buffer }>(
        `SELECT pk_root FROM identities WHERE pin = $1`,
        [pin],
      );
      if (idRes.rows.length === 0) {
        return reply.code(404).send({ error: 'IDENTITY_NOT_FOUND' });
      }

      const nowSec = Math.floor(Date.now() / 1000);
      let cert;
      try {
        cert = parseAndVerifyDeviceCert(rawCert, nowSec, pin, idRes.rows[0].pk_root);
      } catch (err) {
        if (err instanceof DeviceCertError) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        throw err;
      }

      const prev = await pool.query<{ status: string }>(
        `SELECT status FROM devices WHERE device_id = $1`,
        [cert.deviceId],
      );
      if (prev.rows.length > 0) {
        if (prev.rows[0].status === 'revoked') {
          return reply.code(403).send({ error: 'DEVICE_ID_REVOKED' });
        }
        return reply.code(409).send({ error: 'DEVICE_ALREADY_ENROLLED', deviceId: cert.deviceId });
      }

      await pool.query(
        `INSERT INTO devices (
           device_id, pin, pk_dev, device_cert_raw, status, cert_issued_at, cert_expires_at
         ) VALUES ($1, $2, $3, $4, 'active', to_timestamp($5), to_timestamp($6))`,
        [cert.deviceId, cert.pin, cert.pkDev, rawCert, cert.issuedAtSec, cert.expiresAtSec],
      );

      return reply.code(201).send({
        ok: true,
        pin: cert.pin,
        deviceId: cert.deviceId,
        certExpiresAtSec: cert.expiresAtSec,
      });
    },
  );

  // 2b. GET /v1/devices — Listar dispositivos del PIN + estado en línea + secuencia de revocación
  fastify.get(
    '/v1/devices',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const pin = req.auth!.pin;
      const currentDeviceId = req.auth!.deviceId!.toLowerCase();

      const [devRes, revRes] = await Promise.all([
        pool.query<{
          device_id: string;
          status: 'active' | 'revoked';
          cert_issued_at: Date;
          cert_expires_at: Date;
          created_at: Date;
        }>(
          `SELECT device_id, status, cert_issued_at, cert_expires_at, created_at
           FROM devices
           WHERE pin = $1
           ORDER BY created_at ASC`,
          [pin],
        ),
        pool.query<{ seq_num: string; revoked_device_ids: string[] }>(
          `SELECT seq_num, revoked_device_ids
           FROM revocation_manifests
           WHERE pin = $1`,
          [pin],
        ),
      ]);

      const devices = await Promise.all(
        devRes.rows.map(async (row) => {
          const id = row.device_id.toLowerCase();
          const online =
            row.status === 'active'
              ? (await cmdRedis.exists(presenceKey(id))) === 1
              : false;
          return {
            deviceId: id,
            status: row.status,
            isCurrent: id === currentDeviceId,
            online,
            certIssuedAt: row.cert_issued_at.toISOString(),
            certExpiresAt: row.cert_expires_at.toISOString(),
            createdAt: row.created_at.toISOString(),
          };
        }),
      );

      const revRow = revRes.rows[0];
      const revocationSeqNum = revRow ? revRow.seq_num : '0';
      const revokedDeviceIds =
        revRow && Array.isArray(revRow.revoked_device_ids)
          ? revRow.revoked_device_ids.map((id) => id.toLowerCase())
          : [];

      return reply.code(200).header('Cache-Control', 'no-store').send({
        pin,
        currentDeviceId,
        revocationSeqNum,
        revokedDeviceIds,
        devices,
      });
    },
  );

  // 3. PUT /v1/devices/push-token — Registrar token FCM o APNs (JWT)
  fastify.put<{ Body: PushTokenBody }>(
    '/v1/devices/push-token',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const deviceId = req.auth!.deviceId!;
      const platform = req.body?.platform;
      const pushToken = typeof req.body?.pushToken === 'string' ? req.body.pushToken.trim() : '';

      if (platform !== 'fcm' && platform !== 'apns') {
        return reply.code(400).send({ error: 'INVALID_PUSH_PLATFORM' });
      }
      if (platform === 'apns' && !APNS_HEX_TOKEN_RE.test(pushToken)) {
        return reply.code(400).send({ error: 'INVALID_APNS_TOKEN' });
      }
      if (platform === 'fcm' && !FCM_TOKEN_RE.test(pushToken)) {
        return reply.code(400).send({ error: 'INVALID_FCM_TOKEN' });
      }

      await pool.query(
        `UPDATE devices SET push_platform = $2, push_token = $3 WHERE device_id = $1`,
        [deviceId, platform, pushToken],
      );
      return reply.code(200).send({ ok: true });
    },
  );

  // 4. GET /v1/identities/:pin/invite-profile — Perfil público para cifrar invitación
  fastify.get<{ Params: { pin: string } }>(
    '/v1/identities/:pin/invite-profile',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const targetPin = req.params.pin.toUpperCase();
      if (!PIN_CROCKFORD_RE.test(targetPin)) {
        return reply.code(400).send({ error: 'INVALID_PIN' });
      }

      const { rows } = await pool.query<{
        pin: string;
        pk_root: Buffer;
        pk_invite: Buffer;
        sig_invite: Buffer;
        invite_policy: string;
      }>(
        `SELECT pin, pk_root, pk_invite, sig_invite, invite_policy FROM identities WHERE pin = $1`,
        [targetPin],
      );
      if (rows.length === 0) {
        return reply.code(404).send({ error: 'IDENTITY_NOT_FOUND' });
      }

      const r = rows[0];
      return reply.code(200).send({
        pin: r.pin,
        pkRoot: r.pk_root.toString('base64url'),
        pkInvite: r.pk_invite.toString('base64url'),
        sigInvite: r.sig_invite.toString('base64url'),
        invitePolicy: r.invite_policy,
      });
    },
  );

  // 5. GET /v1/identities/:pin/revocations — Último manifiesto binario revmanifest-v1
  fastify.get<{ Params: { pin: string } }>(
    '/v1/identities/:pin/revocations',
    { preHandler: [fastify.verifyJwt] },
    async (req, reply) => {
      const targetPin = req.params.pin.toUpperCase();
      if (!PIN_CROCKFORD_RE.test(targetPin)) {
        return reply.code(400).send({ error: 'INVALID_PIN' });
      }

      const { rows } = await pool.query<{ manifest_raw: Buffer; sig_root: Buffer }>(
        `SELECT manifest_raw, sig_root FROM revocation_manifests WHERE pin = $1`,
        [targetPin],
      );
      if (rows.length === 0) {
        return reply.code(404).send({ error: 'NO_REVOCATION_MANIFEST' });
      }

      const wire = Buffer.concat([rows[0].manifest_raw, rows[0].sig_root]);
      return reply
        .code(200)
        .header('Content-Type', 'application/octet-stream')
        .header('Cache-Control', 'no-store')
        .send(wire);
    },
  );
}
