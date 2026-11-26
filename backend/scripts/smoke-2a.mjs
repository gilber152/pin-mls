import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
} from 'node:crypto';
import argon2 from 'argon2';

const API_URL = (process.env.API_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return { publicKey, privateKey, rawPub32: spki.subarray(spki.length - 32) };
}

function edSign(privateKey, msgBuf) {
  return cryptoSign(null, msgBuf, privateKey);
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function uuidToBytes(uuid) {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function countLeadingZeroBits(buf) {
  let zeros = 0;
  for (const byte of buf) {
    if (byte === 0) zeros += 8;
    else {
      zeros += Math.clz32(byte) - 24;
      break;
    }
  }
  return zeros;
}

async function solvePow(action, subjectBytes) {
  const chRes = await fetch(`${API_URL}/v1/pow/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  });
  assert.equal(chRes.status, 200);
  const ch = await chRes.json();
  const payload = Buffer.from(ch.challengePayload, 'base64url');
  const salt16 = Buffer.from(ch.challengeId, 'base64url');
  const nonce8 = Buffer.alloc(8);
  for (let counter = 0n; counter < 1_000_000n; counter += 1n) {
    nonce8.writeBigUInt64BE(counter, 0);
    const hash = await argon2.hash(Buffer.concat([payload, subjectBytes, nonce8]), {
      type: argon2.argon2id,
      memoryCost: 16384,
      timeCost: 2,
      parallelism: 1,
      hashLength: 32,
      salt: salt16,
      raw: true,
    });
    if (countLeadingZeroBits(hash) >= ch.difficultyBits) {
      return {
        powPayload: ch.challengePayload,
        powMac: ch.challengeMac,
        powNonce: nonce8.toString('base64url'),
      };
    }
  }
  throw new Error('PoW cap reached');
}

function signHttp({ method, path, rawBody, privateKey, idHeaderName, idHeaderValue }) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomUUID();
  const canonical = Buffer.from(
    `ed25519-http-v1\n${method}\n${path}\n${ts}\n${nonce}\n${sha256Hex(rawBody)}`,
    'utf8',
  );
  return {
    [idHeaderName]: idHeaderValue,
    'X-Timestamp': ts,
    'X-Nonce': nonce,
    'X-Signature': edSign(privateKey, canonical).toString('base64url'),
  };
}

function buildDeviceCert(pin, rootKeys, deviceId, pkDev32) {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const expSec = nowSec + BigInt(180 * 24 * 3600);
  const body = Buffer.alloc(105);
  body[0] = 1;
  Buffer.from(pin, 'ascii').copy(body, 1);
  rootKeys.rawPub32.copy(body, 9);
  uuidToBytes(deviceId).copy(body, 41);
  pkDev32.copy(body, 57);
  body.writeBigUInt64BE(nowSec, 89);
  body.writeBigUInt64BE(expSec, 97);
  const sig = edSign(rootKeys.privateKey, Buffer.concat([Buffer.from('devicecert-v1', 'ascii'), body]));
  return Buffer.concat([body, sig]);
}

function buildRevManifest(pin, seqNum, deviceIds, rootKeys) {
  const sorted = deviceIds.map(uuidToBytes).sort(Buffer.compare);
  const body = Buffer.alloc(19 + sorted.length * 16);
  body[0] = 1;
  Buffer.from(pin, 'ascii').copy(body, 1);
  body.writeBigUInt64BE(BigInt(seqNum), 9);
  body.writeUInt16BE(sorted.length, 17);
  sorted.forEach((b, i) => b.copy(body, 19 + i * 16));
  const sig = edSign(rootKeys.privateKey, Buffer.concat([Buffer.from('revmanifest-v1', 'ascii'), body]));
  return Buffer.concat([body, sig]);
}

async function main() {
  console.log(`==> Verificando Bloque 2A (GET /v1/devices + revocación acumulativa) contra ${API_URL}`);
  const rootKeys = genEd25519();
  const pkInvite = randomBytes(32);
  const sigInvite = edSign(rootKeys.privateKey, Buffer.concat([Buffer.from('pin-invite-key-v1', 'ascii'), pkInvite]));
  const pop = edSign(rootKeys.privateKey, Buffer.concat([Buffer.from('pin-register-pop-v1', 'ascii'), rootKeys.rawPub32, pkInvite]));
  const pow = await solvePow(1, rootKeys.rawPub32);

  const regRes = await fetch(`${API_URL}/v1/identities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pkRoot: rootKeys.rawPub32.toString('base64url'),
      pkInvite: pkInvite.toString('base64url'),
      sigInvite: sigInvite.toString('base64url'),
      proofOfPossession: pop.toString('base64url'),
      ...pow,
    }),
  });
  assert.equal(regRes.status, 201);
  const { pin } = await regRes.json();

  // Enroll Dev 1 & Dev 2
  const dev1Id = randomUUID();
  const dev1Keys = genEd25519();
  const cert1 = buildDeviceCert(pin, rootKeys, dev1Id, dev1Keys.rawPub32);
  assert.equal(
    (await fetch(`${API_URL}/v1/devices/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        ...signHttp({ method: 'POST', path: '/v1/devices/enroll', rawBody: cert1, privateKey: rootKeys.privateKey, idHeaderName: 'X-Pin', idHeaderValue: pin }),
      },
      body: cert1,
    })).status,
    201,
  );

  const tokBody = Buffer.from('{}', 'utf8');
  const { accessToken: jwt1 } = await (
    await fetch(`${API_URL}/v1/auth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...signHttp({ method: 'POST', path: '/v1/auth/token', rawBody: tokBody, privateKey: dev1Keys.privateKey, idHeaderName: 'X-Device-Id', idHeaderValue: dev1Id }),
      },
      body: tokBody,
    })
  ).json();

  const dev2Id = randomUUID();
  const dev2Keys = genEd25519();
  const cert2 = buildDeviceCert(pin, rootKeys, dev2Id, dev2Keys.rawPub32);
  assert.equal(
    (await fetch(`${API_URL}/v1/devices/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        ...signHttp({ method: 'POST', path: '/v1/devices/enroll', rawBody: cert2, privateKey: rootKeys.privateKey, idHeaderName: 'X-Pin', idHeaderValue: pin }),
      },
      body: cert2,
    })).status,
    201,
  );

  // 1. GET /v1/devices before revocation
  const list1 = await (await fetch(`${API_URL}/v1/devices`, { headers: { Authorization: `Bearer ${jwt1}` } })).json();
  assert.equal(list1.devices.length, 2);
  assert.equal(list1.revocationSeqNum, '0');
  assert.deepEqual(list1.revokedDeviceIds, []);
  assert.equal(list1.devices.find((d) => d.deviceId === dev1Id).isCurrent, true);
  console.log('  [1/2] GET /v1/devices (2 activos, seq=0) OK');

  // 2. Revoke Dev 2 & verify GET /v1/devices reflects seq=1 and revoked status
  const revWire = buildRevManifest(pin, 1, [dev2Id], rootKeys);
  const revRes = await fetch(`${API_URL}/v1/identities/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      ...signHttp({ method: 'POST', path: '/v1/identities/revoke', rawBody: revWire, privateKey: rootKeys.privateKey, idHeaderName: 'X-Pin', idHeaderValue: pin }),
    },
    body: revWire,
  });
  assert.equal(revRes.status, 200);

  const list2 = await (await fetch(`${API_URL}/v1/devices`, { headers: { Authorization: `Bearer ${jwt1}` } })).json();
  assert.equal(list2.revocationSeqNum, '1');
  assert.deepEqual(list2.revokedDeviceIds, [dev2Id]);
  assert.equal(list2.devices.find((d) => d.deviceId === dev2Id).status, 'revoked');
  console.log('  [2/2] GET /v1/devices tras revocación (seq=1, dev2=revoked) OK');
  console.log('==> SMOKE 2A VERIFICADO EN VERDE.');
}

main().catch((err) => {
  console.error('SMOKE 2A FAILED:', err);
  process.exit(1);
});
