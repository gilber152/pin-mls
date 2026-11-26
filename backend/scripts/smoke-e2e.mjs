import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
} from 'node:crypto';
import argon2 from 'argon2';
import WebSocket from 'ws';

const API_URL = (process.env.API_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const WS_URL = API_URL.replace(/^http/, 'ws') + '/v1/ws';

function genEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  // SPKI DER for Ed25519 is 44 bytes: 12-byte header + 32-byte raw public key
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const rawPub32 = spki.subarray(spki.length - 32);
  return { publicKey, privateKey, rawPub32 };
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
    if (byte === 0) {
      zeros += 8;
    } else {
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
  assert.equal(chRes.status, 200, `PoW challenge action=${action} failed`);
  const ch = await chRes.json();

  const payload = Buffer.from(ch.challengePayload, 'base64url');
  const salt16 = Buffer.from(ch.challengeId, 'base64url');
  const nonce8 = Buffer.alloc(8);

  for (let counter = 0n; counter < 1_000_000n; counter += 1n) {
    nonce8.writeBigUInt64BE(counter, 0);
    const input = Buffer.concat([payload, subjectBytes, nonce8]);
    const hash = await argon2.hash(input, {
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
  throw new Error('Failed to solve PoW within iteration cap');
}

function signHttpHeaders({ method, pathWithQuery, rawBody, privateKey, idHeaderName, idHeaderValue }) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomUUID();
  const canonical = Buffer.from(
    `ed25519-http-v1\n${method.toUpperCase()}\n${pathWithQuery}\n${ts}\n${nonce}\n${sha256Hex(rawBody)}`,
    'utf8',
  );
  const sig = edSign(privateKey, canonical).toString('base64url');
  return {
    [idHeaderName]: idHeaderValue,
    'X-Timestamp': ts,
    'X-Nonce': nonce,
    'X-Signature': sig,
  };
}

function buildDeviceCert({ pin, rootKeys, deviceId, pkDev32 }) {
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

function buildKeyPackageGrant({ targetPin, requesterPin, signerDeviceId, signerDevKeys }) {
  const grantId = randomUUID();
  const expSec = BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 3600);
  const body = Buffer.alloc(57);
  body[0] = 1;
  uuidToBytes(grantId).copy(body, 1);
  Buffer.from(targetPin, 'ascii').copy(body, 17);
  Buffer.from(requesterPin, 'ascii').copy(body, 25);
  uuidToBytes(signerDeviceId).copy(body, 33);
  body.writeBigUInt64BE(expSec, 49);

  const sig = edSign(signerDevKeys.privateKey, Buffer.concat([Buffer.from('kpgrant-v1', 'ascii'), body]));
  return { grantId, raw: Buffer.concat([body, sig]) };
}

function buildRevocationManifest({ pin, seqNum, deviceIds, rootKeys }) {
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

async function createAndEnrollUser(label) {
  const rootKeys = genEd25519();
  const pkInvite32 = randomBytes(32);
  const sigInvite = edSign(
    rootKeys.privateKey,
    Buffer.concat([Buffer.from('pin-invite-key-v1', 'ascii'), pkInvite32]),
  );
  const pop = edSign(
    rootKeys.privateKey,
    Buffer.concat([Buffer.from('pin-register-pop-v1', 'ascii'), rootKeys.rawPub32, pkInvite32]),
  );
  const pow = await solvePow(1, rootKeys.rawPub32);

  const regRes = await fetch(`${API_URL}/v1/identities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pkRoot: rootKeys.rawPub32.toString('base64url'),
      pkInvite: pkInvite32.toString('base64url'),
      sigInvite: sigInvite.toString('base64url'),
      proofOfPossession: pop.toString('base64url'),
      ...pow,
    }),
  });
  assert.equal(regRes.status, 201, `Register ${label} failed`);
  const { pin } = await regRes.json();

  const deviceId = randomUUID();
  const devKeys = genEd25519();
  const cert = buildDeviceCert({ pin, rootKeys, deviceId, pkDev32: devKeys.rawPub32 });
  const enrollHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/devices/enroll',
    rawBody: cert,
    privateKey: rootKeys.privateKey,
    idHeaderName: 'X-Pin',
    idHeaderValue: pin,
  });

  const enrRes = await fetch(`${API_URL}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', ...enrollHdrs },
    body: cert,
  });
  assert.equal(enrRes.status, 201, `Enroll ${label} failed`);

  const tokenBody = Buffer.from('{}', 'utf8');
  const tokHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/auth/token',
    rawBody: tokenBody,
    privateKey: devKeys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: deviceId,
  });
  const tokRes = await fetch(`${API_URL}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tokHdrs },
    body: tokenBody,
  });
  assert.equal(tokRes.status, 200, `JWT token ${label} failed`);
  const { accessToken } = await tokRes.json();

  // Upload 5 one-time KPs + 1 last_resort
  const exp = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const keyPackages = Array.from({ length: 6 }, (_, i) => ({
    kpRef: randomBytes(32).toString('base64'),
    kpRaw: randomBytes(128).toString('base64'),
    isLastResort: i === 5,
    expiresAt: exp,
  }));
  const kpBody = Buffer.from(JSON.stringify({ keyPackages }), 'utf8');
  const kpHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/keypackages',
    rawBody: kpBody,
    privateKey: devKeys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: deviceId,
  });
  const kpRes = await fetch(`${API_URL}/v1/keypackages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...kpHdrs },
    body: kpBody,
  });
  assert.equal(kpRes.status, 200, `Upload KPs ${label} failed`);

  return { pin, rootKeys, deviceId, devKeys, jwt: accessToken };
}

function connectWs(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    const frames = [];
    let resolved = false;

    ws.on('message', (data) => {
      const parsed = JSON.parse(data.toString('utf8'));
      frames.push(parsed);
      if (!resolved && parsed.type === 'hello') {
        resolved = true;
        resolve({ ws, frames, hello: parsed });
      }
    });
    ws.on('unexpected-response', (_req, res) => {
      if (!resolved) {
        resolved = true;
        reject(Object.assign(new Error(`HTTP ${res.statusCode}`), { statusCode: res.statusCode }));
      }
    });
    ws.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });
  });
}

async function waitForFrame(frames, predicate, timeoutMs = 4000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const found = frames.find(predicate);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('Timed out waiting for WS frame');
}

async function main() {
  console.log(`==> Running PIN-MLS Smoke E2E against ${API_URL}`);

  // 1. /readyz
  const ready = await fetch(`${API_URL}/readyz`);
  assert.equal(ready.status, 200, '/readyz must return 200');
  console.log('  [1/11] /readyz OK');

  // 2. Register + Enroll + JWT + KeyPackages for Alice & Bob
  const alice = await createAndEnrollUser('Alice');
  const bob = await createAndEnrollUser('Bob');
  console.log(`  [2/11] Registered & enrolled Alice (${alice.pin}) and Bob (${bob.pin})`);

  // 3. CSWSH Origin protection + WS ticket single-use + Bearer WS
  const tickRes = await fetch(`${API_URL}/v1/auth/ws-ticket`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${alice.jwt}` },
  });
  assert.equal(tickRes.status, 201);
  const { ticket } = await tickRes.json();

  await assert.rejects(
    () => connectWs(`${WS_URL}?ticket=${ticket}`, { Origin: 'https://evil.example' }),
    (err) => err.statusCode === 403,
    'Bad Origin must be rejected with 403 (CSWSH)',
  );

  const aliceWs = await connectWs(`${WS_URL}?ticket=${ticket}`, { Origin: 'http://localhost:5173' });
  assert.equal(aliceWs.hello.type, 'hello');

  // Reusing same ticket must fail 401
  await assert.rejects(
    () => connectWs(`${WS_URL}?ticket=${ticket}`, { Origin: 'http://localhost:5173' }),
    (err) => err.statusCode === 401,
    'Reused WS ticket must be rejected with 401',
  );

  const bobWs = await connectWs(WS_URL, { Authorization: `Bearer ${bob.jwt}` });
  assert.equal(bobWs.hello.type, 'hello');
  console.log('  [3/11] WebSocket Bearer, single-use ticket and CSWSH 403 OK');

  // 4. Invite flow (HPKE mock + PoW action=2 + WS delivery + KeyPackageGrant accept)
  const profRes = await fetch(`${API_URL}/v1/identities/${bob.pin}/invite-profile`, {
    headers: { Authorization: `Bearer ${alice.jwt}` },
  });
  assert.equal(profRes.status, 200);

  const invPow = await solvePow(2, Buffer.from(bob.pin, 'ascii'));
  const invRes = await fetch(`${API_URL}/v1/invites`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice.jwt}` },
    body: JSON.stringify({
      targetPin: bob.pin,
      ciphertext: randomBytes(96).toString('base64'),
      ...invPow,
    }),
  });
  assert.equal(invRes.status, 201);
  const { requestId } = await invRes.json();
  await waitForFrame(bobWs.frames, (f) => f.type === 'contact_request' && f.request_id === requestId);

  const grant = buildKeyPackageGrant({
    targetPin: bob.pin,
    requesterPin: alice.pin,
    signerDeviceId: bob.deviceId,
    signerDevKeys: bob.devKeys,
  });
  const respRes = await fetch(`${API_URL}/v1/invites/${requestId}/respond`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bob.jwt}` },
    body: JSON.stringify({ decision: 'accept', grantRaw: grant.raw.toString('base64url') }),
  });
  assert.equal(respRes.status, 200);
  await waitForFrame(aliceWs.frames, (f) => f.type === 'keypackage_grant' && f.grant_id === grant.grantId);
  console.log('  [4/11] Invite + PoW action=2 + KeyPackageGrant 121B + WS push OK');

  // 5. Claim KeyPackageGrant (single-use) + Create MLS Group + Commit Add + Welcome
  const claimBody = Buffer.from(JSON.stringify({ grantRaw: grant.raw.toString('base64url') }), 'utf8');
  const claimHdrs1 = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/keypackages/claim',
    rawBody: claimBody,
    privateKey: alice.devKeys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: alice.deviceId,
  });
  const claimRes1 = await fetch(`${API_URL}/v1/keypackages/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...claimHdrs1 },
    body: claimBody,
  });
  assert.equal(claimRes1.status, 200);
  const claimed = await claimRes1.json();
  assert.equal(claimed.keyPackages.length, 1);

  // Second claim with same grant must return 409 GRANT_ALREADY_CONSUMED
  const claimHdrs2 = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/keypackages/claim',
    rawBody: claimBody,
    privateKey: alice.devKeys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: alice.deviceId,
  });
  const claimRes2 = await fetch(`${API_URL}/v1/keypackages/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...claimHdrs2 },
    body: claimBody,
  });
  assert.equal(claimRes2.status, 409);

  const groupId = randomBytes(32);
  const grpRes = await fetch(`${API_URL}/v1/groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice.jwt}` },
    body: JSON.stringify({ groupId: groupId.toString('base64'), cipherSuite: 1 }),
  });
  assert.equal(grpRes.status, 201);

  const commitRes = await fetch(`${API_URL}/v1/groups/${groupId.toString('base64url')}/commits`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice.jwt}` },
    body: JSON.stringify({
      expectedBaseEpoch: 0,
      clientMsgId: randomUUID(),
      commitRaw: randomBytes(120).toString('base64'),
      welcomeRaw: randomBytes(180).toString('base64'),
      addedDevices: [bob.deviceId],
      addedKpRefs: [claimed.keyPackages[0].kpRef],
      removedDevices: [],
    }),
  });
  assert.equal(commitRes.status, 200);
  await waitForFrame(bobWs.frames, (f) => f.type === 'mls_welcome');

  // Stale epoch commit -> 409 EPOCH_CONFLICT with missingCommits
  const conflictCommit = await fetch(`${API_URL}/v1/groups/${groupId.toString('base64url')}/commits`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice.jwt}` },
    body: JSON.stringify({
      expectedBaseEpoch: 0,
      clientMsgId: randomUUID(),
      commitRaw: randomBytes(64).toString('base64'),
    }),
  });
  assert.equal(conflictCommit.status, 409);
  const conflictBody = await conflictCommit.json();
  assert.equal(conflictBody.currentEpoch, 1);
  assert.equal(conflictBody.missingCommits.length, 1);
  console.log('  [5/11] KeyPackage claim, MLS group, Commit+Welcome and 409 catch-up OK');

  // 6. Application message (idempotent) + /v1/sync + /v1/acks + WS ack
  const msgId = randomUUID();
  const sendMsg = () =>
    fetch(`${API_URL}/v1/groups/${groupId.toString('base64url')}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${alice.jwt}` },
      body: JSON.stringify({
        msgType: 'application',
        epoch: 1,
        clientMsgId: msgId,
        ciphertext: randomBytes(64).toString('base64'),
      }),
    });
  const msg1 = await (await sendMsg()).json();
  const msg2 = await (await sendMsg()).json();
  assert.equal(msg1.groupSeq, msg2.groupSeq, 'Idempotent clientMsgId must return same groupSeq');

  const syncRes = await fetch(`${API_URL}/v1/sync`, {
    headers: { Authorization: `Bearer ${bob.jwt}` },
  });
  assert.equal(syncRes.status, 200);
  const syncData = await syncRes.json();
  assert.equal(syncData.welcomes.length, 1);
  assert.equal(syncData.envelopes.length, 1);

  const ackRes = await fetch(`${API_URL}/v1/acks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bob.jwt}` },
    body: JSON.stringify({
      welcomeBlobIds: [syncData.welcomes[0].welcomeBlobId],
      groupCursors: [{ groupId: groupId.toString('base64'), lastSeq: msg1.groupSeq }],
    }),
  });
  assert.equal(ackRes.status, 204);
  bobWs.ws.send(JSON.stringify({ type: 'ack', group_id: groupId.toString('base64'), last_seq: msg1.groupSeq }));
  console.log('  [6/11] Idempotent message, /v1/sync and /v1/acks OK');

  // 7. Safe Backup (428 PoW action=3 -> 200 -> 409 conflict -> GET + X-Safe-Revision)
  const safeKeys = genEd25519();
  const backupIdBuf = randomBytes(32);
  const backupIdHex = backupIdBuf.toString('hex');
  const safePath = `/v1/safe/${backupIdHex}`;
  const safeBlob = randomBytes(24 + 16384);

  const signSafe = (method, rev, bodyBuf) => {
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = randomUUID();
    const canonical = Buffer.from(
      `safe-http-v1\n${method}\n${safePath}\n${rev}\n${ts}\n${nonce}\n${sha256Hex(bodyBuf)}`,
      'utf8',
    );
    return {
      'X-Safe-PubKey': safeKeys.rawPub32.toString('base64url'),
      'X-Safe-Revision': String(rev),
      'X-Timestamp': ts,
      'X-Nonce': nonce,
      'X-Safe-Signature': edSign(safeKeys.privateKey, canonical).toString('base64url'),
    };
  };

  const safe428 = await fetch(`${API_URL}${safePath}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', ...signSafe('PUT', 1, safeBlob) },
    body: safeBlob,
  });
  assert.equal(safe428.status, 428, 'First Safe PUT without PoW must return 428');

  const safePow = await solvePow(3, backupIdBuf);
  const safe200 = await fetch(`${API_URL}${safePath}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/octet-stream',
      ...signSafe('PUT', 1, safeBlob),
      'X-Pow-Payload': safePow.powPayload,
      'X-Pow-Mac': safePow.powMac,
      'X-Pow-Nonce': safePow.powNonce,
    },
    body: safeBlob,
  });
  assert.equal(safe200.status, 200);

  const safe409 = await fetch(`${API_URL}${safePath}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', ...signSafe('PUT', 1, safeBlob) },
    body: safeBlob,
  });
  assert.equal(safe409.status, 409);

  const safeGet = await fetch(`${API_URL}${safePath}`, {
    method: 'GET',
    headers: signSafe('GET', 0, Buffer.alloc(0)),
  });
  assert.equal(safeGet.status, 200);
  assert.equal(safeGet.headers.get('x-safe-revision'), '1');
  const gotBlob = Buffer.from(await safeGet.arrayBuffer());
  assert.equal(Buffer.compare(gotBlob, safeBlob), 0);
  console.log('  [7/11] Safe Backup 428 PoW, 409 conflict and GET X-Safe-Revision OK');

  // 8. Link session (PUT -> GET 204 -> PUT -> GET 200 -> GET 410)
  const readSecret = randomBytes(32);
  const sessionIdHex = createHash('sha256')
    .update(Buffer.from('pin-link-session-v1', 'ascii'))
    .update(readSecret)
    .digest('hex');
  const linkPath = `/v1/link-sessions/${sessionIdHex}`;
  const linkBundle = randomBytes(256);

  const link204 = await fetch(`${API_URL}${linkPath}`, {
    headers: { 'X-Link-Read-Secret': readSecret.toString('base64url') },
  });
  assert.equal(link204.status, 204);

  const linkPut = await fetch(`${API_URL}${linkPath}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${alice.jwt}` },
    body: linkBundle,
  });
  assert.equal(linkPut.status, 201);

  const link200 = await fetch(`${API_URL}${linkPath}`, {
    headers: { 'X-Link-Read-Secret': readSecret.toString('base64url') },
  });
  assert.equal(link200.status, 200);
  assert.equal(Buffer.compare(Buffer.from(await link200.arrayBuffer()), linkBundle), 0);

  const link410 = await fetch(`${API_URL}${linkPath}`, {
    headers: { 'X-Link-Read-Secret': readSecret.toString('base64url') },
  });
  assert.equal(link410.status, 410);
  console.log('  [8/11] Link session 204 -> PUT 201 -> GET 200 -> Tombstone 410 OK');

  // 9. Enroll Alice Device 2 + self-claim KeyPackage
  const dev2Id = randomUUID();
  const dev2Keys = genEd25519();
  const dev2Cert = buildDeviceCert({
    pin: alice.pin,
    rootKeys: alice.rootKeys,
    deviceId: dev2Id,
    pkDev32: dev2Keys.rawPub32,
  });
  const enr2Hdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/devices/enroll',
    rawBody: dev2Cert,
    privateKey: alice.rootKeys.privateKey,
    idHeaderName: 'X-Pin',
    idHeaderValue: alice.pin,
  });
  const enr2Res = await fetch(`${API_URL}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', ...enr2Hdrs },
    body: dev2Cert,
  });
  assert.equal(enr2Res.status, 201);

  const kp2Body = Buffer.from(
    JSON.stringify({
      keyPackages: [
        {
          kpRef: randomBytes(32).toString('base64'),
          kpRaw: randomBytes(128).toString('base64'),
          isLastResort: false,
          expiresAt: Math.floor(Date.now() / 1000) + 86400,
        },
      ],
    }),
    'utf8',
  );
  const kp2Hdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/keypackages',
    rawBody: kp2Body,
    privateKey: dev2Keys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: dev2Id,
  });
  assert.equal(
    (await fetch(`${API_URL}/v1/keypackages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...kp2Hdrs },
      body: kp2Body,
    })).status,
    200,
  );

  const selfClaimBody = Buffer.from(JSON.stringify({ targetDeviceId: dev2Id }), 'utf8');
  const selfClaimHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/keypackages/self-claim',
    rawBody: selfClaimBody,
    privateKey: alice.devKeys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: alice.deviceId,
  });
  const selfClaimRes = await fetch(`${API_URL}/v1/keypackages/self-claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...selfClaimHdrs },
    body: selfClaimBody,
  });
  assert.equal(selfClaimRes.status, 200);
  console.log('  [9/11] Secondary device enrollment + POST /v1/keypackages/self-claim OK');

  // 10. Revocation manifest revmanifest-v1 + instant WS close 4001 on Alice Device 2
  const tok2Body = Buffer.from('{}', 'utf8');
  const tok2Hdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/auth/token',
    rawBody: tok2Body,
    privateKey: dev2Keys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: dev2Id,
  });
  const { accessToken: dev2Jwt } = await (
    await fetch(`${API_URL}/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...tok2Hdrs },
      body: tok2Body,
    })
  ).json();

  const dev2Ws = await connectWs(WS_URL, { Authorization: `Bearer ${dev2Jwt}` });
  const closedWith4001 = new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('Timed out waiting for WS 4001 kick')), 5000);
    dev2Ws.ws.once('close', (code) => {
      clearTimeout(t);
      resolve(code);
    });
  });

  const revWire = buildRevocationManifest({
    pin: alice.pin,
    seqNum: 1,
    deviceIds: [dev2Id],
    rootKeys: alice.rootKeys,
  });
  const revHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/identities/revoke',
    rawBody: revWire,
    privateKey: alice.rootKeys.privateKey,
    idHeaderName: 'X-Pin',
    idHeaderValue: alice.pin,
  });
  const revRes = await fetch(`${API_URL}/v1/identities/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', ...revHdrs },
    body: revWire,
  });
  assert.equal(revRes.status, 200);

  const closeCode = await closedWith4001;
  assert.equal(closeCode, 4001, `Expected WS close 4001, got ${closeCode}`);
  console.log('  [10/11] Revocation revmanifest-v1 + instant WS 4001 kick OK');

  // 11. Revoked device cannot refresh JWT
  const tok2AfterHdrs = signHttpHeaders({
    method: 'POST',
    pathWithQuery: '/v1/auth/token',
    rawBody: tok2Body,
    privateKey: dev2Keys.privateKey,
    idHeaderName: 'X-Device-Id',
    idHeaderValue: dev2Id,
  });
  const tok2After = await fetch(`${API_URL}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...tok2AfterHdrs },
    body: tok2Body,
  });
  assert.equal(tok2After.status, 401);
  console.log('  [11/11] Revoked device rejected on /v1/auth/token (401) OK');

  aliceWs.ws.close();
  bobWs.ws.close();
  console.log('==> ALL 11 E2E SMOKE FLOWS PASSED.');
}

main().catch((err) => {
  console.error('SMOKE E2E FAILED:', err);
  process.exit(1);
});
