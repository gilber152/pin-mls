import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import argon2 from 'argon2';
import { sha256Hex, verifyEd25519 } from '../dist/infra/crypto.js';
import { parseAndVerifyDeviceCert } from '../dist/infra/deviceCert.js';
import {
  parseKeyPackageGrant,
  verifyKeyPackageGrantSignature,
} from '../dist/infra/keyPackageGrant.js';
import {
  parseAndVerifyRevocationManifest,
  RevocationManifestError,
} from '../dist/infra/revocationManifest.js';
import {
  deriveLinkSessionIdBytes,
  verifyLinkReadSecret,
  parseLinkQrUri,
  LinkQrError,
} from '../dist/infra/linkSession.js';

const vectorPath = process.argv[2] || 'target/interop_vectors.json';
const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'));

function verifyDeviceCertVector(v) {
  const certBuf = Buffer.from(v.certHex, 'hex');
  const pkRoot = Buffer.from(v.pkRootHex, 'hex');
  const parsed = parseAndVerifyDeviceCert(certBuf, v.nowSec, v.pin, pkRoot);
  assert.equal(parsed.pin, v.pin);
  assert.equal(parsed.deviceId, v.deviceId);
  assert.equal(parsed.pkDev.toString('hex'), v.pkDevHex);
  console.log(`  [OK] devicecert-v1 (169B, pin=${parsed.pin}, dev=${parsed.deviceId})`);
}

function verifyKeyPackageGrantVector(v) {
  const grantBuf = Buffer.from(v.grantHex, 'hex');
  const pkDev = Buffer.from(v.signerPkDevHex, 'hex');
  const parsed = parseKeyPackageGrant(grantBuf, v.nowSec);
  assert.equal(parsed.grantId, v.grantId);
  assert.equal(parsed.targetPin, v.targetPin);
  assert.equal(parsed.requesterPin, v.requesterPin);
  assert.equal(parsed.signerDeviceId, v.signerDeviceId);
  assert.equal(verifyKeyPackageGrantSignature(parsed, pkDev), true);
  console.log(`  [OK] kpgrant-v1 (121B, target=${parsed.targetPin}, req=${parsed.requesterPin})`);
}

function verifySafeBackupVector(v) {
  const blob = Buffer.from(v.blobHex, 'hex');
  assert.equal(blob.length, v.blobLen);
  assert.equal((blob.length - 24) % 16384, 0, 'Safe blob debe ser 24B + múltiplo de 16 KiB');

  const pkSafe = Buffer.from(v.pkSafeAuthHex, 'hex');
  const canonical = Buffer.from(
    `safe-http-v1\nPUT\n${v.safePath}\n${v.revision}\n${v.timestamp}\n${v.nonce}\n${sha256Hex(blob)}`,
    'utf8',
  );
  const sig = Buffer.from(v.signatureB64Url, 'base64url');
  assert.equal(verifyEd25519(pkSafe, canonical, sig), true);
  console.log(`  [OK] safe-http-v1 + cubeta 16 KiB (${blob.length}B)`);
}

async function verifyArgon2PowVector(v) {
  const input = Buffer.concat([
    Buffer.from(v.payloadHex, 'hex'),
    Buffer.from(v.subjectHex, 'hex'),
    Buffer.from(v.nonceHex, 'hex'),
  ]);
  const salt = Buffer.from(v.saltHex, 'hex');
  const nodeHash = await argon2.hash(input, {
    type: argon2.argon2id,
    memoryCost: 16384,
    timeCost: 2,
    parallelism: 1,
    hashLength: 32,
    salt,
    raw: true,
  });
  assert.equal(nodeHash.toString('hex'), v.expectedHashHex);
  console.log(`  [OK] argon2id-pow (m=16384, t=2, p=1 coincidencia exacta 32B)`);
}

function verifyRevocationManifestVector(v) {
  const pkRoot = Buffer.from(v.pkRootHex, 'hex');
  const wire = Buffer.from(v.wireHex, 'hex');
  const parsed = parseAndVerifyRevocationManifest(wire, v.pin, pkRoot);
  assert.equal(parsed.seqNum, BigInt(v.seqNum));
  assert.deepEqual(parsed.revokedDeviceIds, v.expectedSortedDeviceIds);
  assert.equal(parsed.manifestRaw.toString('hex'), v.manifestRawHex);
  assert.equal(parsed.sigRoot.toString('hex'), v.sigRootHex);

  const http = v.httpRevoke;
  const canonicalHttp = Buffer.from(
    `ed25519-http-v1\n${http.method}\n${http.path}\n${http.timestamp}\n${http.nonce}\n${sha256Hex(wire)}`,
    'utf8',
  );
  assert.equal(
    verifyEd25519(pkRoot, canonicalHttp, Buffer.from(http.signatureB64Url, 'base64url')),
    true,
  );

  const neg = v.negativeVectors;
  assert.throws(
    () => parseAndVerifyRevocationManifest(Buffer.from(neg.tamperedWireHex, 'hex'), v.pin, pkRoot),
    (e) => e instanceof RevocationManifestError && e.code === 'INVALID_MANIFEST_SIGNATURE',
  );
  assert.throws(
    () => parseAndVerifyRevocationManifest(Buffer.from(neg.unsortedValidSigWireHex, 'hex'), v.pin, pkRoot),
    (e) => e instanceof RevocationManifestError && e.code === 'UNSORTED_OR_DUPLICATE_UUIDS',
  );
  assert.throws(
    () => parseAndVerifyRevocationManifest(Buffer.from(neg.duplicateValidSigWireHex, 'hex'), v.pin, pkRoot),
    (e) => e instanceof RevocationManifestError && e.code === 'UNSORTED_OR_DUPLICATE_UUIDS',
  );
  assert.throws(
    () => parseAndVerifyRevocationManifest(Buffer.from(neg.zeroSeqValidSigWireHex, 'hex'), v.pin, pkRoot),
    (e) => e instanceof RevocationManifestError && e.code === 'INVALID_MANIFEST_SEQ',
  );
  console.log(`  [OK] revmanifest-v1 (${parsed.revokedDeviceIds.length} UUIDs, seq=${parsed.seqNum} y 4 negativos)`);
}

function verifyLinkSessionVector(v) {
  const derived = deriveLinkSessionIdBytes(Buffer.from(v.readSecretHex, 'hex'));
  assert.equal(derived.toString('hex'), v.sessionIdHex);
  assert.equal(verifyLinkReadSecret(v.sessionIdHex, v.readSecretB64Url), true);

  const parsedQr = parseLinkQrUri(v.linkQrUri);
  assert.equal(parsedQr.sessionIdHex, v.sessionIdHex);
  assert.equal(parsedQr.deviceIdUuid, v.deviceIdUuid);
  assert.equal(parsedQr.pkDev32.toString('hex'), v.pkDevHex);
  assert.equal(parsedQr.pkLinkEph32.toString('hex'), v.pkLinkEphHex);

  const neg = v.negativeVectors;
  assert.equal(verifyLinkReadSecret(v.sessionIdHex, neg.wrongSecretB64Url), false);
  assert.equal(verifyLinkReadSecret(v.sessionIdHex, neg.shortSecretB64Url), false);
  assert.throws(
    () => parseLinkQrUri(neg.nonUuidV4QrUri),
    (e) => e instanceof LinkQrError && e.code === 'INVALID_DEVICE_UUID_V4',
  );
  assert.throws(
    () => parseLinkQrUri(neg.wrongPrefixQrUri),
    (e) => e instanceof LinkQrError && e.code === 'INVALID_LINK_QR_PREFIX',
  );
  assert.throws(
    () => parseLinkQrUri(neg.missingEkQrUri),
    (e) => e instanceof LinkQrError && e.code === 'INVALID_PK_LINK_EPH_PARAM',
  );
  console.log(`  [OK] pin-link-session-v1 + LinkQr (session=${v.sessionIdHex.slice(0, 12)}... y 5 negativos)`);
}

async function main() {
  console.log(`==> Verificando interoperabilidad Rust <-> Node.js desde ${vectorPath}`);
  verifyDeviceCertVector(vectors.deviceCert);
  verifyKeyPackageGrantVector(vectors.keyPackageGrant);
  verifySafeBackupVector(vectors.safeBackup);
  await verifyArgon2PowVector(vectors.argon2Pow);
  verifyRevocationManifestVector(vectors.revocationManifest);
  verifyLinkSessionVector(vectors.linkSession);
  console.log('==> TODA LA INTEROPERABILIDAD RUST <-> NODE.JS VERIFICADA BYTE A BYTE.');
}

main().catch((err) => {
  console.error('INTEROP VERIFICATION FAILED:', err);
  process.exit(1);
});
