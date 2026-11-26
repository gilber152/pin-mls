import type { VaultState } from '../types.js';
import type {
  CryptoWorkerClient,
  LinkBundlePayloadDto,
  RestoredSafeDto,
} from '../worker/workerClient.js';

export const API_BASE = ((import.meta.env.VITE_API_URL as string | undefined) ?? '').replace(/\/+$/, '');

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64UrlToBytes(b64Url: string): Uint8Array {
  const padded =
    b64Url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64Url.length % 4)) % 4);
  return b64ToBytes(padded);
}

export function bytesToB64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.byteLength);
  copy.set(u8);
  return copy.buffer;
}

export interface PowChallengeResp {
  challengeId: string;
  challengePayload: string;
  challengeMac: string;
  difficultyBits: number;
}

export interface DeviceInfoDto {
  deviceId: string;
  status: 'active' | 'revoked';
  isCurrent: boolean;
  online: boolean;
  certIssuedAt: string;
  certExpiresAt: string;
  createdAt: string;
}

export interface DevicesListResponse {
  pin: string;
  currentDeviceId: string;
  revocationSeqNum: string;
  revokedDeviceIds: string[];
  devices: DeviceInfoDto[];
}

export interface SelfClaimKpResponse {
  targetPin: string;
  targetDeviceId: string;
  kpRef: string;
  kpRaw: string;
  usedLastResort: boolean;
  expiresAt: number;
}

export interface SyncResponse {
  kpRemaining: number;
  welcomes: Array<{
    welcomeBlobId: string;
    groupId: string;
    targetEpoch: number;
    commitSeq: number;
    kpRef: string;
    welcomeRaw: string;
  }>;
  contactRequests: Array<{
    requestId: string;
    senderPin: string;
    ciphertext: string;
    createdAt: string;
  }>;
  pendingGrants: Array<{
    grantId: string;
    targetPin: string;
    grantRaw: string;
    expiresAt: string;
  }>;
  envelopes: Array<{
    groupId: string;
    groupSeq: number;
    msgType: string;
    epoch: number;
    ciphertext: string;
    serverTimestamp: number;
  }>;
  hasMoreEnvelopes: boolean;
}

export class PinApiClient {
  private jwt: string | null = null;
  private jwtExpSec = 0;

  constructor(private readonly worker: CryptoWorkerClient) {}

  clearSession(): void {
    this.jwt = null;
    this.jwtExpSec = 0;
  }

  wsEndpointUrl(ticket: string): string {
    if (API_BASE) {
      return `${API_BASE.replace(/^http/, 'ws')}/v1/ws?ticket=${encodeURIComponent(ticket)}`;
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/v1/ws?ticket=${encodeURIComponent(ticket)}`;
  }

  async solvePowChallenge(
    action: 1 | 2 | 3,
    subjectBytes: Uint8Array,
  ): Promise<{ powPayload: string; powMac: string; powNonce: string }> {
    const chRes = await fetch(`${API_BASE}/v1/pow/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!chRes.ok) throw new Error(`Error pidiendo PoW (${chRes.status})`);
    const ch = (await chRes.json()) as PowChallengeResp;

    const nonceBytes = await this.worker.solvePow({
      challengePayloadRaw: b64UrlToBytes(ch.challengePayload),
      challengeId16: b64UrlToBytes(ch.challengeId),
      subjectBytes,
      difficultyBits: ch.difficultyBits,
    });

    return {
      powPayload: ch.challengePayload,
      powMac: ch.challengeMac,
      powNonce: bytesToB64Url(nonceBytes),
    };
  }

  async signedDevicePost<T>(vault: VaultState, path: string, bodyObj: unknown): Promise<T> {
    const jsonText = JSON.stringify(bodyObj);
    const rawBytes = new TextEncoder().encode(jsonText);
    const sig = await this.worker.signDeviceHttp({
      skDevHex: vault.skDevHex,
      deviceId: vault.deviceId,
      method: 'POST',
      pathWithQuery: path,
      rawBody: rawBytes,
      nowUnixSec: Math.floor(Date.now() / 1000),
    });

    const res = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': sig.xDeviceId,
        'X-Timestamp': sig.xTimestamp,
        'X-Nonce': sig.xNonce,
        'X-Signature': sig.xSignature,
      },
      body: jsonText,
      credentials: 'omit',
      cache: 'no-store',
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} en ${path}: ${txt.slice(0, 180)}`);
    }
    return (await res.json()) as T;
  }

  async getJwt(vault: VaultState, forceRefresh = false): Promise<string> {
    const nowSec = Math.floor(Date.now() / 1000);
    if (!forceRefresh && this.jwt && this.jwtExpSec - nowSec > 45) {
      return this.jwt;
    }
    const resp = await this.signedDevicePost<{ accessToken: string; expiresAtSec: number }>(
      vault,
      '/v1/auth/token',
      {},
    );
    this.jwt = resp.accessToken;
    this.jwtExpSec = resp.expiresAtSec;
    return this.jwt;
  }

  async authedFetch(
    vault: VaultState,
    path: string,
    init: RequestInit = {},
  ): Promise<Response> {
    const run = async (token: string) => {
      const headers = new Headers(init.headers);
      headers.set('Authorization', `Bearer ${token}`);
      return fetch(`${API_BASE}${path}`, {
        ...init,
        headers,
        credentials: 'omit',
        cache: 'no-store',
      });
    };

    let res = await run(await this.getJwt(vault));
    if (res.status === 401) {
      res = await run(await this.getJwt(vault, true));
    }
    return res;
  }

  async authedJson<T>(vault: VaultState, path: string, method = 'GET', bodyObj?: unknown): Promise<T> {
    const init: RequestInit = { method };
    if (bodyObj !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(bodyObj);
    }
    const res = await this.authedFetch(vault, path, init);
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} en ${path}: ${txt.slice(0, 180)}`);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  async enrollDeviceWithMnemonic(
    mnemonic: string,
    pin: string,
    pkRootHex: string,
    skInviteHex: string,
    pkInviteHex: string,
    onProgress: (msg: string) => void,
  ): Promise<VaultState> {
    onProgress(`Firmando DeviceCert (169B) y enrolando navegador para PIN ${pin}...`);
    const enr = await this.worker.prepareDeviceEnrollment(
      mnemonic,
      pin,
      Math.floor(Date.now() / 1000),
    );
    const certBytes = b64ToBytes(enr.deviceCertB64);

    const enrRes = await fetch(`${API_BASE}/v1/devices/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Pin': enr.enrollHeaders.xPin,
        'X-Timestamp': enr.enrollHeaders.xTimestamp,
        'X-Nonce': enr.enrollHeaders.xNonce,
        'X-Signature': enr.enrollHeaders.xSignature,
      },
      body: toArrayBuffer(certBytes),
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!enrRes.ok) {
      const txt = await enrRes.text().catch(() => '');
      throw new Error(`Fallo enrolando dispositivo (${enrRes.status}): ${txt}`);
    }

    onProgress('Inicializando motor OpenMLS RFC 9420 (TreeKEM)...');
    const rtInit = await this.worker.mlsInitRuntime({
      storageJson: '',
      pin,
      deviceId: enr.deviceId,
      sigPkB64: '',
    });

    const vault: VaultState = {
      vaultSchemaVersion: 2,
      pin,
      deviceId: enr.deviceId,
      pkRootHex,
      skInviteHex,
      pkInviteHex,
      skDevHex: enr.skDevHex,
      pkDevHex: enr.pkDevHex,
      mlsSigPkB64: rtInit.sigPkB64,
      mlsStorageJson: rtInit.storageJson,
      safeBackupRevision: 0,
      contacts: [],
      incomingInvites: [],
      groups: {},
    };

    onProgress('Generando y subiendo 20 KeyPackages OpenMLS + last_resort...');
    await this.replenishKeyPackages(vault, 20, true);
    await this.getJwt(vault, true);
    return vault;
  }

  async replenishKeyPackages(vault: VaultState, count = 20, includeLastResort = true): Promise<void> {
    const generated = await this.worker.mlsGenerateKeyPackages({
      count,
      includeLastResort,
      nowUnixSec: Math.floor(Date.now() / 1000),
    });

    vault.mlsStorageJson = generated.storageJson;

    await this.signedDevicePost(vault, '/v1/keypackages', {
      keyPackages: generated.keyPackages.map((k) => ({
        kpRef: k.kpRef,
        kpRaw: k.kpRaw,
        isLastResort: k.isLastResort,
        expiresAt: k.expiresAt,
      })),
    });
  }

  // ==========================================================================
  // DISPOSITIVOS, LINKQR Y REVOCACIÓN
  // ==========================================================================

  async listDevices(vault: VaultState): Promise<DevicesListResponse> {
    return this.authedJson<DevicesListResponse>(vault, '/v1/devices');
  }

  async selfClaimKeyPackage(vault: VaultState, targetDeviceId: string): Promise<SelfClaimKpResponse> {
    return this.signedDevicePost<SelfClaimKpResponse>(vault, '/v1/keypackages/self-claim', {
      targetDeviceId,
    });
  }

  async authorizeAndUploadLinkSession(
    vault: VaultState,
    mnemonic: string,
    linkQrUri: string,
    onProgress: (msg: string) => void,
  ): Promise<{ targetDeviceId: string; sessionIdHex: string }> {
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, ' ');
    const payload: LinkBundlePayloadDto = {
      pin: vault.pin,
      pkRootHex: vault.pkRootHex,
      skInviteHex: vault.skInviteHex,
      pkInviteHex: vault.pkInviteHex,
      safeBackupRevision: vault.safeBackupRevision,
      contacts: vault.contacts,
    };

    onProgress('Verificando clave raíz, firmando DeviceCert (169B) y cifrando LinkBundle...');
    const authz = await this.worker.prepareLinkAuthorization({
      mnemonic: cleanMnemonic,
      myPin: vault.pin,
      expectedPkRootHex: vault.pkRootHex,
      linkQrUri: linkQrUri.trim(),
      bundlePayloadJson: JSON.stringify(payload),
      nowUnixSec: Math.floor(Date.now() / 1000),
    });

    onProgress('Enrolando nuevo dispositivo en POST /v1/devices/enroll...');
    const certBytes = b64ToBytes(authz.deviceCertB64);
    const enrRes = await fetch(`${API_BASE}/v1/devices/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Pin': authz.enrollHeaders.xPin,
        'X-Timestamp': authz.enrollHeaders.xTimestamp,
        'X-Nonce': authz.enrollHeaders.xNonce,
        'X-Signature': authz.enrollHeaders.xSignature,
      },
      body: toArrayBuffer(certBytes),
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!enrRes.ok && enrRes.status !== 409) {
      const txt = await enrRes.text().catch(() => '');
      throw new Error(`Fallo enrolando dispositivo (${enrRes.status}): ${txt.slice(0, 160)}`);
    }

    onProgress('Subiendo LinkBundle cifrado a PUT /v1/link-sessions/...');
    const bundleBytes = b64ToBytes(authz.sealedBundleB64);
    const putRes = await this.authedFetch(vault, `/v1/link-sessions/${authz.sessionIdHex}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: toArrayBuffer(bundleBytes),
    });
    if (!putRes.ok) {
      const txt = await putRes.text().catch(() => '');
      throw new Error(`Fallo subiendo LinkBundle (${putRes.status}): ${txt.slice(0, 160)}`);
    }

    return {
      targetDeviceId: authz.targetDeviceId,
      sessionIdHex: authz.sessionIdHex,
    };
  }

  async pollLinkSessionOnce(
    sessionIdHex: string,
    readSecretB64Url: string,
  ): Promise<{ status: 'waiting' } | { status: 'expired' } | { status: 'ready'; bundleWire: Uint8Array }> {
    const res = await fetch(`${API_BASE}/v1/link-sessions/${sessionIdHex}`, {
      method: 'GET',
      headers: { 'X-Link-Read-Secret': readSecretB64Url },
      credentials: 'omit',
      cache: 'no-store',
    });

    if (res.status === 204) return { status: 'waiting' };
    if (res.status === 410) return { status: 'expired' };
    if (res.status === 200) {
      return { status: 'ready', bundleWire: new Uint8Array(await res.arrayBuffer()) };
    }
    const txt = await res.text().catch(() => '');
    throw new Error(`Error consultando link-session (${res.status}): ${txt.slice(0, 140)}`);
  }

  async revokeDevice(
    vault: VaultState,
    mnemonic: string,
    targetDeviceId: string,
    onProgress: (msg: string) => void,
  ): Promise<{ seqNum: number; revokedCount: number }> {
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, ' ');

    onProgress('Consultando manifiesto acumulativo actual del servidor...');
    const info = await this.listDevices(vault);
    const nextSeqNum = Number(info.revocationSeqNum) + 1;
    const allRevokedIds = Array.from(
      new Set([...info.revokedDeviceIds, targetDeviceId.toLowerCase()]),
    );

    onProgress(`Firmando revmanifest-v1 (seq #${nextSeqNum}, ${allRevokedIds.length} dispositivos)...`);
    const prep = await this.worker.prepareRevocationManifest({
      mnemonic: cleanMnemonic,
      myPin: vault.pin,
      expectedPkRootHex: vault.pkRootHex,
      nextSeqNum,
      revokedDeviceIdsJson: JSON.stringify(allRevokedIds),
      nowUnixSec: Math.floor(Date.now() / 1000),
    });

    onProgress('Enviando POST /v1/identities/revoke (expulsión WS 4001)...');
    const wireBytes = b64ToBytes(prep.wireB64);
    const res = await fetch(`${API_BASE}/v1/identities/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Pin': prep.revokeHeaders.xPin,
        'X-Timestamp': prep.revokeHeaders.xTimestamp,
        'X-Nonce': prep.revokeHeaders.xNonce,
        'X-Signature': prep.revokeHeaders.xSignature,
      },
      body: toArrayBuffer(wireBytes),
      credentials: 'omit',
      cache: 'no-store',
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`Fallo revocando dispositivo (${res.status}): ${txt.slice(0, 160)}`);
    }
    return { seqNum: prep.seqNum, revokedCount: allRevokedIds.length };
  }

  // ==========================================================================
  // SAFE BACKUP
  // ==========================================================================

  async uploadSafeBackup(
    vault: VaultState,
    mnemonic: string,
    onProgress: (msg: string) => void,
  ): Promise<{ revision: number; contactsCount: number }> {
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, ' ');
    let targetRev = (vault.safeBackupRevision || 0) + 1;
    let pendingPow: { powPayload: string; powMac: string; powNonce: string } | null = null;

    for (let attempt = 0; attempt < 4; attempt += 1) {
      onProgress(`Cifrando Safe Backup (rev #${targetRev}) en cubeta de 16 KiB...`);
      const exported = await this.worker.exportSafeBackup({
        mnemonic: cleanMnemonic,
        pin: vault.pin,
        contactsJson: JSON.stringify(vault.contacts),
        targetRevision: targetRev,
        nowUnixSec: Math.floor(Date.now() / 1000),
      });

      const wireBytes = b64ToBytes(exported.wireBlobB64);
      const sig = await this.worker.signSafeHttp({
        mnemonic: cleanMnemonic,
        method: 'PUT',
        pathWithQuery: exported.safePath,
        revision: exported.revision,
        rawBody: wireBytes,
        nowUnixSec: Math.floor(Date.now() / 1000),
      });

      const headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
        'X-Safe-PubKey': sig.xSafePubkey,
        'X-Safe-Revision': sig.xSafeRevision,
        'X-Timestamp': sig.xTimestamp,
        'X-Nonce': sig.xNonce,
        'X-Safe-Signature': sig.xSafeSignature,
      };
      if (pendingPow) {
        headers['X-Pow-Payload'] = pendingPow.powPayload;
        headers['X-Pow-Mac'] = pendingPow.powMac;
        headers['X-Pow-Nonce'] = pendingPow.powNonce;
      }

      onProgress(`Subiendo PUT ${exported.safePath}...`);
      const res = await fetch(`${API_BASE}${exported.safePath}`, {
        method: 'PUT',
        headers,
        body: toArrayBuffer(wireBytes),
        credentials: 'omit',
        cache: 'no-store',
      });

      if (res.status === 200) {
        vault.safeBackupRevision = exported.revision;
        return { revision: exported.revision, contactsCount: exported.contactsCount };
      }

      if (res.status === 428) {
        onProgress('Primer respaldo (428). Resolviendo PoW Argon2id (action=3) en Worker...');
        pendingPow = await this.solvePowChallenge(3, hexToBytes(exported.backupIdHex));
        continue;
      }

      if (res.status === 409) {
        const body = (await res.json().catch(() => ({}))) as { currentRevision?: string | number };
        const serverRev = Number(body.currentRevision ?? 0);
        pendingPow = null;
        targetRev = serverRev + 1;
        onProgress(`Conflicto 409 (servidor en rev #${serverRev}). Reintentando con rev #${targetRev}...`);
        continue;
      }

      const txt = await res.text().catch(() => '');
      throw new Error(`Error subiendo Safe Backup (${res.status}): ${txt.slice(0, 160)}`);
    }

    throw new Error('Se agotaron los reintentos de Safe Backup');
  }

  async downloadAndRestoreSafeBackup(
    mnemonic: string,
    existingVault: VaultState | null,
    onProgress: (msg: string) => void,
  ): Promise<RestoredSafeDto> {
    const cleanMnemonic = mnemonic.trim().replace(/\s+/g, ' ');
    onProgress('Derivando backup_id desde las 12 palabras...');
    const safeId = await this.worker.deriveSafeIdentity(cleanMnemonic);

    const sig = await this.worker.signSafeHttp({
      mnemonic: cleanMnemonic,
      method: 'GET',
      pathWithQuery: safeId.safePath,
      revision: 0,
      rawBody: new Uint8Array(0),
      nowUnixSec: Math.floor(Date.now() / 1000),
    });

    onProgress('Descargando respaldo cifrado...');
    const res = await fetch(`${API_BASE}${safeId.safePath}`, {
      method: 'GET',
      headers: {
        'X-Safe-PubKey': sig.xSafePubkey,
        'X-Safe-Revision': sig.xSafeRevision,
        'X-Timestamp': sig.xTimestamp,
        'X-Nonce': sig.xNonce,
        'X-Safe-Signature': sig.xSafeSignature,
      },
      credentials: 'omit',
      cache: 'no-store',
    });

    if (res.status === 404) {
      throw new Error('No existe ningún Safe Backup guardado para esas 12 palabras.');
    }
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} descargando Safe Backup: ${txt.slice(0, 160)}`);
    }

    const revHeader = res.headers.get('x-safe-revision');
    const serverRevision = Number(revHeader);
    if (!Number.isSafeInteger(serverRevision) || serverRevision <= 0) {
      throw new Error('Falta cabecera X-Safe-Revision en la respuesta del servidor.');
    }

    const blob = new Uint8Array(await res.arrayBuffer());
    onProgress(`Descifrando y fusionando contactos (rev #${serverRevision})...`);
    return this.worker.restoreSafeBackup({
      mnemonic: cleanMnemonic,
      serverRevision,
      wireBlob: blob,
      existingPin: existingVault?.pin ?? '',
      existingContactsJson: JSON.stringify(existingVault?.contacts ?? []),
    });
  }
}
