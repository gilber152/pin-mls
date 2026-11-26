import type { VaultContact } from '../types.js';

export interface IdentityRegistrationDto {
  pkRootB64Url: string;
  pkInviteB64Url: string;
  sigInviteB64Url: string;
  proofOfPossessionB64Url: string;
  pkRootHex: string;
  skInviteHex: string;
  pkInviteHex: string;
}

export interface RootHttpHeadersDto {
  xPin: string;
  xTimestamp: string;
  xNonce: string;
  xSignature: string;
}

export interface DeviceEnrollmentDto {
  deviceId: string;
  skDevHex: string;
  pkDevHex: string;
  deviceCertB64: string;
  enrollHeaders: RootHttpHeadersDto;
}

export interface DeviceHttpHeadersDto {
  xDeviceId: string;
  xTimestamp: string;
  xNonce: string;
  xSignature: string;
}

export interface MlsRuntimeInitDto {
  sigPkB64: string;
  storageJson: string;
}

export interface MlsGeneratedKpItemDto {
  kpRef: string;
  kpRaw: string;
  isLastResort: boolean;
  expiresAt: number;
}

export interface MlsGeneratedKpsDto {
  keyPackages: MlsGeneratedKpItemDto[];
  storageJson: string;
}

export interface MlsCreatedGroupDto {
  groupIdB64: string;
  groupIdB64Url: string;
  cipherSuite: number;
  baseEpoch: number;
  commitRawB64: string;
  welcomeRawB64: string;
  addedDeviceIds: string[];
  storageJson: string;
}

export interface MlsEpochStateDto {
  epoch: number;
  storageJson: string;
}

export interface MlsJoinedGroupDto {
  groupIdB64: string;
  groupIdB64Url: string;
  peerPin: string;
  epoch: number;
  storageJson: string;
}

export interface MlsPreparedCommitDto {
  skipped: boolean;
  baseEpoch: number;
  commitRawB64: string;
  welcomeRawB64: string | null;
  storageJson: string;
}

export interface MlsEncryptedMsgDto {
  epoch: number;
  ciphertextB64: string;
  storageJson: string;
}

export interface MlsProcessedEnvelopeDto {
  kind: 'application' | 'commit' | 'proposal';
  epoch: number;
  active: boolean;
  senderPin: string;
  senderDeviceId: string;
  plaintextJson: string | null;
  storageJson: string;
}

export interface StartedLinkSessionDto {
  deviceId: string;
  skDevHex: string;
  pkDevHex: string;
  skLinkEphHex: string;
  pkLinkEphHex: string;
  readSecretB64Url: string;
  sessionIdHex: string;
  linkQrUri: string;
}

export interface ParsedLinkQrDto {
  sessionIdHex: string;
  deviceId: string;
  pkDevHex: string;
  pkLinkEphHex: string;
}

export interface LinkAuthorizationDto {
  sessionIdHex: string;
  targetDeviceId: string;
  deviceCertB64: string;
  enrollHeaders: RootHttpHeadersDto;
  sealedBundleB64: string;
}

export interface LinkBundlePayloadDto {
  pin: string;
  pkRootHex: string;
  skInviteHex: string;
  pkInviteHex: string;
  safeBackupRevision: number;
  contacts: VaultContact[];
}

export interface PreparedRevocationDto {
  seqNum: number;
  wireB64: string;
  revokeHeaders: RootHttpHeadersDto;
}

export interface SafeIdentityDto {
  backupIdHex: string;
  safePath: string;
  pkSafeAuthB64Url: string;
}

export interface ExportedSafeDto {
  backupIdHex: string;
  safePath: string;
  revision: number;
  contactsCount: number;
  wireBlobB64: string;
}

export interface SafeHttpHeadersDto {
  xSafePubkey: string;
  xSafeRevision: string;
  xTimestamp: string;
  xNonce: string;
  xSafeSignature: string;
}

export interface RestoredSafeDto {
  restoredPin: string;
  restoredRevision: number;
  contactsImported: number;
  contactsUpdated: number;
  conflictingPins: string[];
  mergedContacts: VaultContact[];
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

export class CryptoWorkerClient {
  private worker: Worker;
  private nextId = 1;
  private pending = new Map<number, PendingCall>();

  constructor() {
    this.worker = new Worker(new URL('./mls.worker.ts', import.meta.url), {
      type: 'module',
    });
    this.worker.onmessage = (
      event: MessageEvent<{ id: number; ok: boolean; result?: unknown; error?: string }>,
    ) => {
      const { id, ok, result, error } = event.data;
      const entry = this.pending.get(id);
      if (!entry) return;
      this.pending.delete(id);
      if (ok) {
        entry.resolve(result);
      } else {
        entry.reject(new Error(error || 'Error interno en WASM worker'));
      }
    };
  }

  private call<T>(op: string, args: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (v) => resolve(v as T),
        reject,
      });
      this.worker.postMessage({ id, op, args });
    });
  }

  generateMnemonic(): Promise<string> {
    return this.call('generateMnemonic');
  }

  deriveIdentityRegistration(mnemonic: string): Promise<IdentityRegistrationDto> {
    return this.call('deriveIdentityRegistration', { mnemonic });
  }

  solvePow(params: {
    challengePayloadRaw: Uint8Array;
    challengeId16: Uint8Array;
    subjectBytes: Uint8Array;
    difficultyBits: number;
  }): Promise<Uint8Array> {
    return this.call('solvePow', params);
  }

  prepareDeviceEnrollment(mnemonic: string, pin: string, nowUnixSec: number): Promise<DeviceEnrollmentDto> {
    return this.call('prepareDeviceEnrollment', { mnemonic, pin, nowUnixSec });
  }

  signDeviceHttp(params: {
    skDevHex: string;
    deviceId: string;
    method: string;
    pathWithQuery: string;
    rawBody: Uint8Array;
    nowUnixSec: number;
  }): Promise<DeviceHttpHeadersDto> {
    return this.call('signDeviceHttp', params);
  }

  sealInvite(params: {
    senderPin: string;
    targetPin: string;
    targetPkRootB64Url: string;
    targetPkInviteB64Url: string;
    targetSigInviteB64Url: string;
    note: string;
  }): Promise<{ ciphertextB64: string; verifiedPkRootB64: string }> {
    return this.call('sealInvite', params);
  }

  openInvite(params: {
    skInviteHex: string;
    pkInviteHex: string;
    myPin: string;
    ciphertextB64: string;
  }): Promise<{ senderPin: string; note: string }> {
    return this.call('openInvite', params);
  }

  buildKeyPackageGrant(params: {
    targetPin: string;
    requesterPin: string;
    signerDeviceId: string;
    skDevHex: string;
    nowUnixSec: number;
  }): Promise<string> {
    return this.call('buildKeyPackageGrant', params);
  }

  // ---- OpenMLS RFC 9420 ----
  mlsInitRuntime(params: {
    storageJson: string;
    pin: string;
    deviceId: string;
    sigPkB64: string;
  }): Promise<MlsRuntimeInitDto> {
    return this.call('mlsInitRuntime', params);
  }

  mlsGenerateKeyPackages(params: {
    count: number;
    includeLastResort: boolean;
    nowUnixSec: number;
  }): Promise<MlsGeneratedKpsDto> {
    return this.call('mlsGenerateKeyPackages', params);
  }

  mlsCreateGroupAndAddMembers(peerKpsRawB64Json: string): Promise<MlsCreatedGroupDto> {
    return this.call('mlsCreateGroupAndAddMembers', { peerKpsRawB64Json });
  }

  mlsConfirmPendingCommit(groupIdB64: string): Promise<MlsEpochStateDto> {
    return this.call('mlsConfirmPendingCommit', { groupIdB64 });
  }

  mlsClearPendingCommit(groupIdB64: string): Promise<MlsEpochStateDto> {
    return this.call('mlsClearPendingCommit', { groupIdB64 });
  }

  mlsJoinFromWelcome(welcomeRawB64: string): Promise<MlsJoinedGroupDto> {
    return this.call('mlsJoinFromWelcome', { welcomeRawB64 });
  }

  mlsPrepareAddMember(groupIdB64: string, targetKpRawB64: string): Promise<MlsPreparedCommitDto> {
    return this.call('mlsPrepareAddMember', { groupIdB64, targetKpRawB64 });
  }

  mlsPrepareRemoveDevice(groupIdB64: string, targetDeviceId: string): Promise<MlsPreparedCommitDto> {
    return this.call('mlsPrepareRemoveDevice', { groupIdB64, targetDeviceId });
  }

  mlsEncryptMessage(groupIdB64: string, plaintextJson: string): Promise<MlsEncryptedMsgDto> {
    return this.call('mlsEncryptMessage', { groupIdB64, plaintextJson });
  }

  mlsProcessEnvelope(groupIdB64: string, envelopeRawB64: string): Promise<MlsProcessedEnvelopeDto> {
    return this.call('mlsProcessEnvelope', { groupIdB64, envelopeRawB64 });
  }

  // ---- LinkQr & Revocation ----
  startLinkSession(): Promise<StartedLinkSessionDto> {
    return this.call('startLinkSession');
  }

  parseLinkQr(uri: string): Promise<ParsedLinkQrDto> {
    return this.call('parseLinkQr', { uri });
  }

  prepareLinkAuthorization(params: {
    mnemonic: string;
    myPin: string;
    expectedPkRootHex: string;
    linkQrUri: string;
    bundlePayloadJson: string;
    nowUnixSec: number;
  }): Promise<LinkAuthorizationDto> {
    return this.call('prepareLinkAuthorization', params);
  }

  openLinkBundle(params: {
    skLinkEphHex: string;
    sessionIdHex: string;
    deviceId: string;
    bundleWire: Uint8Array;
  }): Promise<LinkBundlePayloadDto> {
    return this.call('openLinkBundle', params);
  }

  prepareRevocationManifest(params: {
    mnemonic: string;
    myPin: string;
    expectedPkRootHex: string;
    nextSeqNum: number;
    revokedDeviceIdsJson: string;
    nowUnixSec: number;
  }): Promise<PreparedRevocationDto> {
    return this.call('prepareRevocationManifest', params);
  }

  // ---- Safe Backup ----
  deriveSafeIdentity(mnemonic: string): Promise<SafeIdentityDto> {
    return this.call('deriveSafeIdentity', { mnemonic });
  }

  exportSafeBackup(params: {
    mnemonic: string;
    pin: string;
    contactsJson: string;
    targetRevision: number;
    nowUnixSec: number;
  }): Promise<ExportedSafeDto> {
    return this.call('exportSafeBackup', params);
  }

  signSafeHttp(params: {
    mnemonic: string;
    method: 'PUT' | 'GET' | 'DELETE';
    pathWithQuery: string;
    revision: number;
    rawBody: Uint8Array;
    nowUnixSec: number;
  }): Promise<SafeHttpHeadersDto> {
    return this.call('signSafeHttp', params);
  }

  restoreSafeBackup(params: {
    mnemonic: string;
    serverRevision: number;
    wireBlob: Uint8Array;
    existingPin: string;
    existingContactsJson: string;
  }): Promise<RestoredSafeDto> {
    return this.call('restoreSafeBackup', params);
  }
}
