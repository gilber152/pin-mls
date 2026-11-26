import init, {
  generateMnemonic12Words,
  deriveIdentityRegistrationJson,
  solvePowNonce,
  prepareDeviceEnrollmentJson,
  signDeviceHttpJson,
  sealInviteJson,
  openInviteJson,
  buildKeyPackageGrantB64Url,
  mlsInitRuntimeJson,
  mlsGenerateKeyPackagesJson,
  mlsCreateGroupAndAddMembersJson,
  mlsConfirmPendingCommitJson,
  mlsClearPendingCommitJson,
  mlsJoinFromWelcomeJson,
  mlsPrepareAddMemberJson,
  mlsPrepareRemoveDeviceJson,
  mlsEncryptMessageJson,
  mlsProcessEnvelopeJson,
  startLinkSessionJson,
  parseLinkQrJson,
  prepareLinkAuthorizationJson,
  openLinkBundleJson,
  prepareRevocationManifestJson,
  deriveSafeIdentityJson,
  exportSafeBackupJson,
  signSafeHttpJson,
  restoreSafeBackupJson,
} from '../wasm/pin_web_wasm.js';

let wasmReadyPromise: Promise<unknown> | null = null;

function ensureWasm(): Promise<unknown> {
  if (!wasmReadyPromise) {
    wasmReadyPromise = init();
  }
  return wasmReadyPromise;
}

interface WorkerRequest {
  id: number;
  op: string;
  args: Record<string, unknown>;
}

const workerCtx = self as unknown as {
  onmessage: ((ev: MessageEvent<WorkerRequest>) => void) | null;
  postMessage: (msg: unknown) => void;
};

workerCtx.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const { id, op, args } = event.data;
  try {
    await ensureWasm();
    let result: unknown;

    switch (op) {
      case 'generateMnemonic':
        result = generateMnemonic12Words();
        break;

      case 'deriveIdentityRegistration':
        result = JSON.parse(deriveIdentityRegistrationJson(String(args.mnemonic)));
        break;

      case 'solvePow':
        result = solvePowNonce(
          args.challengePayloadRaw as Uint8Array,
          args.challengeId16 as Uint8Array,
          args.subjectBytes as Uint8Array,
          Number(args.difficultyBits),
        );
        break;

      case 'prepareDeviceEnrollment':
        result = JSON.parse(
          prepareDeviceEnrollmentJson(
            String(args.mnemonic),
            String(args.pin),
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'signDeviceHttp':
        result = JSON.parse(
          signDeviceHttpJson(
            String(args.skDevHex),
            String(args.deviceId),
            String(args.method),
            String(args.pathWithQuery),
            args.rawBody as Uint8Array,
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'sealInvite':
        result = JSON.parse(
          sealInviteJson(
            String(args.senderPin),
            String(args.targetPin),
            String(args.targetPkRootB64Url),
            String(args.targetPkInviteB64Url),
            String(args.targetSigInviteB64Url),
            String(args.note ?? ''),
          ),
        );
        break;

      case 'openInvite':
        result = JSON.parse(
          openInviteJson(
            String(args.skInviteHex),
            String(args.pkInviteHex),
            String(args.myPin),
            String(args.ciphertextB64),
          ),
        );
        break;

      case 'buildKeyPackageGrant':
        result = buildKeyPackageGrantB64Url(
          String(args.targetPin),
          String(args.requesterPin),
          String(args.signerDeviceId),
          String(args.skDevHex),
          Number(args.nowUnixSec),
        );
        break;

      // ---- OpenMLS RFC 9420 ----
      case 'mlsInitRuntime':
        result = JSON.parse(
          mlsInitRuntimeJson(
            String(args.storageJson ?? ''),
            String(args.pin),
            String(args.deviceId),
            String(args.sigPkB64 ?? ''),
          ),
        );
        break;

      case 'mlsGenerateKeyPackages':
        result = JSON.parse(
          mlsGenerateKeyPackagesJson(
            Number(args.count),
            Boolean(args.includeLastResort),
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'mlsCreateGroupAndAddMembers':
        result = JSON.parse(
          mlsCreateGroupAndAddMembersJson(String(args.peerKpsRawB64Json)),
        );
        break;

      case 'mlsConfirmPendingCommit':
        result = JSON.parse(mlsConfirmPendingCommitJson(String(args.groupIdB64)));
        break;

      case 'mlsClearPendingCommit':
        result = JSON.parse(mlsClearPendingCommitJson(String(args.groupIdB64)));
        break;

      case 'mlsJoinFromWelcome':
        result = JSON.parse(mlsJoinFromWelcomeJson(String(args.welcomeRawB64)));
        break;

      case 'mlsPrepareAddMember':
        result = JSON.parse(
          mlsPrepareAddMemberJson(
            String(args.groupIdB64),
            String(args.targetKpRawB64),
          ),
        );
        break;

      case 'mlsPrepareRemoveDevice':
        result = JSON.parse(
          mlsPrepareRemoveDeviceJson(
            String(args.groupIdB64),
            String(args.targetDeviceId),
          ),
        );
        break;

      case 'mlsEncryptMessage':
        result = JSON.parse(
          mlsEncryptMessageJson(
            String(args.groupIdB64),
            String(args.plaintextJson),
          ),
        );
        break;

      case 'mlsProcessEnvelope':
        result = JSON.parse(
          mlsProcessEnvelopeJson(
            String(args.groupIdB64),
            String(args.envelopeRawB64),
          ),
        );
        break;

      // ---- LinkQr & Revocation ----
      case 'startLinkSession':
        result = JSON.parse(startLinkSessionJson());
        break;

      case 'parseLinkQr':
        result = JSON.parse(parseLinkQrJson(String(args.uri)));
        break;

      case 'prepareLinkAuthorization':
        result = JSON.parse(
          prepareLinkAuthorizationJson(
            String(args.mnemonic),
            String(args.myPin),
            String(args.expectedPkRootHex),
            String(args.linkQrUri),
            String(args.bundlePayloadJson),
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'openLinkBundle':
        result = JSON.parse(
          openLinkBundleJson(
            String(args.skLinkEphHex),
            String(args.sessionIdHex),
            String(args.deviceId),
            args.bundleWire as Uint8Array,
          ),
        );
        break;

      case 'prepareRevocationManifest':
        result = JSON.parse(
          prepareRevocationManifestJson(
            String(args.mnemonic),
            String(args.myPin),
            String(args.expectedPkRootHex),
            Number(args.nextSeqNum),
            String(args.revokedDeviceIdsJson),
            Number(args.nowUnixSec),
          ),
        );
        break;

      // ---- Safe Backup ----
      case 'deriveSafeIdentity':
        result = JSON.parse(deriveSafeIdentityJson(String(args.mnemonic)));
        break;

      case 'exportSafeBackup':
        result = JSON.parse(
          exportSafeBackupJson(
            String(args.mnemonic),
            String(args.pin),
            String(args.contactsJson),
            Number(args.targetRevision),
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'signSafeHttp':
        result = JSON.parse(
          signSafeHttpJson(
            String(args.mnemonic),
            String(args.method),
            String(args.pathWithQuery),
            Number(args.revision),
            args.rawBody as Uint8Array,
            Number(args.nowUnixSec),
          ),
        );
        break;

      case 'restoreSafeBackup':
        result = JSON.parse(
          restoreSafeBackupJson(
            String(args.mnemonic),
            Number(args.serverRevision),
            args.wireBlob as Uint8Array,
            String(args.existingPin ?? ''),
            String(args.existingContactsJson),
          ),
        );
        break;

      default:
        throw new Error(`Operación desconocida en worker: ${op}`);
    }

    workerCtx.postMessage({ id, ok: true, result });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    workerCtx.postMessage({ id, ok: false, error: message });
  }
};
