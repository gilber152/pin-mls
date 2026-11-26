/* tslint:disable */
/* eslint-disable */

export function buildKeyPackageGrantB64Url(target_pin: string, requester_pin: string, signer_device_id: string, sk_dev_hex: string, now_unix_sec: number): string;

export function deriveIdentityRegistrationJson(mnemonic_12_words: string): string;

export function deriveSafeIdentityJson(mnemonic_12_words: string): string;

export function exportSafeBackupJson(mnemonic_12_words: string, pin: string, contacts_json: string, target_revision: number, now_unix_sec: number): string;

export function generateMnemonic12Words(): string;

export function mlsClearPendingCommitJson(group_id_b64: string): string;

export function mlsConfirmPendingCommitJson(group_id_b64: string): string;

export function mlsCreateGroupAndAddMembersJson(peer_kps_raw_b64_json: string): string;

export function mlsEncryptMessageJson(group_id_b64: string, plaintext_json: string): string;

export function mlsGenerateKeyPackagesJson(count: number, include_last_resort: boolean, now_unix_sec: number): string;

export function mlsInitRuntimeJson(storage_json: string, pin: string, device_id: string, sig_pk_b64: string): string;

export function mlsJoinFromWelcomeJson(welcome_raw_b64: string): string;

export function mlsPrepareAddMemberJson(group_id_b64: string, target_kp_raw_b64: string): string;

export function mlsPrepareRemoveDeviceJson(group_id_b64: string, target_device_id: string): string;

export function mlsProcessEnvelopeJson(group_id_b64: string, envelope_raw_b64: string): string;

export function openInviteJson(sk_invite_hex: string, pk_invite_hex: string, my_pin: string, ciphertext_b64: string): string;

export function openLinkBundleJson(sk_link_eph_hex: string, session_id_hex: string, device_id: string, bundle_wire: Uint8Array | number[]): string;

export function parseLinkQrJson(uri: string): string;

export function prepareDeviceEnrollmentJson(mnemonic_12_words: string, pin: string, now_unix_sec: number): string;

export function prepareLinkAuthorizationJson(mnemonic_12_words: string, my_pin: string, expected_pk_root_hex: string, link_qr_uri: string, bundle_payload_json: string, now_unix_sec: number): string;

export function prepareRevocationManifestJson(mnemonic_12_words: string, my_pin: string, expected_pk_root_hex: string, next_seq_num: number, revoked_device_ids_json: string, now_unix_sec: number): string;

export function restoreSafeBackupJson(mnemonic_12_words: string, server_revision: number, wire_blob: Uint8Array | number[], existing_pin: string, existing_contacts_json: string): string;

export function sealInviteJson(sender_pin: string, target_pin: string, target_pk_root_b64_url: string, target_pk_invite_b64_url: string, target_sig_invite_b64_url: string, note: string): string;

export function signDeviceHttpJson(sk_dev_hex: string, device_id: string, method: string, path_with_query: string, raw_body: Uint8Array | number[], now_unix_sec: number): string;

export function signSafeHttpJson(mnemonic_12_words: string, method: string, path_with_query: string, revision: number, raw_body: Uint8Array | number[], now_unix_sec: number): string;

export function solvePowNonce(challenge_payload_raw: Uint8Array | number[], challenge_id_16: Uint8Array | number[], subject_bytes: Uint8Array | number[], difficulty_bits: number): Uint8Array;

export function startLinkSessionJson(): string;

export function wasm_init(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly buildKeyPackageGrantB64Url: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly deriveIdentityRegistrationJson: (a: number, b: number) => [number, number, number, number];
    readonly deriveSafeIdentityJson: (a: number, b: number) => [number, number, number, number];
    readonly exportSafeBackupJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly generateMnemonic12Words: () => [number, number, number, number];
    readonly mlsClearPendingCommitJson: (a: number, b: number) => [number, number, number, number];
    readonly mlsConfirmPendingCommitJson: (a: number, b: number) => [number, number, number, number];
    readonly mlsCreateGroupAndAddMembersJson: (a: number, b: number) => [number, number, number, number];
    readonly mlsEncryptMessageJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly mlsGenerateKeyPackagesJson: (a: number, b: number, c: number) => [number, number, number, number];
    readonly mlsInitRuntimeJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly mlsJoinFromWelcomeJson: (a: number, b: number) => [number, number, number, number];
    readonly mlsPrepareAddMemberJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly mlsPrepareRemoveDeviceJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly mlsProcessEnvelopeJson: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly openInviteJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly openLinkBundleJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly parseLinkQrJson: (a: number, b: number) => [number, number, number, number];
    readonly prepareDeviceEnrollmentJson: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly prepareLinkAuthorizationJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly prepareRevocationManifestJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly restoreSafeBackupJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly sealInviteJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly signDeviceHttpJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly signSafeHttpJson: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly solvePowNonce: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly startLinkSessionJson: () => [number, number, number, number];
    readonly wasm_init: () => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
