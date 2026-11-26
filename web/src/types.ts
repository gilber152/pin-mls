export interface VaultContact {
  pin: string;
  pk_root_b64: string;
  trust_state: 'tofu' | 'verified';
  alias_local: string | null;
  updated_at: number;
}

export interface VaultIncomingInvite {
  requestId: string;
  senderPin: string;
  note: string;
  createdAt: string;
}

export interface VaultChatMessage {
  groupSeq: number;
  senderPin: string;
  senderDeviceId: string;
  text: string;
  sentAtMs: number;
  mine: boolean;
}

export interface VaultGroup {
  groupIdB64: string;
  groupIdB64Url: string;
  peerPin: string;
  cipherSuite: number;
  epoch: number;
  active: boolean;
  lastSeq: number;
  messages: VaultChatMessage[];
}

export interface VaultState {
  vaultSchemaVersion: number;
  pin: string;
  deviceId: string;
  pkRootHex: string;
  skInviteHex: string;
  pkInviteHex: string;
  skDevHex: string;
  pkDevHex: string;
  mlsSigPkB64: string;
  mlsStorageJson: string;
  safeBackupRevision: number;
  contacts: VaultContact[];
  incomingInvites: VaultIncomingInvite[];
  groups: Record<string, VaultGroup>;
}
