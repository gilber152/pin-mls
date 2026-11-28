import { consolidateVaultGroupsByPin, clearArchivedPinHistory, markSeqDeletedForPin } from './pinGroupConsolidator.js';
import type { VaultState } from '../types.js';

const DB_NAME = 'pin_mls_web_vault_v1';
const DB_VERSION = 2;
const STORE_NAME = 'vault';
const ALIAS_STORE = 'aliases';
const RECORD_KEY = 'primary';
const PREFS_KEY = '__prefs__';

export interface UiPreferences {
  soundEnabled: boolean;
  notificationsEnabled: boolean;
}

export type PinAliasMap = Record<string, string>;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
      if (!db.objectStoreNames.contains(ALIAS_STORE)) {
        db.createObjectStore(ALIAS_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function compactPinOnly(pin: string): string {
  return pin.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function canonicalPinKey(pin: string): string {
  const compact = compactPinOnly(pin);
  if (compact.length === 8) {
    return `${compact.slice(0, 4)}-${compact.slice(4)}`;
  }
  return pin.trim().toUpperCase();
}

function pinKeyVariants(pin: string): string[] {
  const raw = pin.trim().toUpperCase();
  const compact = compactPinOnly(pin);
  const canonical = canonicalPinKey(pin);
  return Array.from(new Set([raw, compact, canonical].filter((k) => k.length > 0)));
}

function parseControlDeleteSeq(text: string): number | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{') || !trimmed.includes('__pin_msg_delete')) return null;
  try {
    const obj = JSON.parse(trimmed) as { __pin_msg_delete?: unknown; targetSeq?: unknown };
    if (
      obj.__pin_msg_delete === 1 &&
      typeof obj.targetSeq === 'number' &&
      Number.isInteger(obj.targetSeq) &&
      obj.targetSeq > 0
    ) {
      return obj.targetSeq;
    }
  } catch {
    // No es un sobre de control válido
  }
  return null;
}

function purgeControlDeleteMessagesFromVault(state: VaultState | null): boolean {
  if (!state || !state.groups) return false;
  let changed = false;

  for (const grp of Object.values(state.groups)) {
    if (!grp || !Array.isArray(grp.messages) || grp.messages.length === 0) continue;

    const deletions: Array<{ targetSeq: number; senderCompact: string; mine: boolean }> = [];
    for (const msg of grp.messages) {
      if (typeof msg.text !== 'string') continue;
      const targetSeq = parseControlDeleteSeq(msg.text);
      if (targetSeq !== null) {
        if (typeof grp.peerPin === 'string' && grp.peerPin.trim()) {
          markSeqDeletedForPin(grp.peerPin, msg.senderPin || '', targetSeq, Boolean(msg.mine));
        }
        deletions.push({
          targetSeq,
          senderCompact: compactPinOnly(msg.senderPin || ''),
          mine: Boolean(msg.mine),
        });
      }
    }

    if (deletions.length === 0) continue;

    const beforeLen = grp.messages.length;
    grp.messages = grp.messages.filter((msg) => {
      if (typeof msg.text === 'string' && parseControlDeleteSeq(msg.text) !== null) {
        return false;
      }
      const msgSenderCompact = compactPinOnly(msg.senderPin || '');
      for (const del of deletions) {
        if (msg.groupSeq !== del.targetSeq) continue;
        if ((del.senderCompact && msgSenderCompact === del.senderCompact) || (msg.mine && del.mine)) {
          return false;
        }
      }
      return true;
    });

    if (grp.messages.length !== beforeLen) {
      changed = true;
    }
  }

  return changed;
}

async function writeVaultRecord(state: VaultState): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(state, RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadVault(): Promise<VaultState | null> {
  const loaded = await loadVaultRaw();
  const consolidated = consolidateVaultGroupsByPin(loaded);
  if (consolidated && purgeControlDeleteMessagesFromVault(consolidated)) {
    await writeVaultRecord(consolidated).catch(() => {});
  }
  return consolidated;
}

async function loadVaultRaw(): Promise<VaultState | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(RECORD_KEY);
    req.onsuccess = () => resolve((req.result as VaultState | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function saveVault(state: VaultState): Promise<void> {
  consolidateVaultGroupsByPin(state);
  purgeControlDeleteMessagesFromVault(state);
  await writeVaultRecord(state);
}

export async function wipeVault(): Promise<void> {
  clearArchivedPinHistory();
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function normalizePinKey(pin: string): string {
  return canonicalPinKey(pin);
}

export async function loadPinAliases(): Promise<PinAliasMap> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readonly');
    const req = tx.objectStore(ALIAS_STORE).getAll();
    const keysReq = tx.objectStore(ALIAS_STORE).getAllKeys();
    tx.oncomplete = () => {
      const map: PinAliasMap = {};
      const keys = keysReq.result ?? [];
      const vals = req.result ?? [];
      for (let i = 0; i < keys.length; i++) {
        const key = String(keys[i]);
        if (key === PREFS_KEY) continue;
        const val = vals[i];
        if (typeof val === 'string' && val.trim().length > 0) {
          map[normalizePinKey(key)] = val.trim();
        }
      }
      resolve(map);
    };
    tx.onerror = () => reject(tx.error);
  });
}

export async function setPinAlias(pin: string, alias: string): Promise<PinAliasMap> {
  const next = await setPinAliasRaw(pin, alias);
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('pin:aliases-updated', { detail: { aliases: next, source: 'local', changedPin: normalizePinKey(pin), changedAlias: alias.trim() } }));
  }
  return next;
}

async function setPinAliasRaw(pin: string, alias: string): Promise<PinAliasMap> {
  const cleanPin = canonicalPinKey(pin);
  const variants = pinKeyVariants(pin);
  const cleanAlias = alias.trim();
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readwrite');
    const store = tx.objectStore(ALIAS_STORE);
    for (const variant of variants) {
      store.delete(variant);
    }
    if (cleanAlias && cleanPin) {
      store.put(cleanAlias, cleanPin);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return loadPinAliases();
}

export async function loadUiPreferences(): Promise<UiPreferences> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readonly');
    const req = tx.objectStore(ALIAS_STORE).get(PREFS_KEY);
    req.onsuccess = () => {
      const data = (req.result as Partial<UiPreferences> | undefined) ?? {};
      resolve({
        soundEnabled: data.soundEnabled ?? true,
        notificationsEnabled: data.notificationsEnabled ?? true,
      });
    };
    req.onerror = () => reject(req.error);
  });
}

export async function saveUiPreferences(prefs: UiPreferences): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readwrite');
    tx.objectStore(ALIAS_STORE).put(prefs, PREFS_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function applySyncedPinAliases(
  updates: Record<string, string>,
  removedPins: string[] = [],
): Promise<PinAliasMap> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readwrite');
    const store = tx.objectStore(ALIAS_STORE);
    for (const rawPin of removedPins) {
      for (const variant of pinKeyVariants(rawPin)) {
        store.delete(variant);
      }
    }
    for (const [rawPin, rawAlias] of Object.entries(updates)) {
      const cleanPin = canonicalPinKey(rawPin);
      const variants = pinKeyVariants(rawPin);
      const cleanAlias = rawAlias.trim();
      for (const variant of variants) {
        store.delete(variant);
      }
      if (cleanPin && cleanAlias) {
        store.put(cleanAlias, cleanPin);
      }
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  const next = await loadPinAliases();
  if (typeof window !== 'undefined') {
    window.dispatchEvent(
      new CustomEvent('pin:aliases-updated', {
        detail: { aliases: next, source: 'remote-sync' },
      }),
    );
  }
  return next;
}
