import { consolidateVaultGroupsByPin, clearArchivedPinHistory } from './pinGroupConsolidator.js';
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

export async function loadVault(): Promise<VaultState | null> {
  const loaded = await loadVaultRaw();
  return consolidateVaultGroupsByPin(loaded);
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
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(state, RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
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
  return pin.trim().toUpperCase();
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
  const cleanPin = normalizePinKey(pin);
  const cleanAlias = alias.trim();
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(ALIAS_STORE, 'readwrite');
    const store = tx.objectStore(ALIAS_STORE);
    if (!cleanAlias) {
      store.delete(cleanPin);
    } else {
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
