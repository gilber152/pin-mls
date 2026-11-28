const PIN_HISTORY_STORAGE_KEY = 'pin_mls_pin_history_v1';
const GROUP_FIRST_SEEN_KEY = 'pin_mls_group_first_seen_v1';
const PIN_DELETED_MSGS_STORAGE_KEY = 'pin_mls_deleted_msgs_v1';

type AnyRecord = Record<string, unknown>;

interface StoredPinHistory {
  [canonicalPin: string]: AnyRecord[];
}

interface FirstSeenMap {
  [groupIdB64: string]: number;
}

interface DeletedPinBucket {
  keys: string[];
  seqs: string[];
}

interface StoredDeletedMessages {
  [canonicalPin: string]: DeletedPinBucket;
}

function normalizeCompact(pin: string): string {
  return pin.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function toCanonicalPin(pin: string): string {
  const c = normalizeCompact(pin);
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : pin.trim().toUpperCase();
}

function extractCleanMessageText(rawText: string): string {
  const trimmed = rawText.trim();
  if (!trimmed) return '';
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (parsed && typeof parsed === 'object' && 'text' in parsed) {
      const val = (parsed as { text?: unknown }).text;
      if (typeof val === 'string' && val.trim()) return val.trim();
    }
  } catch {
    // Texto plano
  }
  return trimmed;
}

function parseControlDeleteSeq(rawText: string): number | null {
  const trimmed = rawText.trim();
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
    // No es señal de control
  }
  return null;
}

function loadJsonStorage<T>(key: string, fallback: T): T {
  if (typeof window === 'undefined') return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as T;
    }
  } catch {
    // Ignorado si localStorage no está disponible
  }
  return fallback;
}

function saveJsonStorage(key: string, value: unknown): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignorado si excede cuota
  }
}

function getOrCreateDeletedBucket(
  store: StoredDeletedMessages,
  canonicalPin: string,
): DeletedPinBucket {
  const existing = store[canonicalPin];
  if (existing && Array.isArray(existing.keys) && Array.isArray(existing.seqs)) {
    return existing;
  }
  const fresh: DeletedPinBucket = { keys: [], seqs: [] };
  store[canonicalPin] = fresh;
  return fresh;
}

export function clearArchivedPinHistory(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(PIN_HISTORY_STORAGE_KEY);
    window.localStorage.removeItem(GROUP_FIRST_SEEN_KEY);
    window.localStorage.removeItem(PIN_DELETED_MSGS_STORAGE_KEY);
  } catch {
    // Ignorado
  }
}

function getDirectPeerPin(grp: AnyRecord, ownCompact: string): string | null {
  const rawPeer = grp['peerPin'];
  if (typeof rawPeer !== 'string') return null;
  const trimmed = rawPeer.trim();
  // Evitar agrupar chats multi-PIN (ej. "ABCD-EFGH, JKLM-NPQR")
  if (!trimmed || trimmed.includes(',')) return null;
  const compact = normalizeCompact(trimmed);
  if (compact.length !== 8 || compact === ownCompact) return null;
  return toCanonicalPin(compact);
}

function getMessageTime(msg: AnyRecord): number {
  const t = msg['sentAtMs'] ?? msg['timestamp'] ?? msg['createdAtMs'] ?? 0;
  return typeof t === 'number' && Number.isFinite(t) ? t : 0;
}

function getMessageSeq(msg: AnyRecord): number {
  const s = msg['groupSeq'] ?? msg['seq'] ?? 0;
  return typeof s === 'number' && Number.isFinite(s) ? s : 0;
}

function getLastMessageTime(grp: AnyRecord): number {
  if (!Array.isArray(grp['messages'])) return 0;
  let maxTime = 0;
  for (const item of grp['messages'] as unknown[]) {
    if (item && typeof item === 'object') {
      const t = getMessageTime(item as AnyRecord);
      if (t > maxTime) maxTime = t;
    }
  }
  return maxTime;
}

function buildMessageDedupKey(msg: AnyRecord): string {
  const id = msg['id'] ?? msg['msgId'] ?? msg['clientMsgId'];
  if (typeof id === 'string' && id.trim()) {
    return `id:${id.trim()}`;
  }
  const mine = msg['mine'] === true ? '1' : '0';
  const sender = typeof msg['senderPin'] === 'string' ? normalizeCompact(msg['senderPin']) : '';
  const ts = getMessageTime(msg);
  const rawText = typeof msg['text'] === 'string' ? msg['text'] : '';
  const cleanText = extractCleanMessageText(rawText).trim();
  return `sig:${mine}|${sender}|${ts}|${cleanText}`;
}

function buildSeqToken(senderPin: string, seq: number): string {
  return `${normalizeCompact(senderPin)}:${seq}`;
}

function filterMessagesAgainstDeleted(
  canonicalPin: string,
  messages: AnyRecord[],
  deletedStore: StoredDeletedMessages,
): { filtered: AnyRecord[]; deletedDirty: boolean } {
  const bucket = getOrCreateDeletedBucket(deletedStore, canonicalPin);
  const keySet = new Set(bucket.keys);
  const seqSet = new Set(bucket.seqs);
  let deletedDirty = false;

  // 1. Absorber cualquier sobre de control __pin_msg_delete presente en los mensajes
  for (const msg of messages) {
    const rawText = typeof msg['text'] === 'string' ? msg['text'] : '';
    const targetSeq = parseControlDeleteSeq(rawText);
    if (targetSeq === null) continue;
    const sender = typeof msg['senderPin'] === 'string' ? msg['senderPin'] : '';
    const token = buildSeqToken(sender, targetSeq);
    if (normalizeCompact(sender) && !seqSet.has(token)) {
      seqSet.add(token);
      bucket.seqs.push(token);
      deletedDirty = true;
    }
    if (msg['mine'] === true) {
      const mineToken = `mine:${targetSeq}`;
      if (!seqSet.has(mineToken)) {
        seqSet.add(mineToken);
        bucket.seqs.push(mineToken);
        deletedDirty = true;
      }
    }
  }

  // 2. Descartar señales de control y mensajes marcados como eliminados
  const filtered = messages.filter((msg) => {
    const rawText = typeof msg['text'] === 'string' ? msg['text'] : '';
    if (parseControlDeleteSeq(rawText) !== null) return false;

    const dedupKey = buildMessageDedupKey(msg);
    if (keySet.has(dedupKey)) return false;

    const seq = getMessageSeq(msg);
    if (seq > 0) {
      const sender = typeof msg['senderPin'] === 'string' ? msg['senderPin'] : '';
      if (normalizeCompact(sender) && seqSet.has(buildSeqToken(sender, seq))) {
        return false;
      }
      if (msg['mine'] === true && seqSet.has(`mine:${seq}`)) {
        return false;
      }
    }
    return true;
  });

  return { filtered, deletedDirty };
}

function mergeMessageArrays(lists: AnyRecord[][]): AnyRecord[] {
  const byKey = new Map<string, AnyRecord>();
  for (const list of lists) {
    for (const msg of list) {
      if (!msg || typeof msg !== 'object') continue;
      const key = buildMessageDedupKey(msg);
      if (!byKey.has(key)) {
        byKey.set(key, msg);
      }
    }
  }
  return Array.from(byKey.values()).sort((a, b) => {
    const dt = getMessageTime(a) - getMessageTime(b);
    if (dt !== 0) return dt;
    return getMessageSeq(a) - getMessageSeq(b);
  });
}

export function markMessageDeletedForPin(
  pin: string,
  msg: Record<string, unknown>,
  alsoBySeq = false,
): void {
  const canonical = toCanonicalPin(pin);
  if (!canonical || !msg || typeof msg !== 'object') return;

  const deletedStore = loadJsonStorage<StoredDeletedMessages>(PIN_DELETED_MSGS_STORAGE_KEY, {});
  const bucket = getOrCreateDeletedBucket(deletedStore, canonical);

  const dedupKey = buildMessageDedupKey(msg);
  if (!bucket.keys.includes(dedupKey)) {
    bucket.keys.push(dedupKey);
  }

  if (alsoBySeq) {
    const seq = getMessageSeq(msg);
    if (seq > 0) {
      const sender = typeof msg['senderPin'] === 'string' ? msg['senderPin'] : '';
      const token = buildSeqToken(sender, seq);
      if (normalizeCompact(sender) && !bucket.seqs.includes(token)) {
        bucket.seqs.push(token);
      }
      if (msg['mine'] === true) {
        const mineToken = `mine:${seq}`;
        if (!bucket.seqs.includes(mineToken)) {
          bucket.seqs.push(mineToken);
        }
      }
    }
  }

  saveJsonStorage(PIN_DELETED_MSGS_STORAGE_KEY, deletedStore);

  const historyStore = loadJsonStorage<StoredPinHistory>(PIN_HISTORY_STORAGE_KEY, {});
  if (Array.isArray(historyStore[canonical])) {
    const { filtered } = filterMessagesAgainstDeleted(canonical, historyStore[canonical], deletedStore);
    historyStore[canonical] = filtered;
    saveJsonStorage(PIN_HISTORY_STORAGE_KEY, historyStore);
  }
}

export function markSeqDeletedForPin(
  pin: string,
  senderPin: string,
  groupSeq: number,
  isMine = false,
): void {
  const canonical = toCanonicalPin(pin);
  if (!canonical || !Number.isInteger(groupSeq) || groupSeq <= 0) return;

  const deletedStore = loadJsonStorage<StoredDeletedMessages>(PIN_DELETED_MSGS_STORAGE_KEY, {});
  const bucket = getOrCreateDeletedBucket(deletedStore, canonical);
  const token = buildSeqToken(senderPin, groupSeq);
  if (normalizeCompact(senderPin) && !bucket.seqs.includes(token)) {
    bucket.seqs.push(token);
  }
  if (isMine) {
    const mineToken = `mine:${groupSeq}`;
    if (!bucket.seqs.includes(mineToken)) {
      bucket.seqs.push(mineToken);
    }
  }
  saveJsonStorage(PIN_DELETED_MSGS_STORAGE_KEY, deletedStore);

  const historyStore = loadJsonStorage<StoredPinHistory>(PIN_HISTORY_STORAGE_KEY, {});
  if (Array.isArray(historyStore[canonical])) {
    const { filtered } = filterMessagesAgainstDeleted(canonical, historyStore[canonical], deletedStore);
    historyStore[canonical] = filtered;
    saveJsonStorage(PIN_HISTORY_STORAGE_KEY, historyStore);
  }
}

export function archiveMessagesForPin(pin: string, messages: unknown[]): void {
  const canonical = toCanonicalPin(pin);
  if (!canonical || !Array.isArray(messages) || messages.length === 0) return;
  const store = loadJsonStorage<StoredPinHistory>(PIN_HISTORY_STORAGE_KEY, {});
  const deletedStore = loadJsonStorage<StoredDeletedMessages>(PIN_DELETED_MSGS_STORAGE_KEY, {});
  const prev = Array.isArray(store[canonical]) ? store[canonical] : [];
  const incoming = messages.filter(
    (m): m is AnyRecord => Boolean(m && typeof m === 'object')
  );
  if (incoming.length === 0) return;
  const merged = mergeMessageArrays([prev, incoming]);
  const { filtered, deletedDirty } = filterMessagesAgainstDeleted(canonical, merged, deletedStore);
  store[canonical] = filtered;
  saveJsonStorage(PIN_HISTORY_STORAGE_KEY, store);
  if (deletedDirty) saveJsonStorage(PIN_DELETED_MSGS_STORAGE_KEY, deletedStore);
}

export function consolidateVaultGroupsByPin<T>(state: T | null): T | null {
  if (!state || typeof state !== 'object') return state;
  const vault = state as AnyRecord;
  const rawGroups = vault['groups'];
  if (!rawGroups || typeof rawGroups !== 'object' || Array.isArray(rawGroups)) return state;

  const groupsRecord = rawGroups as Record<string, AnyRecord>;
  const entries = Object.entries(groupsRecord)
    .map(([key, grp], order) => ({ key, grp, order }))
    .filter((e) => Boolean(e.grp && typeof e.grp === 'object'));

  if (entries.length === 0) return state;

  const ownPinRaw = typeof vault['pin'] === 'string' ? vault['pin'] : '';
  const ownCompact = normalizeCompact(ownPinRaw);

  // Rastrear orden cronológico real de creación de cada groupIdB64
  const firstSeen = loadJsonStorage<FirstSeenMap>(GROUP_FIRST_SEEN_KEY, {});
  const isInitialSeed = Object.keys(firstSeen).length === 0;
  let firstSeenDirty = false;
  const now = Date.now();

  for (const e of entries) {
    if (typeof firstSeen[e.key] !== 'number') {
      const lastMsg = getLastMessageTime(e.grp);
      firstSeen[e.key] = isInitialSeed ? (lastMsg > 0 ? lastMsg : e.order) : now + e.order;
      firstSeenDirty = true;
    }
  }

  const byPin = new Map<string, Array<{ key: string; grp: AnyRecord; order: number }>>();
  for (const entry of entries) {
    const peerPin = getDirectPeerPin(entry.grp, ownCompact);
    if (!peerPin) continue;
    const bucket = byPin.get(peerPin) ?? [];
    bucket.push(entry);
    byPin.set(peerPin, bucket);
  }

  if (byPin.size === 0) {
    if (firstSeenDirty) saveJsonStorage(GROUP_FIRST_SEEN_KEY, firstSeen);
    return state;
  }

  const historyStore = loadJsonStorage<StoredPinHistory>(PIN_HISTORY_STORAGE_KEY, {});
  const deletedStore = loadJsonStorage<StoredDeletedMessages>(PIN_DELETED_MSGS_STORAGE_KEY, {});
  let historyDirty = false;
  let deletedDirty = false;
  const keysToRemove = new Set<string>();
  const redirects: Record<string, string> = {};

  for (const [peerPin, bucket] of byPin.entries()) {
    // 1) Activo vence a inactivo; 2) Más reciente (creación o último mensaje); 3) epoch/lastSeq/orden
    const sorted = [...bucket].sort((a, b) => {
      const activeA = a.grp['active'] === false ? 0 : 1;
      const activeB = b.grp['active'] === false ? 0 : 1;
      if (activeB !== activeA) return activeB - activeA;

      const scoreA = Math.max(firstSeen[a.key] ?? 0, getLastMessageTime(a.grp));
      const scoreB = Math.max(firstSeen[b.key] ?? 0, getLastMessageTime(b.grp));
      if (scoreB !== scoreA) return scoreB - scoreA;

      const epochA = typeof a.grp['epoch'] === 'number' ? a.grp['epoch'] : 0;
      const epochB = typeof b.grp['epoch'] === 'number' ? b.grp['epoch'] : 0;
      if (epochB !== epochA) return epochB - epochA;

      const seqA = typeof a.grp['lastSeq'] === 'number' ? a.grp['lastSeq'] : 0;
      const seqB = typeof b.grp['lastSeq'] === 'number' ? b.grp['lastSeq'] : 0;
      if (seqB !== seqA) return seqB - seqA;

      return b.order - a.order;
    });

    const winner = sorted[0];
    if (!winner) continue;

    const winnerId =
      typeof winner.grp['groupIdB64'] === 'string' ? winner.grp['groupIdB64'] : winner.key;

    const archived = Array.isArray(historyStore[peerPin]) ? historyStore[peerPin] : [];
    const messageBuckets: AnyRecord[][] = [archived];

    for (const item of bucket) {
      const msgs = Array.isArray(item.grp['messages'])
        ? (item.grp['messages'] as unknown[]).filter(
            (m): m is AnyRecord => Boolean(m && typeof m === 'object')
          )
        : [];
      messageBuckets.push(msgs);

      if (item !== winner) {
        keysToRemove.add(item.key);
        const loserId =
          typeof item.grp['groupIdB64'] === 'string' ? item.grp['groupIdB64'] : item.key;
        if (loserId && winnerId && loserId !== winnerId) {
          redirects[loserId] = winnerId;
        }
      }
    }

    const mergedRaw = mergeMessageArrays(messageBuckets);
    const cleaned = filterMessagesAgainstDeleted(peerPin, mergedRaw, deletedStore);
    if (cleaned.deletedDirty) deletedDirty = true;
    const merged = cleaned.filtered;
    winner.grp['messages'] = merged;

    const prevLast = archived[archived.length - 1];
    const nextLast = merged[merged.length - 1];
    if (
      merged.length !== archived.length ||
      (prevLast && !nextLast) ||
      (!prevLast && nextLast) ||
      (prevLast && nextLast && buildMessageDedupKey(prevLast) !== buildMessageDedupKey(nextLast))
    ) {
      historyStore[peerPin] = merged;
      historyDirty = true;
    }
  }

  if (keysToRemove.size > 0) {
    for (const k of keysToRemove) {
      delete groupsRecord[k];
      if (k in firstSeen) {
        delete firstSeen[k];
        firstSeenDirty = true;
      }
    }
  }

  if (deletedDirty) saveJsonStorage(PIN_DELETED_MSGS_STORAGE_KEY, deletedStore);
  if (historyDirty) saveJsonStorage(PIN_HISTORY_STORAGE_KEY, historyStore);
  if (firstSeenDirty) saveJsonStorage(GROUP_FIRST_SEEN_KEY, firstSeen);

  if (typeof window !== 'undefined' && Object.keys(redirects).length > 0) {
    window.dispatchEvent(
      new CustomEvent('pin:groups-consolidated', { detail: { redirects } })
    );
  }

  return state;
}
