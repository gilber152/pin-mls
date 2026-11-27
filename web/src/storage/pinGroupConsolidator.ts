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

const PIN_HISTORY_STORAGE_KEY = 'pin_mls_pin_history_v1';
const PIN_RE_GLOBAL = /\b[A-Z0-9]{4}-?[A-Z0-9]{4}\b/g;

type AnyRecord = Record<string, unknown>;

interface StoredPinHistory {
  [canonicalPin: string]: AnyRecord[];
}

function normalizeCompact(pin: string): string {
  return pin.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function toCanonicalPin(pin: string): string {
  const c = normalizeCompact(pin);
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : pin.trim().toUpperCase();
}

function loadHistoryStore(): StoredPinHistory {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(PIN_HISTORY_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as StoredPinHistory;
    }
  } catch {
    // Ignorado si localStorage no está disponible
  }
  return {};
}

function saveHistoryStore(store: StoredPinHistory): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(PIN_HISTORY_STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Ignorado si se excede la cuota
  }
}

export function clearArchivedPinHistory(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(PIN_HISTORY_STORAGE_KEY);
  } catch {
    // Ignorado
  }
}

function getOwnPinCompact(vault: AnyRecord): string {
  const candidates = [vault['myPin'], vault['pin'], vault['selfPin'], vault['localPin']];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim()) {
      return normalizeCompact(c);
    }
  }
  return '';
}

function collectPinsFromValue(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 3 || value === null || value === undefined) return;
  if (typeof value === 'string') {
    const matches = value.toUpperCase().match(PIN_RE_GLOBAL);
    if (matches) {
      for (const m of matches) {
        const compact = normalizeCompact(m);
        if (compact.length === 8) out.add(compact);
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectPinsFromValue(item, out, depth + 1);
    }
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as AnyRecord)) {
      if (k === 'messages' || k === 'mlsState' || k === 'groupIdB64' || k === 'id') continue;
      collectPinsFromValue(v, out, depth + 1);
    }
  }
}

function detectDirectPeerPin(grp: AnyRecord, ownCompact: string): string | null {
  if (grp['isGroup'] === true || grp['kind'] === 'group') return null;

  const remotePins = new Set<string>();
  const priorityFields = [
    'peerPin',
    'remotePin',
    'contactPin',
    'targetPin',
    'peerPins',
    'memberPins',
    'members',
    'participants',
    'title',
    'name',
    'label',
  ];

  for (const field of priorityFields) {
    if (field in grp) {
      collectPinsFromValue(grp[field], remotePins);
    }
  }

  if (ownCompact) {
    remotePins.delete(ownCompact);
  }

  // Fallback: si no hubo metadatos explícitos, revisar remitentes entrantes en messages
  if (remotePins.size === 0 && Array.isArray(grp['messages'])) {
    for (const msg of grp['messages'] as unknown[]) {
      if (!msg || typeof msg !== 'object') continue;
      const m = msg as AnyRecord;
      if (m['mine'] === true) continue;
      if (typeof m['senderPin'] === 'string') {
        const compact = normalizeCompact(m['senderPin']);
        if (compact.length === 8 && compact !== ownCompact) {
          remotePins.add(compact);
        }
      }
    }
  }

  // Solo consolidar chats directos 1-a-1 (exactamente 1 PIN remoto)
  if (remotePins.size !== 1) return null;
  const onlyPin = Array.from(remotePins)[0];
  return onlyPin ? toCanonicalPin(onlyPin) : null;
}

function getMessageTime(msg: AnyRecord): number {
  const t = msg['sentAtMs'] ?? msg['timestamp'] ?? msg['createdAtMs'] ?? 0;
  return typeof t === 'number' && Number.isFinite(t) ? t : 0;
}

function getMessageSeq(msg: AnyRecord): number {
  const s = msg['groupSeq'] ?? msg['seq'] ?? 0;
  return typeof s === 'number' && Number.isFinite(s) ? s : 0;
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

function getGroupFreshnessScore(grp: AnyRecord): number {
  const created =
    typeof grp['createdAtMs'] === 'number'
      ? grp['createdAtMs']
      : typeof grp['updatedAtMs'] === 'number'
        ? grp['updatedAtMs']
        : 0;
  let lastMsg = 0;
  if (Array.isArray(grp['messages'])) {
    for (const item of grp['messages'] as unknown[]) {
      if (item && typeof item === 'object') {
        const t = getMessageTime(item as AnyRecord);
        if (t > lastMsg) lastMsg = t;
      }
    }
  }
  return Math.max(created, lastMsg);
}

export function archiveMessagesForPin(pin: string, messages: unknown[]): void {
  const canonical = toCanonicalPin(pin);
  if (!canonical || !Array.isArray(messages) || messages.length === 0) return;
  const store = loadHistoryStore();
  const prev = Array.isArray(store[canonical]) ? store[canonical] : [];
  const incoming = messages.filter(
    (m): m is AnyRecord => Boolean(m && typeof m === 'object')
  );
  if (incoming.length === 0) return;
  store[canonical] = mergeMessageArrays([prev, incoming]);
  saveHistoryStore(store);
}

export function consolidateVaultGroupsByPin<T>(state: T | null): T | null {
  if (!state || typeof state !== 'object') return state;
  const vault = state as AnyRecord;
  const rawGroups = vault['groups'];
  if (!rawGroups || typeof rawGroups !== 'object') return state;

  const isArray = Array.isArray(rawGroups);
  const entries: Array<{ key: string; grp: AnyRecord; order: number }> = isArray
    ? (rawGroups as unknown[])
        .map((g, idx) => ({
          key: String(idx),
          grp: g as AnyRecord,
          order: idx,
        }))
        .filter((e) => Boolean(e.grp && typeof e.grp === 'object'))
    : Object.entries(rawGroups as AnyRecord)
        .map(([k, v], idx) => ({
          key: k,
          grp: v as AnyRecord,
          order: idx,
        }))
        .filter((e) => Boolean(e.grp && typeof e.grp === 'object'));

  if (entries.length === 0) return state;

  const ownCompact = getOwnPinCompact(vault);
  const byPin = new Map<string, Array<{ key: string; grp: AnyRecord; order: number }>>();

  for (const entry of entries) {
    const peerPin = detectDirectPeerPin(entry.grp, ownCompact);
    if (!peerPin) continue;
    const bucket = byPin.get(peerPin) ?? [];
    bucket.push(entry);
    byPin.set(peerPin, bucket);
  }

  if (byPin.size === 0) return state;

  const historyStore = loadHistoryStore();
  let historyDirty = false;
  const keysToRemove = new Set<string>();
  const redirects: Record<string, string> = {};

  for (const [peerPin, bucket] of byPin.entries()) {
    // Elegir el grupo MLS más reciente como ganador (conserva sus claves TreeKEM y groupIdB64 activos)
    const sorted = [...bucket].sort((a, b) => {
      const scoreDiff = getGroupFreshnessScore(b.grp) - getGroupFreshnessScore(a.grp);
      if (scoreDiff !== 0) return scoreDiff;
      return b.order - a.order;
    });

    const winnerEntry = sorted[0];
    if (!winnerEntry) continue;
    const winnerId =
      typeof winnerEntry.grp['groupIdB64'] === 'string'
        ? winnerEntry.grp['groupIdB64']
        : winnerEntry.key;

    const archived = Array.isArray(historyStore[peerPin]) ? historyStore[peerPin] : [];
    const messageBuckets: AnyRecord[][] = [archived];

    for (const item of bucket) {
      const msgs = Array.isArray(item.grp['messages'])
        ? (item.grp['messages'] as unknown[]).filter(
            (m): m is AnyRecord => Boolean(m && typeof m === 'object')
          )
        : [];
      messageBuckets.push(msgs);

      if (item !== winnerEntry) {
        keysToRemove.add(item.key);
        const loserId =
          typeof item.grp['groupIdB64'] === 'string' ? item.grp['groupIdB64'] : item.key;
        if (loserId && winnerId && loserId !== winnerId) {
          redirects[loserId] = winnerId;
        }
      }
    }

    const merged = mergeMessageArrays(messageBuckets);
    winnerEntry.grp['messages'] = merged;

    if (merged.length > 0 && merged.length !== archived.length) {
      historyStore[peerPin] = merged;
      historyDirty = true;
    } else if (merged.length > 0) {
      const prevLast = archived[archived.length - 1];
      const nextLast = merged[merged.length - 1];
      if (!prevLast || !nextLast || buildMessageDedupKey(prevLast) !== buildMessageDedupKey(nextLast)) {
        historyStore[peerPin] = merged;
        historyDirty = true;
      }
    }
  }

  if (historyDirty) {
    saveHistoryStore(historyStore);
  }

  if (keysToRemove.size > 0) {
    if (isArray) {
      vault['groups'] = (rawGroups as unknown[]).filter((_, idx) => !keysToRemove.has(String(idx)));
    } else {
      const rec = rawGroups as AnyRecord;
      for (const k of keysToRemove) {
        delete rec[k];
      }
    }

    if (typeof window !== 'undefined' && Object.keys(redirects).length > 0) {
      window.dispatchEvent(
        new CustomEvent('pin:groups-consolidated', { detail: { redirects } })
      );
    }
  }

  return state;
}
