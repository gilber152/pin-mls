import type { VaultState } from '../types.js';

export type MediaAttachmentKind = 'image' | 'audio' | 'video' | 'file';

export interface RemoteMediaDescriptor {
  storage: 'supabase';
  mediaId: string;
  keyB64: string;
  ivB64: string;
  sha256B64: string;
  name: string;
  mime: string;
  sizeBytes: number;
  kind: MediaAttachmentKind;
  caption?: string;
}

export interface MediaAuthContext {
  authedFetch: (vault: VaultState, path: string, init?: RequestInit) => Promise<Response>;
  vault: VaultState;
  activeGroupIdB64: string | null;
}

export const MAX_E2EE_MEDIA_BYTES = 25 * 1024 * 1024; // 25 MB

let authProvider: (() => MediaAuthContext | null) | null = null;
const memoryBlobUrlCache = new Map<string, string>();
const inflightDownloads = new Map<string, Promise<string>>();

export function setMediaAuthProvider(provider: () => MediaAuthContext | null): void {
  authProvider = provider;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function getSafeDownloadMime(mime: string, kind: MediaAttachmentKind): string {
  if (kind !== 'file') return mime || 'application/octet-stream';
  const m = (mime || '').toLowerCase().trim();
  if (
    !m ||
    m.includes('html') ||
    m.includes('svg') ||
    m.includes('javascript') ||
    m.includes('ecmascript') ||
    m.includes('xml')
  ) {
    return 'application/octet-stream';
  }
  return m;
}

// === CACHÉ INDEPENDIENTE EN INDEXEDDB (NO INFLA VAULTSTATE) ===

const MEDIA_CACHE_DB = 'pin_mls_media_cache_v1';
const MEDIA_CACHE_STORE = 'blobs';

function openMediaCacheDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null);
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(MEDIA_CACHE_DB, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(MEDIA_CACHE_STORE)) {
          db.createObjectStore(MEDIA_CACHE_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

async function readCachedBlob(mediaId: string): Promise<Blob | null> {
  const db = await openMediaCacheDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(MEDIA_CACHE_STORE, 'readonly');
      const req = tx.objectStore(MEDIA_CACHE_STORE).get(mediaId);
      req.onsuccess = () => resolve(req.result instanceof Blob ? req.result : null);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

async function writeCachedBlob(mediaId: string, blob: Blob): Promise<void> {
  const db = await openMediaCacheDb();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(MEDIA_CACHE_STORE, 'readwrite');
      tx.objectStore(MEDIA_CACHE_STORE).put(blob, mediaId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

export async function hasCachedMedia(mediaId: string): Promise<boolean> {
  if (memoryBlobUrlCache.has(mediaId)) return true;
  const cached = await readCachedBlob(mediaId);
  return cached !== null;
}

// === SUBIDA CIFRADA AES-256-GCM ===

export async function uploadEncryptedMediaFile(
  file: File,
  kind: MediaAttachmentKind,
  onProgress?: (label: string) => void,
): Promise<RemoteMediaDescriptor> {
  const ctx = authProvider?.();
  if (!ctx || !ctx.activeGroupIdB64) {
    throw new Error('Abre una conversación activa antes de enviar un archivo.');
  }

  if (file.size <= 0) {
    throw new Error('El archivo seleccionado está vacío.');
  }
  if (file.size > MAX_E2EE_MEDIA_BYTES) {
    throw new Error('El archivo supera el límite de 25 MB.');
  }
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API no está disponible (requiere HTTPS).');
  }

  onProgress?.('Cifrando archivo (AES-256-GCM)…');

  const plainBuffer = await file.arrayBuffer();
  const keyRawBuf = new ArrayBuffer(32);
  const keyBytes = new Uint8Array(keyRawBuf);
  crypto.getRandomValues(keyBytes);

  const ivRawBuf = new ArrayBuffer(12);
  const ivBytes = new Uint8Array(ivRawBuf);
  crypto.getRandomValues(ivBytes);

  const aesKey = await crypto.subtle.importKey('raw', keyRawBuf, { name: 'AES-GCM' }, false, ['encrypt']);
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes }, aesKey, plainBuffer);
  const sha256Buffer = await crypto.subtle.digest('SHA-256', cipherBuffer);

  onProgress?.('Solicitando canal seguro de subida…');

  const signRes = await ctx.authedFetch(ctx.vault, '/v1/media/upload-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      groupIdB64: ctx.activeGroupIdB64,
      cipherBytes: cipherBuffer.byteLength,
    }),
  });

  if (!signRes.ok) {
    const errBody = (await signRes.json().catch(() => ({}))) as { error?: string };
    if (signRes.status === 503 || errBody.error === 'MEDIA_STORAGE_NOT_CONFIGURED') {
      throw new Error(
        'Falta configurar SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY en Render (pin-mls-api).',
      );
    }
    throw new Error(errBody.error || `Error del servidor (${signRes.status}) al autorizar subida.`);
  }

  const signedData = (await signRes.json()) as {
    mediaId?: string;
    signedUrl?: string;
  };
  if (!signedData.mediaId || !signedData.signedUrl) {
    throw new Error('Respuesta incompleta del servidor de almacenamiento.');
  }

  onProgress?.('Subiendo archivo cifrado…');

  const cipherBlob = new Blob([cipherBuffer], { type: 'application/octet-stream' });
  const formData = new FormData();
  formData.append('cacheControl', '3600');
  formData.append('', cipherBlob, `${signedData.mediaId}.enc`);

  const uploadRes = await fetch(signedData.signedUrl, {
    method: 'PUT',
    body: formData,
    headers: { 'x-upsert': 'false' },
  });

  if (!uploadRes.ok) {
    const errTxt = await uploadRes.text().catch(() => '');
    throw new Error(
      `Falló la subida a Supabase Storage (HTTP ${uploadRes.status}${errTxt ? `: ${errTxt.slice(0, 120)}` : ''}).`,
    );
  }

  // Guardar copia descifrada en caché local para que el emisor lo vea al instante sin re-descargar
  const safeMime = getSafeDownloadMime(file.type || 'application/octet-stream', kind);
  const localPlainBlob = new Blob([plainBuffer], { type: safeMime });
  await writeCachedBlob(signedData.mediaId, localPlainBlob);
  const objUrl = URL.createObjectURL(localPlainBlob);
  memoryBlobUrlCache.set(signedData.mediaId, objUrl);

  return {
    storage: 'supabase',
    mediaId: signedData.mediaId,
    keyB64: bytesToBase64(keyBytes),
    ivB64: bytesToBase64(ivBytes),
    sha256B64: bytesToBase64(new Uint8Array(sha256Buffer)),
    name: (file.name || 'archivo').trim(),
    mime: file.type || 'application/octet-stream',
    sizeBytes: file.size,
    kind,
  };
}

// === DESCARGA Y DESCIFRADO CON VERIFICACIÓN SHA-256 ===

export async function downloadAndDecryptMedia(att: RemoteMediaDescriptor): Promise<string> {
  const cachedMem = memoryBlobUrlCache.get(att.mediaId);
  if (cachedMem) return cachedMem;

  const existingPromise = inflightDownloads.get(att.mediaId);
  if (existingPromise) return existingPromise;

  const task = (async () => {
    const safeMime = getSafeDownloadMime(att.mime, att.kind);

    const cachedIdb = await readCachedBlob(att.mediaId);
    if (cachedIdb) {
      const typedBlob =
        cachedIdb.type === safeMime ? cachedIdb : new Blob([await cachedIdb.arrayBuffer()], { type: safeMime });
      const url = URL.createObjectURL(typedBlob);
      memoryBlobUrlCache.set(att.mediaId, url);
      return url;
    }

    const ctx = authProvider?.();
    if (!ctx) {
      throw new Error('Sesión no activa para descargar adjunto.');
    }

    const signRes = await ctx.authedFetch(
      ctx.vault,
      `/v1/media/${encodeURIComponent(att.mediaId)}/download-url`,
      { method: 'GET' },
    );

    if (!signRes.ok) {
      const errBody = (await signRes.json().catch(() => ({}))) as { error?: string };
      if (signRes.status === 410 || errBody.error === 'MEDIA_EXPIRED') {
        throw new Error('Este archivo expiró en el servidor (más de 14 días).');
      }
      if (signRes.status === 404 || errBody.error === 'MEDIA_NOT_FOUND') {
        throw new Error('Archivo no encontrado en almacenamiento.');
      }
      throw new Error(errBody.error || `Error descargando archivo (HTTP ${signRes.status}).`);
    }

    const { signedUrl } = (await signRes.json()) as { signedUrl?: string };
    if (!signedUrl) {
      throw new Error('URL de descarga inválida.');
    }

    const binRes = await fetch(signedUrl);
    if (!binRes.ok) {
      throw new Error(`No se pudo descargar el archivo cifrado (HTTP ${binRes.status}).`);
    }
    const cipherBuffer = await binRes.arrayBuffer();

    const actualSha = bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', cipherBuffer)));
    if (actualSha !== att.sha256B64) {
      throw new Error('Integridad criptográfica inválida (SHA-256 no coincide).');
    }

    const keyBuf = base64ToArrayBuffer(att.keyB64);
    const ivBuf = base64ToArrayBuffer(att.ivB64);
    const aesKey = await crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, ['decrypt']);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(ivBuf) },
      aesKey,
      cipherBuffer,
    );

    const plainBlob = new Blob([plainBuffer], { type: safeMime });
    await writeCachedBlob(att.mediaId, plainBlob);
    const url = URL.createObjectURL(plainBlob);
    memoryBlobUrlCache.set(att.mediaId, url);
    return url;
  })().finally(() => {
    inflightDownloads.delete(att.mediaId);
  });

  inflightDownloads.set(att.mediaId, task);
  return task;
}
