import type { VaultState } from '../types.js';

export interface AuthedFetchLike {
  authedFetch(vault: VaultState, path: string, init?: RequestInit): Promise<Response>;
}

let swRegPromise: Promise<ServiceWorkerRegistration | null> | null = null;
let swMessageBound = false;

function urlBase64ToUint8Array(base64String: string): Uint8Array<ArrayBuffer> {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const buffer = new ArrayBuffer(rawData.length);
  const output = new Uint8Array(buffer);
  for (let i = 0; i < rawData.length; i++) {
    output[i] = rawData.charCodeAt(i);
  }
  return output;
}

export function registerAppServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
    return Promise.resolve(null);
  }

  if (!swMessageBound) {
    swMessageBound = true;
    navigator.serviceWorker.addEventListener('message', (ev: MessageEvent) => {
      const data = ev.data as { type?: string; groupIdB64?: string } | null;
      if (!data) return;

      if (data.type === 'PIN_PUSH_WAKE') {
        const isAwakeAndOnline = typeof navigator !== 'undefined' && navigator.onLine !== false;
        const port = ev.ports?.[0];
        if (port) {
          port.postMessage({ handledByPage: isAwakeAndOnline });
        }
        window.dispatchEvent(new CustomEvent('pin:sw-wake-sync'));
      } else if (data.type === 'PIN_OPEN_GROUP') {
        window.dispatchEvent(
          new CustomEvent('pin:sw-open-group', {
            detail: { groupIdB64: data.groupIdB64 ?? '' },
          }),
        );
      }
    });
  }

  if (!swRegPromise) {
    swRegPromise = navigator.serviceWorker
      .register('/sw.js', { scope: '/' })
      .then((reg) => reg)
      .catch(() => null);
  }
  return swRegPromise;
}

export async function ensureWebPushSubscribed(
  api: AuthedFetchLike,
  vault: VaultState,
  requestPermissionIfDefault: boolean,
): Promise<{ subscribed: boolean; reason?: string }> {
  if (typeof window === 'undefined' || !('Notification' in window)) {
    return { subscribed: false, reason: 'Este navegador no soporta notificaciones.' };
  }

  let permission: NotificationPermission = Notification.permission;
  if (permission === 'default' && requestPermissionIfDefault) {
    try {
      permission = await Notification.requestPermission();
    } catch {
      permission = 'denied';
    }
  }

  if (permission !== 'granted') {
    return {
      subscribed: false,
      reason:
        permission === 'denied'
          ? 'Permiso de notificaciones bloqueado en el navegador.'
          : 'Pulsa la campana (🔔) para permitir notificaciones.',
    };
  }

  const reg = await registerAppServiceWorker();
  if (!reg || !('pushManager' in reg)) {
    return {
      subscribed: false,
      reason: 'Notificaciones locales activas (en iPhone instala la app en pantalla de inicio para Push).',
    };
  }

  try {
    const keyRes = await api.authedFetch(vault, '/v1/push/vapid-public-key', { method: 'GET' });
    if (!keyRes.ok) {
      return { subscribed: false, reason: 'No se pudo consultar la clave VAPID del servidor.' };
    }
    const keyData = (await keyRes.json()) as { enabled?: boolean; publicKey?: string | null };
    if (!keyData.enabled || !keyData.publicKey) {
      return {
        subscribed: false,
        reason: 'Notificaciones en segundo plano activas (falta configurar VAPID en Render para app cerrada).',
      };
    }

    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(keyData.publicKey),
      });
    }

    const subJson = sub.toJSON();
    const saveRes = await api.authedFetch(vault, '/v1/push/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        endpoint: sub.endpoint,
        keys: {
          p256dh: subJson.keys?.p256dh ?? '',
          auth: subJson.keys?.auth ?? '',
        },
      }),
    });

    if (!saveRes.ok) {
      return { subscribed: false, reason: 'Error guardando la suscripción Push en el servidor.' };
    }
    return { subscribed: true };
  } catch (err) {
    return {
      subscribed: false,
      reason: `Aviso Push: ${(err as Error).message}`,
    };
  }
}

export async function unsubscribeWebPush(api: AuthedFetchLike, vault: VaultState): Promise<void> {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.getRegistration('/');
    const sub = await reg?.pushManager?.getSubscription();
    const endpoint = sub?.endpoint;
    if (sub) {
      await sub.unsubscribe().catch(() => undefined);
    }
    await api
      .authedFetch(vault, '/v1/push/subscribe', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(endpoint ? { endpoint } : {}),
      })
      .catch(() => undefined);
  } catch {
    // Ignorado
  }
}
