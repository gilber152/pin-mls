self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function pingClient(client, payload, timeoutMs = 750) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };
    const timer = setTimeout(() => done(null), timeoutMs);
    try {
      const channel = new MessageChannel();
      channel.port1.onmessage = (ev) => {
        clearTimeout(timer);
        done(ev.data || null);
      };
      client.postMessage(payload, [channel.port2]);
    } catch {
      clearTimeout(timer);
      done(null);
    }
  });
}

self.addEventListener('push', (event) => {
  let data = { kind: 'message', groupIdB64: '' };
  if (event.data) {
    try {
      const parsed = event.data.json();
      if (parsed && typeof parsed === 'object') {
        data = { ...data, ...parsed };
      }
    } catch {
      // Fallback por defecto
    }
  }

  event.waitUntil(
    (async () => {
      const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });

      // Si el usuario está mirando la ventana activamente, no molestar con notificación del SO
      if (clients.some((c) => c.visibilityState === 'visible' && c.focused)) {
        return;
      }

      // Si hay una pestaña abierta en segundo plano (ej. PC), verificar si está despierta para que muestre alias+preview
      if (clients.length > 0 && data.kind === 'message') {
        const responses = await Promise.all(
          clients.map((c) =>
            pingClient(c, {
              type: 'PIN_PUSH_WAKE',
              kind: data.kind,
              groupIdB64: data.groupIdB64 || '',
            }),
          ),
        );
        if (responses.some((r) => r && r.handledByPage === true)) {
          return;
        }
      }

      const isInvite = data.kind === 'invite';
      const title = 'PIN-MLS';
      const body = isInvite
        ? 'Tienes una nueva solicitud de contacto.'
        : 'Tienes un nuevo mensaje cifrado.';
      const tag = isInvite
        ? 'pin-mls-invite'
        : data.groupIdB64
          ? `pin-mls-msg-${data.groupIdB64}`
          : 'pin-mls-msg';

      await self.registration.showNotification(title, {
        body,
        icon: '/icon-192.png',
        badge: '/badge-72.png',
        tag,
        renotify: true,
        data: {
          url: '/',
          groupIdB64: data.groupIdB64 || '',
          kind: data.kind,
        },
      });
    })(),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const notifData = event.notification.data || {};
  const targetUrl = notifData.url || '/';
  const groupIdB64 = notifData.groupIdB64 || '';

  event.waitUntil(
    (async () => {
      const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of clients) {
        if ('focus' in client) {
          await client.focus();
          client.postMessage({ type: 'PIN_OPEN_GROUP', groupIdB64 });
          return;
        }
      }
      if (self.clients.openWindow) {
        await self.clients.openWindow(targetUrl);
      }
    })(),
  );
});
