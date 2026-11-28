interface BeforeInstallPromptEvent extends Event {
  readonly platforms?: string[];
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
}

type PwaWindow = Window & {
  __pinDeferredInstallPrompt?: BeforeInstallPromptEvent | null;
};

function isRunningStandalone(): boolean {
  if (typeof window === 'undefined') return false;
  const nav = navigator as Navigator & { standalone?: boolean };
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    window.matchMedia('(display-mode: fullscreen)').matches ||
    nav.standalone === true
  );
}

function setToastMessage(msg: string): void {
  const status = document.getElementById('global-status');
  if (status) {
    status.textContent = msg;
  }
}

function closeTopMenuIfOpen(): void {
  document.body.classList.remove('pin-mobile-menu-open');
  const toggleBtn = document.getElementById('btn-mobile-menu-toggle');
  if (toggleBtn) {
    toggleBtn.textContent = '☰ Menú';
    toggleBtn.setAttribute('aria-expanded', 'false');
  }
}

function showManualInstallHelp(): void {
  document.getElementById('pin-install-help-modal')?.remove();

  const ua = navigator.userAgent || '';
  const isIOS = /iPad|iPhone|iPod/i.test(ua);
  const isAndroid = /Android/i.test(ua);

  const overlay = document.createElement('div');
  overlay.id = 'pin-install-help-modal';
  overlay.className = 'pin-msg-action-overlay';

  const closeModal = () => {
    overlay.remove();
    window.removeEventListener('keydown', onEsc);
  };
  const onEsc = (e: KeyboardEvent) => {
    if (e.key === 'Escape') closeModal();
  };
  window.addEventListener('keydown', onEsc);
  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) closeModal();
  });

  const card = document.createElement('div');
  card.className = 'pin-msg-action-card';
  card.setAttribute('role', 'dialog');

  const title = document.createElement('div');
  title.className = 'pin-msg-action-title';
  title.textContent = 'Instalar PIN-MLS en tu dispositivo';

  const body = document.createElement('div');
  body.className = 'pin-install-help-body';

  if (isIOS) {
    body.innerHTML =
      '<p>En iPhone/iPad la instalación se hace desde <strong>Safari</strong>:</p>' +
      '<ol>' +
      '<li>Toca el botón <strong>Compartir</strong> (cuadro con flecha hacia arriba).</li>' +
      '<li>Elige <strong>Agregar a inicio</strong> y luego toca <strong>Agregar</strong>.</li>' +
      '</ol>';
  } else if (isAndroid) {
    body.innerHTML =
      '<p>Tu navegador no mostró el instalador automático todavía. Hazlo en 2 pasos:</p>' +
      '<ol>' +
      '<li>Toca el menú <strong>⋮</strong> (arriba a la derecha) en Chrome o Brave.</li>' +
      '<li>Elige <strong>Instalar aplicación</strong> o <strong>Agregar a la pantalla principal</strong>.</li>' +
      '</ol>' +
      '<p class="pin-install-help-note">Si abriste el enlace desde WhatsApp o Telegram, primero elige «Abrir en el navegador».</p>';
  } else {
    body.innerHTML =
      '<p>Para instalar PIN-MLS como aplicación en este equipo:</p>' +
      '<ol>' +
      '<li>Haz clic en el ícono de <strong>Instalar</strong> en el extremo derecho de la barra de direcciones.</li>' +
      '<li>O abre el menú del navegador → <strong>Instalar PIN-MLS</strong>.</li>' +
      '</ol>';
  }

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'pin-msg-action-btn is-primary';
  closeBtn.style.textAlign = 'center';
  closeBtn.textContent = 'Entendido';
  closeBtn.addEventListener('click', closeModal);

  card.append(title, body, closeBtn);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
}

export function installPwaInstallButton(): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  // Registrar el Service Worker desde el arranque para habilitar el prompt nativo en Android
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // Ignorado si el navegador restringe SW (ej. modo privado estricto)
    });
  }

  const w = window as PwaWindow;
  const btn = document.getElementById('btn-install-pwa') as HTMLButtonElement | null;
  if (!btn) return;

  const syncButtonVisibility = () => {
    const installed = isRunningStandalone();
    btn.hidden = installed;
    if (!installed && w.__pinDeferredInstallPrompt) {
      btn.classList.add('pin-install-ready');
    } else {
      btn.classList.remove('pin-install-ready');
    }
  };

  window.addEventListener('beforeinstallprompt', (ev: Event) => {
    ev.preventDefault();
    w.__pinDeferredInstallPrompt = ev as BeforeInstallPromptEvent;
    syncButtonVisibility();
  });

  window.addEventListener('pin:install-available', () => {
    syncButtonVisibility();
  });

  window.addEventListener('appinstalled', () => {
    w.__pinDeferredInstallPrompt = null;
    syncButtonVisibility();
    setToastMessage('PIN-MLS instalada correctamente en tu dispositivo.');
  });

  const mq = window.matchMedia('(display-mode: standalone)');
  if (typeof mq.addEventListener === 'function') {
    mq.addEventListener('change', syncButtonVisibility);
  }

  btn.addEventListener('click', () => {
    closeTopMenuIfOpen();

    if (isRunningStandalone()) {
      syncButtonVisibility();
      setToastMessage('PIN-MLS ya está instalada en este dispositivo.');
      return;
    }

    const promptEv = w.__pinDeferredInstallPrompt ?? null;
    if (!promptEv) {
      showManualInstallHelp();
      return;
    }

    void (async () => {
      try {
        await promptEv.prompt();
        const choice = await promptEv.userChoice;
        w.__pinDeferredInstallPrompt = null;
        syncButtonVisibility();
        if (choice.outcome === 'accepted') {
          setToastMessage('Instalando PIN-MLS en tu dispositivo…');
        } else {
          setToastMessage('Instalación cancelada. Puedes volver a intentarlo desde Menú.');
        }
      } catch {
        w.__pinDeferredInstallPrompt = null;
        showManualInstallHelp();
      }
    })();
  });

  syncButtonVisibility();
}
