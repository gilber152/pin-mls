import {
  loadPinAliases,
  loadUiPreferences,
  saveUiPreferences,
  setPinAlias,
  type PinAliasMap,
  type UiPreferences,
} from '../storage/vaultDb.js';

export interface Step1Controller {
  getDisplayName: (pin: string) => string;
  setAliasForPin: (pin: string, alias: string) => Promise<void>;
  getAliases: () => PinAliasMap;
  openMobileChatView: () => void;
  closeMobileChatView: () => void;
  notifyIncomingMessage: (senderPin: string, previewText: string) => void;
  applySearchFilter: (query: string) => void;
  refreshSidebarBadges: () => void;
}

function playSoftTone(enabled: boolean): void {
  if (!enabled) return;
  try {
    const AudioCtx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(660, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.09);

    gain.gain.setValueAtTime(0.001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.05, ctx.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.16);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.17);
    osc.onended = () => {
      void ctx.close().catch(() => {});
    };
  } catch {
    // Ignorar restricciones de audio antes de interacción
  }
}

async function showBrowserNotification(
  prefs: UiPreferences,
  title: string,
  body: string,
): Promise<void> {
  if (!prefs.notificationsEnabled) return;
  if (document.visibilityState === 'visible' && document.hasFocus()) return;
  if (!('Notification' in window)) return;

  if (Notification.permission === 'default') {
    try {
      await Notification.requestPermission();
    } catch {
      return;
    }
  }

  if (Notification.permission === 'granted') {
    try {
      new Notification(title, {
        body,
        silent: true,
      });
    } catch {
      // Ignorar si el navegador bloquea notificaciones
    }
  }
}

export async function initStep1Enhancements(options?: {
  onAliasChanged?: (pin: string, alias: string) => void;
  onSearchQuery?: (query: string) => void;
}): Promise<Step1Controller> {
  let aliases: PinAliasMap = await loadPinAliases();
  let prefs: UiPreferences = await loadUiPreferences();

  document.body.classList.add('pin-step1-ready');

  const existingToolbar = document.getElementById('pin-step1-toolbar');
  if (existingToolbar) existingToolbar.remove();

  const toolbar = document.createElement('div');
  toolbar.id = 'pin-step1-toolbar';
  toolbar.className = 'pin-step1-toolbar';
  toolbar.innerHTML = `
    <button type="button" id="pin-btn-mobile-back" class="pin-btn-ghost pin-mobile-only" aria-label="Volver a chats">
      ← Chats
    </button>
    <div class="pin-search-wrap">
      <input
        type="search"
        id="pin-local-search"
        class="pin-search-input"
        placeholder="Buscar localmente en mensajes o PINs..."
        autocomplete="off"
      />
      <button type="button" id="pin-btn-clear-search" class="pin-btn-icon" title="Limpiar búsqueda">✕</button>
    </div>
    <div class="pin-step1-actions">
      <button type="button" id="pin-btn-edit-alias" class="pin-btn-secondary" title="Asignar alias local a un PIN">
        Alias PIN
      </button>
      <button type="button" id="pin-btn-toggle-sound" class="pin-btn-icon" title="Alternar sonido">
        ${prefs.soundEnabled ? '🔊' : '🔇'}
      </button>
      <button type="button" id="pin-btn-toggle-notif" class="pin-btn-icon" title="Alternar notificaciones del navegador">
        ${prefs.notificationsEnabled ? '🔔' : '🔕'}
      </button>
    </div>
  `;

  const appRoot = document.getElementById('app') ?? document.body;
  appRoot.prepend(toolbar);

  const backBtn = toolbar.querySelector('#pin-btn-mobile-back') as HTMLButtonElement;
  const searchInput = toolbar.querySelector('#pin-local-search') as HTMLInputElement;
  const clearSearchBtn = toolbar.querySelector('#pin-btn-clear-search') as HTMLButtonElement;
  const aliasBtn = toolbar.querySelector('#pin-btn-edit-alias') as HTMLButtonElement;
  const soundBtn = toolbar.querySelector('#pin-btn-toggle-sound') as HTMLButtonElement;
  const notifBtn = toolbar.querySelector('#pin-btn-toggle-notif') as HTMLButtonElement;

  const getDisplayName = (pin: string): string => {
    const clean = pin.trim().toUpperCase();
    const alias = aliases[clean];
    return alias ? `${alias} (${clean})` : clean;
  };

  const applySearchFilter = (query: string): void => {
    const q = query.trim().toLowerCase();
    const searchableNodes = document.querySelectorAll<HTMLElement>(
      '[data-searchable], .conversation-item, .conv-item, .chat-item, .message-item, .msg-item, .bubble',
    );

    searchableNodes.forEach((el) => {
      if (
        el.querySelector(
          '[data-searchable], .conversation-item, .conv-item, .chat-item, .message-item, .msg-item, .bubble',
        )
      ) {
        return;
      }
      if (!q) {
        el.classList.remove('pin-search-hidden');
        return;
      }
      const text = (el.textContent ?? '').toLowerCase();
      el.classList.toggle('pin-search-hidden', !text.includes(q));
    });

    options?.onSearchQuery?.(query);
  };

  const refreshSidebarBadges = (): void => {
    const items = document.querySelectorAll<HTMLElement>(
      '[data-pin], .conversation-item, .conv-item, .chat-item',
    );
    items.forEach((el) => {
      const rawText = el.textContent ?? '';
      const match =
        el.dataset.pin ?? rawText.match(/\b[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\b/i)?.[0];
      if (!match) return;
      const pinKey = match.trim().toUpperCase();
      const alias = aliases[pinKey];
      let badge = el.querySelector('.pin-alias-pill') as HTMLElement | null;
      if (alias) {
        if (!badge) {
          badge = document.createElement('span');
          badge.className = 'pin-alias-pill';
          el.prepend(badge);
        }
        badge.textContent = alias;
      } else if (badge) {
        badge.remove();
      }
    });
  };

  const setAliasForPin = async (pin: string, alias: string): Promise<void> => {
    const cleanPin = pin.trim().toUpperCase();
    aliases = await setPinAlias(cleanPin, alias);
    window.dispatchEvent(new CustomEvent("pin:aliases-updated", { detail: { aliases } }));
    refreshSidebarBadges();
    options?.onAliasChanged?.(cleanPin, aliases[cleanPin] ?? '');
  };

  backBtn.addEventListener('click', () => {
    document.body.classList.remove('pin-mobile-chat-open');
  });

  searchInput.addEventListener('input', () => {
    applySearchFilter(searchInput.value);
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    applySearchFilter('');
    searchInput.focus();
  });

  aliasBtn.addEventListener('click', async () => {
    const targetPin = window.prompt(
      'Ingresa el PIN (ej. TPP1-MET5) al que quieres asignar un alias local:',
    );
    if (!targetPin || !targetPin.trim()) return;
    const cleanPin = targetPin.trim().toUpperCase();
    const currentAlias = aliases[cleanPin] ?? '';
    const nextAlias = window.prompt(
      `Alias local para ${cleanPin} (déjalo vacío para quitarlo):`,
      currentAlias,
    );
    if (nextAlias === null) return;
    await setAliasForPin(cleanPin, nextAlias);
  });

  soundBtn.addEventListener('click', async () => {
    prefs = { ...prefs, soundEnabled: !prefs.soundEnabled };
    soundBtn.textContent = prefs.soundEnabled ? '🔊' : '🔇';
    await saveUiPreferences(prefs);
    if (prefs.soundEnabled) playSoftTone(true);
  });

  notifBtn.addEventListener('click', async () => {
    const nextEnabled = !prefs.notificationsEnabled;
    if (nextEnabled && 'Notification' in window && Notification.permission === 'default') {
      try {
        await Notification.requestPermission();
      } catch {
        // Ignorar
      }
    }
    prefs = { ...prefs, notificationsEnabled: nextEnabled };
    notifBtn.textContent = prefs.notificationsEnabled ? '🔔' : '🔕';
    await saveUiPreferences(prefs);
  });

  document.addEventListener('click', (ev) => {
    const target = ev.target as HTMLElement | null;
    if (!target) return;
    if (target.closest('.conversation-item, .conv-item, .chat-item, [data-open-chat]')) {
      if (window.matchMedia('(max-width: 768px)').matches) {
        document.body.classList.add('pin-mobile-chat-open');
      }
    }
  });

  refreshSidebarBadges();

  return {
    getDisplayName,
    setAliasForPin,
    getAliases: () => ({ ...aliases }),
    openMobileChatView: () => {
      if (window.matchMedia('(max-width: 768px)').matches) {
        document.body.classList.add('pin-mobile-chat-open');
      }
    },
    closeMobileChatView: () => {
      document.body.classList.remove('pin-mobile-chat-open');
    },
    notifyIncomingMessage: (senderPin: string, previewText: string) => {
      playSoftTone(prefs.soundEnabled);
      void showBrowserNotification(
        prefs,
        `PIN-MLS · ${getDisplayName(senderPin)}`,
        previewText || 'Nuevo mensaje cifrado recibido',
      );
    },
    applySearchFilter,
    refreshSidebarBadges,
  };
}
