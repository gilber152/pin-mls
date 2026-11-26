export interface PresenceInfo {
  online: boolean;
  lastSeenMs: number;
}

export type DeliveryStatus = 'sending' | 'sent' | 'delivered';

export interface Step4Controller {
  markPeerActivity: (pin: string, online?: boolean, tsMs?: number) => void;
  getPeerPresenceText: (pin: string) => string;
  setMessageDeliveryStatus: (msgEl: HTMLElement, status: DeliveryStatus) => void;
  refreshPresenceBadges: () => void;
}

function formatLastSeen(tsMs: number): string {
  if (!tsMs) return 'Sin registro de conexión';
  const diffSec = Math.max(0, Math.floor((Date.now() - tsMs) / 1000));
  if (diffSec < 60) return 'Visto hace menos de 1 min';
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `Últ. vez hace ${mins} min`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `Últ. vez hace ${hrs} h`;
  const days = Math.floor(hrs / 24);
  return `Últ. vez hace ${days} d`;
}

export async function initStep4GroupsAndPresence(options?: {
  onInvitePin?: (pin: string, note: string) => Promise<void> | void;
}): Promise<Step4Controller> {
  const presenceMap = new Map<string, PresenceInfo>();

  const existingBar = document.getElementById('pin-step4-bar');
  if (existingBar) existingBar.remove();

  const bar = document.createElement('div');
  bar.id = 'pin-step4-bar';
  bar.className = 'pin-step4-bar';
  bar.innerHTML = `
    <div class="pin-multi-invite-box">
      <input
        type="text"
        id="pin-multi-pins-input"
        class="pin-multi-input"
        placeholder="Invitar varios PINs al grupo (separados por coma, ej. ABCD-EFGH, JKLM-NPQR)"
        autocomplete="off"
      />
      <button type="button" id="pin-btn-invite-many" class="pin-btn-secondary">
        + Invitar grupo
      </button>
    </div>
    <span id="pin-presence-summary" class="pin-presence-summary">Estado: conectado</span>
  `;

  const toolbar = document.getElementById('pin-step1-toolbar');
  if (toolbar && toolbar.parentElement) {
    toolbar.insertAdjacentElement('afterend', bar);
  } else {
    (document.getElementById('app') ?? document.body).prepend(bar);
  }

  const pinsInput = bar.querySelector('#pin-multi-pins-input') as HTMLInputElement;
  const inviteManyBtn = bar.querySelector('#pin-btn-invite-many') as HTMLButtonElement;
  const presenceSummaryEl = bar.querySelector('#pin-presence-summary') as HTMLElement;

  const markPeerActivity = (pin: string, online = true, tsMs = Date.now()): void => {
    const clean = pin.trim().toUpperCase();
    if (!clean) return;
    presenceMap.set(clean, { online, lastSeenMs: tsMs });
    refreshPresenceBadges();
  };

  const getPeerPresenceText = (pin: string): string => {
    const clean = pin.trim().toUpperCase();
    const info = presenceMap.get(clean);
    if (!info) return 'Estado no verificado';
    if (info.online) return '● En línea';
    return formatLastSeen(info.lastSeenMs);
  };

  const refreshPresenceBadges = (): void => {
    const onlineCount = [...presenceMap.values()].filter((p) => p.online).length;
    if (onlineCount > 0) {
      presenceSummaryEl.textContent = `● ${onlineCount} contacto(s) activos recientemente`;
      presenceSummaryEl.classList.add('is-online');
    } else if (presenceMap.size > 0) {
      const latest = Math.max(...[...presenceMap.values()].map((p) => p.lastSeenMs));
      presenceSummaryEl.textContent = formatLastSeen(latest);
      presenceSummaryEl.classList.remove('is-online');
    } else {
      presenceSummaryEl.textContent = '● Sesión lista (presencia local)';
      presenceSummaryEl.classList.add('is-online');
    }

    const items = document.querySelectorAll<HTMLElement>(
      '[data-pin], .conversation-item, .conv-item, .chat-item',
    );
    items.forEach((el) => {
      const rawText = el.textContent ?? '';
      const match =
        el.dataset.pin ?? rawText.match(/\b[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\b/i)?.[0];
      if (!match) return;
      const pinKey = match.trim().toUpperCase();
      const info = presenceMap.get(pinKey);
      let dot = el.querySelector<HTMLElement>('.pin-presence-tag');
      if (!info) {
        dot?.remove();
        return;
      }
      if (!dot) {
        dot = document.createElement('span');
        dot.className = 'pin-presence-tag';
        el.appendChild(dot);
      }
      dot.textContent = info.online ? '● En línea' : formatLastSeen(info.lastSeenMs);
      dot.classList.toggle('is-online', info.online);
    });
  };

  const setMessageDeliveryStatus = (msgEl: HTMLElement, status: DeliveryStatus): void => {
    let badge = msgEl.querySelector<HTMLElement>('.pin-delivery-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'pin-delivery-badge';
      msgEl.appendChild(badge);
    }
    if (status === 'sending') {
      badge.textContent = '⏳';
      badge.title = 'Cifrando y enviando...';
    } else if (status === 'sent') {
      badge.textContent = '✓';
      badge.title = 'Enviado al servidor';
    } else {
      badge.textContent = '✓✓';
      badge.title = 'Entregado / sincronizado';
    }
  };

  inviteManyBtn.addEventListener('click', async () => {
    const raw = pinsInput.value.trim();
    if (!raw) return;
    const pins = raw
      .split(/[\s,;]+/)
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);
    if (pins.length === 0) return;

    inviteManyBtn.disabled = true;
    try {
      for (let i = 0; i < pins.length; i++) {
        const pin = pins[i];
        presenceSummaryEl.textContent = `Invitando (${i + 1}/${pins.length}): ${pin}...`;
        if (options?.onInvitePin) {
          await options.onInvitePin(pin, 'Invitación grupal PIN-MLS');
        } else {
          // Fallback si el formulario de invitación existe en el DOM
          const inviteInput = document.querySelector<HTMLInputElement>(
            '#invite-pin-input, input[placeholder*="PIN" i]:not(#pin-multi-pins-input)',
          );
          const inviteForm = inviteInput?.closest('form');
          if (inviteInput && inviteForm) {
            inviteInput.value = pin;
            inviteForm.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          }
        }
      }
      pinsInput.value = '';
      refreshPresenceBadges();
    } finally {
      inviteManyBtn.disabled = false;
    }
  });

  // Marcar burbujas salientes existentes como enviadas/entregadas
  const syncBubbles = (): void => {
    const outgoing = document.querySelectorAll<HTMLElement>(
      '.message-item.mine, .msg-item.mine, .bubble.mine, .outgoing, [data-outgoing="true"]',
    );
    outgoing.forEach((el) => {
      if (!el.querySelector('.pin-delivery-badge')) {
        setMessageDeliveryStatus(el, 'delivered');
      }
    });
  };

  const observer = new MutationObserver(() => syncBubbles());
  observer.observe(document.body, { childList: true, subtree: true });
  syncBubbles();
  refreshPresenceBadges();

  return {
    markPeerActivity,
    getPeerPresenceText,
    setMessageDeliveryStatus,
    refreshPresenceBadges,
  };
}
