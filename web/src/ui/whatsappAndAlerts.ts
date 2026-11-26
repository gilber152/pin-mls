export interface IncomingMessageAlert {
  senderLabel: string;
  previewText: string;
  groupId?: string;
}

const ALIAS_STORAGE_KEY = 'pin_mls_pin_aliases_v1';
const PIN_PATTERN = /\b[A-Z0-9]{4}-[A-Z0-9]{4}\b/g;

function escapeRegexLiteral(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function extractCleanMessageText(rawText: string): string {
  const trimmed = rawText.trim();
  if (!trimmed) return '';

  const tryParse = (candidate: string): string | null => {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (parsed && typeof parsed === 'object' && 'text' in parsed) {
        const val = (parsed as { text?: unknown }).text;
        if (typeof val === 'string' && val.trim().length > 0) {
          return val;
        }
      }
    } catch {
      // No es JSON válido
    }
    return null;
  };

  const direct = tryParse(trimmed);
  if (direct !== null) return direct;

  const quotedTextMatch = trimmed.match(/"text"\s*:\s*"((?:\\.|[^"\\])*)"/);
  if (quotedTextMatch && quotedTextMatch[1] !== undefined) {
    try {
      return JSON.parse(`"${quotedTextMatch[1]}"`) as string;
    } catch {
      return quotedTextMatch[1];
    }
  }

  const jsonMatch = trimmed.match(/\{[\s\S]*"__pin_v"[\s\S]*\}/);
  if (jsonMatch) {
    const extracted = tryParse(jsonMatch[0]);
    if (extracted !== null) return extracted;
  }

  return trimmed;
}

class SoundAndNotificationController {
  private audioCtx: AudioContext | null = null;
  private userInteracted = false;
  private soundEnabled = true;
  private desktopNotifEnabled = true;
  private seenMessageKeys = new Set<string>();
  private observer: MutationObserver | null = null;
  private aliases: Record<string, string> = {};
  private syncingUi = false;

  constructor() {
    this.loadAliases();
    if (typeof window !== 'undefined') {
      const onGesture = () => {
        this.userInteracted = true;
        if (this.audioCtx && this.audioCtx.state === 'suspended') {
          this.audioCtx.resume().catch(() => {});
        }
      };
      window.addEventListener('pointerdown', onGesture, { passive: true });
      window.addEventListener('keydown', onGesture, { passive: true });
    }
  }

  private loadAliases(): void {
    if (typeof window === 'undefined') return;
    try {
      const raw = window.localStorage.getItem(ALIAS_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Record<string, string>;
        if (parsed && typeof parsed === 'object') {
          this.aliases = parsed;
        }
      }
    } catch {
      this.aliases = {};
    }
  }

  private saveAliases(): void {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(ALIAS_STORAGE_KEY, JSON.stringify(this.aliases));
    } catch {
      // Ignorado si storage no está disponible
    }
  }

  setPinAlias(pin: string, alias: string): void {
    const cleanPin = pin.trim().toUpperCase();
    const cleanAlias = alias.trim();
    if (!cleanPin) return;
    if (cleanAlias) {
      this.aliases[cleanPin] = cleanAlias;
    } else {
      delete this.aliases[cleanPin];
    }
    this.saveAliases();
    this.syncAllViews();
  }

  getAliasForPin(pin: string): string | undefined {
    return this.aliases[pin.trim().toUpperCase()];
  }

  replacePinsWithAliasesInText(text: string): string {
    let result = text;
    for (const [pin, alias] of Object.entries(this.aliases)) {
      const cleanAlias = (alias || '').trim();
      if (!cleanAlias) continue;
      const escapedPin = escapeRegexLiteral(pin);
      const escapedAlias = escapeRegexLiteral(cleanAlias);
      const reAlready = new RegExp(`\\b${escapedAlias}\\s*\\(${escapedPin}\\)`, 'gi');
      result = result.replace(reAlready, `${cleanAlias} (${pin})`);
      const reBare = new RegExp(`\\b${escapedPin}\\b`, 'gi');
      result = result.replace(reBare, `${cleanAlias} (${pin})`);
    }
    return result;
  }

  private ensureContextAfterGesture(): AudioContext | null {
    if (typeof window === 'undefined' || !this.userInteracted) return null;
    if (this.audioCtx) return this.audioCtx;

    const Ctx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctx) return null;

    this.audioCtx = new Ctx();
    return this.audioCtx;
  }

  async requestNotificationPermissionIfNeeded(): Promise<NotificationPermission | 'unsupported'> {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      return 'unsupported';
    }
    if (Notification.permission === 'default') {
      try {
        return await Notification.requestPermission();
      } catch {
        return 'denied';
      }
    }
    return Notification.permission;
  }

  setPreferences(opts: { soundEnabled?: boolean; desktopNotifEnabled?: boolean }): void {
    if (typeof opts.soundEnabled === 'boolean') this.soundEnabled = opts.soundEnabled;
    if (typeof opts.desktopNotifEnabled === 'boolean') this.desktopNotifEnabled = opts.desktopNotifEnabled;
  }

  async playMessageTone(): Promise<void> {
    if (!this.soundEnabled) return;
    const ctx = this.ensureContextAfterGesture();
    if (!ctx) return;

    try {
      if (ctx.state === 'suspended') {
        await ctx.resume();
      }
      const now = ctx.currentTime;
      const notes = [
        { freq: 784, start: 0, duration: 0.08 },
        { freq: 1046.5, start: 0.09, duration: 0.13 },
      ];
      for (const n of notes) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(n.freq, now + n.start);

        gain.gain.setValueAtTime(0.0001, now + n.start);
        gain.gain.exponentialRampToValueAtTime(0.14, now + n.start + 0.015);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + n.start + n.duration);

        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + n.start);
        osc.stop(now + n.start + n.duration + 0.02);
      }
    } catch {
      // Ignorado si el navegador bloquea el audio
    }
  }

  private showInAppToast(alert: IncomingMessageAlert): void {
    if (typeof document === 'undefined') return;
    let container = document.getElementById('pin-top-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'pin-top-toast-container';
      container.className = 'pin-top-toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'pin-top-toast';
    toast.setAttribute('role', 'status');

    const title = document.createElement('div');
    title.className = 'pin-top-toast-title';
    title.textContent = this.replacePinsWithAliasesInText(alert.senderLabel);

    const body = document.createElement('div');
    body.className = 'pin-top-toast-body';
    body.textContent = this.replacePinsWithAliasesInText(extractCleanMessageText(alert.previewText));

    toast.append(title, body);
    container.appendChild(toast);

    window.setTimeout(() => {
      toast.classList.add('pin-top-toast-hide');
      window.setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  async notifyIncomingMessage(alert: IncomingMessageAlert): Promise<void> {
    const cleanPreview = this.replacePinsWithAliasesInText(extractCleanMessageText(alert.previewText));
    const cleanSender = this.replacePinsWithAliasesInText(alert.senderLabel);
    this.showInAppToast({ ...alert, senderLabel: cleanSender, previewText: cleanPreview });

    if (
      this.desktopNotifEnabled &&
      typeof window !== 'undefined' &&
      'Notification' in window &&
      Notification.permission === 'granted' &&
      (document.hidden || !document.hasFocus())
    ) {
      try {
        const notif = new Notification(cleanSender, {
          body: cleanPreview,
          tag: alert.groupId ? `pin-mls-${alert.groupId}` : 'pin-mls-msg',
        });
        notif.onclick = () => {
          window.focus();
          notif.close();
        };
      } catch {
        // Ignorado si no está disponible
      }
    }

    await this.playMessageTone();
  }

  private sanitizeBubbleNode(bubble: HTMLElement): string {
    const metaEl = bubble.querySelector<HTMLElement>('.msg-meta');
    const metaText = metaEl ? (metaEl.textContent || '').trim() : '';

    let bodySource = '';
    for (const child of Array.from(bubble.childNodes)) {
      if (child === metaEl) continue;
      bodySource += child.textContent || '';
    }

    const cleanedBody = this.replacePinsWithAliasesInText(extractCleanMessageText(bodySource));
    if (cleanedBody && cleanedBody.trim() !== bodySource.trim()) {
      for (const child of Array.from(bubble.childNodes)) {
        if (child !== metaEl) {
          child.remove();
        }
      }
      const cleanSpan = document.createElement('div');
      cleanSpan.className = 'pin-clean-msg-text';
      cleanSpan.textContent = cleanedBody;
      if (metaEl) {
        bubble.insertBefore(cleanSpan, metaEl);
      } else {
        bubble.appendChild(cleanSpan);
      }
    }

    return cleanedBody || (bubble.textContent || '').replace(metaText, '').trim();
  }

  private renderAliasElement(el: HTMLElement): void {
    const raw = (el.textContent || '').trim();
    if (!raw) return;

    for (const [pin, alias] of Object.entries(this.aliases)) {
      const cleanAlias = (alias || '').trim();
      if (!cleanAlias) continue;
      const upperPin = pin.toUpperCase();
      if (!raw.toUpperCase().includes(upperPin)) continue;

      const suffix = raw
        .replace(new RegExp(`\\b${escapeRegexLiteral(cleanAlias)}\\s*\\(${escapeRegexLiteral(upperPin)}\\)`, 'i'), '')
        .replace(new RegExp(`\\b(?:PIN\\s*)?${escapeRegexLiteral(upperPin)}\\b`, 'i'), '')
        .trim();

      el.textContent = '';
      const wrap = document.createElement('span');
      wrap.className = 'pin-alias-wrap';

      const nameEl = document.createElement('span');
      nameEl.className = 'pin-alias-name';
      nameEl.textContent = cleanAlias;

      const pinEl = document.createElement('span');
      pinEl.className = 'pin-sub-code';
      pinEl.textContent = suffix ? `${upperPin} ${suffix}` : upperPin;

      wrap.append(nameEl, pinEl);
      el.appendChild(wrap);
      return;
    }
  }

  private sanitizeChatListPreviews(): void {
    if (typeof document === 'undefined') return;
    const chatCards = document.querySelectorAll<HTMLElement>('#list-chats .list-card');
    chatCards.forEach((card) => {
      const previewEls = card.querySelectorAll<HTMLElement>('.muted-small, small, p');
      previewEls.forEach((el) => {
        const raw = el.textContent || '';
        const cleaned = this.replacePinsWithAliasesInText(extractCleanMessageText(raw));
        if (cleaned && cleaned !== raw.trim()) {
          el.textContent = cleaned;
        }
      });

      const titleEls = card.querySelectorAll<HTMLElement>('strong, b, h3, h4, .card-row > span:first-child');
      titleEls.forEach((el) => {
        this.renderAliasElement(el);
      });
    });

    const activeTitle = document.getElementById('active-chat-title');
    if (activeTitle && activeTitle.textContent) {
      this.renderAliasElement(activeTitle);
    }
  }

  private captureAliasInputsFromDom(): void {
    if (typeof document === 'undefined') return;
    const aliasInputs = document.querySelectorAll<HTMLInputElement>(
      'input[id*="alias" i], input[placeholder*="alias" i], input[aria-label*="alias" i]'
    );
    aliasInputs.forEach((input) => {
      const val = input.value.trim();
      if (!val) return;
      const scope = input.closest<HTMLElement>('dialog, [role="dialog"], .modal, .card, form, section, body');
      const scopeText = scope ? scope.textContent || '' : '';
      const pins = scopeText.match(PIN_PATTERN) || [];
      const firstPin = pins[0];
      if (firstPin) {
        const targetPin = firstPin.toUpperCase();
        if (this.aliases[targetPin] !== val) {
          this.aliases[targetPin] = val;
          this.saveAliases();
        }
      }
    });
  }

  syncInvitesVisibility(): void {
    if (typeof document === 'undefined') return;
    const listInvites = document.getElementById('list-invites');
    const badgeInvites = document.getElementById('badge-invites');
    if (!listInvites) return;

    const badgeNum = badgeInvites ? Number((badgeInvites.textContent || '').trim()) : 0;
    const hasPendingCards = listInvites.querySelectorAll('.list-card').length > 0;
    const shouldShow = (!Number.isNaN(badgeNum) && badgeNum > 0) || hasPendingCards;

    const container =
      listInvites.closest<HTMLElement>('section, .card, .panel, .sidebar-section, [data-invites-box]') ||
      listInvites.parentElement;

    if (container && container !== document.body) {
      container.classList.toggle('pin-invites-hidden', !shouldShow);
    } else {
      listInvites.classList.toggle('pin-invites-hidden', !shouldShow);
    }
  }

  private collectSavedContacts(): Array<{ pin: string; element: HTMLElement }> {
    if (typeof document === 'undefined') return [];
    const contacts: Array<{ pin: string; element: HTMLElement }> = [];
    const seenPins = new Set<string>();

    document.querySelectorAll<HTMLElement>('#list-chats .list-card').forEach((card) => {
      const text = (card.textContent || '').trim();
      const pins = text.match(PIN_PATTERN) || [];
      const pin = (pins[0] || text.split('\n')[0] || '').trim().toUpperCase();
      if (!pin || seenPins.has(pin)) return;
      seenPins.add(pin);
      contacts.push({ pin, element: card });
    });

    for (const pin of Object.keys(this.aliases)) {
      const upper = pin.toUpperCase();
      if (!seenPins.has(upper)) {
        seenPins.add(upper);
        contacts.push({ pin: upper, element: document.createElement('div') });
      }
    }

    return contacts;
  }

  private openContactsSearchPopover(): void {
    if (typeof document === 'undefined') return;
    const existing = document.getElementById('pin-contacts-popover');
    if (existing) {
      existing.remove();
      return;
    }

    const popover = document.createElement('div');
    popover.id = 'pin-contacts-popover';
    popover.className = 'pin-contacts-popover';
    popover.setAttribute('role', 'dialog');

    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.alignItems = 'center';
    header.style.marginBottom = '8px';

    const title = document.createElement('strong');
    title.textContent = 'Contactos guardados';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = 'Cerrar';
    closeBtn.addEventListener('click', () => popover.remove());

    header.append(title, closeBtn);

    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.placeholder = 'Buscar por alias o PIN...';
    searchInput.style.width = '100%';
    searchInput.style.padding = '8px 10px';
    searchInput.style.boxSizing = 'border-box';

    const resultsBox = document.createElement('div');

    const renderList = (query: string) => {
      resultsBox.innerHTML = '';
      const q = query.trim().toLowerCase();
      const all = this.collectSavedContacts().filter((c) => {
        const alias = (this.getAliasForPin(c.pin) || '').toLowerCase();
        return !q || alias.includes(q) || c.pin.toLowerCase().includes(q);
      });

      if (all.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted-small';
        empty.style.marginTop = '10px';
        empty.textContent = 'No se encontraron contactos guardados.';
        resultsBox.appendChild(empty);
        return;
      }

      for (const item of all) {
        const row = document.createElement('div');
        row.className = 'pin-contacts-row';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'pin-alias-wrap';
        const aliasOnly = this.getAliasForPin(item.pin);
        if (aliasOnly) {
          const aEl = document.createElement('span');
          aEl.className = 'pin-alias-name';
          aEl.textContent = aliasOnly;
          const pEl = document.createElement('span');
          pEl.className = 'pin-sub-code';
          pEl.textContent = item.pin;
          nameSpan.append(aEl, pEl);
        } else {
          nameSpan.textContent = item.pin;
        }

        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'btn-primary';
        openBtn.textContent = 'Abrir';
        openBtn.addEventListener('click', () => {
          if (item.element.isConnected) {
            item.element.click();
            item.element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          } else {
            const inviteInput = document.getElementById('input-invite-pin') as HTMLInputElement | null;
            if (inviteInput) {
              inviteInput.value = item.pin;
              inviteInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
          }
          popover.remove();
        });

        row.append(nameSpan, openBtn);
        resultsBox.appendChild(row);
      }
    };

    searchInput.addEventListener('input', () => renderList(searchInput.value));
    renderList('');

    popover.append(header, searchInput, resultsBox);
    document.body.appendChild(popover);
    searchInput.focus();
  }

  installContactsSearchButton(): void {
    if (typeof document === 'undefined') return;
    if (document.getElementById('btn-search-saved-contacts')) return;

    const btn = document.createElement('button');
    btn.id = 'btn-search-saved-contacts';
    btn.type = 'button';
    btn.className = 'pin-contacts-btn';
    btn.textContent = 'Contactos';
    btn.title = 'Buscar contactos guardados';
    btn.addEventListener('click', () => this.openContactsSearchPopover());

    const searchInput = document.querySelector<HTMLElement>(
      'input[placeholder*="Buscar" i], input[id*="search" i]'
    );
    if (searchInput && searchInput.parentElement) {
      searchInput.parentElement.appendChild(btn);
    } else {
      const header = document.querySelector<HTMLElement>('#view-chat > header, header, .topbar');
      if (header) header.appendChild(btn);
    }
  }

  syncAllViews(): void {
    if (typeof document === 'undefined' || this.syncingUi) return;
    this.syncingUi = true;
    try {
      this.captureAliasInputsFromDom();
      this.syncInvitesVisibility();
      this.sanitizeChatListPreviews();
      this.installContactsSearchButton();
      document.querySelectorAll<HTMLElement>('.msg-bubble').forEach((el) => {
        this.sanitizeBubbleNode(el);
      });
    } finally {
      this.syncingUi = false;
    }
  }

  installIncomingDomWatcher(): void {
    if (typeof document === 'undefined' || this.observer) return;

    const seedExisting = () => {
      this.syncAllViews();
      document.querySelectorAll<HTMLElement>('.msg-bubble, [data-message-id]').forEach((el) => {
        const cleanText = this.sanitizeBubbleNode(el);
        const key = el.getAttribute('data-message-id') || cleanText;
        if (key) this.seenMessageKeys.add(key);
      });
    };

    seedExisting();

    if (typeof window !== 'undefined') {
      (window as unknown as { pinSetAlias?: (pin: string, alias: string) => void }).pinSetAlias = (
        pin: string,
        alias: string
      ) => this.setPinAlias(pin, alias);

      document.addEventListener('input', () => {
        this.captureAliasInputsFromDom();
      });
      document.addEventListener('change', () => {
        this.captureAliasInputsFromDom();
        this.syncAllViews();
      });
    }

    this.observer = new MutationObserver((mutations) => {
      this.syncAllViews();

      for (const mut of mutations) {
        mut.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) return;
          if (node.closest('#pin-top-toast-container') || node.closest('#pin-contacts-popover')) return;

          const candidates = node.matches('.msg-bubble, [data-message-id]')
            ? [node]
            : Array.from(node.querySelectorAll<HTMLElement>('.msg-bubble, [data-message-id]'));

          for (const el of candidates) {
            const cleanText = this.sanitizeBubbleNode(el);
            if (el.classList.contains('mine')) continue;
            if (!cleanText) continue;

            const key = `${el.getAttribute('data-message-id') || ''}|${cleanText}`;
            if (this.seenMessageKeys.has(key)) continue;
            this.seenMessageKeys.add(key);

            void this.notifyIncomingMessage({
              senderLabel: 'Nuevo mensaje',
              previewText: cleanText.slice(0, 120),
            });
          }
        });
      }
    });

    this.observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }
}

export const waAlerts = new SoundAndNotificationController();

export function applyWhatsAppLayoutClasses(): void {
  if (typeof document === 'undefined') return;
  document.body.classList.add('pin-wa-topbars');
}
