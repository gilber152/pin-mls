import {
  loadPinAliases,
  setPinAlias as saveVaultPinAlias,
  type PinAliasMap,
} from '../storage/vaultDb.js';

export interface IncomingMessageAlert {
  senderLabel: string;
  previewText: string;
  groupId?: string;
}

const PIN_PATTERN = /\b[A-Z0-9]{4}-?[A-Z0-9]{4}\b/g;
const SINGLE_PIN_RE = /\b[A-Z0-9]{4}-?[A-Z0-9]{4}\b/;
const MOBILE_MEDIA_QUERY = '(max-width: 860px)';

type PatchedWindow = Window & {
  pinSetAlias?: (pin: string, alias: string) => Promise<void>;
  webkitAudioContext?: typeof AudioContext;
};

function escapeRegexLiteral(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizePinCompact(pin: string): string {
  return pin.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function formatPinCanonical(pin: string): string {
  const compact = normalizePinCompact(pin);
  if (compact.length === 8) {
    return `${compact.slice(0, 4)}-${compact.slice(4)}`;
  }
  return pin.trim().toUpperCase();
}

export function extractCleanMessageText(rawText: string): string {
  const trimmed = rawText.trim();
  if (!trimmed) return '';

  const prefixMatch = trimmed.match(/^(Tú:\s*)/i);
  const prefix = prefixMatch?.[1] ?? '';
  const body = prefix ? trimmed.slice(prefix.length).trim() : trimmed;

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

  const direct = tryParse(body);
  if (direct !== null) return `${prefix}${direct}`;

  const quotedTextMatch = body.match(/"text"\s*:\s*"((?:\\.|[^"\\])*)"/);
  const captured = quotedTextMatch?.[1];
  if (captured !== undefined) {
    try {
      const unescaped = JSON.parse(`"${captured}"`) as string;
      return `${prefix}${unescaped}`;
    } catch {
      return `${prefix}${captured}`;
    }
  }

  const jsonMatch = body.match(/\{[\s\S]*"__pin_v"[\s\S]*\}/);
  const matchedJson = jsonMatch?.[0];
  if (matchedJson) {
    const extracted = tryParse(matchedJson);
    if (extracted !== null) return `${prefix}${extracted}`;
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
  private aliasesByCanonical: Record<string, string> = {};
  private aliasesByCompact: Record<string, string> = {};
  private syncingUi = false;
  private mobileEventsBound = false;
  private lastActiveChatKey = '';
  private suppressAlertsUntil = Date.now() + 2500;
  private seenChatPreviews = new Map<string, string>();
  private lastSoundPlayedAt = 0;

  constructor() {
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
    void this.refreshAliasesFromVault();
  }

  private suppressNotificationsFor(ms = 900): void {
    const target = Date.now() + ms;
    if (target > this.suppressAlertsUntil) {
      this.suppressAlertsUntil = target;
    }
  }

  private getCurrentActiveChatKey(): string {
    if (typeof document === 'undefined') return '';
    const activeCard = document.querySelector<HTMLElement>('#list-chats .list-card.active');
    if (activeCard?.dataset.groupId) {
      return `gid:${activeCard.dataset.groupId}`;
    }
    const activeTitle = document.getElementById('active-chat-title');
    const raw = (activeTitle?.dataset.pinOriginal || activeTitle?.textContent || '')
      .trim()
      .toUpperCase();
    const pin = raw.match(SINGLE_PIN_RE)?.[0];
    if (pin) return `pin:${formatPinCanonical(pin)}`;
    return raw ? `title:${raw}` : '';
  }

  private buildBubbleKey(el: HTMLElement, cleanText: string, chatKey: string): string {
    const dataId = el.getAttribute('data-message-id') || '';
    if (dataId) return `${chatKey}|id:${dataId}`;
    const metaEl = el.querySelector<HTMLElement>('.msg-meta');
    const metaRaw = (metaEl?.textContent || '').trim();
    const seq = metaRaw.match(/#\d+/)?.[0] ?? '';
    const mineFlag = el.classList.contains('mine') ? '1' : '0';
    if (seq) {
      return `${chatKey}|${mineFlag}|${seq}`;
    }
    return `${chatKey}|${mineFlag}|${cleanText}`;
  }

  private seedVisibleBubblesSilently(chatKey: string): void {
    document.querySelectorAll<HTMLElement>('.msg-bubble, [data-message-id]').forEach((el) => {
      const cleanText = this.sanitizeBubbleNode(el);
      if (!cleanText) return;
      const key = this.buildBubbleKey(el, cleanText, chatKey);
      this.seenMessageKeys.add(key);
    });
  }

  private syncChatListPreviewAlerts(silent: boolean): void {
    if (typeof document === 'undefined') return;
    const cards = document.querySelectorAll<HTMLElement>('#list-chats .list-card');
    cards.forEach((card) => {
      const rawText = (card.textContent || '').trim();
      const pinMatch = rawText.toUpperCase().match(SINGLE_PIN_RE)?.[0];
      const canonicalPin = pinMatch ? formatPinCanonical(pinMatch) : '';
      const cardKey = card.dataset.groupId
        ? `gid:${card.dataset.groupId}`
        : canonicalPin
          ? `pin:${canonicalPin}`
          : '';
      if (!cardKey) return;

      let previewText = '';
      const previewEls = Array.from(card.querySelectorAll<HTMLElement>('.muted-small, small, p'));
      for (const el of previewEls) {
        if (el.hidden) continue;
        const t = extractCleanMessageText((el.textContent || '').trim()).trim();
        if (!t || /^[·•\s-]*[eé]poca\s*\d+[·•\s-]*$/i.test(t)) continue;
        previewText = t;
      }

      const prev = this.seenChatPreviews.get(cardKey);
      this.seenChatPreviews.set(cardKey, previewText);

      if (silent || prev === undefined || prev === previewText) return;
      if (card.classList.contains('active')) return;
      if (!previewText) return;
      if (/^t[uú]:/i.test(previewText)) return;
      if (/sin mensajes|a[uú]n no|conversaci[oó]n creada/i.test(previewText)) return;

      const senderLabel =
        (canonicalPin && this.getAliasForPin(canonicalPin)) ||
        canonicalPin ||
        'Nuevo mensaje';

      const groupId = card.dataset.groupId || canonicalPin;
      void this.notifyIncomingMessage({
        senderLabel,
        previewText: previewText.slice(0, 120),
        ...(groupId ? { groupId } : {}),
      });
    });
  }

  private isMobileViewport(): boolean {
    if (typeof window === 'undefined') return false;
    if (typeof window.matchMedia === 'function') {
      return window.matchMedia(MOBILE_MEDIA_QUERY).matches;
    }
    return window.innerWidth <= 860;
  }

  private setMobileChatOpen(open: boolean): void {
    if (typeof document === 'undefined') return;
    if (open && this.isMobileViewport()) {
      this.tagMobileLayoutContainers();
      document.body.classList.add('pin-mobile-chat-open');
      document.body.classList.remove('pin-mobile-menu-open');
      window.requestAnimationFrame(() => {
        const msgs = document.getElementById('messages-list');
        if (msgs) msgs.scrollTop = msgs.scrollHeight;
      });
    } else {
      document.body.classList.remove('pin-mobile-chat-open');
    }
    this.syncMobileMenuButtonLabel();
  }

  private syncMobileMenuButtonLabel(): void {
    const toggleBtn = document.getElementById('btn-mobile-menu-toggle');
    if (!toggleBtn) return;
    const isOpen = document.body.classList.contains('pin-mobile-menu-open');
    toggleBtn.textContent = isOpen ? '✕ Cerrar' : '☰ Menú';
    toggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }

  private syncOnboardingStateClass(): void {
    if (typeof document === 'undefined') return;
    const onboarding = document.getElementById('view-onboarding');
    const chatView = document.getElementById('view-chat');
    const isOnboardingVisible =
      Boolean(
        onboarding &&
          !onboarding.hidden &&
          !onboarding.classList.contains('hidden') &&
          onboarding.style.display !== 'none'
      ) || Boolean(chatView && (chatView.hidden || chatView.classList.contains('hidden')));

    document.body.classList.toggle('pin-onboarding-visible', isOnboardingVisible);
    if (isOnboardingVisible) {
      document.body.classList.remove('pin-mobile-chat-open', 'pin-mobile-menu-open');
      this.syncMobileMenuButtonLabel();
    }
  }

  private tagMobileLayoutContainers(): void {
    if (typeof document === 'undefined') return;

    this.syncOnboardingStateClass();

    const listChats = document.getElementById('list-chats');
    const chatActive = document.getElementById('chat-active');
    const viewChat = document.getElementById('view-chat');
    let sidebarRoot: HTMLElement | null = null;
    let stageRoot: HTMLElement | null = null;

    if (listChats && chatActive) {
      const sidebarAncestors: HTMLElement[] = [];
      let cur: HTMLElement | null = listChats;
      while (cur && cur !== document.body) {
        sidebarAncestors.push(cur);
        cur = cur.parentElement;
      }

      const stageAncestors: HTMLElement[] = [];
      cur = chatActive;
      let lca: HTMLElement | null = null;
      while (cur && cur !== document.body) {
        if (sidebarAncestors.includes(cur)) {
          lca = cur;
          break;
        }
        stageAncestors.push(cur);
        cur = cur.parentElement;
      }

      if (lca) {
        sidebarRoot = sidebarAncestors.find((el) => el.parentElement === lca) ?? null;
        stageRoot = stageAncestors.find((el) => el.parentElement === lca) ?? null;
        if (sidebarRoot && stageRoot && sidebarRoot !== stageRoot) {
          lca.setAttribute('data-pin-mobile-grid', 'true');
          sidebarRoot.setAttribute('data-pin-mobile-sidebar', 'true');
          stageRoot.setAttribute('data-pin-mobile-stage', 'true');

          let up: HTMLElement | null = lca.parentElement;
          while (up && up !== viewChat && up !== document.body) {
            up.setAttribute('data-pin-mobile-fill', 'true');
            up = up.parentElement;
          }
          up = chatActive.parentElement;
          while (up && up !== stageRoot && up !== document.body) {
            up.setAttribute('data-pin-mobile-fill', 'true');
            up = up.parentElement;
          }
          up = listChats.parentElement;
          while (up && up !== sidebarRoot && up !== document.body) {
            up.setAttribute('data-pin-mobile-chats-wrapper', 'true');
            up = up.parentElement;
          }
        }
      }
    }

    const syncBtn = document.getElementById('btn-sync-now');
    const headerAnchor = syncBtn || document.getElementById('my-pin-label');
    let mainHeader: HTMLElement | null = null;
    if (headerAnchor) {
      let cur: HTMLElement | null = headerAnchor;
      while (cur && cur.parentElement && cur.parentElement !== document.body) {
        if (cur.parentElement === viewChat || cur.tagName === 'HEADER') {
          mainHeader = cur;
          break;
        }
        cur = cur.parentElement;
      }
      if (mainHeader && (!listChats || !mainHeader.contains(listChats))) {
        mainHeader.setAttribute('data-pin-mobile-main-header', 'true');
      }
    }

    if (syncBtn && mainHeader && syncBtn.parentElement && syncBtn.parentElement !== mainHeader) {
      const actionsGroup = syncBtn.parentElement;
      const myPin = document.getElementById('my-pin-label');
      const contactsBtn = document.getElementById('btn-search-saved-contacts');
      const menuBtn = document.getElementById('btn-mobile-menu-toggle');
      if (
        (!myPin || !actionsGroup.contains(myPin)) &&
        (!contactsBtn || !actionsGroup.contains(contactsBtn)) &&
        (!menuBtn || !actionsGroup.contains(menuBtn))
      ) {
        actionsGroup.setAttribute('data-pin-mobile-actions-group', 'true');
      }
    }

    const extraAnchors = [
      document.getElementById('pin-btn-edit-alias'),
      document.querySelector<HTMLElement>('input[placeholder*="Invitar varios" i]'),
      document.querySelector<HTMLElement>('input[placeholder*="Buscar localmente" i]'),
    ];

    for (const anchor of extraAnchors) {
      if (!anchor) continue;
      if (sidebarRoot && sidebarRoot.contains(anchor)) continue;
      if (stageRoot && stageRoot.contains(anchor)) continue;

      let cur: HTMLElement | null = anchor;
      while (
        cur &&
        cur.parentElement &&
        cur.parentElement !== document.body &&
        cur.parentElement !== viewChat &&
        (!listChats || !cur.parentElement.contains(listChats)) &&
        (!mainHeader || !cur.parentElement.contains(mainHeader))
      ) {
        cur = cur.parentElement;
      }
      if (
        cur &&
        cur !== document.body &&
        cur !== viewChat &&
        cur !== mainHeader &&
        (!listChats || !cur.contains(listChats)) &&
        (!chatActive || !cur.contains(chatActive))
      ) {
        cur.setAttribute('data-pin-mobile-collapsible', 'true');
      }
    }

    if (mainHeader && !document.getElementById('btn-mobile-menu-toggle')) {
      const menuBtn = document.createElement('button');
      menuBtn.id = 'btn-mobile-menu-toggle';
      menuBtn.type = 'button';
      menuBtn.className = 'pin-mobile-only-btn';
      menuBtn.textContent = '☰ Menú';
      menuBtn.setAttribute('aria-expanded', 'false');
      menuBtn.addEventListener('click', () => {
        document.body.classList.toggle('pin-mobile-menu-open');
        this.syncMobileMenuButtonLabel();
      });
      mainHeader.appendChild(menuBtn);
    }

    const activeTitle = document.getElementById('active-chat-title');
    if (activeTitle && activeTitle.parentElement) {
      activeTitle.parentElement.setAttribute('data-pin-mobile-chat-header', 'true');
      if (!document.getElementById('btn-mobile-chat-back')) {
        const backBtn = document.createElement('button');
        backBtn.id = 'btn-mobile-chat-back';
        backBtn.type = 'button';
        backBtn.className = 'pin-mobile-back-btn';
        backBtn.textContent = '←';
        backBtn.title = 'Volver a conversaciones';
        backBtn.setAttribute('aria-label', 'Volver a conversaciones');
        backBtn.addEventListener('click', () => {
          this.setMobileChatOpen(false);
        });
        activeTitle.insertAdjacentElement('beforebegin', backBtn);
      }
    }

    if (!this.mobileEventsBound && typeof window !== 'undefined') {
      this.mobileEventsBound = true;

      document.addEventListener(
        'click',
        (ev) => {
          const target = ev.target instanceof HTMLElement ? ev.target : null;
          if (!target) return;

          const path = typeof ev.composedPath === 'function' ? ev.composedPath() : [];
          const clickedDelete =
            Boolean(target.closest('.pin-delete-contact-btn')) ||
            path.some(
              (n) => n instanceof HTMLElement && n.classList.contains('pin-delete-contact-btn')
            );

          const chatCard =
            target.closest<HTMLElement>('#list-chats .list-card') ||
            (path.find(
              (n): n is HTMLElement =>
                n instanceof HTMLElement &&
                n.classList.contains('list-card') &&
                (n.parentElement?.id === 'list-chats' || Boolean(n.closest('#list-chats')))
            ) ??
              null);

          // Silenciar alertas antes de que main.ts cargue el historial de ese contacto
          if (chatCard && !clickedDelete) {
            this.suppressNotificationsFor(900);
            this.setMobileChatOpen(true);
            return;
          }

          if (target.closest('#btn-logout-session, #btn-wipe-vault')) {
            this.suppressNotificationsFor(1500);
            window.setTimeout(() => {
              document.body.classList.remove('pin-mobile-chat-open', 'pin-mobile-menu-open');
              this.syncMobileMenuButtonLabel();
            }, 0);
            return;
          }

          if (
            target.closest(
              '#btn-open-devices, #btn-open-safe, #btn-sync-now, #pin-btn-edit-alias'
            )
          ) {
            window.setTimeout(() => {
              document.body.classList.remove('pin-mobile-menu-open');
              this.syncMobileMenuButtonLabel();
            }, 0);
          }
        },
        true
      );

      window.addEventListener('pin:delete-contact', () => {
        this.suppressNotificationsFor(1000);
        this.setMobileChatOpen(false);
      });

      const syncVisualViewport = () => {
        const vv = window.visualViewport;
        const h = vv ? vv.height : window.innerHeight;
        if (h > 0) {
          document.documentElement.style.setProperty('--pin-vvh', `${Math.round(h)}px`);
        }
        if (this.isMobileViewport() && window.scrollY !== 0) {
          window.scrollTo(0, 0);
        }
      };

      syncVisualViewport();
      window.visualViewport?.addEventListener('resize', syncVisualViewport);
      window.visualViewport?.addEventListener('scroll', syncVisualViewport);
      window.addEventListener('orientationchange', () => window.setTimeout(syncVisualViewport, 160));

      window.addEventListener('resize', () => {
        syncVisualViewport();
        if (!this.isMobileViewport()) {
          document.body.classList.remove('pin-mobile-chat-open', 'pin-mobile-menu-open');
          this.syncMobileMenuButtonLabel();
        }
      });
    }
  }

  private applyAliasMap(map: PinAliasMap): void {
    const byCanonical: Record<string, string> = {};
    const byCompact: Record<string, string> = {};

    for (const [rawPin, rawAlias] of Object.entries(map)) {
      if (typeof rawAlias !== 'string') continue;
      const cleanAlias = rawAlias.trim();
      if (!cleanAlias) continue;
      const canonical = formatPinCanonical(rawPin);
      const compact = normalizePinCompact(rawPin);
      if (!canonical) continue;
      byCanonical[canonical] = cleanAlias;
      if (compact) byCompact[compact] = cleanAlias;
    }

    this.aliasesByCanonical = byCanonical;
    this.aliasesByCompact = byCompact;
  }

  async refreshAliasesFromVault(): Promise<void> {
    try {
      const loaded = await loadPinAliases();
      this.applyAliasMap(loaded);
      this.syncAllViews();
    } catch {
      // Ignorado si IndexedDB aún no está listo
    }
  }

  async setPinAlias(pin: string, alias: string): Promise<void> {
    const canonical = formatPinCanonical(pin);
    if (!canonical) return;
    const updated = await saveVaultPinAlias(canonical, alias.trim());
    this.applyAliasMap(updated);
    this.syncAllViews();
  }

  getAliasForPin(pin: string): string | undefined {
    const canonical = formatPinCanonical(pin);
    const compact = normalizePinCompact(pin);
    return this.aliasesByCanonical[canonical] ?? this.aliasesByCompact[compact];
  }

  requestDeleteContact(pin: string, groupIdB64 = ''): void {
    const canonical = pin ? formatPinCanonical(pin) : '';
    const alias = canonical ? this.getAliasForPin(canonical) : undefined;
    const displayLabel =
      alias && canonical ? `${alias} (${canonical})` : canonical || 'este contacto';
    const confirmed = window.confirm(
      `¿Eliminar a ${displayLabel} y su conversación local de este dispositivo?`
    );
    if (!confirmed) return;

    window.dispatchEvent(
      new CustomEvent('pin:delete-contact', {
        detail: { pin: canonical, groupIdB64 },
      })
    );
  }

  replacePinsWithAliasesInText(text: string): string {
    let result = text;
    for (const [pin, alias] of Object.entries(this.aliasesByCanonical)) {
      const cleanAlias = alias.trim();
      if (!cleanAlias) continue;
      const compact = normalizePinCompact(pin);
      const escapedPin = escapeRegexLiteral(pin);
      const escapedCompact = escapeRegexLiteral(compact);
      const escapedAlias = escapeRegexLiteral(cleanAlias);

      const combinedRe = new RegExp(
        `(?:\\b${escapedAlias}\\s*\\((?:${escapedPin}|${escapedCompact})\\)|\\b${escapedPin}\\b|\\b${escapedCompact}\\b)`,
        'gi'
      );
      result = result.replace(combinedRe, `${cleanAlias} (${pin})`);
    }
    return result;
  }

  private ensureContextAfterGesture(): AudioContext | null {
    if (typeof window === 'undefined' || !this.userInteracted) return null;
    if (this.audioCtx) return this.audioCtx;

    const w = window as PatchedWindow;
    const Ctx = window.AudioContext || w.webkitAudioContext;
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
    this.soundEnabled = true;
    if (typeof opts.desktopNotifEnabled === 'boolean') {
      this.desktopNotifEnabled = opts.desktopNotifEnabled;
    }
  }

  async playMessageTone(): Promise<void> {
    if (!this.soundEnabled) return;
    const nowMs = Date.now();
    if (nowMs - this.lastSoundPlayedAt < 350) return;
    this.lastSoundPlayedAt = nowMs;

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
        gain.gain.exponentialRampToValueAtTime(0.28, now + n.start + 0.015);
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
    body.textContent = this.replacePinsWithAliasesInText(
      extractCleanMessageText(alert.previewText)
    );

    toast.append(title, body);
    container.appendChild(toast);

    window.setTimeout(() => {
      toast.classList.add('pin-top-toast-hide');
      window.setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  async notifyIncomingMessage(alert: IncomingMessageAlert): Promise<void> {
    const cleanPreview = this.replacePinsWithAliasesInText(
      extractCleanMessageText(alert.previewText)
    );
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
    if (metaEl && metaEl.textContent) {
      const updatedMeta = this.replacePinsWithAliasesInText(metaEl.textContent);
      if (updatedMeta !== metaEl.textContent) {
        metaEl.textContent = updatedMeta;
      }
    }
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
    el.querySelectorAll('.pin-alias-pill').forEach((pill) => pill.remove());

    const hasWrap = el.querySelector('.pin-alias-wrap') !== null;
    if (!hasWrap) {
      const freshRaw = (el.textContent || '').trim();
      if (!freshRaw) return;
      el.dataset.pinOriginal = freshRaw;
      delete el.dataset.pinRenderedAlias;
    }

    const original = (el.dataset.pinOriginal || '').trim();
    if (!original) return;

    const pinMatch = original.toUpperCase().match(SINGLE_PIN_RE);
    const rawMatchedPin = pinMatch?.[0];
    if (!rawMatchedPin) return;

    const canonicalPin = formatPinCanonical(rawMatchedPin);
    const cleanAlias = (this.getAliasForPin(canonicalPin) || '').trim();

    if (!cleanAlias) {
      if (hasWrap) {
        el.textContent = original;
        delete el.dataset.pinRenderedAlias;
      }
      return;
    }

    if (hasWrap && el.dataset.pinRenderedAlias === cleanAlias) {
      return;
    }

    const suffix = original
      .replace(
        new RegExp(
          `\\b${escapeRegexLiteral(cleanAlias)}\\s*\\(${escapeRegexLiteral(rawMatchedPin)}\\)`,
          'i'
        ),
        ''
      )
      .replace(new RegExp(`\\b(?:PIN\\s*)?${escapeRegexLiteral(rawMatchedPin)}\\b`, 'i'), '')
      .replace(/\s*[·•]?\s*[eé]poca\s*\d+/gi, '')
      .replace(/^[·•\s]+|[·•\s]+$/g, '')
      .trim();

    el.textContent = '';
    const wrap = document.createElement('span');
    wrap.className = 'pin-alias-wrap';

    const nameEl = document.createElement('span');
    nameEl.className = 'pin-alias-name';
    nameEl.textContent = cleanAlias;

    const pinEl = document.createElement('span');
    pinEl.className = 'pin-sub-code';
    pinEl.textContent = suffix ? `${canonicalPin} ${suffix}` : canonicalPin;

    wrap.append(nameEl, pinEl);
    el.appendChild(wrap);
    el.dataset.pinRenderedAlias = cleanAlias;
  }

  private ensureCardDeleteButton(card: HTMLElement): void {
    if (card.querySelector('.pin-delete-contact-btn')) return;
    const text = (card.textContent || '').trim();
    const matchedPin = text.toUpperCase().match(SINGLE_PIN_RE)?.[0] ?? '';
    const groupIdB64 = card.dataset.groupId ?? '';
    if (!matchedPin && !groupIdB64) return;

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'pin-delete-contact-btn';
    delBtn.textContent = 'Eliminar';
    delBtn.title = 'Eliminar contacto y chat local';
    delBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      ev.preventDefault();
      this.requestDeleteContact(matchedPin, groupIdB64);
    });

    const row = card.querySelector<HTMLElement>('.card-row');
    if (row) {
      row.appendChild(delBtn);
    } else {
      card.appendChild(delBtn);
    }
  }

  private ensureActiveChatDeleteButton(): void {
    const existing = document.getElementById('btn-delete-active-contact');
    if (existing) existing.remove();
  }

  private cleanEpochAndStatusLabels(): void {
    if (typeof document === 'undefined') return;

    document
      .querySelectorAll<HTMLElement>(
        '#list-chats .list-card span, #list-chats .list-card small, #list-chats .list-card div'
      )
      .forEach((el) => {
        if (el.children.length > 0) return;
        const txt = (el.textContent || '').trim();
        if (/^[·•\s-]*[eé]poca\s*\d+[·•\s-]*$/i.test(txt)) {
          el.textContent = '';
          el.hidden = true;
        }
      });

    const chatHeader =
      document.querySelector<HTMLElement>('[data-pin-mobile-chat-header="true"]') ||
      document.getElementById('active-chat-title')?.parentElement;
    if (chatHeader) {
      chatHeader.querySelectorAll<HTMLElement>('span, small, div, p').forEach((el) => {
        if (
          el.id === 'active-chat-title' ||
          el.closest('#active-chat-title') ||
          el.children.length > 0
        ) {
          return;
        }
        const raw = el.textContent || '';
        if (/[eé]poca\s*\d+/i.test(raw)) {
          const cleaned = raw
            .replace(/\s*[·•]?\s*[eé]poca\s*\d+/gi, '')
            .replace(/^\s*[·•]\s*/, '')
            .replace(/\s*[·•]\s*$/, '')
            .replace(/\s*[·•]\s*[·•]\s*/g, ' · ')
            .trim();
          el.textContent = cleaned;
          if (!cleaned) el.hidden = true;
        }
      });
    }

    const mainHeader =
      document.querySelector<HTMLElement>('[data-pin-mobile-main-header="true"]') ||
      document.querySelector<HTMLElement>('#view-chat > header, header, .topbar');
    if (mainHeader) {
      mainHeader.querySelectorAll<HTMLElement>('span, div, small, button').forEach((el) => {
        if (el.children.length > 0) return;
        const raw = el.textContent || '';
        if (/en\s+l[ií]nea\s*\(\s*wss\s*\)/i.test(raw)) {
          el.textContent = raw.replace(/en\s+l[ií]nea\s*\(\s*wss\s*\)/gi, 'En línea');
        }
      });
    }
  }

  private hideDisabledControls(): void {
    if (typeof document === 'undefined') return;

    document
      .querySelectorAll<HTMLInputElement>(
        'input[placeholder*="Buscar localmente" i], input[placeholder*="mensajes o PINs" i]'
      )
      .forEach((inp) => {
        inp.setAttribute('data-pin-force-hidden', 'true');
        const next = inp.nextElementSibling as HTMLElement | null;
        if (
          next &&
          next.tagName === 'BUTTON' &&
          next.id !== 'pin-btn-edit-alias' &&
          next.id !== 'btn-search-saved-contacts'
        ) {
          const t = (next.textContent || '').trim();
          const title = (
            next.getAttribute('title') ||
            next.getAttribute('aria-label') ||
            ''
          ).toLowerCase();
          if (
            t === '×' ||
            t === '✕' ||
            t.toLowerCase() === 'x' ||
            title.includes('limpiar') ||
            title.includes('clear')
          ) {
            next.setAttribute('data-pin-force-hidden', 'true');
          }
        }
      });

    document.querySelectorAll<HTMLElement>('button').forEach((btn) => {
      if (btn.id === 'pin-btn-edit-alias' || btn.id === 'btn-search-saved-contacts') return;
      const meta = [
        btn.id,
        btn.className,
        btn.getAttribute('title') || '',
        btn.getAttribute('aria-label') || '',
        btn.textContent || '',
      ]
        .join(' ')
        .toLowerCase();

      if (/sonido|sound|audio|volumen|volume|mute|silenciar|🔊|🔇|🔉|🔈/.test(meta)) {
        btn.setAttribute('data-pin-force-hidden', 'true');
      }
    });

    document.querySelectorAll<HTMLElement>('span, div, small, p').forEach((el) => {
      if (el.children.length > 0) return;
      const txt = (el.textContent || '').trim();
      if (/sesi[oó]n\s+lista\s*\(\s*presencia\s+local\s*\)/i.test(txt)) {
        el.setAttribute('data-pin-force-hidden', 'true');
      }
    });
  }

  private sanitizeChatListPreviews(): void {
    if (typeof document === 'undefined') return;
    const chatCards = document.querySelectorAll<HTMLElement>('#list-chats .list-card');
    chatCards.forEach((card) => {
      card.querySelectorAll('.pin-alias-pill').forEach((pill) => pill.remove());

      const previewEls = card.querySelectorAll<HTMLElement>('.muted-small, small, p');
      previewEls.forEach((el) => {
        const raw = el.textContent || '';
        const cleaned = this.replacePinsWithAliasesInText(extractCleanMessageText(raw));
        if (cleaned && cleaned !== raw.trim()) {
          el.textContent = cleaned;
        }
      });

      const titleEl =
        card.querySelector<HTMLElement>(
          '.card-row strong, .card-row b, .card-row > span:first-child, .card-row > div:first-child'
        ) || card.querySelector<HTMLElement>('strong, b, h3, h4');
      if (titleEl) {
        this.renderAliasElement(titleEl);
      }

      this.ensureCardDeleteButton(card);
    });

    const activeTitle = document.getElementById('active-chat-title');
    if (activeTitle) {
      this.renderAliasElement(activeTitle);
      this.ensureActiveChatDeleteButton();
    }
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
      listInvites.closest<HTMLElement>(
        'section, .card, .panel, .sidebar-section, [data-invites-box]'
      ) || listInvites.parentElement;

    if (container && container !== document.body) {
      container.classList.toggle('pin-invites-hidden', !shouldShow);
    } else {
      listInvites.classList.toggle('pin-invites-hidden', !shouldShow);
    }
  }

  private findLiveChatCard(pin: string, groupIdB64: string): HTMLElement | null {
    const cards = Array.from(document.querySelectorAll<HTMLElement>('#list-chats .list-card'));
    if (groupIdB64) {
      const byId = cards.find((c) => c.dataset.groupId === groupIdB64);
      if (byId) return byId;
    }
    const targetCompact = normalizePinCompact(pin);
    if (!targetCompact) return null;
    return (
      cards.find((c) =>
        (c.textContent || '').toUpperCase().replace(/[^A-Z0-9]/g, '').includes(targetCompact)
      ) ?? null
    );
  }

  private collectSavedContacts(): Array<{ pin: string; groupIdB64: string }> {
    if (typeof document === 'undefined') return [];
    const contacts: Array<{ pin: string; groupIdB64: string }> = [];
    const seenPins = new Set<string>();

    document.querySelectorAll<HTMLElement>('#list-chats .list-card').forEach((card) => {
      const text = (card.textContent || '').trim();
      const pins = text.match(PIN_PATTERN) || [];
      const firstPin = pins[0];
      if (!firstPin) return;
      const pin = formatPinCanonical(firstPin);
      if (seenPins.has(pin)) return;
      seenPins.add(pin);
      contacts.push({ pin, groupIdB64: card.dataset.groupId ?? '' });
    });

    for (const pin of Object.keys(this.aliasesByCanonical)) {
      if (!seenPins.has(pin)) {
        seenPins.add(pin);
        contacts.push({ pin, groupIdB64: '' });
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

    void this.refreshAliasesFromVault();

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

        const actionsWrap = document.createElement('div');
        actionsWrap.className = 'pin-contacts-actions';

        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'btn-primary';
        openBtn.textContent = 'Abrir';
        openBtn.addEventListener('click', () => {
          const liveCard = this.findLiveChatCard(item.pin, item.groupIdB64);
          if (liveCard) {
            this.suppressNotificationsFor(900);
            liveCard.click();
            this.setMobileChatOpen(true);
            liveCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          } else {
            const inviteInput = document.getElementById(
              'input-invite-pin'
            ) as HTMLInputElement | null;
            if (inviteInput) {
              inviteInput.value = item.pin;
              inviteInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
            this.setMobileChatOpen(false);
          }
          popover.remove();
        });

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'pin-delete-contact-btn';
        delBtn.textContent = 'Eliminar';
        delBtn.addEventListener('click', () => {
          this.requestDeleteContact(item.pin, item.groupIdB64);
          window.setTimeout(() => renderList(searchInput.value), 250);
        });

        actionsWrap.append(openBtn, delBtn);
        row.append(nameSpan, actionsWrap);
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

    const header = document.querySelector<HTMLElement>(
      '[data-pin-mobile-main-header="true"], #view-chat > header, header, .topbar'
    );
    if (header) {
      const menuBtn = document.getElementById('btn-mobile-menu-toggle');
      if (menuBtn && menuBtn.parentElement === header) {
        header.insertBefore(btn, menuBtn);
      } else {
        header.appendChild(btn);
      }
    }
  }

  syncAllViews(): void {
    if (typeof document === 'undefined' || this.syncingUi) return;
    this.syncingUi = true;
    try {
      this.tagMobileLayoutContainers();
      this.syncInvitesVisibility();
      this.sanitizeChatListPreviews();
      this.cleanEpochAndStatusLabels();
      this.hideDisabledControls();
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
      this.suppressNotificationsFor(2500);
      this.syncAllViews();
      this.lastActiveChatKey = this.getCurrentActiveChatKey();
      this.seedVisibleBubblesSilently(this.lastActiveChatKey);
      this.syncChatListPreviewAlerts(true);
    };

    seedExisting();
    void this.refreshAliasesFromVault();

    if (typeof window !== 'undefined') {
      const w = window as PatchedWindow;
      w.pinSetAlias = (pin: string, alias: string) => this.setPinAlias(pin, alias);

      window.addEventListener('pin:aliases-updated', (ev: Event) => {
        this.suppressNotificationsFor(700);
        const detail = (ev as CustomEvent<{ aliases?: PinAliasMap }>).detail;
        if (detail && detail.aliases) {
          this.applyAliasMap(detail.aliases);
          this.syncAllViews();
        } else {
          void this.refreshAliasesFromVault();
        }
      });

      document.addEventListener('click', (ev) => {
        const target = ev.target as HTMLElement | null;
        if (target && target.closest('#pin-btn-edit-alias')) {
          this.suppressNotificationsFor(700);
          window.setTimeout(() => void this.refreshAliasesFromVault(), 400);
        }
      });
    }

    this.observer = new MutationObserver((mutations) => {
      this.syncAllViews();

      const currentChatKey = this.getCurrentActiveChatKey();
      const chatChanged = currentChatKey !== this.lastActiveChatKey;
      if (chatChanged) {
        this.lastActiveChatKey = currentChatKey;
        this.suppressNotificationsFor(700);
      }

      const isSuppressed = chatChanged || Date.now() < this.suppressAlertsUntil;
      if (isSuppressed) {
        this.seedVisibleBubblesSilently(currentChatKey);
        this.syncChatListPreviewAlerts(true);
        return;
      }

      const newlyReceived: IncomingMessageAlert[] = [];

      for (const mut of mutations) {
        mut.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) return;
          if (
            node.closest('#pin-top-toast-container') ||
            node.closest('#pin-contacts-popover')
          ) {
            return;
          }

          const candidates = node.matches('.msg-bubble, [data-message-id]')
            ? [node]
            : Array.from(node.querySelectorAll<HTMLElement>('.msg-bubble, [data-message-id]'));

          for (const el of candidates) {
            const cleanText = this.sanitizeBubbleNode(el);
            if (!cleanText) continue;

            const key = this.buildBubbleKey(el, cleanText, currentChatKey);
            if (this.seenMessageKeys.has(key)) continue;
            this.seenMessageKeys.add(key);

            if (el.classList.contains('mine')) continue;

            const activeTitle = document.getElementById('active-chat-title');
            const sender =
              activeTitle?.querySelector('.pin-alias-name')?.textContent?.trim() ||
              activeTitle?.dataset.pinOriginal ||
              'Nuevo mensaje';

            newlyReceived.push({
              senderLabel: sender,
              previewText: cleanText.slice(0, 120),
              ...(currentChatKey ? { groupId: currentChatKey } : {}),
            });
          }
        });
      }

      if (newlyReceived.length > 0) {
        const latest = newlyReceived[newlyReceived.length - 1];
        if (latest) {
          void this.notifyIncomingMessage(latest);
        }
      }

      this.syncChatListPreviewAlerts(false);
    });

    this.observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }
}

export const waAlerts = new SoundAndNotificationController();

export function applyWhatsAppLayoutClasses(): void {
  if (typeof document === 'undefined') return;
  document.body.classList.add('pin-wa-topbars');
}
