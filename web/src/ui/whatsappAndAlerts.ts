export interface IncomingMessageAlert {
  senderLabel: string;
  previewText: string;
  groupId?: string;
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

  const jsonMatch = trimmed.match(/\{[\s\S]*"__pin_v"[\s\S]*"text"\s*:\s*"[\s\S]*?"\s*\}/);
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
    title.textContent = alert.senderLabel;

    const body = document.createElement('div');
    body.className = 'pin-top-toast-body';
    body.textContent = extractCleanMessageText(alert.previewText);

    toast.append(title, body);
    container.appendChild(toast);

    window.setTimeout(() => {
      toast.classList.add('pin-top-toast-hide');
      window.setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  async notifyIncomingMessage(alert: IncomingMessageAlert): Promise<void> {
    const cleanPreview = extractCleanMessageText(alert.previewText);
    this.showInAppToast({ ...alert, previewText: cleanPreview });

    if (
      this.desktopNotifEnabled &&
      typeof window !== 'undefined' &&
      'Notification' in window &&
      Notification.permission === 'granted' &&
      (document.hidden || !document.hasFocus())
    ) {
      try {
        const notif = new Notification(alert.senderLabel, {
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

    const cleanedBody = extractCleanMessageText(bodySource);
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

  installIncomingDomWatcher(): void {
    if (typeof document === 'undefined' || this.observer) return;

    const seedExisting = () => {
      this.syncInvitesVisibility();
      document.querySelectorAll<HTMLElement>('.msg-bubble, [data-message-id]').forEach((el) => {
        const cleanText = this.sanitizeBubbleNode(el);
        const key = el.getAttribute('data-message-id') || cleanText;
        if (key) this.seenMessageKeys.add(key);
      });
    };

    seedExisting();

    this.observer = new MutationObserver((mutations) => {
      this.syncInvitesVisibility();

      for (const mut of mutations) {
        mut.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) return;
          if (node.closest('#pin-top-toast-container')) return;

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
