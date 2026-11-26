export interface IncomingMessageAlert {
  senderLabel: string;
  previewText: string;
  groupId?: string;
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
        const ctx = this.getExistingContext();
        if (ctx && ctx.state === 'suspended') {
          ctx.resume().catch(() => {});
        }
      };
      window.addEventListener('pointerdown', onGesture, { passive: true });
      window.addEventListener('keydown', onGesture, { passive: true });
    }
  }

  private getExistingContext(): AudioContext | null {
    return this.audioCtx;
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
      // Ignorado si el navegador bloquea audio
    }
  }

  private showInAppToast(alert: IncomingMessageAlert): void {
    if (typeof document === 'undefined') return;
    let container = document.getElementById('wa-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'wa-toast-container';
      container.className = 'wa-toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'wa-toast';
    toast.setAttribute('role', 'status');

    const title = document.createElement('div');
    title.className = 'wa-toast-title';
    title.textContent = alert.senderLabel;

    const body = document.createElement('div');
    body.className = 'wa-toast-body';
    body.textContent = alert.previewText;

    toast.append(title, body);
    container.appendChild(toast);

    window.setTimeout(() => {
      toast.classList.add('wa-toast-hide');
      window.setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  async notifyIncomingMessage(alert: IncomingMessageAlert): Promise<void> {
    this.showInAppToast(alert);

    if (
      this.desktopNotifEnabled &&
      typeof window !== 'undefined' &&
      'Notification' in window &&
      Notification.permission === 'granted' &&
      (document.hidden || !document.hasFocus())
    ) {
      try {
        const notif = new Notification(alert.senderLabel, {
          body: alert.previewText,
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

  installIncomingDomWatcher(): void {
    if (typeof document === 'undefined' || this.observer) return;

    const seedExisting = () => {
      document
        .querySelectorAll<HTMLElement>('.message, .msg-item, .chat-message, [data-message-id]')
        .forEach((el) => {
          const key = el.getAttribute('data-message-id') || (el.textContent || '').trim();
          if (key) this.seenMessageKeys.add(key);
        });
    };

    seedExisting();

    this.observer = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        mut.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) return;
          if (node.closest('#wa-toast-container')) return;

          const candidates = node.matches('.message, .msg-item, .chat-message, [data-message-id]')
            ? [node]
            : Array.from(
                node.querySelectorAll<HTMLElement>('.message, .msg-item, .chat-message, [data-message-id]')
              );

          for (const el of candidates) {
            const isOutgoing =
              el.classList.contains('outgoing') ||
              el.classList.contains('self') ||
              el.classList.contains('me') ||
              el.classList.contains('sent') ||
              el.getAttribute('data-outgoing') === 'true';

            if (isOutgoing) continue;

            const text = (el.textContent || '').trim().replace(/\s+/g, ' ');
            if (!text) continue;
            const key = `${el.getAttribute('data-message-id') || ''}|${text}`;
            if (this.seenMessageKeys.has(key)) continue;
            this.seenMessageKeys.add(key);

            void this.notifyIncomingMessage({
              senderLabel: 'Nuevo mensaje',
              previewText: text.slice(0, 120),
            });
          }
        });
      }
    });

    this.observer.observe(document.body, { childList: true, subtree: true });
  }
}

export const waAlerts = new SoundAndNotificationController();

export function applyWhatsAppLayoutClasses(): void {
  if (typeof document === 'undefined') return;
  document.body.classList.add('wa-theme-shell');
}
