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

interface ReplyContext {
  sender: string;
  preview: string;
}

interface VoicePayload {
  mime: string;
  dataB64: string;
  durationSec?: number;
}

interface ParsedPinEnvelope {
  text: string;
  replyTo?: ReplyContext;
  voice?: VoicePayload;
}

const PIN_PATTERN = /\b[A-Z0-9]{4}-?[A-Z0-9]{4}\b/g;
const SINGLE_PIN_RE = /\b[A-Z0-9]{4}-?[A-Z0-9]{4}\b/;
const MOBILE_MEDIA_QUERY = '(max-width: 860px)';
const MAX_VOICE_SECONDS = 35;

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

function formatDurationMMSS(totalSeconds: number): string {
  const sec = Math.max(0, Math.round(totalSeconds));
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function base64ToBlobUrl(dataB64: string, mime: string): string | null {
  try {
    const binary = window.atob(dataB64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: mime || 'audio/webm' });
    return URL.createObjectURL(blob);
  } catch {
    return null;
  }
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      const res = typeof reader.result === 'string' ? reader.result : '';
      const commaIdx = res.indexOf(',');
      if (commaIdx === -1) {
        reject(new Error('No se pudo codificar el audio.'));
        return;
      }
      resolve(res.slice(commaIdx + 1));
    };
    reader.onerror = () => reject(new Error('Error leyendo el audio grabado.'));
    reader.readAsDataURL(blob);
  });
}

function pickSupportedAudioMime(): string {
  if (typeof MediaRecorder === 'undefined' || typeof MediaRecorder.isTypeSupported !== 'function') {
    return '';
  }
  const candidates = [
    'audio/webm;codecs=opus',
    'audio/webm',
    'audio/mp4',
    'audio/ogg;codecs=opus',
  ];
  for (const mime of candidates) {
    if (MediaRecorder.isTypeSupported(mime)) return mime;
  }
  return '';
}

function parsePinEnvelope(rawText: string): ParsedPinEnvelope | null {
  const trimmed = rawText.trim();
  if (!trimmed) return null;

  const tryParseObj = (candidate: string): ParsedPinEnvelope | null => {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      const rec = parsed as Record<string, unknown>;

      let replyTo: ReplyContext | undefined;
      if (rec['replyTo'] && typeof rec['replyTo'] === 'object' && !Array.isArray(rec['replyTo'])) {
        const r = rec['replyTo'] as Record<string, unknown>;
        const sender = typeof r['sender'] === 'string' ? r['sender'].trim() : '';
        const preview = typeof r['preview'] === 'string' ? r['preview'].trim() : '';
        if (preview) {
          replyTo = { sender: sender || 'Mensaje', preview };
        }
      }

      let voice: VoicePayload | undefined;
      if (rec['voice'] && typeof rec['voice'] === 'object' && !Array.isArray(rec['voice'])) {
        const v = rec['voice'] as Record<string, unknown>;
        const dataB64 = typeof v['dataB64'] === 'string' ? v['dataB64'].trim() : '';
        const mime = typeof v['mime'] === 'string' ? v['mime'].trim() : 'audio/webm';
        const durationSec = typeof v['durationSec'] === 'number' ? v['durationSec'] : undefined;
        if (dataB64) {
          voice = {
            mime: mime || 'audio/webm',
            dataB64,
            ...(durationSec !== undefined ? { durationSec } : {}),
          };
        }
      }

      const rawT = typeof rec['text'] === 'string' ? rec['text'] : '';
      if (!rawT && !voice && !replyTo) return null;

      const text =
        rawT.trim() ||
        (voice
          ? `🎤 Nota de voz${voice.durationSec ? ` (${formatDurationMMSS(voice.durationSec)})` : ''}`
          : '');

      return {
        text,
        ...(replyTo ? { replyTo } : {}),
        ...(voice ? { voice } : {}),
      };
    } catch {
      return null;
    }
  };

  const direct = tryParseObj(trimmed);
  if (direct) return direct;

  const jsonMatch = trimmed.match(/\{[\s\S]*"__pin_v"[\s\S]*\}/);
  const matchedJson = jsonMatch?.[0];
  if (matchedJson) {
    return tryParseObj(matchedJson);
  }

  return null;
}

export function extractCleanMessageText(rawText: string): string {
  const trimmed = rawText.trim();
  if (!trimmed) return '';

  const prefixMatch = trimmed.match(/^(Tú:\s*)/i);
  const prefix = prefixMatch?.[1] ?? '';
  const body = prefix ? trimmed.slice(prefix.length).trim() : trimmed;

  const parsed = parsePinEnvelope(body);
  if (parsed && parsed.text) {
    return `${prefix}${parsed.text}`;
  }

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
  private observerFlushTimer: number | null = null;
  private pendingAddedNodes: HTMLElement[] = [];

  // Estado de swipe-to-reply
  private activeReply: ReplyContext | null = null;
  private swipeBound = false;

  // Estado de notas de voz
  private mediaRecorder: MediaRecorder | null = null;
  private recordingStream: MediaStream | null = null;
  private recordingChunks: Blob[] = [];
  private recordingStartMs = 0;
  private recordingTimerId: number | null = null;
  private recordingCancelled = false;
  private voiceBlobUrlCache = new Map<string, string>();

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

  // === RESPUESTA CITADA (SWIPE-TO-REPLY) ===

  consumeReplyAndWrapText(rawText: string): string {
    const trimmed = rawText.trim();
    if (!trimmed) return rawText;
    if (!this.activeReply) return rawText;

    const replyTo = this.activeReply;
    this.clearActiveReply();

    if (trimmed.startsWith('{"__pin_v":2')) {
      return trimmed;
    }

    return JSON.stringify({
      __pin_v: 2,
      kind: 'text',
      text: trimmed,
      replyTo,
    });
  }

  private setActiveReply(reply: ReplyContext): void {
    this.activeReply = reply;
    this.renderReplyBanner();
    const inputMsg = document.getElementById('input-msg') as HTMLInputElement | null;
    if (inputMsg) inputMsg.focus();
  }

  private clearActiveReply(): void {
    this.activeReply = null;
    this.renderReplyBanner();
  }

  private renderReplyBanner(): void {
    if (typeof document === 'undefined') return;
    const form = document.getElementById('form-send-msg');
    if (!form) return;

    let banner = document.getElementById('pin-reply-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'pin-reply-banner';
      banner.className = 'pin-reply-banner';
      banner.hidden = true;

      const body = document.createElement('div');
      body.className = 'pin-reply-banner-body';

      const senderEl = document.createElement('div');
      senderEl.className = 'pin-reply-banner-sender';
      senderEl.id = 'pin-reply-banner-sender';

      const previewEl = document.createElement('div');
      previewEl.className = 'pin-reply-banner-preview';
      previewEl.id = 'pin-reply-banner-preview';

      body.append(senderEl, previewEl);

      const closeBtn = document.createElement('button');
      closeBtn.type = 'button';
      closeBtn.className = 'pin-reply-banner-close';
      closeBtn.textContent = '✕';
      closeBtn.title = 'Cancelar respuesta';
      closeBtn.addEventListener('click', () => this.clearActiveReply());

      banner.append(body, closeBtn);
      form.insertAdjacentElement('beforebegin', banner);
    }

    if (!this.activeReply) {
      banner.hidden = true;
      return;
    }

    const senderEl = document.getElementById('pin-reply-banner-sender');
    const previewEl = document.getElementById('pin-reply-banner-preview');
    if (senderEl) senderEl.textContent = `Respondiendo a ${this.activeReply.sender}`;
    if (previewEl) previewEl.textContent = this.activeReply.preview;
    banner.hidden = false;
  }

  private extractBubbleReplyContext(bubble: HTMLElement): ReplyContext | null {
    const cleanText = (
      bubble.dataset.pinCleanText ||
      bubble.querySelector<HTMLElement>('.pin-clean-msg-text')?.textContent ||
      ''
    ).trim();

    const preview =
      cleanText ||
      (bubble.querySelector('.pin-voice-player') ? '🎤 Nota de voz' : '') ||
      extractCleanMessageText((bubble.textContent || '').trim());

    if (!preview) return null;

    let sender = 'Contacto';
    if (bubble.classList.contains('mine')) {
      sender = 'Tú';
    } else {
      const metaRaw = (bubble.querySelector('.msg-meta')?.textContent || '').trim();
      const firstPart = metaRaw.split('·')[0]?.trim() || '';
      if (firstPart) {
        sender = this.replacePinsWithAliasesInText(firstPart);
      } else {
        document.querySelectorAll<HTMLElement>('#list-invites .list-card').forEach((card) => {
      const inviteTitle = card.querySelector<HTMLElement>('strong, b, h3, h4');
      if (inviteTitle) {
        this.renderAliasElement(inviteTitle);
      }
    });

    const activeTitle = document.getElementById('active-chat-title');
        sender =
          activeTitle?.querySelector('.pin-alias-name')?.textContent?.trim() ||
          activeTitle?.dataset.pinOriginal ||
          'Contacto';
      }
    }

    return {
      sender,
      preview: preview.slice(0, 140),
    };
  }

  private bindSwipeToReply(): void {
    if (typeof document === 'undefined' || this.swipeBound) return;
    const list = document.getElementById('messages-list');
    if (!list) return;
    this.swipeBound = true;

    let activeBubble: HTMLElement | null = null;
    let pointerId: number | null = null;
    let startX = 0;
    let startY = 0;
    let dragging = false;
    let readyToReply = false;
    let vibrated = false;

    const resetBubble = () => {
      if (!activeBubble) return;
      const b = activeBubble;
      b.classList.remove('pin-swipe-ready');
      b.style.transition = 'transform 0.18s ease';
      b.style.transform = 'translateX(0px)';
      window.setTimeout(() => {
        b.style.transition = '';
        b.style.transform = '';
      }, 200);
      activeBubble = null;
      pointerId = null;
      dragging = false;
      readyToReply = false;
      vibrated = false;
    };

    list.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0 && ev.pointerType === 'mouse') return;
      const target = ev.target instanceof HTMLElement ? ev.target : null;
      if (!target) return;
      if (target.closest('audio, button, a, input, textarea')) return;

      const bubble = target.closest<HTMLElement>('.msg-bubble');
      if (!bubble) return;

      activeBubble = bubble;
      pointerId = ev.pointerId;
      startX = ev.clientX;
      startY = ev.clientY;
      dragging = false;
      readyToReply = false;
      vibrated = false;
    });

    list.addEventListener('pointermove', (ev) => {
      if (!activeBubble || ev.pointerId !== pointerId) return;
      const dx = ev.clientX - startX;
      const dy = ev.clientY - startY;

      if (!dragging) {
        // Ignorar si el usuario está haciendo scroll vertical o deslizando a la izquierda
        if (Math.abs(dy) > 14 && Math.abs(dy) > Math.abs(dx)) {
          resetBubble();
          return;
        }
        if (dx > 12 && dx > Math.abs(dy) * 1.4) {
          dragging = true;
          activeBubble.style.transition = 'none';
        } else {
          return;
        }
      }

      const clampedX = Math.max(0, Math.min(dx, 68));
      activeBubble.style.transform = `translateX(${clampedX}px)`;
      readyToReply = clampedX >= 48;
      activeBubble.classList.toggle('pin-swipe-ready', readyToReply);

      if (readyToReply && !vibrated) {
        vibrated = true;
        if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
          navigator.vibrate(14);
        }
      }
    });

    const finishSwipe = (ev: PointerEvent) => {
      if (!activeBubble || ev.pointerId !== pointerId) return;
      const shouldTrigger = dragging && readyToReply;
      const targetBubble = activeBubble;
      resetBubble();

      if (shouldTrigger) {
        const ctx = this.extractBubbleReplyContext(targetBubble);
        if (ctx) {
          this.setActiveReply(ctx);
        }
      }
    };

    list.addEventListener('pointerup', finishSwipe);
    list.addEventListener('pointercancel', finishSwipe);

    window.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && this.activeReply) {
        this.clearActiveReply();
      }
    });
  }

  // === NOTAS DE VOZ E2EE ===

  private installVoiceControls(): void {
    if (typeof document === 'undefined') return;
    const form = document.getElementById('form-send-msg');
    if (!form) return;

    if (!document.getElementById('pin-voice-bar')) {
      const bar = document.createElement('div');
      bar.id = 'pin-voice-bar';
      bar.className = 'pin-voice-bar';
      bar.hidden = true;

      const status = document.createElement('div');
      status.className = 'pin-voice-status';

      const dot = document.createElement('span');
      dot.className = 'pin-voice-dot';

      const timer = document.createElement('span');
      timer.id = 'pin-voice-timer';
      timer.textContent = 'Grabando 0:00';

      status.append(dot, timer);

      const actions = document.createElement('div');
      actions.className = 'pin-voice-actions';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'pin-voice-cancel-btn';
      cancelBtn.textContent = 'Cancelar';
      cancelBtn.addEventListener('click', () => this.stopVoiceRecording(true));

      const sendBtn = document.createElement('button');
      sendBtn.type = 'button';
      sendBtn.className = 'pin-voice-send-btn';
      sendBtn.textContent = 'Enviar nota';
      sendBtn.addEventListener('click', () => this.stopVoiceRecording(false));

      actions.append(cancelBtn, sendBtn);
      bar.append(status, actions);
      form.insertAdjacentElement('beforebegin', bar);
    }

    if (!document.getElementById('btn-voice-record')) {
      const micBtn = document.createElement('button');
      micBtn.id = 'btn-voice-record';
      micBtn.type = 'button';
      micBtn.textContent = '🎤';
      micBtn.title = 'Grabar nota de voz cifrada';
      micBtn.setAttribute('aria-label', 'Grabar nota de voz cifrada');
      micBtn.addEventListener('click', () => {
        if (this.mediaRecorder && this.mediaRecorder.state === 'recording') {
          this.stopVoiceRecording(false);
        } else {
          void this.startVoiceRecording();
        }
      });

      const submitBtn = form.querySelector<HTMLElement>('button[type="submit"]');
      if (submitBtn) {
        form.insertBefore(micBtn, submitBtn);
      } else {
        form.appendChild(micBtn);
      }
    }
  }

  private setVoiceUiRecording(isRecording: boolean): void {
    const micBtn = document.getElementById('btn-voice-record');
    const bar = document.getElementById('pin-voice-bar');
    if (micBtn) {
      micBtn.classList.toggle('recording', isRecording);
      micBtn.title = isRecording ? 'Detener y enviar nota de voz' : 'Grabar nota de voz cifrada';
    }
    if (bar) {
      bar.hidden = !isRecording;
    }
  }

  private cleanupRecordingResources(): void {
    if (this.recordingTimerId !== null) {
      window.clearInterval(this.recordingTimerId);
      this.recordingTimerId = null;
    }
    if (this.recordingStream) {
      this.recordingStream.getTracks().forEach((t) => t.stop());
      this.recordingStream = null;
    }
    this.mediaRecorder = null;
    this.setVoiceUiRecording(false);
  }

  private async startVoiceRecording(): Promise<void> {
    if (
      typeof navigator === 'undefined' ||
      !navigator.mediaDevices ||
      typeof navigator.mediaDevices.getUserMedia !== 'function' ||
      typeof MediaRecorder === 'undefined'
    ) {
      const status = document.getElementById('global-status');
      if (status) {
        status.textContent = 'Tu navegador no soporta grabación de notas de voz.';
      }
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.recordingStream = stream;
      this.recordingChunks = [];
      this.recordingCancelled = false;
      this.recordingStartMs = Date.now();

      const mimeType = pickSupportedAudioMime();
      const options: MediaRecorderOptions = {
        audioBitsPerSecond: 16000,
        ...(mimeType ? { mimeType } : {}),
      };

      const recorder = new MediaRecorder(stream, options);
      this.mediaRecorder = recorder;

      recorder.ondataavailable = (ev) => {
        if (ev.data && ev.data.size > 0) {
          this.recordingChunks.push(ev.data);
        }
      };

      recorder.onstop = () => {
        const wasCancelled = this.recordingCancelled;
        const durationSec = Math.max(1, Math.round((Date.now() - this.recordingStartMs) / 1000));
        const finalMime = recorder.mimeType || mimeType || 'audio/webm';
        const chunks = [...this.recordingChunks];
        this.recordingChunks = [];
        this.cleanupRecordingResources();

        if (wasCancelled || chunks.length === 0) return;

        void (async () => {
          try {
            const blob = new Blob(chunks, { type: finalMime });
            const dataB64 = await blobToBase64(blob);
            const replyTo = this.activeReply;
            if (replyTo) this.clearActiveReply();

            const envelope = {
              __pin_v: 2,
              kind: 'text',
              text: `🎤 Nota de voz (${formatDurationMMSS(durationSec)})`,
              ...(replyTo ? { replyTo } : {}),
              voice: {
                mime: finalMime,
                dataB64,
                durationSec,
              },
            };

            window.dispatchEvent(
              new CustomEvent('pin:send-raw-payload', {
                detail: { payload: JSON.stringify(envelope) },
              })
            );
          } catch (err) {
            const status = document.getElementById('global-status');
            if (status) {
              status.textContent = `Error procesando nota de voz: ${(err as Error).message}`;
            }
          }
        })();
      };

      recorder.start();
      this.setVoiceUiRecording(true);

      const timerEl = document.getElementById('pin-voice-timer');
      if (timerEl) timerEl.textContent = 'Grabando 0:00';

      this.recordingTimerId = window.setInterval(() => {
        const elapsed = Math.floor((Date.now() - this.recordingStartMs) / 1000);
        const tEl = document.getElementById('pin-voice-timer');
        if (tEl) {
          tEl.textContent = `Grabando ${formatDurationMMSS(elapsed)} / ${formatDurationMMSS(MAX_VOICE_SECONDS)}`;
        }
        if (elapsed >= MAX_VOICE_SECONDS) {
          this.stopVoiceRecording(false);
        }
      }, 250);
    } catch {
      this.cleanupRecordingResources();
      const status = document.getElementById('global-status');
      if (status) {
        status.textContent = 'Permite el acceso al micrófono para enviar notas de voz.';
      }
    }
  }

  private stopVoiceRecording(cancel: boolean): void {
    this.recordingCancelled = cancel;
    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      try {
        this.mediaRecorder.stop();
      } catch {
        this.cleanupRecordingResources();
      }
    } else {
      this.cleanupRecordingResources();
    }
  }

  // === NOTIFICACIONES Y CONTROL DE CHAT ===

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
      this.clearActiveReply();
    }
    this.syncMobileMenuButtonLabel();
  }

  private syncMobileMenuButtonLabel(): void {
    const toggleBtn = document.getElementById('btn-mobile-menu-toggle');
    if (!toggleBtn) return;
    const isOpen = document.body.classList.contains('pin-mobile-menu-open');
    const nextText = isOpen ? '✕ Cerrar' : '☰ Menú';
    const nextExpanded = isOpen ? 'true' : 'false';
    if (toggleBtn.textContent !== nextText) {
      toggleBtn.textContent = nextText;
    }
    if (toggleBtn.getAttribute('aria-expanded') !== nextExpanded) {
      toggleBtn.setAttribute('aria-expanded', nextExpanded);
    }
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

          if (chatCard && !clickedDelete) {
            this.suppressNotificationsFor(900);
            this.clearActiveReply();
            this.setMobileChatOpen(true);
            return;
          }

          if (target.closest('#btn-logout-session, #btn-wipe-vault')) {
            this.suppressNotificationsFor(1500);
            this.clearActiveReply();
            this.stopVoiceRecording(true);
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
        this.clearActiveReply();
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
          document.body.classList.remove('pin-mobile-chat-open');
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

  private async showSystemNotification(title: string, body: string, rawGroupId?: string): Promise<void> {
    if (typeof window === 'undefined' || !('Notification' in window) || Notification.permission !== 'granted') {
      return;
    }
    const cleanGid = (rawGroupId ?? '').replace(/^gid:/, '').trim();
    const tag = cleanGid ? `pin-mls-msg-${cleanGid}` : 'pin-mls-msg';

    if ('serviceWorker' in navigator) {
      try {
        const reg =
          (await navigator.serviceWorker.getRegistration('/')) ||
          (await Promise.race([
            navigator.serviceWorker.ready,
            new Promise<null>((resolve) => window.setTimeout(() => resolve(null), 600)),
          ]));
        if (reg && typeof reg.showNotification === 'function') {
          await reg.showNotification(title, {
            body,
            icon: '/icon-192.png',
            badge: '/badge-72.png',
            tag,
            data: { url: '/', groupIdB64: cleanGid },
          });
          return;
        }
      } catch {
        // Fallback a Notification directo
      }
    }

    try {
      const notif = new Notification(title, {
        body,
        icon: '/icon-192.png',
        tag,
      });
      notif.onclick = () => {
        window.focus();
        notif.close();
      };
    } catch {
      // Ignorado si el navegador móvil bloquea constructor Notification directo
    }
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
      await this.showSystemNotification(cleanSender, cleanPreview, alert.groupId);
    }

    await this.playMessageTone();
  }

  private getOrCreateVoiceUrl(voice: VoicePayload): string | null {
    const cacheKey = `${voice.mime}|${voice.dataB64.length}|${voice.dataB64.slice(0, 40)}`;
    const existing = this.voiceBlobUrlCache.get(cacheKey);
    if (existing) return existing;
    const url = base64ToBlobUrl(voice.dataB64, voice.mime);
    if (url) {
      this.voiceBlobUrlCache.set(cacheKey, url);
    }
    return url;
  }

  private sanitizeBubbleNode(bubble: HTMLElement): string {
    const metaEl = bubble.querySelector<HTMLElement>('.msg-meta');
    if (metaEl && metaEl.textContent) {
      const updatedMeta = this.replacePinsWithAliasesInText(metaEl.textContent);
      if (updatedMeta !== metaEl.textContent) {
        metaEl.textContent = updatedMeta;
      }
    }

    // No recrear DOM de burbujas ricas ya renderizadas (evita cortar la reproducción de audio)
    if (bubble.dataset.pinRichRendered === '1') {
      return bubble.dataset.pinCleanText || '';
    }

    let bodySource = '';
    for (const child of Array.from(bubble.childNodes)) {
      if (child === metaEl) continue;
      bodySource += child.textContent || '';
    }

    const parsed = parsePinEnvelope(bodySource);
    if (parsed && (parsed.replyTo || parsed.voice)) {
      for (const child of Array.from(bubble.childNodes)) {
        if (child !== metaEl) {
          child.remove();
        }
      }

      const frag = document.createDocumentFragment();

      if (parsed.replyTo) {
        const quoteBox = document.createElement('div');
        quoteBox.className = 'pin-reply-quote';

        const qSender = document.createElement('div');
        qSender.className = 'pin-reply-quote-sender';
        qSender.textContent = this.replacePinsWithAliasesInText(parsed.replyTo.sender);

        const qText = document.createElement('div');
        qText.className = 'pin-reply-quote-text';
        qText.textContent = this.replacePinsWithAliasesInText(parsed.replyTo.preview);

        quoteBox.append(qSender, qText);
        frag.appendChild(quoteBox);
      }

      if (parsed.voice) {
        const playerWrap = document.createElement('div');
        playerWrap.className = 'pin-voice-player';

        const audio = document.createElement('audio');
        audio.controls = true;
        audio.preload = 'metadata';
        const blobUrl = this.getOrCreateVoiceUrl(parsed.voice);
        if (blobUrl) {
          audio.src = blobUrl;
        }
        playerWrap.appendChild(audio);

        if (parsed.voice.durationSec) {
          const dur = document.createElement('div');
          dur.className = 'pin-voice-duration';
          dur.textContent = `Nota de voz · ${formatDurationMMSS(parsed.voice.durationSec)}`;
          playerWrap.appendChild(dur);
        }

        frag.appendChild(playerWrap);
      } else {
        const cleanSpan = document.createElement('div');
        cleanSpan.className = 'pin-clean-msg-text';
        cleanSpan.textContent = this.replacePinsWithAliasesInText(parsed.text);
        frag.appendChild(cleanSpan);
      }

      if (metaEl) {
        bubble.insertBefore(frag, metaEl);
      } else {
        bubble.appendChild(frag);
      }

      const summaryText = this.replacePinsWithAliasesInText(parsed.text);
      bubble.dataset.pinRichRendered = '1';
      bubble.dataset.pinCleanText = summaryText;
      return summaryText;
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

    const metaText = metaEl ? (metaEl.textContent || '').trim() : '';
    const finalClean = cleanedBody || (bubble.textContent || '').replace(metaText, '').trim();
    bubble.dataset.pinCleanText = finalClean;
    return finalClean;
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
      if (
        btn.id === 'pin-btn-edit-alias' ||
        btn.id === 'btn-search-saved-contacts' ||
        btn.id === 'btn-voice-record' || btn.id === 'btn-start-voice-call' || Boolean(btn.closest('#pin-call-overlay'))
      ) {
        return;
      }
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

    const hasPendingCards = listInvites.querySelectorAll('.list-card').length > 0;
    const shouldShow = hasPendingCards;

    const formInvite = document.getElementById('form-invite');
    const listChats = document.getElementById('list-chats');

    // Localizar el contenedor propio de "Solicitudes entrantes" sin englobar #form-invite ni #list-chats
    let cur: HTMLElement | null = listInvites.parentElement;
    let safeContainer: HTMLElement | null = null;
    while (cur && cur !== document.body) {
      const touchesSiblings =
        (formInvite && cur.contains(formInvite)) || (listChats && cur.contains(listChats));
      if (touchesSiblings) break;
      safeContainer = cur;
      if (badgeInvites && cur.contains(badgeInvites)) {
        break;
      }
      cur = cur.parentElement;
    }

    if (safeContainer) {
      safeContainer.classList.toggle('pin-invites-hidden', !shouldShow);
      safeContainer.hidden = !shouldShow;
    } else {
      listInvites.classList.toggle('pin-invites-hidden', !shouldShow);
      listInvites.hidden = !shouldShow;
      const headerRow = (
        badgeInvites?.parentElement && badgeInvites.parentElement !== listInvites.parentElement
          ? badgeInvites.parentElement
          : listInvites.previousElementSibling
      ) as HTMLElement | null;

      if (
        headerRow &&
        (!formInvite || !headerRow.contains(formInvite)) &&
        (!listChats || !headerRow.contains(listChats))
      ) {
        headerRow.classList.toggle('pin-invites-hidden', !shouldShow);
        headerRow.hidden = !shouldShow;
      }
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
            this.clearActiveReply();
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
    const obs = this.observer;
    if (obs) {
      obs.disconnect();
    }
    try {
      this.tagMobileLayoutContainers();
      this.syncInvitesVisibility();
      this.sanitizeChatListPreviews();
      this.cleanEpochAndStatusLabels();
      this.hideDisabledControls();
      this.installContactsSearchButton();
      this.bindSwipeToReply();
      this.installVoiceControls();
      window.dispatchEvent(new CustomEvent('pin:sync-call-button'));
      this.renderReplyBanner();
      document.querySelectorAll<HTMLElement>('.msg-bubble').forEach((el) => {
        this.sanitizeBubbleNode(el);
      });
    } finally {
      if (obs && document.body) {
        obs.takeRecords();
        obs.observe(document.body, { childList: true, subtree: true });
      }
      this.syncingUi = false;
    }
  }

  private handleDomMutationBatch(addedNodes: HTMLElement[]): void {
    this.syncAllViews();

    const currentChatKey = this.getCurrentActiveChatKey();
    const chatChanged = currentChatKey !== this.lastActiveChatKey;
    if (chatChanged) {
      this.lastActiveChatKey = currentChatKey;
      this.suppressNotificationsFor(700);
      this.clearActiveReply();
    }

    const isSuppressed = chatChanged || Date.now() < this.suppressAlertsUntil;
    if (isSuppressed) {
      this.seedVisibleBubblesSilently(currentChatKey);
      this.syncChatListPreviewAlerts(true);
      return;
    }

    const newlyReceived: IncomingMessageAlert[] = [];

    for (const node of addedNodes) {
      if (!node.isConnected) continue;
      if (
        node.closest('#pin-top-toast-container') ||
        node.closest('#pin-contacts-popover')
      ) {
        continue;
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
    }

    if (newlyReceived.length > 0) {
      const latest = newlyReceived[newlyReceived.length - 1];
      if (latest) {
        void this.notifyIncomingMessage(latest);
      }
    }

    this.syncChatListPreviewAlerts(false);
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

      window.addEventListener('focus', () => {
        void this.refreshAliasesFromVault();
      });

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
      for (const mut of mutations) {
        mut.addedNodes.forEach((node) => {
          if (node instanceof HTMLElement) {
            this.pendingAddedNodes.push(node);
          }
        });
      }

      if (this.observerFlushTimer !== null) return;
      this.observerFlushTimer = window.setTimeout(() => {
        this.observerFlushTimer = null;
        const batch = this.pendingAddedNodes.splice(0, this.pendingAddedNodes.length);
        this.handleDomMutationBatch(batch);
      }, 0);
    });

    this.observer.observe(document.body, { childList: true, subtree: true });
  }
}

export const waAlerts = new SoundAndNotificationController();

export function applyWhatsAppLayoutClasses(): void {
  if (typeof document === 'undefined') return;
  document.body.classList.add('pin-wa-topbars');
}
