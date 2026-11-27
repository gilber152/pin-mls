export interface ActiveChatCallTarget {
  groupIdB64: string;
  peerPin: string;
  displayName: string;
  active: boolean;
}

export interface IncomingCallSignalContext {
  groupIdB64: string;
  peerPin: string;
  senderPin: string;
  senderDeviceId: string;
  ownPin: string;
  ownDeviceId: string;
  sentAtMs: number;
  rawText: string;
}

export interface VoiceCallDeps {
  getActiveChat: () => ActiveChatCallTarget | null;
  getDisplayNameForPin: (peerPin: string) => string;
  sendEncryptedSignal: (groupIdB64: string, signalJson: string) => Promise<boolean>;
  onStatus: (message: string) => void;
}

interface CallSignalBase {
  __pin_call_v: 1;
  callId: string;
}

interface CallOfferSignal extends CallSignalBase {
  type: 'offer';
  sdp: string;
}

interface CallAnswerSignal extends CallSignalBase {
  type: 'answer';
  sdp: string;
}

interface CallIceSignal extends CallSignalBase {
  type: 'ice';
  candidates: RTCIceCandidateInit[];
}

interface CallControlSignal extends CallSignalBase {
  type: 'hangup' | 'reject' | 'busy';
}

type VoiceCallSignal = CallOfferSignal | CallAnswerSignal | CallIceSignal | CallControlSignal;

type CallPhase = 'calling' | 'ringing' | 'connecting' | 'connected';

interface ActiveCallSession {
  callId: string;
  groupIdB64: string;
  peerPin: string;
  displayName: string;
  direction: 'outgoing' | 'incoming';
  phase: CallPhase;
  pc: RTCPeerConnection | null;
  localStream: MediaStream | null;
  remoteOfferSdp: string | null;
  pendingRemoteIce: RTCIceCandidateInit[];
  pendingOutgoingIce: RTCIceCandidateInit[];
  iceFlushTimer: number | null;
  localSdpSent: boolean;
  muted: boolean;
  connectedAtMs: number | null;
  noAnswerTimer: number | null;
  disconnectTimer: number | null;
}

const CALL_OFFER_MAX_AGE_MS = 50_000;
const CALL_NO_ANSWER_TIMEOUT_MS = 45_000;
const ICE_INITIAL_GATHER_WAIT_MS = 900;
const ICE_BATCH_DELAY_MS = 320;

type PatchedAudioWindow = Window & {
  webkitAudioContext?: typeof AudioContext;
};

export function isVoiceCallSignalText(rawText: string): boolean {
  const t = rawText.trim();
  return t.startsWith('{') && t.includes('"__pin_call_v":1');
}

function parseVoiceCallSignal(rawText: string): VoiceCallSignal | null {
  if (!isVoiceCallSignalText(rawText)) return null;
  try {
    const parsed = JSON.parse(rawText) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const rec = parsed as Record<string, unknown>;
    if (rec['__pin_call_v'] !== 1) return null;
    const callId = typeof rec['callId'] === 'string' ? rec['callId'].trim() : '';
    const type = typeof rec['type'] === 'string' ? rec['type'] : '';
    if (!callId || !type) return null;

    if (type === 'offer' || type === 'answer') {
      const sdp = typeof rec['sdp'] === 'string' ? rec['sdp'] : '';
      if (!sdp) return null;
      return { __pin_call_v: 1, type, callId, sdp };
    }
    if (type === 'ice') {
      const rawCands = Array.isArray(rec['candidates']) ? rec['candidates'] : [];
      const candidates = rawCands.filter(
        (c): c is RTCIceCandidateInit => Boolean(c && typeof c === 'object'),
      );
      if (candidates.length === 0) return null;
      return { __pin_call_v: 1, type: 'ice', callId, candidates };
    }
    if (type === 'hangup' || type === 'reject' || type === 'busy') {
      return { __pin_call_v: 1, type, callId };
    }
    return null;
  } catch {
    return null;
  }
}

function getIceServers(): RTCIceServer[] {
  const servers: RTCIceServer[] = [
    {
      urls: [
        'stun:stun.l.google.com:19302',
        'stun:stun1.l.google.com:19302',
        'stun:stun.cloudflare.com:3478',
      ],
    },
  ];

  const envMap = (import.meta as unknown as { env?: Record<string, string | undefined> }).env ?? {};
  const turnUrlsRaw = (envMap['VITE_TURN_URLS'] ?? '').trim();
  const turnUser = (envMap['VITE_TURN_USERNAME'] ?? '').trim();
  const turnCred = (envMap['VITE_TURN_CREDENTIAL'] ?? '').trim();

  if (turnUrlsRaw) {
    const urls = turnUrlsRaw
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean);
    if (urls.length > 0) {
      servers.push({
        urls,
        ...(turnUser ? { username: turnUser } : {}),
        ...(turnCred ? { credential: turnCred } : {}),
      });
    }
  }

  return servers;
}

function formatCallDuration(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function waitForInitialIceGathering(pc: RTCPeerConnection, timeoutMs: number): Promise<void> {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      pc.removeEventListener('icegatheringstatechange', onStateChange);
      window.clearTimeout(timer);
      resolve();
    };
    const onStateChange = () => {
      if (pc.iceGatheringState === 'complete') finish();
    };
    const timer = window.setTimeout(finish, timeoutMs);
    pc.addEventListener('icegatheringstatechange', onStateChange);
  });
}

export class VoiceCallController {
  private readonly deps: VoiceCallDeps;
  private session: ActiveCallSession | null = null;
  private endedCallIds = new Set<string>();
  private signalQueue: Promise<void> = Promise.resolve();
  private toneTimer: number | null = null;
  private durationTimer: number | null = null;
  private audioCtx: AudioContext | null = null;

  constructor(deps: VoiceCallDeps) {
    this.deps = deps;
    if (typeof window !== 'undefined') {
      window.addEventListener('pin:sync-call-button', () => this.syncCallButton());
      window.addEventListener('beforeunload', () => this.cleanupResourcesOnly());
    }
  }

  // === BOTÓN 📞 EN LA CABECERA DEL CHAT ===

  syncCallButton(): void {
    if (typeof document === 'undefined') return;
    const activeTitle = document.getElementById('active-chat-title');
    const header = activeTitle?.parentElement;
    if (!header) return;

    let btn = document.getElementById('btn-start-voice-call') as HTMLButtonElement | null;
    if (!btn) {
      btn = document.createElement('button');
      btn.id = 'btn-start-voice-call';
      btn.type = 'button';
      btn.className = 'pin-voice-call-btn';
      btn.textContent = '📞';
      btn.title = 'Llamada de voz cifrada (PIN a PIN)';
      btn.setAttribute('aria-label', 'Llamada de voz cifrada');
      btn.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        void this.startOutgoingCall();
      });
      header.appendChild(btn);
    }

    const target = this.deps.getActiveChat();
    const isDirectActive = Boolean(
      target &&
        target.active &&
        target.peerPin.trim().length > 0 &&
        !target.peerPin.includes(','),
    );
    btn.hidden = !isDirectActive;
    btn.disabled = !isDirectActive || this.session !== null;
  }

  // === ENVÍO SECUENCIAL DE SEÑALES CIFRADAS ===

  private enqueueSignal(groupIdB64: string, signal: VoiceCallSignal): Promise<void> {
    const json = JSON.stringify(signal);
    const task = this.signalQueue.then(async () => {
      try {
        await this.deps.sendEncryptedSignal(groupIdB64, json);
      } catch (err) {
        console.warn('[voice-call] Error enviando señal:', err);
      }
    });
    this.signalQueue = task.catch(() => undefined);
    return task;
  }

  // === TONOS DE TIMBRE Y LLAMADA ===

  private ensureToneAudioCtx(): AudioContext | null {
    if (typeof window === 'undefined') return null;
    if (!this.audioCtx) {
      const w = window as PatchedAudioWindow;
      const Ctx = window.AudioContext || w.webkitAudioContext;
      if (!Ctx) return null;
      this.audioCtx = new Ctx();
    }
    if (this.audioCtx.state === 'suspended') {
      this.audioCtx.resume().catch(() => undefined);
    }
    return this.audioCtx;
  }

  private playToneBurst(mode: 'incoming' | 'outgoing'): void {
    const ctx = this.ensureToneAudioCtx();
    if (!ctx) return;

    try {
      const now = ctx.currentTime;
      const pattern =
        mode === 'incoming'
          ? [
              { freq: 659.25, start: 0, dur: 0.22 },
              { freq: 880, start: 0.26, dur: 0.26 },
              { freq: 659.25, start: 0.62, dur: 0.22 },
              { freq: 880, start: 0.88, dur: 0.28 },
            ]
          : [{ freq: 440, start: 0, dur: 0.55 }];

      for (const note of pattern) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(note.freq, now + note.start);
        gain.gain.setValueAtTime(0.0001, now + note.start);
        gain.gain.exponentialRampToValueAtTime(mode === 'incoming' ? 0.22 : 0.12, now + note.start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + note.start + note.dur);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + note.start);
        osc.stop(now + note.start + note.dur + 0.02);
      }
    } catch {
      // Ignorado si el navegador bloquea reproducción sin gesto previo
    }

    if (mode === 'incoming' && typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      navigator.vibrate([260, 140, 260]);
    }
  }

  private startToneLoop(mode: 'incoming' | 'outgoing'): void {
    this.stopToneLoop();
    this.playToneBurst(mode);
    const intervalMs = mode === 'incoming' ? 2300 : 3000;
    this.toneTimer = window.setInterval(() => {
      if (!this.session) {
        this.stopToneLoop();
        return;
      }
      this.playToneBurst(mode);
    }, intervalMs);
  }

  private stopToneLoop(): void {
    if (this.toneTimer !== null) {
      window.clearInterval(this.toneTimer);
      this.toneTimer = null;
    }
  }

  // === AUDIO REMOTO ===

  private getRemoteAudioElement(): HTMLAudioElement {
    let audio = document.getElementById('pin-call-remote-audio') as HTMLAudioElement | null;
    if (!audio) {
      audio = document.createElement('audio');
      audio.id = 'pin-call-remote-audio';
      audio.autoplay = true;
      audio.setAttribute('playsinline', 'true');
      audio.style.display = 'none';
      document.body.appendChild(audio);
    }
    return audio;
  }

  private async requestMicrophone(): Promise<MediaStream> {
    if (
      typeof navigator === 'undefined' ||
      !navigator.mediaDevices ||
      typeof navigator.mediaDevices.getUserMedia !== 'function'
    ) {
      throw new Error('Tu navegador no soporta micrófono para llamadas de voz.');
    }
    return navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
      video: false,
    });
  }

  private setupPeerConnection(session: ActiveCallSession, localStream: MediaStream): RTCPeerConnection {
    if (typeof RTCPeerConnection === 'undefined') {
      throw new Error('Este navegador no soporta WebRTC.');
    }

    const pc = new RTCPeerConnection({ iceServers: getIceServers() });
    session.pc = pc;
    session.localStream = localStream;

    for (const track of localStream.getAudioTracks()) {
      pc.addTrack(track, localStream);
    }

    pc.ontrack = (ev) => {
      const audio = this.getRemoteAudioElement();
      const stream = ev.streams[0] ?? new MediaStream([ev.track]);
      audio.srcObject = stream;
      audio.volume = 1;
      void audio.play().catch(() => undefined);
    };

    pc.onicecandidate = (ev) => {
      if (!ev.candidate || !this.session || this.session.callId !== session.callId) return;
      if (!session.localSdpSent) return;
      session.pendingOutgoingIce.push(ev.candidate.toJSON());
      if (session.iceFlushTimer === null) {
        session.iceFlushTimer = window.setTimeout(() => {
          session.iceFlushTimer = null;
          if (!this.session || this.session.callId !== session.callId) return;
          const batch = session.pendingOutgoingIce.splice(0, session.pendingOutgoingIce.length);
          if (batch.length > 0) {
            void this.enqueueSignal(session.groupIdB64, {
              __pin_call_v: 1,
              type: 'ice',
              callId: session.callId,
              candidates: batch,
            });
          }
        }, ICE_BATCH_DELAY_MS);
      }
    };

    pc.onconnectionstatechange = () => {
      if (!this.session || this.session.callId !== session.callId) return;
      const state = pc.connectionState;

      if (state === 'connected') {
        if (session.disconnectTimer !== null) {
          window.clearTimeout(session.disconnectTimer);
          session.disconnectTimer = null;
        }
        if (session.noAnswerTimer !== null) {
          window.clearTimeout(session.noAnswerTimer);
          session.noAnswerTimer = null;
        }
        this.stopToneLoop();
        session.phase = 'connected';
        if (!session.connectedAtMs) {
          session.connectedAtMs = Date.now();
        }
        this.startDurationTimer();
        this.renderCallOverlay();
        this.deps.onStatus(`En llamada cifrada con ${session.displayName}.`);
      } else if (state === 'disconnected') {
        this.renderCallOverlay('Reconectando audio…');
        if (session.disconnectTimer === null) {
          session.disconnectTimer = window.setTimeout(() => {
            if (this.session && this.session.callId === session.callId && pc.connectionState !== 'connected') {
              void this.endCurrentCall(true, 'Llamada finalizada por pérdida de red.');
            }
          }, 9000);
        }
      } else if (state === 'failed') {
        void this.endCurrentCall(
          true,
          'No se pudo conectar el audio directo (red estricta sin servidor TURN).',
        );
      } else if (state === 'closed') {
        this.cleanupResourcesOnly();
      }
    };

    return pc;
  }

  private async applyRemoteCandidates(session: ActiveCallSession): Promise<void> {
    if (!session.pc || !session.pc.remoteDescription) return;
    const queued = session.pendingRemoteIce.splice(0, session.pendingRemoteIce.length);
    for (const cand of queued) {
      try {
        await session.pc.addIceCandidate(cand);
      } catch {
        // Ignorar candidatos inválidos o tardíos
      }
    }
  }

  // === FLUJOS DE LLAMADA ===

  async startOutgoingCall(): Promise<void> {
    if (this.session) return;
    const target = this.deps.getActiveChat();
    if (!target || !target.active || !target.peerPin || target.peerPin.includes(',')) {
      this.deps.onStatus('Abre un chat 1 a 1 activo para iniciar una llamada de voz.');
      return;
    }

    this.ensureToneAudioCtx();

    let localStream: MediaStream;
    try {
      localStream = await this.requestMicrophone();
    } catch (err) {
      this.deps.onStatus(`No se pudo abrir el micrófono: ${(err as Error).message}`);
      return;
    }

    const callId = crypto.randomUUID();
    const session: ActiveCallSession = {
      callId,
      groupIdB64: target.groupIdB64,
      peerPin: target.peerPin,
      displayName: target.displayName,
      direction: 'outgoing',
      phase: 'calling',
      pc: null,
      localStream,
      remoteOfferSdp: null,
      pendingRemoteIce: [],
      pendingOutgoingIce: [],
      iceFlushTimer: null,
      localSdpSent: false,
      muted: false,
      connectedAtMs: null,
      noAnswerTimer: null,
      disconnectTimer: null,
    };

    this.session = session;
    this.syncCallButton();
    this.renderCallOverlay();
    this.startToneLoop('outgoing');

    try {
      const pc = this.setupPeerConnection(session, localStream);
      const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
      await pc.setLocalDescription(offer);
      await waitForInitialIceGathering(pc, ICE_INITIAL_GATHER_WAIT_MS);

      if (!this.session || this.session.callId !== callId) return;

      session.localSdpSent = true;
      const finalSdp = pc.localDescription?.sdp ?? offer.sdp ?? '';
      await this.enqueueSignal(session.groupIdB64, {
        __pin_call_v: 1,
        type: 'offer',
        callId,
        sdp: finalSdp,
      });

      session.noAnswerTimer = window.setTimeout(() => {
        if (this.session && this.session.callId === callId && this.session.phase === 'calling') {
          void this.endCurrentCall(true, `Sin respuesta de ${session.displayName}.`);
        }
      }, CALL_NO_ANSWER_TIMEOUT_MS);
    } catch (err) {
      void this.endCurrentCall(false, `Error iniciando llamada: ${(err as Error).message}`);
    }
  }

  async acceptIncomingCall(): Promise<void> {
    const session = this.session;
    if (!session || session.direction !== 'incoming' || session.phase !== 'ringing') return;
    if (!session.remoteOfferSdp) {
      void this.endCurrentCall(true, 'Oferta de llamada incompleta.');
      return;
    }

    this.stopToneLoop();
    this.ensureToneAudioCtx();
    session.phase = 'connecting';
    this.renderCallOverlay();

    let localStream: MediaStream;
    try {
      localStream = await this.requestMicrophone();
    } catch (err) {
      void this.endCurrentCall(true, `Permite el micrófono para contestar: ${(err as Error).message}`);
      return;
    }

    if (!this.session || this.session.callId !== session.callId) {
      localStream.getTracks().forEach((t) => t.stop());
      return;
    }

    try {
      const pc = this.setupPeerConnection(session, localStream);
      await pc.setRemoteDescription({ type: 'offer', sdp: session.remoteOfferSdp });
      await this.applyRemoteCandidates(session);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await waitForInitialIceGathering(pc, ICE_INITIAL_GATHER_WAIT_MS);

      if (!this.session || this.session.callId !== session.callId) return;

      session.localSdpSent = true;
      const finalSdp = pc.localDescription?.sdp ?? answer.sdp ?? '';
      await this.enqueueSignal(session.groupIdB64, {
        __pin_call_v: 1,
        type: 'answer',
        callId: session.callId,
        sdp: finalSdp,
      });
    } catch (err) {
      void this.endCurrentCall(true, `Error contestando llamada: ${(err as Error).message}`);
    }
  }

  async rejectIncomingCall(): Promise<void> {
    const session = this.session;
    if (!session) return;
    const { groupIdB64, callId } = session;
    this.endedCallIds.add(callId);
    this.cleanupResourcesOnly();
    await this.enqueueSignal(groupIdB64, {
      __pin_call_v: 1,
      type: 'reject',
      callId,
    });
    this.deps.onStatus('Llamada rechazada.');
  }

  async endCurrentCall(notifyPeer: boolean, statusMsg?: string): Promise<void> {
    const session = this.session;
    if (!session) return;
    const { groupIdB64, callId } = session;
    this.endedCallIds.add(callId);
    this.cleanupResourcesOnly();

    if (notifyPeer) {
      await this.enqueueSignal(groupIdB64, {
        __pin_call_v: 1,
        type: 'hangup',
        callId,
      });
    }
    if (statusMsg) {
      this.deps.onStatus(statusMsg);
    }
  }

  toggleMute(): void {
    const session = this.session;
    if (!session || !session.localStream) return;
    session.muted = !session.muted;
    for (const track of session.localStream.getAudioTracks()) {
      track.enabled = !session.muted;
    }
    this.renderCallOverlay();
  }

  private async showIncomingCallNotification(displayName: string, groupIdB64: string): Promise<void> {
    if (typeof window === 'undefined' || !('Notification' in window)) return;
    if (Notification.permission !== 'granted') return;
    if (!document.hidden && document.hasFocus()) return;

    if ('serviceWorker' in navigator) {
      try {
        const reg = await navigator.serviceWorker.getRegistration('/');
        if (reg && typeof reg.showNotification === 'function') {
          await reg.showNotification(`📞 Llamada entrante`, {
            body: `${displayName} te está llamando (voz cifrada).`,
            icon: '/icon-192.png',
            badge: '/badge-72.png',
            tag: `pin-mls-call-${groupIdB64}`,
            data: { url: '/', groupIdB64 },
          });
          return;
        }
      } catch {
        // Fallback
      }
    }

    try {
      const n = new Notification('📞 Llamada entrante', {
        body: `${displayName} te está llamando (voz cifrada).`,
        icon: '/icon-192.png',
      });
      n.onclick = () => {
        window.focus();
        n.close();
      };
    } catch {
      // Ignorado
    }
  }

  // === RECEPCIÓN DE SEÑALES CIFRADAS DESDE SYNCNOW ===

  async handleIncomingSignal(ctx: IncomingCallSignalContext): Promise<void> {
    const signal = parseVoiceCallSignal(ctx.rawText);
    if (!signal) return;

    // Ignorar ecos de este mismo dispositivo
    if (ctx.senderDeviceId === ctx.ownDeviceId) return;

    // Si otro dispositivo propio respondió, rechazó o colgó esta llamada, cerrar timbre aquí
    if (ctx.senderPin === ctx.ownPin) {
      if (
        this.session &&
        this.session.callId === signal.callId &&
        (signal.type === 'answer' || signal.type === 'reject' || signal.type === 'hangup')
      ) {
        this.endedCallIds.add(signal.callId);
        this.cleanupResourcesOnly();
        this.deps.onStatus(
          signal.type === 'answer'
            ? 'Llamada atendida en otro de tus dispositivos.'
            : 'Llamada cerrada desde otro de tus dispositivos.',
        );
      }
      return;
    }

    if (signal.type === 'offer') {
      if (this.endedCallIds.has(signal.callId)) return;
      if (Date.now() - ctx.sentAtMs > CALL_OFFER_MAX_AGE_MS) return;

      if (this.session && this.session.callId !== signal.callId) {
        await this.enqueueSignal(ctx.groupIdB64, {
          __pin_call_v: 1,
          type: 'busy',
          callId: signal.callId,
        });
        return;
      }

      if (this.session && this.session.callId === signal.callId) return;

      const displayName = this.deps.getDisplayNameForPin(ctx.peerPin || ctx.senderPin);
      const session: ActiveCallSession = {
        callId: signal.callId,
        groupIdB64: ctx.groupIdB64,
        peerPin: ctx.peerPin || ctx.senderPin,
        displayName,
        direction: 'incoming',
        phase: 'ringing',
        pc: null,
        localStream: null,
        remoteOfferSdp: signal.sdp,
        pendingRemoteIce: [],
        pendingOutgoingIce: [],
        iceFlushTimer: null,
        localSdpSent: false,
        muted: false,
        connectedAtMs: null,
        noAnswerTimer: null,
        disconnectTimer: null,
      };

      this.session = session;
      this.syncCallButton();
      this.renderCallOverlay();
      this.startToneLoop('incoming');
      void this.showIncomingCallNotification(displayName, ctx.groupIdB64);

      session.noAnswerTimer = window.setTimeout(() => {
        if (this.session && this.session.callId === signal.callId && this.session.phase === 'ringing') {
          this.endedCallIds.add(signal.callId);
          this.cleanupResourcesOnly();
          this.deps.onStatus(`Llamada perdida de ${displayName}.`);
        }
      }, CALL_NO_ANSWER_TIMEOUT_MS);
      return;
    }

    if (signal.type === 'answer') {
      const session = this.session;
      if (!session || session.callId !== signal.callId || session.direction !== 'outgoing') return;
      if (!session.pc) return;

      if (session.noAnswerTimer !== null) {
        window.clearTimeout(session.noAnswerTimer);
        session.noAnswerTimer = null;
      }
      this.stopToneLoop();
      session.phase = 'connecting';
      this.renderCallOverlay();

      try {
        await session.pc.setRemoteDescription({ type: 'answer', sdp: signal.sdp });
        await this.applyRemoteCandidates(session);
      } catch (err) {
        void this.endCurrentCall(true, `Error enlazando audio: ${(err as Error).message}`);
      }
      return;
    }

    if (signal.type === 'ice') {
      const session = this.session;
      if (!session || session.callId !== signal.callId) return;
      session.pendingRemoteIce.push(...signal.candidates);
      await this.applyRemoteCandidates(session);
      return;
    }

    if (signal.type === 'hangup' || signal.type === 'reject' || signal.type === 'busy') {
      this.endedCallIds.add(signal.callId);
      const session = this.session;
      if (!session || session.callId !== signal.callId) return;

      const label = session.displayName;
      this.cleanupResourcesOnly();
      if (signal.type === 'busy') {
        this.deps.onStatus(`${label} está en otra llamada.`);
      } else if (signal.type === 'reject') {
        this.deps.onStatus(`${label} rechazó la llamada.`);
      } else {
        this.deps.onStatus(`Llamada finalizada con ${label}.`);
      }
    }
  }

  // === LIMPIEZA Y UI FLOTANTE ===

  private startDurationTimer(): void {
    if (this.durationTimer !== null) {
      window.clearInterval(this.durationTimer);
    }
    this.durationTimer = window.setInterval(() => {
      if (!this.session || this.session.phase !== 'connected' || !this.session.connectedAtMs) {
        if (this.durationTimer !== null) {
          window.clearInterval(this.durationTimer);
          this.durationTimer = null;
        }
        return;
      }
      const statusEl = document.getElementById('pin-call-overlay-status');
      if (statusEl) {
        statusEl.textContent = formatCallDuration(Date.now() - this.session.connectedAtMs);
      }
    }, 500);
  }

  private cleanupResourcesOnly(): void {
    this.stopToneLoop();
    if (this.durationTimer !== null) {
      window.clearInterval(this.durationTimer);
      this.durationTimer = null;
    }

    const session = this.session;
    this.session = null;

    if (session) {
      if (session.noAnswerTimer !== null) window.clearTimeout(session.noAnswerTimer);
      if (session.disconnectTimer !== null) window.clearTimeout(session.disconnectTimer);
      if (session.iceFlushTimer !== null) window.clearTimeout(session.iceFlushTimer);

      if (session.localStream) {
        session.localStream.getTracks().forEach((t) => t.stop());
      }
      if (session.pc) {
        try {
          session.pc.onicecandidate = null;
          session.pc.ontrack = null;
          session.pc.onconnectionstatechange = null;
          session.pc.close();
        } catch {
          // Ignorado
        }
      }
    }

    const audio = document.getElementById('pin-call-remote-audio') as HTMLAudioElement | null;
    if (audio) {
      audio.pause();
      audio.srcObject = null;
    }

    const overlay = document.getElementById('pin-call-overlay');
    if (overlay) overlay.remove();

    this.syncCallButton();
  }

  private renderCallOverlay(customStatus?: string): void {
    if (typeof document === 'undefined') return;
    const session = this.session;
    const existing = document.getElementById('pin-call-overlay');

    if (!session) {
      if (existing) existing.remove();
      return;
    }

    const overlay = existing ?? document.createElement('div');
    overlay.id = 'pin-call-overlay';
    overlay.className = 'pin-call-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-live', 'polite');

    const statusText =
      customStatus ??
      (session.phase === 'calling'
        ? 'Llamando…'
        : session.phase === 'ringing'
          ? 'Llamada de voz entrante'
          : session.phase === 'connecting'
            ? 'Estableciendo canal cifrado…'
            : session.connectedAtMs
              ? formatCallDuration(Date.now() - session.connectedAtMs)
              : 'Conectado');

    overlay.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'pin-call-card';

    const badge = document.createElement('div');
    badge.className = 'pin-call-badge';
    badge.textContent = '🔒 Voz cifrada E2EE · OpenMLS + WebRTC';

    const peer = document.createElement('div');
    peer.className = 'pin-call-peer';
    peer.textContent = session.displayName;

    const status = document.createElement('div');
    status.id = 'pin-call-overlay-status';
    status.className = 'pin-call-status';
    status.textContent = statusText;

    const actions = document.createElement('div');
    actions.className = 'pin-call-actions';

    if (session.phase === 'ringing') {
      const acceptBtn = document.createElement('button');
      acceptBtn.type = 'button';
      acceptBtn.className = 'pin-call-btn-accept';
      acceptBtn.textContent = '📞 Contestar';
      acceptBtn.addEventListener('click', () => void this.acceptIncomingCall());

      const rejectBtn = document.createElement('button');
      rejectBtn.type = 'button';
      rejectBtn.className = 'pin-call-btn-hangup';
      rejectBtn.textContent = '✕ Rechazar';
      rejectBtn.addEventListener('click', () => void this.rejectIncomingCall());

      actions.append(acceptBtn, rejectBtn);
    } else {
      const muteBtn = document.createElement('button');
      muteBtn.type = 'button';
      muteBtn.className = `pin-call-btn-mute${session.muted ? ' is-muted' : ''}`;
      muteBtn.textContent = session.muted ? '🔇 Silenciado' : '🎤 Mic activo';
      muteBtn.addEventListener('click', () => this.toggleMute());

      const hangupBtn = document.createElement('button');
      hangupBtn.type = 'button';
      hangupBtn.className = 'pin-call-btn-hangup';
      hangupBtn.textContent = 'Colgar';
      hangupBtn.addEventListener('click', () => void this.endCurrentCall(true, 'Llamada finalizada.'));

      actions.append(muteBtn, hangupBtn);
    }

    card.append(badge, peer, status, actions);
    overlay.appendChild(card);

    if (!existing) {
      document.body.appendChild(overlay);
    }
  }
}
