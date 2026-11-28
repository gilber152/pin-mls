import { installPwaInstallButton } from './ui/pwaInstall.js';
import { installAndroidNativeBridge } from './native/androidBridge.js';
import { setMediaAuthProvider } from './net/e2eeMedia.js';
import { VoiceCallController, isVoiceCallSignalText } from './call/voiceCall.js';
import { ensureWebPushSubscribed, registerAppServiceWorker, unsubscribeWebPush } from './net/webPush.js';
import { applyWhatsAppLayoutClasses, waAlerts } from './ui/whatsappAndAlerts.js';
import type { VaultGroup, VaultState } from './types.js';
import { loadVault, saveVault, wipeVault, setPinAlias, loadPinAliases, applySyncedPinAliases } from './storage/vaultDb.js';
import { archiveMessagesForPin, consolidateVaultGroupsByPin, markMessageDeletedForPin, markSeqDeletedForPin } from './storage/pinGroupConsolidator.js';
import { CryptoWorkerClient, type StartedLinkSessionDto } from './worker/workerClient.js';
import {
  API_BASE,
  type DevicesListResponse,
  hexToBytes,
  PinApiClient,
  type SyncResponse,
} from './net/api.js';

import { initStep1Enhancements, type Step1Controller } from './ui/step1Enhancements.js';

import { initStep2Enhancements, type Step2Controller } from './ui/step2Enhancements.js';

import { initStep4GroupsAndPresence, type Step4Controller } from './ui/step4GroupsAndPresence.js';

const worker = new CryptoWorkerClient();
const api = new PinApiClient(worker);

let vault: VaultState | null = null;
let activeGroupIdB64: string | null = null;
let ws: WebSocket | null = null;
let wsReconnectTimer: number | null = null;
let syncInFlight = false;

// Safe Backup modal state
let safeAllowUpload = false;
let safeBusy = false;

// Secondary LinkQr polling state
let linkPollTimer: number | null = null;
let activeLinkSession: StartedLinkSessionDto | null = null;

// Primary Devices modal state
let devicesBusy = false;
let selectedRevokeDeviceId: string | null = null;

// DOM refs
const viewOnboarding = document.getElementById('view-onboarding') as HTMLElement;
const viewChat = document.getElementById('view-chat') as HTMLElement;
const onboardingStatus = document.getElementById('onboarding-status') as HTMLParagraphElement;
const btnCreatePin = document.getElementById('btn-create-pin') as HTMLButtonElement;
const btnOnboardingLink = document.getElementById('btn-onboarding-link') as HTMLButtonElement;
const btnOnboardingRestore = document.getElementById('btn-onboarding-restore') as HTMLButtonElement;

const myPinLabel = document.getElementById('my-pin-label') as HTMLElement;
const btnCopyPin = document.getElementById('btn-copy-pin') as HTMLButtonElement;
const wsBadge = document.getElementById('ws-badge') as HTMLSpanElement;
const btnSyncNow = document.getElementById('btn-sync-now') as HTMLButtonElement;
const btnOpenDevices = document.getElementById('btn-open-devices') as HTMLButtonElement;
const btnOpenSafe = document.getElementById('btn-open-safe') as HTMLButtonElement;
const btnWipeVault = document.getElementById('btn-wipe-vault') as HTMLButtonElement;
const btnLogoutSession = document.getElementById('btn-logout-session') as HTMLButtonElement | null;
const btnResumeSession = document.getElementById('btn-resume-session') as HTMLButtonElement | null;
const PIN_MANUAL_LOGOUT_KEY = 'pin_mls_manual_logout_v1';
const globalStatus = document.getElementById('global-status') as HTMLDivElement;

const mnemonicBanner = document.getElementById('mnemonic-banner') as HTMLDivElement;
const mnemonicWordsText = document.getElementById('mnemonic-words-text') as HTMLElement;
const btnDismissMnemonic = document.getElementById('btn-dismiss-mnemonic') as HTMLButtonElement;

const formInvite = document.getElementById('form-invite') as HTMLFormElement;
const inputInvitePin = document.getElementById('input-invite-pin') as HTMLInputElement;
const inputInviteNote = document.getElementById('input-invite-note') as HTMLInputElement;
const btnSendInvite = document.getElementById('btn-send-invite') as HTMLButtonElement;

const badgeInvites = document.getElementById('badge-invites') as HTMLSpanElement;
const listInvites = document.getElementById('list-invites') as HTMLUListElement;
const badgeChats = document.getElementById('badge-chats') as HTMLSpanElement;
const listChats = document.getElementById('list-chats') as HTMLUListElement;

const chatEmpty = document.getElementById('chat-empty') as HTMLDivElement;
const chatActive = document.getElementById('chat-active') as HTMLDivElement;
const activeChatTitle = document.getElementById('active-chat-title') as HTMLElement;
const activeChatMeta = document.getElementById('active-chat-meta') as HTMLElement;
const messagesList = document.getElementById('messages-list') as HTMLDivElement;
const formSendMsg = document.getElementById('form-send-msg') as HTMLFormElement;
const inputMsg = document.getElementById('input-msg') as HTMLInputElement;

// Safe Backup modal refs
const safeDialog = document.getElementById('safe-dialog') as HTMLDialogElement;
const safeDialogTitle = document.getElementById('safe-dialog-title') as HTMLHeadingElement;
const safeMnemonic = document.getElementById('safe-mnemonic') as HTMLTextAreaElement;
const safeWordCount = document.getElementById('safe-word-count') as HTMLSpanElement;
const safeStatus = document.getElementById('safe-status') as HTMLParagraphElement;
const btnSafeUpload = document.getElementById('btn-safe-upload') as HTMLButtonElement;
const btnSafeRestore = document.getElementById('btn-safe-restore') as HTMLButtonElement;

// LinkQr Secondary modal refs
const linkWaitDialog = document.getElementById('link-wait-dialog') as HTMLDialogElement;
const linkQrOutput = document.getElementById('link-qr-output') as HTMLTextAreaElement;
const btnCopyLinkQr = document.getElementById('btn-copy-link-qr') as HTMLButtonElement;
const linkWaitStatus = document.getElementById('link-wait-status') as HTMLParagraphElement;

// Devices Primary modal refs
const devicesDialog = document.getElementById('devices-dialog') as HTMLDialogElement;
const btnRefreshDevices = document.getElementById('btn-refresh-devices') as HTMLButtonElement;
const devicesList = document.getElementById('devices-list') as HTMLUListElement;
const devicesMnemonic = document.getElementById('devices-mnemonic') as HTMLTextAreaElement;
const devicesWordCount = document.getElementById('devices-word-count') as HTMLSpanElement;
const inputLinkQrUri = document.getElementById('input-link-qr-uri') as HTMLTextAreaElement;
const btnAuthorizeLink = document.getElementById('btn-authorize-link') as HTMLButtonElement;
const revokeConfirmBox = document.getElementById('revoke-confirm-box') as HTMLDivElement;
const revokeTargetLabel = document.getElementById('revoke-target-label') as HTMLParagraphElement;
const btnCancelRevoke = document.getElementById('btn-cancel-revoke') as HTMLButtonElement;
const btnConfirmRevoke = document.getElementById('btn-confirm-revoke') as HTMLButtonElement;
const devicesStatus = document.getElementById('devices-status') as HTMLParagraphElement;

function formatPin(pin: string): string {
  return pin.length === 8 ? `${pin.slice(0, 4)}-${pin.slice(4)}` : pin;
}

function normalizePinInput(raw: string): string {
  return raw.toUpperCase().replace(/[^0-9A-Z]/g, '');
}

let globalStatusHideTimer: number | null = null;
let globalStatusObserverReady = false;

function scheduleGlobalStatusAutoHide(): void {
  if (globalStatusHideTimer !== null) {
    window.clearTimeout(globalStatusHideTimer);
    globalStatusHideTimer = null;
  }
  const text = (globalStatus.textContent ?? '').trim();
  if (!text) {
    globalStatus.classList.remove('pin-toast-visible');
    return;
  }
  globalStatus.classList.add('pin-toast-visible');
  globalStatusHideTimer = window.setTimeout(() => {
    globalStatusHideTimer = null;
    globalStatus.classList.remove('pin-toast-visible');
    window.setTimeout(() => {
      if (!globalStatus.classList.contains('pin-toast-visible')) {
        globalStatus.textContent = '';
      }
    }, 260);
  }, 4000);
}

function ensureGlobalStatusToastObserver(): void {
  if (globalStatusObserverReady || typeof MutationObserver === 'undefined') return;
  globalStatusObserverReady = true;
  const obs = new MutationObserver(() => {
    scheduleGlobalStatusAutoHide();
  });
  obs.observe(globalStatus, { childList: true, characterData: true, subtree: true });
  scheduleGlobalStatusAutoHide();
}

function setGlobalStatus(msg: string): void {
  ensureGlobalStatusToastObserver();
  globalStatus.textContent = msg;
  scheduleGlobalStatusAutoHide();
}

if (typeof document !== 'undefined') {
  ensureGlobalStatusToastObserver();
}

function setWsStatus(online: boolean, label?: string): void {
  wsBadge.className = `ws-badge ${online ? 'online' : 'offline'}`;
  wsBadge.textContent = label ?? (online ? 'En línea' : 'Reconectando...');
}

function showChatView(): void {
  /* === PIN_LOCK_CHAT_VIEW_START === */
  try {
    localStorage.setItem('pin_mls_has_active_session_v1', '1');
    localStorage.removeItem('pin_mls_manual_logout_v1');
  } catch {}
  document.documentElement.classList.add('pin-session-active');
  document.documentElement.classList.remove('pin-boot-hide-onboarding');
  viewOnboarding.hidden = true;
  viewOnboarding.classList.add('hidden');
  viewOnboarding.style.display = 'none';
  viewChat.hidden = false;
  viewChat.classList.remove('hidden');
  viewChat.style.display = '';
  /* === PIN_LOCK_CHAT_VIEW_END === */
  viewOnboarding.classList.add('hidden');
  viewChat.classList.remove('hidden');
  if (vault) myPinLabel.textContent = formatPin(vault.pin);
  renderAll();
}

function showOnboardingView(): void {
  /* === PIN_LOCK_ONBOARDING_VIEW_START === */
  try {
    localStorage.removeItem('pin_mls_has_active_session_v1');
  } catch {}
  document.documentElement.classList.remove('pin-session-active', 'pin-boot-hide-onboarding');
  viewChat.hidden = true;
  viewChat.classList.add('hidden');
  viewChat.style.display = 'none';
  viewOnboarding.hidden = false;
  viewOnboarding.classList.remove('hidden');
  viewOnboarding.style.display = '';
  /* === PIN_LOCK_ONBOARDING_VIEW_END === */
  viewChat.classList.add('hidden');
  viewOnboarding.classList.remove('hidden');
}

async function handleRevokedLocalDevice(reason: string): Promise<void> {
  ws?.close();
  ws = null;
  if (wsReconnectTimer !== null) {
    window.clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  api.clearSession();
  await wipeVault();
  vault = null;
  activeGroupIdB64 = null;
  if (devicesDialog.open) devicesDialog.close();
  if (safeDialog.open) safeDialog.close();
  showOnboardingView();
  onboardingStatus.textContent = reason;
}

function renderAll(): void {
  if (!vault) return;

  badgeInvites.textContent = String(vault.incomingInvites.length);
  listInvites.innerHTML = '';
  if (vault.incomingInvites.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted-small';
    li.textContent = 'Sin solicitudes pendientes.';
    listInvites.appendChild(li);
  } else {
    for (const inv of vault.incomingInvites) {
      const li = document.createElement('li');
      li.className = 'list-card';

      const top = document.createElement('div');
      top.className = 'card-row';
      const strong = document.createElement('strong');
      strong.textContent = formatPin(inv.senderPin);
      top.appendChild(strong);

      const noteEl = document.createElement('p');
      noteEl.className = 'muted-small';
      noteEl.textContent = inv.note || 'Quiere iniciar un chat cifrado contigo.';

      const actions = document.createElement('div');
      actions.className = 'card-actions';

      const btnAccept = document.createElement('button');
      btnAccept.className = 'btn-primary';
      btnAccept.textContent = 'Aceptar';
      btnAccept.onclick = () => { void respondInvite(inv.requestId, inv.senderPin, 'accept'); };

      const btnReject = document.createElement('button');
      btnReject.className = 'btn-danger-ghost';
      btnReject.textContent = 'Rechazar';
      btnReject.onclick = () => { void respondInvite(inv.requestId, inv.senderPin, 'reject'); };

      actions.append(btnAccept, btnReject);
      li.append(top, noteEl, actions);
      listInvites.appendChild(li);
    }
  }

  /* PIN_CONSOLIDATE_BEFORE_RENDER */ consolidateVaultGroupsByPin(vault);
  const groups = Object.values(vault.groups).filter((g) => !isSelfSyncGroup(g, vault!.pin)).sort((a, b) => {
    const aTime = a.messages[a.messages.length - 1]?.sentAtMs ?? 0;
    const bTime = b.messages[b.messages.length - 1]?.sentAtMs ?? 0;
    return bTime - aTime;
  });

  badgeChats.textContent = String(groups.length);
  listChats.innerHTML = '';
  if (groups.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted-small';
    li.textContent = 'Aún no tienes chats activos.';
    listChats.appendChild(li);
  } else {
    for (const grp of groups) {
      const li = document.createElement('li');
      li.className = `list-card clickable ${grp.groupIdB64 === activeGroupIdB64 ? 'active' : ''}`;
      li.dataset.groupId = grp.groupIdB64;
      li.onclick = () => {
        activeGroupIdB64 = grp.groupIdB64;
        renderAll();
      };

      const top = document.createElement('div');
      top.className = 'card-row';
      const name = document.createElement('strong');
      name.textContent = `PIN ${formatPin(grp.peerPin)}`;
      const ep = document.createElement('span');
      ep.className = 'muted-small';
      ep.textContent = grp.active ? '' : 'removido';
      top.append(name, ep);

      const last = grp.messages[grp.messages.length - 1];
      const preview = document.createElement('p');
      preview.className = 'muted-small';
      preview.textContent = last ? `${last.mine ? 'Tú: ' : ''}${last.text}` : 'Chat MLS listo · envía un mensaje';

      li.append(top, preview);
      listChats.appendChild(li);
    }
  }

  const activeGrp = activeGroupIdB64 ? vault.groups[activeGroupIdB64] : undefined;
  if (!activeGrp) {
    chatEmpty.classList.remove('hidden');
    chatActive.classList.add('hidden');
    return;
  }

  chatEmpty.classList.add('hidden');
  chatActive.classList.remove('hidden');
  activeChatTitle.textContent = `PIN ${formatPin(activeGrp.peerPin)}`;
  activeChatMeta.textContent = ` · ${activeGrp.messages.length} mensajes`;

  messagesList.innerHTML = '';
  for (const m of activeGrp.messages) {
    const bubble = document.createElement('div');
    bubble.className = `msg-bubble ${m.mine ? 'mine' : 'theirs'}`;
    bubble.dataset.groupSeq = String(m.groupSeq);
    bubble.dataset.sentAtMs = String(m.sentAtMs);
    bubble.dataset.senderPin = formatPin(m.senderPin);
    bubble.dataset.peerPin = formatPin(activeGrp.peerPin);
    bubble.dataset.mine = m.mine ? '1' : '0';
    bubble.dataset.groupId = activeGrp.groupIdB64;

    const body = document.createElement('div');
    body.textContent = m.text;

    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    const timeStr = new Date(m.sentAtMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const otherOwnDev = m.mine && m.senderDeviceId !== vault.deviceId ? ' (otro disp.)' : '';
    meta.textContent = `${m.mine ? 'Tú' + otherOwnDev : formatPin(m.senderPin)} · ${timeStr} · #${m.groupSeq}`;

    bubble.append(body, meta);
    messagesList.appendChild(bubble);
  }
  messagesList.scrollTop = messagesList.scrollHeight;
}

// ============================================================================
// ONBOARDING: CREAR PIN NUEVO
// ============================================================================

async function createNewIdentity(): Promise<void> {
  localStorage.removeItem(PIN_MANUAL_LOGOUT_KEY);
  if (btnResumeSession) btnResumeSession.hidden = true;
  btnCreatePin.disabled = true;
  btnOnboardingLink.disabled = true;
  btnOnboardingRestore.disabled = true;
  try {
    onboardingStatus.textContent = 'Generando frase semilla BIP-39 (12 palabras) y claves Ed25519/X25519...';
    const mnemonic = await worker.generateMnemonic();
    const reg = await worker.deriveIdentityRegistration(mnemonic);

    onboardingStatus.textContent = 'Resolviendo prueba de trabajo Argon2id (action=1) en Web Worker...';
    const pow = await api.solvePowChallenge(1, hexToBytes(reg.pkRootHex));

    onboardingStatus.textContent = 'Registrando identidad en el servidor...';
    const regRes = await fetch(`${API_BASE}/v1/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pkRoot: reg.pkRootB64Url,
        pkInvite: reg.pkInviteB64Url,
        sigInvite: reg.sigInviteB64Url,
        proofOfPossession: reg.proofOfPossessionB64Url,
        ...pow,
      }),
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!regRes.ok) {
      const txt = await regRes.text().catch(() => '');
      throw new Error(`Fallo registrando PIN (${regRes.status}): ${txt}`);
    }
    const { pin } = (await regRes.json()) as { pin: string };

    vault = await api.enrollDeviceWithMnemonic(
      mnemonic,
      pin,
      reg.pkRootHex,
      reg.skInviteHex,
      reg.pkInviteHex,
      (m) => { onboardingStatus.textContent = m; },
    );
    await saveVault(vault);

    mnemonicWordsText.textContent = mnemonic;
    mnemonicBanner.classList.remove('hidden');

    showChatView();
    setGlobalStatus(`Cuenta OpenMLS creada con PIN ${formatPin(pin)}. Conectando WebSocket...`);
    void connectWebSocket();
    await syncNow();
  } catch (err) {
    onboardingStatus.textContent = `Error: ${(err as Error).message}`;
  } finally {
    btnCreatePin.disabled = false;
    btnOnboardingLink.disabled = false;
    btnOnboardingRestore.disabled = false;
  }
}

// ============================================================================
// VINCULAR DISPOSITIVO SECUNDARIO (LinkQr)
// ============================================================================

function stopLinkPolling(): void {
  if (linkPollTimer !== null) {
    window.clearInterval(linkPollTimer);
    linkPollTimer = null;
  }
  activeLinkSession = null;
}

async function openSecondaryLinkModal(): Promise<void> {
  stopLinkPolling();
  linkQrOutput.value = 'Generando claves efímeras X25519 + Ed25519 en WASM...';
  linkWaitStatus.textContent = 'Iniciando sesión de vinculación...';
  linkWaitDialog.showModal();

  try {
    const sess = await worker.startLinkSession();
    activeLinkSession = sess;
    linkQrOutput.value = sess.linkQrUri;
    linkWaitStatus.textContent = `Esperando autorización del dispositivo principal (device ${sess.deviceId.slice(0, 8)}...)`;

    let polling = false;
    linkPollTimer = window.setInterval(async () => {
      if (polling || !activeLinkSession) return;
      polling = true;
      try {
        const res = await api.pollLinkSessionOnce(
          activeLinkSession.sessionIdHex,
          activeLinkSession.readSecretB64Url,
        );
        if (res.status === 'waiting') return;
        if (res.status === 'expired') {
          stopLinkPolling();
          linkWaitStatus.textContent = 'Sesión expirada o ya consumida (410). Cierra y genera un código nuevo.';
          return;
        }

        const currentSess = activeLinkSession;
        stopLinkPolling();
        linkWaitStatus.textContent = 'Paquete recibido. Descifrando LinkBundle con clave efímera X25519...';
        const bundle = await worker.openLinkBundle({
          skLinkEphHex: currentSess.skLinkEphHex,
          sessionIdHex: currentSess.sessionIdHex,
          deviceId: currentSess.deviceId,
          bundleWire: res.bundleWire,
        });

        linkWaitStatus.textContent = 'Inicializando motor OpenMLS RFC 9420 para este navegador...';
        const rtInit = await worker.mlsInitRuntime({
          storageJson: '',
          pin: bundle.pin,
          deviceId: currentSess.deviceId,
          sigPkB64: '',
        });

        const newVault: VaultState = {
          vaultSchemaVersion: 2,
          pin: bundle.pin,
          deviceId: currentSess.deviceId,
          pkRootHex: bundle.pkRootHex,
          skInviteHex: bundle.skInviteHex,
          pkInviteHex: bundle.pkInviteHex,
          skDevHex: currentSess.skDevHex,
          pkDevHex: currentSess.pkDevHex,
          mlsSigPkB64: rtInit.sigPkB64,
          mlsStorageJson: rtInit.storageJson,
          safeBackupRevision: bundle.safeBackupRevision ?? 0,
          contacts: bundle.contacts ?? [],
          incomingInvites: [],
          groups: {},
        };

        linkWaitStatus.textContent = `PIN ${formatPin(newVault.pin)} vinculado. Subiendo 20 KeyPackages OpenMLS...`;
        /* PIN_LINKQR_RECEIVE_ALIASES */ await hydrateLocalAliasesFromVaultContacts(newVault);
        await api.replenishKeyPackages(newVault, 20, true);
        await api.getJwt(newVault, true);

        vault = newVault;
        await saveVault(vault);
        linkWaitDialog.close();
        showChatView();
        setGlobalStatus(
          `Dispositivo ${vault.deviceId.slice(0, 8)} vinculado al PIN ${formatPin(vault.pin)} (OpenMLS).`,
        );
        void connectWebSocket();
        void syncNow();
      } catch (err) {
        linkWaitStatus.textContent = `Error: ${(err as Error).message}`;
      } finally {
        polling = false;
      }
    }, 2000);
  } catch (err) {
    linkWaitStatus.textContent = `Error generando LinkQr: ${(err as Error).message}`;
  }
}

linkWaitDialog.addEventListener('close', () => {
  stopLinkPolling();
  linkQrOutput.value = '';
});

btnCopyLinkQr.addEventListener('click', async () => {
  if (!linkQrOutput.value) return;
  await navigator.clipboard.writeText(linkQrOutput.value).catch(() => {});
  linkWaitStatus.textContent = 'Código LinkQr copiado. Pégalo en tu dispositivo principal y espera aquí...';
});

// ============================================================================
// CATCH-UP DE CONFLICTO 409 EN COMMITS OPENMLS
// ============================================================================

interface Conflict409Body {
  currentEpoch?: number;
  missingCommits?: Array<{
    groupSeq: number;
    epoch: number;
    ciphertext: string;
    serverTimestamp: number;
  }>;
}

async function handleCommitConflict409(grp: VaultGroup, res: Response): Promise<void> {
  if (!vault) return;
  const cleared = await worker.mlsClearPendingCommit(grp.groupIdB64);
  vault.mlsStorageJson = cleared.storageJson;
  grp.epoch = cleared.epoch;

  const body = (await res.json().catch(() => ({}))) as Conflict409Body;
  const missing = [...(body.missingCommits ?? [])].sort((a, b) => a.groupSeq - b.groupSeq);
  for (const mc of missing) {
    if (mc.groupSeq <= grp.lastSeq) continue;
    const outcome = await worker.mlsProcessEnvelope(grp.groupIdB64, mc.ciphertext);
    vault.mlsStorageJson = outcome.storageJson;
    grp.epoch = outcome.epoch;
    grp.active = outcome.active;
    grp.lastSeq = Math.max(grp.lastSeq, mc.groupSeq);
  }
  await saveVault(vault);
}

// ============================================================================
// GESTIÓN DE DISPOSITIVOS (LISTAR, AUTORIZAR LINKQR, SYNC, REVOCAR PCS)
// ============================================================================

function refreshDevicesButtons(): void {
  const words = devicesMnemonic.value.trim().split(/\s+/).filter(Boolean);
  devicesWordCount.textContent = String(words.length);
  const has12Words = words.length === 12;
  const hasLinkUri = inputLinkQrUri.value.trim().startsWith('pinapp://v1/link?');

  btnAuthorizeLink.disabled = devicesBusy || !has12Words || !hasLinkUri;
  btnConfirmRevoke.disabled = devicesBusy || !has12Words || !selectedRevokeDeviceId;
}

function clearRevokeSelection(): void {
  selectedRevokeDeviceId = null;
  revokeTargetLabel.textContent = '';
  revokeConfirmBox.classList.add('hidden');
  refreshDevicesButtons();
}

async function renderDevicesList(): Promise<DevicesListResponse | null> {
  if (!vault) return null;
  devicesList.innerHTML = '<li class="muted-small">Cargando dispositivos...</li>';
  try {
    const info = await api.listDevices(vault);
    devicesList.innerHTML = '';
    for (const d of info.devices) {
      const li = document.createElement('li');
      li.className = 'list-card';

      const top = document.createElement('div');
      top.className = 'card-row';

      const idSpan = document.createElement('strong');
      idSpan.className = 'mono';
      idSpan.title = d.deviceId;
      idSpan.textContent = d.isCurrent
        ? `${d.deviceId.slice(0, 8)}… (Este navegador)`
        : `${d.deviceId.slice(0, 8)}…`;

      const badge = document.createElement('span');
      if (d.status === 'revoked') {
        badge.className = 'ws-badge revoked';
        badge.textContent = 'Revocado';
      } else if (d.online) {
        badge.className = 'ws-badge online';
        badge.textContent = 'Activo · En línea';
      } else {
        badge.className = 'ws-badge offline';
        badge.textContent = 'Activo · Desconectado';
      }
      top.append(idSpan, badge);

      const meta = document.createElement('p');
      meta.className = 'muted-small';
      meta.textContent = `Creado: ${new Date(d.createdAt).toLocaleString()}`;
      li.append(top, meta);

      if (!d.isCurrent && d.status === 'active') {
        const actions = document.createElement('div');
        actions.className = 'card-actions';

        const btnSyncChats = document.createElement('button');
        btnSyncChats.type = 'button';
        btnSyncChats.className = 'btn-secondary';
        btnSyncChats.textContent = 'Sincronizar chats';
        btnSyncChats.onclick = () => {
          void syncSiblingDeviceIntoAllGroups(d.deviceId, (m) => { devicesStatus.textContent = m; });
        };

        const btnRevoke = document.createElement('button');
        btnRevoke.type = 'button';
        btnRevoke.className = 'btn-danger-ghost';
        btnRevoke.textContent = 'Revocar';
        btnRevoke.onclick = () => {
          selectedRevokeDeviceId = d.deviceId;
          revokeTargetLabel.textContent = `Dispositivo objetivo: ${d.deviceId}`;
          revokeConfirmBox.classList.remove('hidden');
          devicesMnemonic.focus();
          refreshDevicesButtons();
        };

        actions.append(btnSyncChats, btnRevoke);
        li.appendChild(actions);
      }

      devicesList.appendChild(li);
    }
    return info;
  } catch (err) {
    devicesList.innerHTML = `<li class="muted-small">Error cargando dispositivos: ${(err as Error).message}</li>`;
    return null;
  }
}

async function openDevicesModal(): Promise<void> {
  devicesMnemonic.value = '';
  inputLinkQrUri.value = '';
  devicesStatus.textContent = '';
  clearRevokeSelection();
  devicesDialog.showModal();
  await renderDevicesList();
}

async function syncSiblingDeviceIntoAllGroups(
  targetDeviceId: string,
  onProgress: (msg: string) => void,
  maxWaitAttempts = 1,
): Promise<number> {
  if (!vault) return 0;
  const groupIds = Object.keys(vault.groups);
  if (groupIds.length === 0) {
    onProgress('No tienes chats activos aún para sincronizar con ese dispositivo.');
    return 0;
  }

  let syncedCount = 0;
  for (const gid of groupIds) {
    let kp: { kpRef: string; kpRaw: string } | null = null;
    for (let attempt = 1; attempt <= maxWaitAttempts; attempt += 1) {
      try {
        kp = await api.selfClaimKeyPackage(vault, targetDeviceId);
        break;
      } catch (err) {
        const msg = (err as Error).message;
        if (attempt < maxWaitAttempts && msg.includes('404')) {
          onProgress(`Esperando KeyPackages OpenMLS del nuevo dispositivo (${attempt}/${maxWaitAttempts})...`);
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        throw err;
      }
    }
    if (!kp) continue;

    for (let retry = 0; retry < 2; retry += 1) {
      const grp = vault.groups[gid];
      if (!grp || !grp.active) break;

      onProgress(`Ejecutando add_members TreeKEM para ${formatPin(grp.peerPin)}...`);
      const prep = await worker.mlsPrepareAddMember(grp.groupIdB64, kp.kpRaw);
      vault.mlsStorageJson = prep.storageJson;

      const res = await api.authedFetch(vault, `/v1/groups/${grp.groupIdB64Url}/commits`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expectedBaseEpoch: prep.baseEpoch,
          clientMsgId: crypto.randomUUID(),
          commitRaw: prep.commitRawB64,
          welcomeRaw: prep.welcomeRawB64,
          addedDevices: [targetDeviceId],
          addedKpRefs: [kp.kpRef],
          removedDevices: [],
        }),
      });

      if (res.status === 409 && retry === 0) {
        await handleCommitConflict409(grp, res);
        continue;
      }
      if (!res.ok) {
        const cleared = await worker.mlsClearPendingCommit(grp.groupIdB64);
        vault.mlsStorageJson = cleared.storageJson;
        await saveVault(vault);
        const txt = await res.text().catch(() => '');
        throw new Error(`Fallo Commit add (${res.status}): ${txt.slice(0, 140)}`);
      }

      const data = (await res.json()) as { confirmedCommitSeq: number; newEpoch: number };
      const confirmed = await worker.mlsConfirmPendingCommit(grp.groupIdB64);
      vault.mlsStorageJson = confirmed.storageJson;
      grp.epoch = confirmed.epoch;
      grp.lastSeq = Math.max(grp.lastSeq, data.confirmedCommitSeq);
      syncedCount += 1;
      break;
    }
  }

  await saveVault(vault);
  renderAll();
  onProgress(`Sincronizados ${syncedCount} chat(s) OpenMLS con el dispositivo ${targetDeviceId.slice(0, 8)}.`);
  return syncedCount;
}

async function rotateAllGroupsAfterRevocation(
  revokedDeviceId: string,
  onProgress: (msg: string) => void,
): Promise<number> {
  if (!vault) return 0;
  const groupIds = Object.keys(vault.groups);
  let rotated = 0;

  for (const gid of groupIds) {
    for (let retry = 0; retry < 2; retry += 1) {
      const grp = vault.groups[gid];
      if (!grp || !grp.active) break;

      onProgress(`Ejecutando remove_members TreeKEM en chat con ${formatPin(grp.peerPin)} (PCS)...`);
      const prep = await worker.mlsPrepareRemoveDevice(grp.groupIdB64, revokedDeviceId);
      vault.mlsStorageJson = prep.storageJson;
      if (prep.skipped) break;

      const res = await api.authedFetch(vault, `/v1/groups/${grp.groupIdB64Url}/commits`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expectedBaseEpoch: prep.baseEpoch,
          clientMsgId: crypto.randomUUID(),
          commitRaw: prep.commitRawB64,
          removedDevices: [revokedDeviceId],
        }),
      });

      if (res.status === 409 && retry === 0) {
        await handleCommitConflict409(grp, res);
        continue;
      }
      if (!res.ok) {
        const cleared = await worker.mlsClearPendingCommit(grp.groupIdB64);
        vault.mlsStorageJson = cleared.storageJson;
        break;
      }

      const data = (await res.json()) as { confirmedCommitSeq: number; newEpoch: number };
      const confirmed = await worker.mlsConfirmPendingCommit(grp.groupIdB64);
      vault.mlsStorageJson = confirmed.storageJson;
      grp.epoch = confirmed.epoch;
      grp.lastSeq = Math.max(grp.lastSeq, data.confirmedCommitSeq);
      rotated += 1;
      break;
    }
  }

  await saveVault(vault);
  renderAll();
  return rotated;
}

devicesMnemonic.addEventListener('input', refreshDevicesButtons);
inputLinkQrUri.addEventListener('input', refreshDevicesButtons);
devicesDialog.addEventListener('close', () => {
  devicesMnemonic.value = '';
  inputLinkQrUri.value = '';
  clearRevokeSelection();
});
btnRefreshDevices.addEventListener('click', () => { void renderDevicesList(); });
btnCancelRevoke.addEventListener('click', clearRevokeSelection);

btnAuthorizeLink.addEventListener('click', async () => {
  if (!vault) return;
  const phrase = devicesMnemonic.value;
  const uri = inputLinkQrUri.value.trim();
  devicesMnemonic.value = '';
  devicesBusy = true;
  refreshDevicesButtons();

  try {
    /* PIN_LINKQR_UPLOAD_ALIASES */ await mergeLocalAliasesIntoVaultContacts(vault);
    const out = await api.authorizeAndUploadLinkSession(vault, phrase, uri, (m) => {
      devicesStatus.textContent = m;
    });
    inputLinkQrUri.value = '';
    await renderDevicesList();

    if (Object.keys(vault.groups).length > 0) {
      devicesStatus.textContent = `Dispositivo ${out.targetDeviceId.slice(0, 8)} autorizado. Esperando KeyPackages OpenMLS para enviar tus chats...`;
      try {
        await syncSiblingDeviceIntoAllGroups(
          out.targetDeviceId,
          (m) => { devicesStatus.textContent = m; },
          15,
        );
      } catch (syncErr) {
        devicesStatus.textContent = `Dispositivo vinculado, pero falló auto-sync de chats: ${(syncErr as Error).message}. Usa 'Sincronizar chats'.`;
      }
    } else {
      devicesStatus.textContent = `Dispositivo ${out.targetDeviceId.slice(0, 8)} vinculado correctamente.`;
    }
    setGlobalStatus(`Nuevo dispositivo ${out.targetDeviceId.slice(0, 8)} vinculado al PIN ${formatPin(vault.pin)}.`);
  } catch (err) {
    devicesStatus.textContent = `Error: ${(err as Error).message}`;
  } finally {
    devicesBusy = false;
    refreshDevicesButtons();
  }
});

btnConfirmRevoke.addEventListener('click', async () => {
  if (!vault || !selectedRevokeDeviceId) return;
  const targetId = selectedRevokeDeviceId;
  const phrase = devicesMnemonic.value;
  devicesMnemonic.value = '';
  devicesBusy = true;
  refreshDevicesButtons();

  try {
    const rev = await api.revokeDevice(vault, phrase, targetId, (m) => {
      devicesStatus.textContent = m;
    });
    const rotated = await rotateAllGroupsAfterRevocation(targetId, (m) => {
      devicesStatus.textContent = m;
    });
    clearRevokeSelection();
    await renderDevicesList();

    const msg = `Dispositivo ${targetId.slice(0, 8)} revocado (seq #${rev.seqNum}, WS 4001 enviado, ${rotated} chat(s) rotados con TreeKEM PCS).`;
    devicesStatus.textContent = msg;
    setGlobalStatus(msg);
  } catch (err) {
    devicesStatus.textContent = `Error revocando: ${(err as Error).message}`;
  } finally {
    devicesBusy = false;
    refreshDevicesButtons();
  }
});

// ============================================================================
// INVITACIONES, GRANTS Y CREACIÓN DE CHAT OPENMLS RFC 9420
// ============================================================================

async function sendInvite(targetPinRaw: string, note: string): Promise<void> {
  if (!vault) return;
  const targetPin = normalizePinInput(targetPinRaw);
  if (targetPin.length !== 8) {
    setGlobalStatus('El PIN debe tener exactamente 8 caracteres.');
    return;
  }
  if (targetPin === vault.pin) {
    setGlobalStatus('No puedes invitarte a tu propio PIN.');
    return;
  }

  btnSendInvite.disabled = true;
  try {
    setGlobalStatus(`Consultando perfil público de ${formatPin(targetPin)}...`);
    const profile = await api.authedJson<{
      pin: string;
      pkRoot: string;
      pkInvite: string;
      sigInvite: string;
    }>(vault, `/v1/identities/${targetPin}/invite-profile`);

    setGlobalStatus('Verificando firma sigInvite contra pkRoot y cifrando solicitud...');
    const sealed = await worker.sealInvite({
      senderPin: vault.pin,
      targetPin,
      targetPkRootB64Url: profile.pkRoot,
      targetPkInviteB64Url: profile.pkInvite,
      targetSigInviteB64Url: profile.sigInvite,
      note,
    });

    if (!vault.contacts.some((c) => c.pin === targetPin)) {
      vault.contacts.push({
        pin: targetPin,
        pk_root_b64: sealed.verifiedPkRootB64,
        trust_state: 'tofu',
        alias_local: null,
        updated_at: Math.floor(Date.now() / 1000),
      });
      await saveVault(vault);
    }

    setGlobalStatus('Resolviendo PoW Argon2id (action=2) en Web Worker...');
    const pow = await api.solvePowChallenge(2, new TextEncoder().encode(targetPin));

    setGlobalStatus(`Enviando invitación cifrada a ${formatPin(targetPin)}...`);
    await api.authedJson(vault, '/v1/invites', 'POST', {
      targetPin,
      ciphertext: sealed.ciphertextB64,
      ...pow,
    });

    inputInvitePin.value = '';
    inputInviteNote.value = '';
    setGlobalStatus(`Invitación cifrada enviada a ${formatPin(targetPin)}. Esperando aceptación...`);
  } catch (err) {
    setGlobalStatus(`Error enviando invitación: ${(err as Error).message}`);
  } finally {
    btnSendInvite.disabled = false;
  }
}

async function respondInvite(
  requestId: string,
  senderPin: string,
  decision: 'accept' | 'reject',
): Promise<void> {
  if (!vault) return;
  try {
    let grantRaw: string | undefined;
    if (decision === 'accept') {
      setGlobalStatus(`Firmando KeyPackageGrant (121B) para ${formatPin(senderPin)}...`);
      grantRaw = await worker.buildKeyPackageGrant({
        targetPin: vault.pin,
        requesterPin: senderPin,
        signerDeviceId: vault.deviceId,
        skDevHex: vault.skDevHex,
        nowUnixSec: Math.floor(Date.now() / 1000),
      });
    }

    await api.authedJson(vault, `/v1/invites/${requestId}/respond`, 'POST', {
      decision,
      ...(grantRaw ? { grantRaw } : {}),
    });

    vault.incomingInvites = vault.incomingInvites.filter((i) => i.requestId !== requestId);
    await saveVault(vault);
    renderAll();

    setGlobalStatus(
      decision === 'accept'
        ? `Invitación de ${formatPin(senderPin)} aceptada. Esperando Welcome OpenMLS...`
        : `Invitación de ${formatPin(senderPin)} rechazada (cooldown 30 días).`,
    );
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    if (errMsg.includes('CONTACT_REQUEST_NOT_FOUND') || errMsg.includes('HTTP 404')) {
      if (vault) {
        vault.incomingInvites = vault.incomingInvites.filter((i) => i.requestId !== requestId);
        await saveVault(vault);
        renderAll();
      }
      setGlobalStatus('Esta solicitud ya fue procesada o expiró. Actualizando lista...');
      document.getElementById('btn-sync-now')?.click();
    } else {
      setGlobalStatus(`Error respondiendo invitación: ${(err as Error).message}`);
    }
  }
}

async function processGrantAndCreateGroup(targetPin: string, grantRawB64Url: string): Promise<void> {
  if (!vault) return;
  setGlobalStatus(`Canjeando KeyPackageGrant de ${formatPin(targetPin)}...`);
  const claimed = await api.signedDevicePost<{
    targetPin: string;
    keyPackages: Array<{ deviceId: string; kpRef: string; kpRaw: string }>;
  }>(vault, '/v1/keypackages/claim', { grantRaw: grantRawB64Url });

  if (!claimed.keyPackages.length) throw new Error('El contacto no tiene KeyPackages activos.');

  const allTargetKps: Array<{ deviceId: string; kpRef: string; kpRaw: string }> = [...claimed.keyPackages];
  try {
    const devList = await api.listDevices(vault);
    for (const ownDev of devList.devices) {
      if (!ownDev.isCurrent && ownDev.status === 'active') {
        try {
          const ownKp = await api.selfClaimKeyPackage(vault, ownDev.deviceId);
          allTargetKps.push({
            deviceId: ownDev.deviceId,
            kpRef: ownKp.kpRef,
            kpRaw: ownKp.kpRaw,
          });
        } catch {
          // Si otro dispositivo aún no subió KPs, podrá sincronizarse luego
        }
      }
    }
  } catch {
    // Continuar con los dispositivos del contacto
  }

  setGlobalStatus(`Creando grupo OpenMLS RFC 9420 (${allTargetKps.length} disp.) para ${formatPin(targetPin)}...`);
  const created = await worker.mlsCreateGroupAndAddMembers(
    JSON.stringify(allTargetKps.map((k) => k.kpRaw)),
  );
  vault.mlsStorageJson = created.storageJson;

  await api.authedJson(vault, '/v1/groups', 'POST', {
    groupId: created.groupIdB64,
    cipherSuite: created.cipherSuite,
  });

  const commitRes = await api.authedJson<{ confirmedCommitSeq: number; newEpoch: number }>(
    vault,
    `/v1/groups/${created.groupIdB64Url}/commits`,
    'POST',
    {
      expectedBaseEpoch: created.baseEpoch,
      clientMsgId: crypto.randomUUID(),
      commitRaw: created.commitRawB64,
      welcomeRaw: created.welcomeRawB64,
      addedDevices: allTargetKps.map((k) => k.deviceId),
      addedKpRefs: allTargetKps.map((k) => k.kpRef),
      removedDevices: [],
    },
  );

  const confirmed = await worker.mlsConfirmPendingCommit(created.groupIdB64);
  vault.mlsStorageJson = confirmed.storageJson;

  const grp: VaultGroup = {
    groupIdB64: created.groupIdB64,
    groupIdB64Url: created.groupIdB64Url,
    peerPin: targetPin,
    cipherSuite: created.cipherSuite,
    epoch: confirmed.epoch,
    active: true,
    lastSeq: commitRes.confirmedCommitSeq,
    messages: [],
  };

  vault.groups[grp.groupIdB64] = grp;
  activeGroupIdB64 = grp.groupIdB64;
  await saveVault(vault);
  renderAll();
  setGlobalStatus(`Chat OpenMLS RFC 9420 listo con ${formatPin(targetPin)} (época ${grp.epoch}).`);
}

// ============================================================================
// SYNC + ENVIAR MENSAJE + WEBSOCKET TIEMPO REAL
// ============================================================================

async function syncNow(): Promise<void> {
  if (!vault || syncInFlight) return;
  syncInFlight = true;
  try {
    const data = await api.authedJson<SyncResponse>(vault, '/v1/sync');
    let dirty = false;

    // 1. Invitaciones entrantes
    for (const cr of data.contactRequests) {
      if (vault.incomingInvites.some((i) => i.requestId === cr.requestId)) continue;
      let note = '';
      try {
        const opened = await worker.openInvite({
          skInviteHex: vault.skInviteHex,
          pkInviteHex: vault.pkInviteHex,
          myPin: vault.pin,
          ciphertextB64: cr.ciphertext,
        });
        note = opened.note;
      } catch {
        note = '(solicitud cifrada)';
      }
      vault.incomingInvites.push({
        requestId: cr.requestId,
        senderPin: cr.senderPin,
        note,
        createdAt: cr.createdAt,
      });
      dirty = true;
    }

    /* PIN_PRUNE_STALE_INVITES */
    const liveServerInviteIds = new Set(data.contactRequests.map((item) => item.requestId));
    const prevInvitesLen = vault.incomingInvites.length;
    vault.incomingInvites = vault.incomingInvites.filter((inv) => liveServerInviteIds.has(inv.requestId));
    if (vault.incomingInvites.length !== prevInvitesLen) {
      dirty = true;
    }

    // 2. Grants aceptados -> crear grupo OpenMLS
    for (const g of data.pendingGrants) {
      try {
        await processGrantAndCreateGroup(g.targetPin, g.grantRaw);
        dirty = true;
      } catch (err) {
        setGlobalStatus(`Aviso procesando grant de ${formatPin(g.targetPin)}: ${(err as Error).message}`);
      }
    }

    // 3. Welcomes OpenMLS recibidos
    const ackWelcomeIds: string[] = [];
    for (const w of data.welcomes) {
      const existingGrp = vault.groups[w.groupId];
      if (existingGrp && existingGrp.epoch >= w.targetEpoch) {
        ackWelcomeIds.push(w.welcomeBlobId);
        continue;
      }
      try {
        const joined = await worker.mlsJoinFromWelcome(w.welcomeRaw);
        vault.mlsStorageJson = joined.storageJson;

        if (!vault.groups[joined.groupIdB64]) {
          vault.groups[joined.groupIdB64] = {
            groupIdB64: joined.groupIdB64,
            groupIdB64Url: joined.groupIdB64Url,
            peerPin: joined.peerPin,
            cipherSuite: 3,
            epoch: joined.epoch,
            active: true,
            lastSeq: w.commitSeq,
            messages: [],
          };
          const joinedGrp = vault.groups[joined.groupIdB64];
          if (!activeGroupIdB64 && joinedGrp && !isSelfSyncGroup(joinedGrp, vault.pin)) {
            activeGroupIdB64 = joined.groupIdB64;
          }
        } else {
          const grp = vault.groups[joined.groupIdB64];
          grp.epoch = joined.epoch;
          grp.active = true;
          grp.lastSeq = Math.max(grp.lastSeq, w.commitSeq);
        }
        ackWelcomeIds.push(w.welcomeBlobId);
        dirty = true;
      } catch (err) {
        console.warn('Error abriendo Welcome OpenMLS:', err);
      }
    }

    // 4. Sobres MLS (Commits, Proposals y ApplicationMessages) ordenados por groupSeq ASC
    const sortedEnvelopes = [...data.envelopes].sort((a, b) => a.groupSeq - b.groupSeq);
    const groupAckMap = new Map<string, number>();

    for (const env of sortedEnvelopes) {
      const grp = vault.groups[env.groupId];
      if (!grp) continue;
      groupAckMap.set(env.groupId, Math.max(groupAckMap.get(env.groupId) ?? 0, env.groupSeq));

      // Crucial en OpenMLS (Forward Secrecy): jamás re-procesar un groupSeq ya aplicado
      if (env.groupSeq <= grp.lastSeq) continue;

      try {
        const outcome = await worker.mlsProcessEnvelope(grp.groupIdB64, env.ciphertext);
        vault.mlsStorageJson = outcome.storageJson;
        grp.epoch = outcome.epoch;
        grp.active = outcome.active;
        grp.lastSeq = Math.max(grp.lastSeq, env.groupSeq);
        dirty = true;

        if (outcome.kind === 'commit') {
          if (!isSelfSyncGroup(grp, vault.pin)) {
            setGlobalStatus(
            outcome.active
              ? `Grupo OpenMLS con ${formatPin(grp.peerPin)} avanzó a época ${outcome.epoch}.`
              : `Este dispositivo fue excluido del grupo con ${formatPin(grp.peerPin)}.`,
          );
          }
        } else if (outcome.kind === 'application' && outcome.plaintextJson) {
          if (!grp.messages.some((m) => m.groupSeq === env.groupSeq)) {
            const parsed = JSON.parse(outcome.plaintextJson) as { text: string; sentAtMs: number };
            if (outcome.senderPin === vault.pin && (await tryHandleIncomingAliasSync(grp, parsed.text))) {
              dirty = true;
              continue;
            }
            if (tryHandleIncomingMessageDelete(grp, outcome.senderPin, parsed.text)) {
              dirty = true;
              continue;
            }
            if (isVoiceCallSignalText(parsed.text)) {
              void voiceCallController.handleIncomingSignal({
                groupIdB64: grp.groupIdB64,
                peerPin: grp.peerPin,
                senderPin: outcome.senderPin,
                senderDeviceId: outcome.senderDeviceId,
                ownPin: vault.pin,
                ownDeviceId: vault.deviceId,
                sentAtMs: parsed.sentAtMs,
                rawText: parsed.text,
              });
              continue;
            }
            grp.messages.push({
              groupSeq: env.groupSeq,
              senderPin: outcome.senderPin,
              senderDeviceId: outcome.senderDeviceId,
              text: parsed.text,
              sentAtMs: parsed.sentAtMs,
              mine: outcome.senderPin === vault.pin,
            });
            grp.messages.sort((a, b) => a.groupSeq - b.groupSeq);
          }
        }
      } catch (err) {
        console.warn('Error procesando sobre OpenMLS:', err);
      }
    }

    if (dirty) {
      await saveVault(vault);
      renderAll();
    }

    if (ackWelcomeIds.length > 0 || groupAckMap.size > 0) {
      const groupCursors = Array.from(groupAckMap.entries()).map(([groupId, lastSeq]) => ({
        groupId,
        lastSeq,
      }));
      await api.authedJson(vault, '/v1/acks', 'POST', {
        welcomeBlobIds: ackWelcomeIds,
        groupCursors,
      });
    }

    if (data.kpRemaining < 5) {
      await api.replenishKeyPackages(vault, 15, false);
      await saveVault(vault);
    }

    void syncAliasesWithOwnDevicesIfNeeded();
    /* PIN_WEBPUSH_AUTOSYNC */ void ensureWebPushAutoSync();
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('DEVICE_REVOKED')) {
      await handleRevokedLocalDevice('Este dispositivo fue revocado por tu clave raíz.');
      return;
    }
    setGlobalStatus(`Error en sincronización: ${msg}`);
  } finally {
    syncInFlight = false;
  }
}

async function sendMessage(text: string): Promise<void> {
  if (!vault || !activeGroupIdB64) return;
  const grp = vault.groups[activeGroupIdB64];
  if (!grp) return;
  if (!grp.active) {
    setGlobalStatus('Este grupo ya no está activo en este dispositivo.');
    return;
  }

  const clean = text.trim();
  if (!clean) return;

  for (let retry = 0; retry < 2; retry += 1) {
    const sentAtMs = Date.now();
    const enc = await worker.mlsEncryptMessage(
      grp.groupIdB64,
      /* PIN-STEP2-STEP3-SEND-HOOK */(() => {
      const w = window as unknown as {
        __pinStep2?: { wrapOutgoingText?: (t: string) => string };
        __pinStep3?: { getPendingAttachment?: () => unknown };
      };
      const wrappedText = w.__pinStep2?.wrapOutgoingText ? w.__pinStep2.wrapOutgoingText(clean) : clean;
      const att = w.__pinStep3?.getPendingAttachment?.() ?? null;
      return JSON.stringify({
        text: wrappedText,
        sentAtMs,
        ...(att ? { attachment: att } : {}),
      });
    })(),
    );
    vault.mlsStorageJson = enc.storageJson;
    await saveVault(vault);

    const res = await api.authedFetch(vault, `/v1/groups/${grp.groupIdB64Url}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msgType: 'application',
        epoch: enc.epoch,
        clientMsgId: crypto.randomUUID(),
        ciphertext: enc.ciphertextB64,
      }),
    });

    if (res.status === 409 && retry === 0) {
      await syncNow();
      continue;
    }
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${txt.slice(0, 140)}`);
    }

    const resp = (await res.json()) as { groupSeq: number };
    grp.messages.push({
      groupSeq: resp.groupSeq,
      senderPin: vault.pin,
      senderDeviceId: vault.deviceId,
      text: clean,
      sentAtMs,
      mine: true,
    });
    /* PIN-STEP3-CLEAR-ATTACH */ (window as unknown as { __pinStep3?: { clearPendingAttachment?: () => void } }).__pinStep3?.clearPendingAttachment?.();
    grp.lastSeq = Math.max(grp.lastSeq, resp.groupSeq);
    await saveVault(vault);
    renderAll();
    return;
  }
}

async function connectWebSocket(): Promise<void> {
  if (!vault) return;
  if (wsReconnectTimer !== null) {
    window.clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    setWsStatus(false, 'Conectando...');
    const { ticket } = await api.authedJson<{ ticket: string }>(vault, '/v1/auth/ws-ticket', 'POST');
    const socket = new WebSocket(api.wsEndpointUrl(ticket));
    ws = socket;

    socket.onopen = () => {
      setWsStatus(true, 'En línea');
    };

    socket.onmessage = (ev) => {
      try {
        const frame = JSON.parse(String(ev.data)) as { type?: string };
        if (
          frame.type === 'hello' ||
          frame.type === 'contact_request' ||
          frame.type === 'keypackage_grant' ||
          frame.type === 'mls_welcome' ||
          frame.type === 'mls_event'
        ) {
          void syncNow();
        }
      } catch {
        // ignore malformed frame
      }
    };

    socket.onclose = async (ev) => {
      ws = null;
      if (ev.code === 4001) {
        await handleRevokedLocalDevice('Este dispositivo fue revocado por tu clave raíz (WS 4001).');
        return;
      }
      setWsStatus(false, 'Reconectando...');
      if (vault) {
        wsReconnectTimer = window.setTimeout(() => { void connectWebSocket(); }, 3000);
      }
    };
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('DEVICE_REVOKED')) {
      await handleRevokedLocalDevice('Este dispositivo fue revocado por tu clave raíz.');
      return;
    }
    setWsStatus(false, 'Sin conexión');
    setGlobalStatus(`WebSocket: ${msg}`);
    if (vault) {
      wsReconnectTimer = window.setTimeout(() => { void connectWebSocket(); }, 5000);
    }
  }
}

// ============================================================================
// SAFE BACKUP MODAL
// ============================================================================

function refreshSafeButtons(): void {
  const words = safeMnemonic.value.trim().split(/\s+/).filter(Boolean);
  safeWordCount.textContent = String(words.length);
  const ready = words.length === 12 && !safeBusy;
  btnSafeUpload.hidden = !safeAllowUpload;
  btnSafeUpload.disabled = !ready;
  btnSafeRestore.disabled = !ready;
}

function openSafeModal(allowUpload: boolean): void {
  safeAllowUpload = allowUpload;
  safeDialogTitle.textContent = allowUpload ? 'Safe Backup cifrado' : 'Restaurar cuenta (Safe Backup)';
  safeMnemonic.value = '';
  safeStatus.textContent = '';
  refreshSafeButtons();
  safeDialog.showModal();
}

safeMnemonic.addEventListener('input', refreshSafeButtons);
safeDialog.addEventListener('close', () => { safeMnemonic.value = ''; });

btnSafeUpload.addEventListener('click', async () => {
  if (!vault) return;
  const phrase = safeMnemonic.value;
  safeMnemonic.value = '';
  safeBusy = true;
  refreshSafeButtons();
  try {
    /* PIN_SAFE_UPLOAD_ALIASES */ await mergeLocalAliasesIntoVaultContacts(vault);
    const out = await api.uploadSafeBackup(vault, phrase, (m) => { safeStatus.textContent = m; });
    await saveVault(vault);
    const msg = `Safe Backup rev #${out.revision} guardado (${out.contactsCount} contactos).`;
    safeStatus.textContent = msg;
    setGlobalStatus(msg);
  } catch (err) {
    safeStatus.textContent = `Error: ${(err as Error).message}`;
  } finally {
    safeBusy = false;
    refreshSafeButtons();
  }
});

btnSafeRestore.addEventListener('click', async () => {
  const phrase = safeMnemonic.value;
  safeMnemonic.value = '';
  safeBusy = true;
  refreshSafeButtons();
  try {
    const summary = await api.downloadAndRestoreSafeBackup(phrase, vault, (m) => {
      safeStatus.textContent = m;
    });

    if (!vault) {
      const reg = await worker.deriveIdentityRegistration(phrase);
      vault = await api.enrollDeviceWithMnemonic(
        phrase,
        summary.restoredPin,
        reg.pkRootHex,
        reg.skInviteHex,
        reg.pkInviteHex,
        (m) => { safeStatus.textContent = m; },
      );
      vault.contacts = summary.mergedContacts;
      /* PIN_SAFE_RESTORE_ALIASES */ await hydrateLocalAliasesFromVaultContacts(vault);
      vault.safeBackupRevision = summary.restoredRevision;
      await saveVault(vault);
      safeDialog.close();
      showChatView();
      setGlobalStatus(`Cuenta ${formatPin(vault.pin)} restaurada en OpenMLS (rev #${summary.restoredRevision}).`);
      void connectWebSocket();
      void syncNow();
    } else {
      vault.contacts = summary.mergedContacts;
      /* PIN_SAFE_RESTORE_ALIASES */ await hydrateLocalAliasesFromVaultContacts(vault);
      vault.safeBackupRevision = Math.max(vault.safeBackupRevision, summary.restoredRevision);
      await saveVault(vault);
      const msg = `Fusionado rev #${summary.restoredRevision}: ${summary.contactsImported} nuevos, ${summary.contactsUpdated} actualizados.`;
      safeStatus.textContent = msg;
      setGlobalStatus(msg);
    }
  } catch (err) {
    safeStatus.textContent = `Error: ${(err as Error).message}`;
  } finally {
    safeBusy = false;
    refreshSafeButtons();
  }
});

// ============================================================================
// EVENTOS PRINCIPALES Y ARRANQUE (CON MIGRACIÓN AUTOMÁTICA v1 -> v2 OPENMLS)
// ============================================================================

btnCreatePin.addEventListener('click', () => { void createNewIdentity(); });
btnOnboardingLink.addEventListener('click', () => { void openSecondaryLinkModal(); });
btnOnboardingRestore.addEventListener('click', () => openSafeModal(false));
btnOpenDevices.addEventListener('click', () => { void openDevicesModal(); });
btnOpenSafe.addEventListener('click', () => openSafeModal(true));
btnSyncNow.addEventListener('click', () => { void syncNow(); });
btnDismissMnemonic.addEventListener('click', () => {
  mnemonicWordsText.textContent = '';
  mnemonicBanner.classList.add('hidden');
});

btnCopyPin.addEventListener('click', async () => {
  if (!vault) return;
  await navigator.clipboard.writeText(vault.pin).catch(() => {});
  setGlobalStatus(`PIN ${formatPin(vault.pin)} copiado al portapapeles.`);
});

btnWipeVault.addEventListener('click', async () => {
  if (!window.confirm('¿Seguro que deseas borrar la bóveda local de este navegador?')) return;
  ws?.close();
  ws = null;
  api.clearSession();
  await wipeVault();
  vault = null;
  activeGroupIdB64 = null;
  showOnboardingView();
  localStorage.removeItem(PIN_MANUAL_LOGOUT_KEY);
  if (btnResumeSession) btnResumeSession.hidden = true;
  onboardingStatus.textContent = 'Bóveda local borrada.';
});

/* === PIN_LOGOUT_AND_DELETE_CONTACT_START === */
btnLogoutSession?.addEventListener('click', () => {
  const ok = window.confirm('¿Salir de la sesión actual? Tu bóveda local y tus chats seguirán guardados en este dispositivo.');
  if (!ok) return;
  localStorage.setItem(PIN_MANUAL_LOGOUT_KEY, '1');
  ws?.close();
  ws = null;
  api.clearSession();
  vault = null;
  activeGroupIdB64 = null;
  if (btnResumeSession) btnResumeSession.hidden = false;
  showOnboardingView();
  onboardingStatus.textContent = 'Sesión cerrada. Tu bóveda local sigue intacta; pulsa "Reanudar sesión guardada" para volver a entrar.';
});

btnResumeSession?.addEventListener('click', () => {
  localStorage.removeItem(PIN_MANUAL_LOGOUT_KEY);
  window.location.reload();
});

function groupMatchesPin(grp: unknown, compactPin: string): boolean {
  if (!compactPin || !grp || typeof grp !== 'object') return false;
  const rec = grp as Record<string, unknown>;
  const safeCopy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rec)) {
    if (k === 'messages') continue;
    safeCopy[k] = v;
  }
  return JSON.stringify(safeCopy).toUpperCase().replace(/[^A-Z0-9]/g, '').includes(compactPin);
}

window.addEventListener('pin:delete-contact', (ev: Event) => {
  const detail = (ev as CustomEvent<{ pin?: string; groupIdB64?: string }>).detail ?? {};
  const rawPin = (detail.pin ?? '').trim().toUpperCase();
  const compactPin = rawPin.replace(/[^A-Z0-9]/g, '');
  const groupIdB64 = (detail.groupIdB64 ?? '').trim();

  void (async () => {
    const removedIds: string[] = [];
    const pinsToPurge = new Set<string>();
    if (rawPin) pinsToPurge.add(rawPin);
    if (vault) {
    for (const [gid, grp] of Object.entries(vault.groups)) {
      const matchId = Boolean(groupIdB64 && gid === groupIdB64);
      const matchPin = Boolean(compactPin && groupMatchesPin(grp, compactPin));
      if (matchId || matchPin) {
        const pinToArchive = rawPin || (typeof grp.peerPin === 'string' ? grp.peerPin : '');
        if (pinToArchive) pinsToPurge.add(pinToArchive.trim().toUpperCase());
        if (pinToArchive && Array.isArray(grp.messages)) {
          archiveMessagesForPin(pinToArchive, grp.messages);
        }
        delete vault.groups[gid];
        removedIds.push(gid);
      }
    }
      if (removedIds.length > 0) {
        if (activeGroupIdB64 && removedIds.includes(activeGroupIdB64)) {
          activeGroupIdB64 = null;
          chatActive.hidden = true;
          messagesList.innerHTML = '';
        }
        await saveVault(vault);
      }
    }

    // Purgar también todos los alias asociados (con/sin guion) y propagar la baja
    if (pinsToPurge.size > 0) {
      const w = window as unknown as { pinSetAlias?: (pin: string, alias: string) => Promise<void> };
      for (const p of pinsToPurge) {
        try {
          await w.pinSetAlias?.(p, '');
        } catch {
          // Ignorado si el contacto no tenía alias guardado
        }
      }
      const vAny = vault as unknown as { pinAliases?: Record<string, string> } | null;
      if (vAny?.pinAliases) {
        const canonical = rawPin.includes('-')
          ? rawPin
          : compactPin.length === 8
            ? `${compactPin.slice(0, 4)}-${compactPin.slice(4)}`
            : rawPin;
        delete vAny.pinAliases[rawPin];
        delete vAny.pinAliases[canonical];
        delete vAny.pinAliases[compactPin];
      }
    }

    renderAll();
    window.dispatchEvent(new CustomEvent('pin:contacts-updated'));
    setGlobalStatus(
      rawPin
        ? `Contacto ${rawPin} eliminado.`
        : 'Contacto eliminado.',
    );
  })();
});
/* === PIN_LOGOUT_AND_DELETE_CONTACT_END === */

formInvite.addEventListener('submit', (e) => {
  e.preventDefault();
  void sendInvite(inputInvitePin.value, inputInviteNote.value);
});

formSendMsg.addEventListener('submit', async (e) => {
  e.preventDefault();
  const txt = inputMsg.value;
  inputMsg.value = '';
  try {
    const payload = waAlerts.consumeReplyAndWrapText(txt);
    await sendMessage(payload);
  } catch (err) {
    setGlobalStatus(`Error enviando mensaje: ${(err as Error).message}`);
  }
});

async function bootstrap(): Promise<void> {
  const loaded = await loadVault();
  if (loaded && localStorage.getItem(PIN_MANUAL_LOGOUT_KEY) === '1') {
    if (btnResumeSession) btnResumeSession.hidden = false;
    showOnboardingView();
    onboardingStatus.textContent = 'Sesión cerrada manualmente. Tu bóveda local sigue guardada; pulsa "Reanudar sesión guardada" para volver a entrar.';
    return;
  }
  if (!loaded) {
    showOnboardingView();
    return;
  }

  vault = loaded;
  showChatView();

  // Migración limpia si existía una bóveda del Bloque 2A sin estado OpenMLS
  if (vault.vaultSchemaVersion !== 2 || !vault.mlsSigPkB64) {
    try {
      setGlobalStatus('Actualizando bóveda local al motor OpenMLS RFC 9420 (TreeKEM)...');
      const rtInit = await worker.mlsInitRuntime({
        storageJson: '',
        pin: vault.pin,
        deviceId: vault.deviceId,
        sigPkB64: '',
      });
      vault.vaultSchemaVersion = 2;
      vault.mlsSigPkB64 = rtInit.sigPkB64;
      vault.mlsStorageJson = rtInit.storageJson;
      vault.groups = {};
      await api.replenishKeyPackages(vault, 20, true);
      await saveVault(vault);
      renderAll();
      setGlobalStatus(
        `Motor OpenMLS RFC 9420 activado para PIN ${formatPin(vault.pin)}. Inicia nuevos chats TreeKEM.`,
      );
    } catch (err) {
      setGlobalStatus(`Error migrando a OpenMLS: ${(err as Error).message}`);
      return;
    }
  } else {
    try {
      const rtInit = await worker.mlsInitRuntime({
        storageJson: vault.mlsStorageJson,
        pin: vault.pin,
        deviceId: vault.deviceId,
        sigPkB64: vault.mlsSigPkB64,
      });
      vault.mlsStorageJson = rtInit.storageJson;
      setGlobalStatus('');
    } catch (err) {
      setGlobalStatus(`Error cargando estado OpenMLS local: ${(err as Error).message}`);
      return;
    }
  }

  void connectWebSocket();
  void syncNow();
}

void bootstrap();

// PIN-MLS STEP 1 HOOK
let __pinStep1Ctrl: Step1Controller | null = null;
void initStep1Enhancements({
  onAliasChanged: () => {
    __pinStep1Ctrl?.refreshSidebarBadges();
  },
}).then((ctrl) => {
  __pinStep1Ctrl = ctrl;
  (window as unknown as { __pinStep1?: Step1Controller }).__pinStep1 = ctrl;
  ctrl.refreshSidebarBadges();
});

// PIN-MLS STEP 2 HOOK
let __pinStep2Ctrl: Step2Controller | null = null;
void initStep2Enhancements().then((ctrl) => {
  __pinStep2Ctrl = ctrl;
  (window as unknown as { __pinStep2?: Step2Controller }).__pinStep2 = ctrl;
});

// PIN-MLS STEP 4 HOOK
let __pinStep4Ctrl: Step4Controller | null = null;
void initStep4GroupsAndPresence({
  onInvitePin: async (pin, note) => {
    if (typeof sendInvite === "function") {
      await sendInvite(pin, note);
    }
  },
}).then((ctrl) => {
  __pinStep4Ctrl = ctrl;
  (window as unknown as { __pinStep4?: Step4Controller }).__pinStep4 = ctrl;
});

(() => {
  const bootWa = () => {
    applyWhatsAppLayoutClasses();
    waAlerts.installIncomingDomWatcher();
    void waAlerts.requestNotificationPermissionIfNeeded();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootWa, { once: true });
  } else {
    bootWa();
  }
})();

let pinConsolidationRenderQueued = false;
window.addEventListener('pin:groups-consolidated', (ev: Event) => {
  const redirects = (ev as CustomEvent<{ redirects?: Record<string, string> }>).detail?.redirects;
  if (redirects && activeGroupIdB64 && redirects[activeGroupIdB64]) {
    activeGroupIdB64 = redirects[activeGroupIdB64] ?? activeGroupIdB64;
  }
  if (!pinConsolidationRenderQueued && vault) {
    pinConsolidationRenderQueued = true;
    queueMicrotask(() => {
      pinConsolidationRenderQueued = false;
      if (vault) renderAll();
    });
  }
});

/* === PIN_E2EE_ALIAS_SYNC_START === */
const PIN_ALIAS_SYNC_HASH_KEY = 'pin_mls_last_alias_sync_hash_v1';
let pinAliasSyncInFlight = false;

function normalizePinCompactSync(pin: string): string {
  return pin.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function isSelfSyncGroup(grp: VaultGroup | undefined, ownPin: string): boolean {
  if (!grp) return false;
  const peer = normalizePinCompactSync(grp.peerPin || '');
  const own = normalizePinCompactSync(ownPin || '');
  if (!peer) return true;
  return Boolean(own && peer === own);
}

function computeAliasSyncHash(aliases: Record<string, string>, siblingIds: string[]): string {
  const sortedAliases = Object.entries(aliases)
    .map(([k, v]) => [normalizePinCompactSync(k), v.trim()] as const)
    .filter(([k, v]) => k.length === 8 && v.length > 0)
    .sort((a, b) => a[0].localeCompare(b[0]));
  const sortedSiblings = [...siblingIds].sort();
  return JSON.stringify({ a: sortedAliases, s: sortedSiblings });
}

async function mergeLocalAliasesIntoVaultContacts(targetVault: VaultState): Promise<Record<string, string>> {
  const localAliases = await loadPinAliases();
  const now = Date.now();
  let changed = false;

  for (const [rawPin, rawAlias] of Object.entries(localAliases)) {
    const compactPin = normalizePinCompactSync(rawPin);
    const cleanAlias = rawAlias.trim();
    if (compactPin.length !== 8 || !cleanAlias) continue;

    const existing = targetVault.contacts.find(
      (c) => normalizePinCompactSync(c.pin) === compactPin,
    );
    if (existing) {
      if ((existing.alias_local ?? '').trim() !== cleanAlias) {
        existing.alias_local = cleanAlias;
        existing.updated_at = Math.max(existing.updated_at || 0, now);
        changed = true;
      }
    } else {
      targetVault.contacts.push({
        pin: compactPin,
        pk_root_b64: '',
        trust_state: 'tofu',
        alias_local: cleanAlias,
        updated_at: now,
      });
      changed = true;
    }
  }

  if (changed && vault && targetVault === vault) {
    await saveVault(targetVault);
  }
  return localAliases;
}

async function hydrateLocalAliasesFromVaultContacts(targetVault: VaultState): Promise<void> {
  const localAliases = await loadPinAliases();
  const toApply: Record<string, string> = {};
  let hasUpdates = false;

  for (const contact of targetVault.contacts) {
    const compactPin = normalizePinCompactSync(contact.pin);
    const contactAlias = (contact.alias_local ?? '').trim();
    if (compactPin.length !== 8 || !contactAlias) continue;

    const currentLocal = Object.entries(localAliases).find(
      ([k]) => normalizePinCompactSync(k) === compactPin,
    )?.[1];

    if (!currentLocal || currentLocal.trim() !== contactAlias) {
      toApply[compactPin] = contactAlias;
      hasUpdates = true;
    }
  }

  if (hasUpdates) {
    await applySyncedPinAliases(toApply, []);
  }
}

async function ensureSelfSyncGroup(
  activeSiblingIds: string[],
): Promise<VaultGroup | null> {
  if (!vault || activeSiblingIds.length === 0) return null;

  const existingSelfGroups = Object.values(vault.groups)
    .filter((g) => g.active && isSelfSyncGroup(g, vault!.pin))
    .sort((a, b) => (b.epoch - a.epoch) || (b.lastSeq - a.lastSeq));

  if (existingSelfGroups.length > 0 && existingSelfGroups[0]) {
    return existingSelfGroups[0];
  }

  const ownKps: Array<{ deviceId: string; kpRef: string; kpRaw: string }> = [];
  for (const siblingId of activeSiblingIds) {
    try {
      const kp = await api.selfClaimKeyPackage(vault, siblingId);
      ownKps.push({
        deviceId: siblingId,
        kpRef: kp.kpRef,
        kpRaw: kp.kpRaw,
      });
    } catch {
      // El dispositivo hermano aún no ha subido KeyPackages
    }
  }

  if (ownKps.length === 0) return null;

  const created = await worker.mlsCreateGroupAndAddMembers(
    JSON.stringify(ownKps.map((k) => k.kpRaw)),
  );
  vault.mlsStorageJson = created.storageJson;

  await api.authedJson(vault, '/v1/groups', 'POST', {
    groupId: created.groupIdB64,
    cipherSuite: created.cipherSuite,
  });

  const commitRes = await api.authedJson<{ confirmedCommitSeq: number; newEpoch: number }>(
    vault,
    `/v1/groups/${created.groupIdB64Url}/commits`,
    'POST',
    {
      expectedBaseEpoch: created.baseEpoch,
      clientMsgId: crypto.randomUUID(),
      commitRaw: created.commitRawB64,
      welcomeRaw: created.welcomeRawB64,
      addedDevices: ownKps.map((k) => k.deviceId),
      addedKpRefs: ownKps.map((k) => k.kpRef),
      removedDevices: [],
    },
  );

  const confirmed = await worker.mlsConfirmPendingCommit(created.groupIdB64);
  vault.mlsStorageJson = confirmed.storageJson;

  const selfGrp: VaultGroup = {
    groupIdB64: created.groupIdB64,
    groupIdB64Url: created.groupIdB64Url,
    peerPin: vault.pin,
    cipherSuite: created.cipherSuite,
    epoch: confirmed.epoch,
    active: true,
    lastSeq: commitRes.confirmedCommitSeq,
    messages: [],
  };

  vault.groups[selfGrp.groupIdB64] = selfGrp;
  await saveVault(vault);
  return selfGrp;
}

async function sendAliasSyncEnvelope(grp: VaultGroup, payloadJson: string): Promise<boolean> {
  if (!vault || !grp.active) return false;

  for (let retry = 0; retry < 2; retry += 1) {
    const sentAtMs = Date.now();
    const enc = await worker.mlsEncryptMessage(
      grp.groupIdB64,
      JSON.stringify({ text: payloadJson, sentAtMs }),
    );
    vault.mlsStorageJson = enc.storageJson;
    await saveVault(vault);

    const res = await api.authedFetch(vault, `/v1/groups/${grp.groupIdB64Url}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msgType: 'application',
        epoch: enc.epoch,
        clientMsgId: crypto.randomUUID(),
        ciphertext: enc.ciphertextB64,
      }),
    });

    if (res.status === 409 && retry === 0) {
      await syncNow();
      continue;
    }
    if (res.ok) {
      const body = (await res.json().catch(() => null)) as { groupSeq?: number } | null;
      if (body && typeof body.groupSeq === 'number') {
        grp.lastSeq = Math.max(grp.lastSeq, body.groupSeq);
        await saveVault(vault);
      }
      return true;
    }
    return false;
  }
  return false;
}

async function syncAliasesWithOwnDevicesIfNeeded(
  forceSend = false,
  removedPins: string[] = [],
): Promise<void> {
  if (!vault || pinAliasSyncInFlight) return;
  pinAliasSyncInFlight = true;

  try {
    await hydrateLocalAliasesFromVaultContacts(vault);
    const localAliases = await mergeLocalAliasesIntoVaultContacts(vault);

    const devList = await api.listDevices(vault);
    const activeSiblingIds = devList.devices
      .filter((d) => !d.isCurrent && d.status === 'active')
      .map((d) => d.deviceId);

    if (activeSiblingIds.length === 0) return;

    const cleanAliases: Record<string, string> = {};
    for (const [k, v] of Object.entries(localAliases)) {
      const compact = normalizePinCompactSync(k);
      const val = v.trim();
      if (compact.length === 8 && val) {
        cleanAliases[compact] = val;
      }
    }

    // Si este dispositivo no tiene alias todavía y no hubo edición manual, no crear grupo vacío
    if (!forceSend && Object.keys(cleanAliases).length === 0 && removedPins.length === 0) {
      return;
    }

    const nextHash = computeAliasSyncHash(cleanAliases, activeSiblingIds);
    const prevHash = localStorage.getItem(PIN_ALIAS_SYNC_HASH_KEY) ?? '';
    if (!forceSend && nextHash === prevHash) {
      return;
    }

    const selfGrp = await ensureSelfSyncGroup(activeSiblingIds);
    if (!selfGrp) return;

    const payload = JSON.stringify({
      __pin_alias_sync: 1,
      updatedAt: Date.now(),
      aliases: cleanAliases,
      ...(removedPins.length > 0 ? { removed: removedPins } : {}),
    });

    const sent = await sendAliasSyncEnvelope(selfGrp, payload);
    if (sent) {
      try {
        localStorage.setItem(PIN_ALIAS_SYNC_HASH_KEY, nextHash);
      } catch {
        // Ignorado
      }
    }
  } catch (err) {
    console.warn('Aviso sincronizando alias E2EE:', err);
  } finally {
    pinAliasSyncInFlight = false;
  }
}

async function tryHandleIncomingAliasSync(grp: VaultGroup, rawText: string): Promise<boolean> {
  if (!vault || !rawText || !rawText.includes('"__pin_alias_sync"')) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  const rec = parsed as Record<string, unknown>;
  if (rec['__pin_alias_sync'] !== 1) return false;

  // Etiquetar definitivamente este grupo como canal oculto entre dispositivos propios
  grp.peerPin = vault.pin;
  if (activeGroupIdB64 === grp.groupIdB64) {
    activeGroupIdB64 = null;
  }

  const incomingUpdatedAt =
    typeof rec['updatedAt'] === 'number' && Number.isFinite(rec['updatedAt'])
      ? rec['updatedAt']
      : Date.now();

  const rawAliases =
    rec['aliases'] && typeof rec['aliases'] === 'object' && !Array.isArray(rec['aliases'])
      ? (rec['aliases'] as Record<string, unknown>)
      : {};
  const rawRemoved = Array.isArray(rec['removed'])
    ? rec['removed'].filter((x): x is string => typeof x === 'string')
    : [];

  const updatesToApply: Record<string, string> = {};
  const removalsToApply: string[] = [];

  for (const [rawPin, rawVal] of Object.entries(rawAliases)) {
    if (typeof rawVal !== 'string') continue;
    const compactPin = normalizePinCompactSync(rawPin);
    const cleanAlias = rawVal.trim();
    if (compactPin.length !== 8 || !cleanAlias) continue;

    const existing = vault.contacts.find((c) => normalizePinCompactSync(c.pin) === compactPin);
    if (existing) {
      if (!existing.alias_local || incomingUpdatedAt >= (existing.updated_at || 0)) {
        existing.alias_local = cleanAlias;
        existing.updated_at = incomingUpdatedAt;
        updatesToApply[compactPin] = cleanAlias;
      }
    } else {
      vault.contacts.push({
        pin: compactPin,
        pk_root_b64: '',
        trust_state: 'tofu',
        alias_local: cleanAlias,
        updated_at: incomingUpdatedAt,
      });
      updatesToApply[compactPin] = cleanAlias;
    }
  }

  for (const rawPin of rawRemoved) {
    const compactPin = normalizePinCompactSync(rawPin);
    if (compactPin.length !== 8) continue;
    const existing = vault.contacts.find((c) => normalizePinCompactSync(c.pin) === compactPin);
    if (!existing || incomingUpdatedAt >= (existing.updated_at || 0)) {
      if (existing) {
        existing.alias_local = null;
        existing.updated_at = incomingUpdatedAt;
      }
      removalsToApply.push(compactPin);
    }
  }

  const mergedAliases = await applySyncedPinAliases(updatesToApply, removalsToApply);

  try {
    const devList = await api.listDevices(vault);
    const activeSiblingIds = devList.devices
      .filter((d) => !d.isCurrent && d.status === 'active')
      .map((d) => d.deviceId);
    localStorage.setItem(
      PIN_ALIAS_SYNC_HASH_KEY,
      computeAliasSyncHash(mergedAliases, activeSiblingIds),
    );
  } catch {
    // Ignorado
  }

  return true;
}

window.addEventListener('pin:aliases-updated', (ev: Event) => {
  const detail = (
    ev as CustomEvent<{
      aliases?: Record<string, string>;
      source?: string;
      changedPin?: string;
      changedAlias?: string;
    }>
  ).detail;

  if (!vault || !detail || detail.source !== 'local') return;

  const changedPin = detail.changedPin ? normalizePinCompactSync(detail.changedPin) : '';
  const changedAlias = (detail.changedAlias ?? '').trim();
  const removedPins: string[] = [];

  if (changedPin.length === 8) {
    const existing = vault.contacts.find((c) => normalizePinCompactSync(c.pin) === changedPin);
    const now = Date.now();
    if (!changedAlias) {
      removedPins.push(changedPin);
      if (existing) {
        existing.alias_local = null;
        existing.updated_at = now;
      }
    } else if (existing) {
      existing.alias_local = changedAlias;
      existing.updated_at = now;
    } else {
      vault.contacts.push({
        pin: changedPin,
        pk_root_b64: '',
        trust_state: 'tofu',
        alias_local: changedAlias,
        updated_at: now,
      });
    }
    void saveVault(vault);
  }

  void syncAliasesWithOwnDevicesIfNeeded(true, removedPins);
});
/* === PIN_E2EE_ALIAS_SYNC_END === */

/* === PIN_WEBPUSH_CLIENT_START === */
let pinWebPushSyncedThisSession = false;

void registerAppServiceWorker();

async function ensureWebPushAutoSync(): Promise<void> {
  if (!vault || pinWebPushSyncedThisSession) return;
  if (typeof window === 'undefined' || !('Notification' in window)) return;
  if (Notification.permission !== 'granted') return;
  pinWebPushSyncedThisSession = true;
  const res = await ensureWebPushSubscribed(api, vault, false);
  if (!res.subscribed) {
    pinWebPushSyncedThisSession = false;
  }
}

window.addEventListener('pin:notif-toggle', (ev: Event) => {
  const enabled = Boolean((ev as CustomEvent<{ enabled?: boolean }>).detail?.enabled);
  waAlerts.setPreferences({ desktopNotifEnabled: enabled });
  if (!vault) return;

  if (enabled) {
    void (async () => {
      const res = await ensureWebPushSubscribed(api, vault!, true);
      if (res.subscribed) {
        pinWebPushSyncedThisSession = true;
        setGlobalStatus('Notificaciones Push activadas en este dispositivo (incluso con app cerrada).');
      } else if (res.reason) {
        setGlobalStatus(res.reason);
      }
    })();
  } else {
    pinWebPushSyncedThisSession = false;
    void unsubscribeWebPush(api, vault).then(() => {
      setGlobalStatus('Notificaciones desactivadas en este dispositivo.');
    });
  }
});

window.addEventListener('pin:sw-wake-sync', () => {
  if (vault) {
    void syncNow();
  }
});

window.addEventListener('pin:sw-open-group', (ev: Event) => {
  const gid = (ev as CustomEvent<{ groupIdB64?: string }>).detail?.groupIdB64 ?? '';
  if (vault && gid && vault.groups[gid]) {
    activeGroupIdB64 = gid;
    renderAll();
  }
  if (vault) {
    void syncNow();
  }
});

document.addEventListener(
  'click',
  (ev) => {
    const target = ev.target instanceof HTMLElement ? ev.target : null;
    if (vault && target?.closest('#btn-logout-session, #btn-wipe-vault')) {
      pinWebPushSyncedThisSession = false;
      void unsubscribeWebPush(api, vault);
    }
  },
  true,
);
/* === PIN_WEBPUSH_CLIENT_END === */

/* === PIN_VOICE_CALL_CLIENT_START === */
const voiceCallController = new VoiceCallController({
  getActiveChat: () => {
    if (!vault || !activeGroupIdB64) return null;
    const grp = vault.groups[activeGroupIdB64];
    if (!grp || isSelfSyncGroup(grp, vault.pin)) return null;
    const formatted = formatPin(grp.peerPin);
    const alias = waAlerts.getAliasForPin(formatted);
    return {
      groupIdB64: grp.groupIdB64,
      peerPin: grp.peerPin,
      displayName: alias ? `${alias} (${formatted})` : formatted,
      active: grp.active,
    };
  },
  getDisplayNameForPin: (peerPin: string) => {
    const formatted = formatPin(peerPin);
    const alias = waAlerts.getAliasForPin(formatted);
    return alias ? `${alias} (${formatted})` : formatted;
  },
  sendEncryptedSignal: async (groupIdB64: string, signalJson: string) => {
    if (!vault) return false;
    const grp = vault.groups[groupIdB64];
    if (!grp || !grp.active) return false;
    return sendAliasSyncEnvelope(grp, signalJson);
  },
  onStatus: (msg: string) => {
    setGlobalStatus(msg);
  },
});
/* === PIN_VOICE_CALL_CLIENT_END === */

/* === PIN_VOICE_SEND_LISTENER_START === */
window.addEventListener('pin:send-raw-payload', (ev: Event) => {
  const payload = (ev as CustomEvent<{ payload?: string }>).detail?.payload;
  if (typeof payload !== 'string' || !payload.trim()) return;
  if (!vault || !activeGroupIdB64) {
    setGlobalStatus('Abre una conversación activa para enviar la nota de voz.');
    return;
  }
  if (payload.length > 480_000) {
    setGlobalStatus('El archivo o nota de voz supera el límite de 512 KB cifrados.');
    return;
  }
  void (async () => {
    try {
      setGlobalStatus('Enviando archivo/audio cifrado…');
      await sendMessage(payload);
    } catch (err) {
      setGlobalStatus(`Error enviando archivo/audio: ${(err as Error).message}`);
    }
  })();
});
/* === PIN_VOICE_SEND_LISTENER_END === */

/* === PIN_MEDIA_BRIDGE_START === */
setMediaAuthProvider(() => {
  if (!vault) return null;
  return {
    authedFetch: (v, path, init) => api.authedFetch(v, path, init),
    vault,
    activeGroupIdB64,
  };
});
/* === PIN_MEDIA_BRIDGE_END === */

/* === PIN_DELETE_MESSAGE_START === */
function tryHandleIncomingMessageDelete(grp: VaultGroup, senderPin: string, rawText: string): boolean {
  const trimmed = rawText.trim();
  if (!trimmed.startsWith('{') || !trimmed.includes('__pin_msg_delete')) return false;
  try {
    const obj = JSON.parse(trimmed) as { __pin_msg_delete?: unknown; targetSeq?: unknown };
    if (obj.__pin_msg_delete !== 1 || typeof obj.targetSeq !== 'number' || !Number.isInteger(obj.targetSeq)) {
      return false;
    }
    const targetSeq = obj.targetSeq;
    const normSender = senderPin.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const isOwnSender = Boolean(vault && vault.pin.replace(/[^A-Z0-9]/gi, '').toUpperCase() === normSender);
    markSeqDeletedForPin(grp.peerPin, senderPin, targetSeq, isOwnSender);
    grp.messages = grp.messages.filter((m) => {
      if (m.groupSeq !== targetSeq) return true;
      const msgSender = m.senderPin.replace(/[^A-Z0-9]/gi, '').toUpperCase();
      return msgSender !== normSender;
    });
    return true;
  } catch {
    return false;
  }
}

async function sendMessageDeleteControl(grp: VaultGroup, targetSeq: number): Promise<void> {
  if (!vault || !grp.active) return;
  const controlText = JSON.stringify({
    __pin_msg_delete: 1,
    targetSeq,
  });

  for (let retry = 0; retry < 2; retry += 1) {
    const sentAtMs = Date.now();
    const enc = await worker.mlsEncryptMessage(
      grp.groupIdB64,
      JSON.stringify({
        text: controlText,
        sentAtMs,
      }),
    );
    vault.mlsStorageJson = enc.storageJson;
    await saveVault(vault);

    const res = await api.authedFetch(vault, `/v1/groups/${grp.groupIdB64Url}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msgType: 'application',
        epoch: enc.epoch,
        clientMsgId: crypto.randomUUID(),
        ciphertext: enc.ciphertextB64,
      }),
    });

    if (res.status === 409 && retry === 0) {
      await syncNow();
      continue;
    }
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${txt.slice(0, 120)}`);
    }

    const resp = (await res.json()) as { groupSeq: number };
    grp.lastSeq = Math.max(grp.lastSeq, resp.groupSeq);
    await saveVault(vault);
    return;
  }
}

window.addEventListener('pin:delete-message', (ev: Event) => {
  const detail = (
    ev as CustomEvent<{
      groupIdB64?: string;
      groupSeq?: number;
      sentAtMs?: number;
      scope?: 'me' | 'everyone';
    }>
  ).detail;
  if (!detail || typeof detail.groupSeq !== 'number' || !Number.isInteger(detail.groupSeq)) return;
  if (!vault) return;

  const gid = detail.groupIdB64 || activeGroupIdB64;
  if (!gid) return;
  const grp = vault.groups[gid];
  if (!grp) return;

  const targetSeq = detail.groupSeq;
  const targetTs =
    typeof detail.sentAtMs === 'number' && Number.isFinite(detail.sentAtMs) && detail.sentAtMs > 0
      ? detail.sentAtMs
      : null;
  const scope = detail.scope === 'everyone' ? 'everyone' : 'me';

  void (async () => {
    try {
      const targetMsg =
        (targetTs !== null
          ? grp.messages.find((m) => m.groupSeq === targetSeq && m.sentAtMs === targetTs)
          : undefined) ?? grp.messages.find((m) => m.groupSeq === targetSeq);
      if (!targetMsg) {
        setGlobalStatus('No se encontró ese mensaje en el historial local.');
        return;
      }

      if (scope === 'everyone' && !targetMsg.mine) {
        setGlobalStatus('Solo puedes eliminar para todos tus propios mensajes.');
        return;
      }

      if (scope === 'everyone') {
        if (!grp.active) {
          setGlobalStatus('El chat no está activo para eliminar el mensaje en el otro dispositivo.');
          return;
        }
        setGlobalStatus('Eliminando mensaje para todos…');
        await sendMessageDeleteControl(grp, targetSeq);
      }

      // Registrar tombstone y purgar el respaldo en localStorage ANTES de saveVault()
      markMessageDeletedForPin(
        grp.peerPin,
        targetMsg as unknown as Record<string, unknown>,
        scope === 'everyone',
      );
      if (scope === 'everyone') {
        markSeqDeletedForPin(grp.peerPin, targetMsg.senderPin, targetSeq, true);
      }

      grp.messages = grp.messages.filter((m) => {
        if (m === targetMsg) return false;
        if (targetTs !== null && m.groupSeq === targetSeq && m.sentAtMs === targetTs) return false;
        if (scope === 'everyone' && m.groupSeq === targetSeq && m.mine) return false;
        return true;
      });

      await saveVault(vault);
      renderAll();
      setGlobalStatus(
        scope === 'everyone'
          ? 'Mensaje eliminado para todos.'
          : 'Mensaje eliminado de este dispositivo.',
      );
    } catch (err) {
      setGlobalStatus(`Error eliminando mensaje: ${(err as Error).message}`);
    }
  })();
});
/* === PIN_DELETE_MESSAGE_END === */

installAndroidNativeBridge();

installPwaInstallButton();
