export interface QuotedRef {
  id: string;
  sender: string;
  snippet: string;
}

export type PinEnvelopeV2 =
  | {
      __pin_v: 2;
      kind: 'chat';
      id: string;
      text: string;
      replyTo?: QuotedRef;
    }
  | {
      __pin_v: 2;
      kind: 'react';
      targetId: string;
      emoji: string;
    }
  | {
      __pin_v: 2;
      kind: 'edit';
      targetId: string;
      newText: string;
    }
  | {
      __pin_v: 2;
      kind: 'delete';
      targetId: string;
    }
  | {
      __pin_v: 2;
      kind: 'typing';
      isTyping: boolean;
    };

export interface Step2Controller {
  wrapOutgoingText: (plainText: string) => string;
  unwrapIncomingPayload: (rawPayload: string, senderPin?: string) => {
    renderText: string | null;
    envelope: PinEnvelopeV2 | null;
  };
  setReplyTarget: (ref: QuotedRef | null) => void;
  getReplyTarget: () => QuotedRef | null;
  showPeerTyping: (senderLabel: string, isTyping: boolean) => void;
  attachBubbleActions: () => void;
}

const QUICK_REACTIONS = ['👍', '❤️', '😂', '🔥', '👀'];

export function generateMsgId(): string {
  return `m_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

export async function initStep2Enhancements(options?: {
  onSendControlEnvelope?: (serializedPayload: string) => Promise<void> | void;
}): Promise<Step2Controller> {
  let activeReply: QuotedRef | null = null;
  const reactionsByMsg = new Map<string, Map<string, number>>();
  const editedTextByMsg = new Map<string, string>();
  const deletedMsgs = new Set<string>();
  let typingHideTimer: number | null = null;
  let lastTypingSentAt = 0;

  // Banner flotante de cita activa + indicador "escribiendo..."
  const existingBar = document.getElementById('pin-step2-composer-bar');
  if (existingBar) existingBar.remove();

  const composerBar = document.createElement('div');
  composerBar.id = 'pin-step2-composer-bar';
  composerBar.className = 'pin-step2-bar';
  composerBar.innerHTML = `
    <div id="pin-typing-indicator" class="pin-typing-indicator hidden"></div>
    <div id="pin-reply-preview" class="pin-reply-preview hidden">
      <div class="pin-reply-content">
        <span class="pin-reply-author" id="pin-reply-author"></span>
        <span class="pin-reply-snippet" id="pin-reply-snippet"></span>
      </div>
      <button type="button" id="pin-reply-cancel" class="pin-btn-icon" title="Cancelar respuesta">✕</button>
    </div>
  `;

  const msgInput =
    document.querySelector<HTMLInputElement | HTMLTextAreaElement>(
      '#msg-input, #message-input, input[placeholder*="mensaje" i], textarea[placeholder*="mensaje" i]',
    );

  if (msgInput && msgInput.parentElement) {
    msgInput.parentElement.prepend(composerBar);
  } else {
    (document.getElementById('app') ?? document.body).append(composerBar);
  }

  const typingEl = composerBar.querySelector('#pin-typing-indicator') as HTMLElement;
  const replyPreviewEl = composerBar.querySelector('#pin-reply-preview') as HTMLElement;
  const replyAuthorEl = composerBar.querySelector('#pin-reply-author') as HTMLElement;
  const replySnippetEl = composerBar.querySelector('#pin-reply-snippet') as HTMLElement;
  const replyCancelBtn = composerBar.querySelector('#pin-reply-cancel') as HTMLButtonElement;

  const setReplyTarget = (ref: QuotedRef | null): void => {
    activeReply = ref;
    if (!ref) {
      replyPreviewEl.classList.add('hidden');
      replyAuthorEl.textContent = '';
      replySnippetEl.textContent = '';
      return;
    }
    replyAuthorEl.textContent = `Respondiendo a ${ref.sender}`;
    replySnippetEl.textContent = ref.snippet.slice(0, 90);
    replyPreviewEl.classList.remove('hidden');
    msgInput?.focus();
  };

  replyCancelBtn.addEventListener('click', () => setReplyTarget(null));

  const showPeerTyping = (senderLabel: string, isTyping: boolean): void => {
    if (typingHideTimer !== null) {
      window.clearTimeout(typingHideTimer);
      typingHideTimer = null;
    }
    if (!isTyping) {
      typingEl.classList.add('hidden');
      typingEl.textContent = '';
      return;
    }
    typingEl.textContent = `${senderLabel} está escribiendo...`;
    typingEl.classList.remove('hidden');
    typingHideTimer = window.setTimeout(() => {
      typingEl.classList.add('hidden');
      typingEl.textContent = '';
    }, 3500);
  };

  // Emitir evento efímero de "escribiendo..." con throttle de 2.5s
  if (msgInput && options?.onSendControlEnvelope) {
    msgInput.addEventListener('input', () => {
      const now = Date.now();
      if (now - lastTypingSentAt < 2500) return;
      lastTypingSentAt = now;
      const env: PinEnvelopeV2 = { __pin_v: 2, kind: 'typing', isTyping: true };
      void options.onSendControlEnvelope?.(JSON.stringify(env));
    });
  }

  const wrapOutgoingText = (plainText: string): string => {
    const trimmed = plainText.trim();
    if (!trimmed) return plainText;
    // Si ya es un sobre JSON v2, devolver tal cual
    if (trimmed.startsWith('{"__pin_v":2')) return trimmed;

    const env: PinEnvelopeV2 = {
      __pin_v: 2,
      kind: 'chat',
      id: generateMsgId(),
      text: plainText,
      ...(activeReply ? { replyTo: activeReply } : {}),
    };
    setReplyTarget(null);
    return JSON.stringify(env);
  };

  const applyReactionsDom = (msgId: string): void => {
    const bubble = document.querySelector<HTMLElement>(`[data-msg-id="${CSS.escape(msgId)}"]`);
    if (!bubble) return;
    const counts = reactionsByMsg.get(msgId);
    let tray = bubble.querySelector<HTMLElement>('.pin-reactions-tray');
    if (!counts || counts.size === 0) {
      tray?.remove();
      return;
    }
    if (!tray) {
      tray = document.createElement('div');
      tray.className = 'pin-reactions-tray';
      bubble.appendChild(tray);
    }
    tray.innerHTML = [...counts.entries()]
      .filter(([, c]) => c > 0)
      .map(([emoji, count]) => `<span class="pin-reaction-chip">${emoji} ${count}</span>`)
      .join('');
  };

  const applyEditOrDeleteDom = (msgId: string): void => {
    const bubble = document.querySelector<HTMLElement>(`[data-msg-id="${CSS.escape(msgId)}"]`);
    if (!bubble) return;
    const textNode = bubble.querySelector<HTMLElement>('.msg-text, .bubble-text, p') ?? bubble;
    if (deletedMsgs.has(msgId)) {
      textNode.textContent = '🚫 Mensaje eliminado';
      bubble.classList.add('pin-msg-deleted');
      return;
    }
    const edited = editedTextByMsg.get(msgId);
    if (edited !== undefined) {
      textNode.textContent = `${edited} (editado)`;
    }
  };

  const unwrapIncomingPayload = (
    rawPayload: string,
    senderPin = 'Contacto',
  ): { renderText: string | null; envelope: PinEnvelopeV2 | null } => {
    const trimmed = rawPayload.trim();
    if (!trimmed.startsWith('{') || !trimmed.includes('"__pin_v":2')) {
      return { renderText: rawPayload, envelope: null };
    }
    try {
      const parsed = JSON.parse(trimmed) as PinEnvelopeV2;
      if (parsed.__pin_v !== 2) return { renderText: rawPayload, envelope: null };

      if (parsed.kind === 'typing') {
        showPeerTyping(senderPin, parsed.isTyping);
        return { renderText: null, envelope: parsed };
      }

      if (parsed.kind === 'react') {
        const map = reactionsByMsg.get(parsed.targetId) ?? new Map<string, number>();
        map.set(parsed.emoji, (map.get(parsed.emoji) ?? 0) + 1);
        reactionsByMsg.set(parsed.targetId, map);
        applyReactionsDom(parsed.targetId);
        return { renderText: null, envelope: parsed };
      }

      if (parsed.kind === 'edit') {
        editedTextByMsg.set(parsed.targetId, parsed.newText);
        applyEditOrDeleteDom(parsed.targetId);
        return { renderText: null, envelope: parsed };
      }

      if (parsed.kind === 'delete') {
        deletedMsgs.add(parsed.targetId);
        applyEditOrDeleteDom(parsed.targetId);
        return { renderText: null, envelope: parsed };
      }

      if (parsed.kind === 'chat') {
        showPeerTyping(senderPin, false);
        const prefix = parsed.replyTo
          ? `↪ [${parsed.replyTo.sender}: "${parsed.replyTo.snippet.slice(0, 50)}"]\n`
          : '';
        return { renderText: `${prefix}${parsed.text}`, envelope: parsed };
      }
    } catch {
      // Fallback a texto plano si no es JSON válido
    }
    return { renderText: rawPayload, envelope: null };
  };

  const attachBubbleActions = (): void => {
    const bubbles = document.querySelectorAll<HTMLElement>(
      '.message-item, .msg-item, .bubble, [data-message]',
    );
    bubbles.forEach((bubble, idx) => {
      if (bubble.dataset.step2Bound === '1') return;
      bubble.dataset.step2Bound = '1';
      if (!bubble.dataset.msgId) {
        bubble.dataset.msgId = `dom_msg_${idx}_${(bubble.textContent ?? '').slice(0, 12).replace(/\s+/g, '_')}`;
      }
      const msgId = bubble.dataset.msgId;

      const actions = document.createElement('div');
      actions.className = 'pin-bubble-actions';

      const replyBtn = document.createElement('button');
      replyBtn.type = 'button';
      replyBtn.className = 'pin-mini-btn';
      replyBtn.title = 'Citar mensaje';
      replyBtn.textContent = '↩';
      replyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const raw = (bubble.textContent ?? '').replace(/[↩👍❤️😂🔥👀✏️🗑️]/g, '').trim();
        setReplyTarget({
          id: msgId,
          sender: bubble.classList.contains('mine') || bubble.classList.contains('outgoing') ? 'Tú' : 'Contacto',
          snippet: raw || 'Mensaje',
        });
      });
      actions.appendChild(replyBtn);

      for (const emoji of QUICK_REACTIONS) {
        const rBtn = document.createElement('button');
        rBtn.type = 'button';
        rBtn.className = 'pin-mini-btn';
        rBtn.textContent = emoji;
        rBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const map = reactionsByMsg.get(msgId) ?? new Map<string, number>();
          map.set(emoji, (map.get(emoji) ?? 0) + 1);
          reactionsByMsg.set(msgId, map);
          applyReactionsDom(msgId);
          if (options?.onSendControlEnvelope) {
            const env: PinEnvelopeV2 = { __pin_v: 2, kind: 'react', targetId: msgId, emoji };
            void options.onSendControlEnvelope(JSON.stringify(env));
          }
        });
        actions.appendChild(rBtn);
      }

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'pin-mini-btn';
      editBtn.title = 'Editar mensaje';
      editBtn.textContent = '✏️';
      editBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const current = (bubble.textContent ?? '').replace(/[↩👍❤️😂🔥👀✏️🗑️]/g, '').trim();
        const next = window.prompt('Editar texto del mensaje:', current);
        if (!next || !next.trim()) return;
        editedTextByMsg.set(msgId, next.trim());
        applyEditOrDeleteDom(msgId);
        if (options?.onSendControlEnvelope) {
          const env: PinEnvelopeV2 = { __pin_v: 2, kind: 'edit', targetId: msgId, newText: next.trim() };
          void options.onSendControlEnvelope(JSON.stringify(env));
        }
      });
      actions.appendChild(editBtn);

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'pin-mini-btn';
      delBtn.title = 'Eliminar mensaje';
      delBtn.textContent = '🗑️';
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        deletedMsgs.add(msgId);
        applyEditOrDeleteDom(msgId);
        if (options?.onSendControlEnvelope) {
          const env: PinEnvelopeV2 = { __pin_v: 2, kind: 'delete', targetId: msgId };
          void options.onSendControlEnvelope(JSON.stringify(env));
        }
      });
      actions.appendChild(delBtn);

      bubble.appendChild(actions);
    });
  };

  // Observador automático para decorar burbujas nuevas al renderizarse
  const observer = new MutationObserver(() => {
    attachBubbleActions();
  });
  observer.observe(document.body, { childList: true, subtree: true });
  attachBubbleActions();

  return {
    wrapOutgoingText,
    unwrapIncomingPayload,
    setReplyTarget,
    getReplyTarget: () => activeReply,
    showPeerTyping,
    attachBubbleActions,
  };
}
