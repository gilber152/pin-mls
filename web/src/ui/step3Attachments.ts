export interface EncryptedAttachmentPayload {
  name: string;
  mimeType: string;
  sizeBytes: number;
  kind: 'image' | 'audio' | 'file';
  dataUrl: string;
}

export interface Step3Controller {
  getPendingAttachment: () => EncryptedAttachmentPayload | null;
  clearPendingAttachment: () => void;
  renderAttachmentHtml: (att?: EncryptedAttachmentPayload) => string;
}

const MAX_RAW_BYTES = 1_500_000; // ~1.5 MB originales para mantener JSON cifrado cómodo bajo 7 MiB

function classifyMime(mime: string, fileName: string): 'image' | 'audio' | 'file' {
  const m = mime.toLowerCase();
  const n = fileName.toLowerCase();
  if (m.startsWith('image/') || /\.(png|jpe?g|webp|gif)$/i.test(n)) return 'image';
  if (m.startsWith('audio/') || /\.(webm|ogg|mp3|m4a|wav)$/i.test(n)) return 'audio';
  return 'file';
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('Error leyendo archivo'));
    reader.readAsDataURL(file);
  });
}

function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

export async function initStep3Attachments(): Promise<Step3Controller> {
  let pending: EncryptedAttachmentPayload | null = null;
  let mediaRecorder: MediaRecorder | null = null;
  let audioChunks: BlobPart[] = [];

  const existingBar = document.getElementById('pin-step3-bar');
  if (existingBar) existingBar.remove();

  const bar = document.createElement('div');
  bar.id = 'pin-step3-bar';
  bar.className = 'pin-step3-bar';
  bar.innerHTML = `
    <input type="file" id="pin-attach-file-input" class="pin-hidden-input" accept="image/*,audio/*,.pdf,.txt,.csv,.json,.zip,.doc,.docx" />
    <button type="button" id="pin-btn-pick-file" class="pin-btn-secondary" title="Adjuntar imagen o documento cifrado">
      📎 Adjunto
    </button>
    <button type="button" id="pin-btn-record-voice" class="pin-btn-secondary" title="Grabar nota de voz cifrada">
      🎤 Nota voz
    </button>
    <span id="pin-attach-preview" class="pin-attach-preview hidden"></span>
    <button type="button" id="pin-btn-clear-attach" class="pin-btn-icon hidden" title="Quitar adjunto">✕</button>
  `;

  const msgInput = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(
    '#msg-input, #message-input, input[placeholder*="mensaje" i], textarea[placeholder*="mensaje" i]',
  );
  if (msgInput && msgInput.parentElement) {
    msgInput.parentElement.prepend(bar);
  } else {
    (document.getElementById('app') ?? document.body).append(bar);
  }

  const fileInput = bar.querySelector('#pin-attach-file-input') as HTMLInputElement;
  const pickBtn = bar.querySelector('#pin-btn-pick-file') as HTMLButtonElement;
  const voiceBtn = bar.querySelector('#pin-btn-record-voice') as HTMLButtonElement;
  const previewEl = bar.querySelector('#pin-attach-preview') as HTMLElement;
  const clearBtn = bar.querySelector('#pin-btn-clear-attach') as HTMLButtonElement;

  const syncPreviewUi = (): void => {
    if (!pending) {
      previewEl.textContent = '';
      previewEl.classList.add('hidden');
      clearBtn.classList.add('hidden');
      return;
    }
    const kb = Math.max(1, Math.round(pending.sizeBytes / 1024));
    previewEl.textContent = `🔒 ${pending.name} (${kb} KB)`;
    previewEl.classList.remove('hidden');
    clearBtn.classList.remove('hidden');
  };

  const attachFile = async (file: File): Promise<void> => {
    if (file.size > MAX_RAW_BYTES) {
      window.alert('El archivo supera ~1.5 MB. Elige uno más liviano para mantener el cifrado fluido.');
      return;
    }
    const dataUrl = await readFileAsDataUrl(file);
    pending = {
      name: file.name || 'adjunto',
      mimeType: file.type || 'application/octet-stream',
      sizeBytes: file.size,
      kind: classifyMime(file.type || '', file.name || ''),
      dataUrl,
    };
    syncPreviewUi();
  };

  pickBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files?.[0];
    fileInput.value = '';
    if (f) await attachFile(f);
  });

  clearBtn.addEventListener('click', () => {
    pending = null;
    syncPreviewUi();
  });

  voiceBtn.addEventListener('click', async () => {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
      mediaRecorder.stop();
      voiceBtn.textContent = '🎤 Nota voz';
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      window.alert('Tu navegador no soporta grabación de audio aquí.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      audioChunks = [];
      mediaRecorder = new MediaRecorder(stream);
      mediaRecorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) audioChunks.push(ev.data);
      };
      mediaRecorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(audioChunks, { type: mediaRecorder?.mimeType || 'audio/webm' });
        const voiceFile = new File([blob], `nota-voz-${Date.now()}.webm`, { type: blob.type });
        await attachFile(voiceFile);
      };
      mediaRecorder.start();
      voiceBtn.textContent = '⏹ Detener';
    } catch {
      window.alert('No se pudo acceder al micrófono.');
    }
  });

  const renderAttachmentHtml = (att?: EncryptedAttachmentPayload): string => {
    if (!att || !att.dataUrl.startsWith('data:')) return '';
    const safeName = escapeHtml(att.name);
    const safeUrl = escapeHtml(att.dataUrl);
    if (att.kind === 'image') {
      return `<div class="pin-att-box"><img src="${safeUrl}" alt="${safeName}" class="pin-att-img" /></div>`;
    }
    if (att.kind === 'audio') {
      return `<div class="pin-att-box"><audio controls src="${safeUrl}" class="pin-att-audio"></audio></div>`;
    }
    return `<div class="pin-att-box"><a href="${safeUrl}" download="${safeName}" class="pin-att-link">📄 ${safeName}</a></div>`;
  };

  return {
    getPendingAttachment: () => pending,
    clearPendingAttachment: () => {
      pending = null;
      syncPreviewUi();
    },
    renderAttachmentHtml,
  };
}
