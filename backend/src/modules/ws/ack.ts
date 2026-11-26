import { pool } from '../../infra/db.js';

const GROUP_ID_BYTES = 32;
const BASE64_32B_RE = /^[A-Za-z0-9+/]{43}=$/;
const BASE64URL_32B_RE = /^[A-Za-z0-9_-]{43}$/;

function decodeGroupId32(raw: string): Buffer | null {
  if (BASE64_32B_RE.test(raw)) {
    const buf = Buffer.from(raw, 'base64');
    return buf.length === GROUP_ID_BYTES ? buf : null;
  }
  if (BASE64URL_32B_RE.test(raw)) {
    const buf = Buffer.from(raw, 'base64url');
    return buf.length === GROUP_ID_BYTES ? buf : null;
  }
  return null;
}

export async function handleWsAck(
  deviceId: string,
  groupIdB64: string,
  lastSeq: number,
): Promise<void> {
  if (!Number.isSafeInteger(lastSeq) || lastSeq <= 0) return;

  const groupIdBuf = decodeGroupId32(groupIdB64);
  if (!groupIdBuf) return;

  await pool.query(
    `WITH bounds AS (
       SELECT COALESCE(MAX(group_seq), 0)::bigint AS max_seq
       FROM mls_envelopes
       WHERE group_id = $2
     )
     UPDATE group_members gm
     SET last_acked_seq = LEAST($3::bigint, b.max_seq)
     FROM bounds b
     WHERE gm.device_id = $1
       AND gm.group_id = $2
       AND b.max_seq > gm.last_acked_seq
       AND LEAST($3::bigint, b.max_seq) > gm.last_acked_seq`,
    [deviceId.toLowerCase(), groupIdBuf, String(lastSeq)],
  );
}
