import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import type { FastifyInstance } from 'fastify';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
import { pool } from '../../infra/db.js';
import { cmdRedis } from '../../infra/redis.js';
import { createWsUpgradeAuthenticator } from './auth.js';
import {
  claimPresence,
  deviceChannel,
  refreshPresence,
  releasePresence,
  type ControlKickFrame,
} from './presence.js';
import { handleWsAck } from './ack.js';

const WS_PATH = '/v1/ws';
const WS_MAX_PAYLOAD_BYTES = 64 * 1024;
const WS_MAX_BUFFERED_BYTES = 2 * 1024 * 1024;
const HEARTBEAT_INTERVAL_MS = 30_000;

const WS_CLOSE_REVOKED = 4001;
const WS_CLOSE_SESSION_REPLACED = 4002;
const WS_CLOSE_SERVER_SHUTDOWN = 1001;

interface ManagedConn {
  connId: string;
  deviceId: string;
  pin: string;
  ws: WebSocket;
  isAlive: boolean;
  cleanedUp: boolean;
}

interface HelloCounts {
  active: boolean;
  kpRemaining: number;
  pendingWelcomes: number;
  pendingInvites: number;
  syncRequired: boolean;
}

function writeUpgradeHttpError(socket: Duplex, statusCode: number, errorCode: string): void {
  const statusText =
    statusCode === 400
      ? 'Bad Request'
      : statusCode === 401
        ? 'Unauthorized'
        : statusCode === 403
          ? 'Forbidden'
          : 'Not Found';

  const body = JSON.stringify({ error: errorCode });
  const raw =
    `HTTP/1.1 ${statusCode} ${statusText}\r\n` +
    `Content-Type: application/json\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `Connection: close\r\n\r\n` +
    body;

  socket.write(raw);
  socket.destroy();
}

async function fetchHelloState(deviceId: string, pin: string): Promise<HelloCounts> {
  const { rows } = await pool.query<{
    is_active: boolean;
    kp_remaining: string;
    pending_welcomes: string;
    pending_invites: string;
    pending_grants: string;
    has_pending_envelopes: boolean;
  }>(
    `SELECT
       EXISTS(
         SELECT 1 FROM devices
         WHERE device_id = $1 AND pin = $2 AND status = 'active' AND cert_expires_at > NOW()
       ) AS is_active,
       (
         SELECT COUNT(*) FROM key_packages
         WHERE device_id = $1 AND is_last_resort = FALSE AND expires_at > NOW()
       ) AS kp_remaining,
       (
         SELECT COUNT(*) FROM welcome_deliveries
         WHERE device_id = $1 AND acked_at IS NULL
       ) AS pending_welcomes,
       (
         SELECT COUNT(*) FROM contact_requests
         WHERE target_pin = $2 AND expires_at > NOW()
       ) AS pending_invites,
       (
         SELECT COUNT(*) FROM pending_keypackage_grants
         WHERE requester_pin = $2 AND expires_at > NOW()
       ) AS pending_grants,
       EXISTS(
         SELECT 1
         FROM group_members gm
         JOIN mls_envelopes env
           ON env.group_id = gm.group_id
          AND env.group_seq > gm.last_acked_seq
         WHERE gm.device_id = $1
       ) AS has_pending_envelopes`,
    [deviceId, pin],
  );

  const r = rows[0];
  if (!r || !r.is_active) {
    return { active: false, kpRemaining: 0, pendingWelcomes: 0, pendingInvites: 0, syncRequired: false };
  }

  const kpRemaining = Number(r.kp_remaining);
  const pendingWelcomes = Number(r.pending_welcomes);
  const pendingInvites = Number(r.pending_invites);
  const pendingGrants = Number(r.pending_grants);

  return {
    active: true,
    kpRemaining,
    pendingWelcomes,
    pendingInvites,
    syncRequired: pendingWelcomes > 0 || pendingInvites > 0 || pendingGrants > 0 || r.has_pending_envelopes,
  };
}

function sendJsonSafe(ws: WebSocket, rawJson: string): void {
  if (ws.readyState !== WebSocket.OPEN) return;
  if (ws.bufferedAmount > WS_MAX_BUFFERED_BYTES) {
    ws.terminate();
    return;
  }
  ws.send(rawJson);
}

export async function attachWsGateway(fastify: FastifyInstance): Promise<void> {
  const nodeId = randomUUID();
  const authenticateUpgrade = await createWsUpgradeAuthenticator();

  const subRedis = cmdRedis.duplicate({ lazyConnect: false });
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: WS_MAX_PAYLOAD_BYTES,
  });

  const localConnections = new Map<string, Map<string, ManagedConn>>();

  subRedis.on('smessage', (channel: string, rawPayload: string) => {
    const prefix = 'ws:dev:';
    if (!channel.startsWith(prefix)) return;

    const deviceId = channel.slice(prefix.length);
    const deviceConns = localConnections.get(deviceId);
    if (!deviceConns || deviceConns.size === 0) return;

    let parsedType: string | undefined;
    let kickFrame: ControlKickFrame | null = null;
    try {
      const obj = JSON.parse(rawPayload) as { type?: unknown; reason?: unknown; targetConnId?: unknown };
      if (typeof obj.type === 'string') parsedType = obj.type;
      if (obj.type === 'control_kick' && (obj.reason === 'DEVICE_REVOKED' || obj.reason === 'SESSION_REPLACED')) {
        kickFrame = {
          type: 'control_kick',
          reason: obj.reason,
          targetConnId: typeof obj.targetConnId === 'string' ? obj.targetConnId : undefined,
        };
      }
    } catch {
      return;
    }

    if (parsedType === 'control_kick' && kickFrame) {
      if (kickFrame.reason === 'DEVICE_REVOKED') {
        for (const conn of deviceConns.values()) {
          if (conn.ws.readyState === WebSocket.OPEN || conn.ws.readyState === WebSocket.CONNECTING) {
            conn.ws.close(WS_CLOSE_REVOKED, 'DEVICE_REVOKED');
          }
        }
        return;
      }
      if (kickFrame.targetConnId) {
        const oldConn = deviceConns.get(kickFrame.targetConnId);
        if (oldConn && (oldConn.ws.readyState === WebSocket.OPEN || oldConn.ws.readyState === WebSocket.CONNECTING)) {
          oldConn.ws.close(WS_CLOSE_SESSION_REPLACED, 'SESSION_REPLACED');
        }
      }
      return;
    }

    for (const conn of deviceConns.values()) {
      sendJsonSafe(conn.ws, rawPayload);
    }
  });

  subRedis.on('error', (err) => {
    fastify.log.error({ err }, 'WS subRedis error');
  });

  async function cleanupConnection(conn: ManagedConn): Promise<void> {
    if (conn.cleanedUp) return;
    conn.cleanedUp = true;

    const deviceConns = localConnections.get(conn.deviceId);
    let shouldUnsubscribe = false;

    if (deviceConns) {
      deviceConns.delete(conn.connId);
      if (deviceConns.size === 0) {
        localConnections.delete(conn.deviceId);
        shouldUnsubscribe = true;
      }
    }

    const tasks: Promise<unknown>[] = [
      releasePresence(cmdRedis, conn.deviceId, nodeId, conn.connId).catch(() => false),
    ];
    if (shouldUnsubscribe) {
      tasks.push(subRedis.sunsubscribe(deviceChannel(conn.deviceId)).catch(() => undefined));
    }
    await Promise.all(tasks);
  }

  async function onSocketConnected(ws: WebSocket, deviceId: string, pin: string): Promise<void> {
    const connId = randomUUID();
    const conn: ManagedConn = { connId, deviceId, pin, ws, isAlive: true, cleanedUp: false };

    ws.once('close', () => { void cleanupConnection(conn); });
    ws.once('error', () => { void cleanupConnection(conn); });

    let hello: HelloCounts;
    try {
      hello = await fetchHelloState(deviceId, pin);
    } catch (err) {
      fastify.log.error({ err, deviceId }, 'Failed fetching WS hello state');
      ws.close(1011, 'INTERNAL_ERROR');
      return;
    }

    if (!hello.active) {
      ws.close(WS_CLOSE_REVOKED, 'DEVICE_REVOKED');
      return;
    }

    let deviceConns = localConnections.get(deviceId);
    const needsSubscribe = !deviceConns || deviceConns.size === 0;
    if (!deviceConns) {
      deviceConns = new Map<string, ManagedConn>();
      localConnections.set(deviceId, deviceConns);
    }
    deviceConns.set(connId, conn);

    try {
      if (needsSubscribe) {
        await subRedis.ssubscribe(deviceChannel(deviceId));
      }
      await claimPresence(cmdRedis, deviceId, nodeId, connId);
    } catch (err) {
      fastify.log.error({ err, deviceId }, 'Failed registering WS presence');
      ws.close(1011, 'PRESENCE_ERROR');
      await cleanupConnection(conn);
      return;
    }

    if (ws.readyState !== WebSocket.OPEN) {
      await cleanupConnection(conn);
      return;
    }

    sendJsonSafe(
      ws,
      JSON.stringify({
        type: 'hello',
        kp_remaining: hello.kpRemaining,
        pending_welcomes: hello.pendingWelcomes,
        pending_invites: hello.pendingInvites,
        sync_required: hello.syncRequired,
      }),
    );

    ws.on('pong', () => {
      conn.isAlive = true;
      void refreshPresence(cmdRedis, deviceId, nodeId, connId)
        .then((stillOwner) => {
          if (!stillOwner && ws.readyState === WebSocket.OPEN) {
            ws.close(WS_CLOSE_SESSION_REPLACED, 'SESSION_REPLACED');
          }
        })
        .catch(() => {});
    });

    ws.on('message', (data: RawData, isBinary: boolean) => {
      if (isBinary) return;
      let frame: { type?: unknown; group_id?: unknown; last_seq?: unknown };
      try {
        frame = JSON.parse(data.toString('utf8')) as {
          type?: unknown;
          group_id?: unknown;
          last_seq?: unknown;
        };
      } catch {
        return;
      }

      if (frame.type === 'ping') {
        sendJsonSafe(ws, '{"type":"pong"}');
        return;
      }

      if (
        frame.type === 'ack' &&
        typeof frame.group_id === 'string' &&
        typeof frame.last_seq === 'number' &&
        Number.isSafeInteger(frame.last_seq) &&
        frame.last_seq > 0
      ) {
        void handleWsAck(deviceId, frame.group_id, frame.last_seq).catch((err) => {
          fastify.log.warn({ err, deviceId }, 'Failed processing WS ack frame');
        });
      }
    });
  }

  const onUpgrade = (req: IncomingMessage, socket: Duplex, head: Buffer): void => {
    let pathname = '';
    try {
      pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
    } catch {
      writeUpgradeHttpError(socket, 400, 'INVALID_REQUEST_URL');
      return;
    }

    if (pathname !== WS_PATH) {
      writeUpgradeHttpError(socket, 404, 'WS_ROUTE_NOT_FOUND');
      return;
    }

    void authenticateUpgrade(req)
      .then((authRes) => {
        if (!authRes.ok) {
          writeUpgradeHttpError(socket, authRes.statusCode, authRes.error);
          return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
          void onSocketConnected(ws, authRes.deviceId, authRes.pin);
        });
      })
      .catch((err) => {
        fastify.log.error({ err }, 'Unhandled error during WS upgrade');
        writeUpgradeHttpError(socket, 401, 'WS_AUTH_ERROR');
      });
  };

  fastify.server.on('upgrade', onUpgrade);

  const heartbeatTimer = setInterval(() => {
    for (const deviceConns of localConnections.values()) {
      for (const conn of deviceConns.values()) {
        if (!conn.isAlive) {
          conn.ws.terminate();
          continue;
        }
        conn.isAlive = false;
        if (conn.ws.readyState === WebSocket.OPEN) {
          conn.ws.ping();
        }
      }
    }
  }, HEARTBEAT_INTERVAL_MS);
  heartbeatTimer.unref();

  fastify.addHook('onClose', async () => {
    clearInterval(heartbeatTimer);
    fastify.server.off('upgrade', onUpgrade);

    const cleanups: Promise<void>[] = [];
    for (const deviceConns of localConnections.values()) {
      for (const conn of deviceConns.values()) {
        if (conn.ws.readyState === WebSocket.OPEN) {
          conn.ws.close(WS_CLOSE_SERVER_SHUTDOWN, 'SERVER_SHUTDOWN');
        }
        cleanups.push(cleanupConnection(conn));
      }
    }
    await Promise.allSettled(cleanups);
    await new Promise<void>((resolve) => { wss.close(() => resolve()); });
    await subRedis.quit().catch(() => undefined);
  });
}
