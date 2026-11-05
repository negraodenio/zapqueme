// lib/session_store.js — Persistência de Sessão WhatsApp na Nuvem (Upstash Redis)
import fs from 'fs';
import path from 'path';
import crypto from 'node:crypto';

const AUTH_DIR = './auth_info_baileys';
const REDIS_KEY = 'zapqueme:baileys_auth_bundle';
const SESSION_CLOUD_RETENTION_SECONDS = 180 * 24 * 60 * 60;
const ENCRYPTED_PREFIX = 'v1:';
const MESSAGE_DEDUPE_TTL_SECONDS = 24 * 60 * 60;
const MESSAGE_RATE_WINDOW_SECONDS = 60;
const MAX_MEMORY_DEDUPE_ENTRIES = 5000;
const memoryDedupe = new Map();
const memoryRateLimits = new Map();
let warnedMissingEncryptionKey = false;
let lastDedupeWarningAt = 0;

function encryptionKey() {
  const configured = process.env.WHATSAPP_SESSION_ENCRYPTION_KEY;
  if (!configured || configured.length < 32) return null;
  return crypto.createHash('sha256').update(configured, 'utf8').digest();
}

function encryptBundle(value) {
  const key = encryptionKey();
  if (!key) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return ENCRYPTED_PREFIX + Buffer.from(JSON.stringify({
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  })).toString('base64');
}

function decryptBundle(value) {
  if (!value.startsWith(ENCRYPTED_PREFIX)) return value;
  const key = encryptionKey();
  if (!key) throw new Error('WHATSAPP_SESSION_ENCRYPTION_KEY is required to restore this session');
  const envelope = JSON.parse(Buffer.from(value.slice(ENCRYPTED_PREFIX.length), 'base64').toString('utf8'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');
}

async function refreshCloudSessionTtl(url, token) {
  try {
    const response = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([['EXPIRE', REDIS_KEY, SESSION_CLOUD_RETENTION_SECONDS]]),
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);
    const results = await response.json();
    if (results.some(item => item?.error)) throw new Error('Redis session expiry command failed');
  } catch (err) {
    console.warn('[Nuvem] Não foi possível renovar a expiração da cópia de sessão:', err.message);
  }
}

export async function restoreSessionFromCloud() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return false;

  try {
    const res = await fetch(`${url}/get/${REDIS_KEY}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return false;
    const data = await res.json();
    if (!data.result) return false;
    await refreshCloudSessionTtl(url, token);

    const isLegacyBundle = !String(data.result).startsWith(ENCRYPTED_PREFIX);
    const bundle = JSON.parse(decryptBundle(String(data.result)));
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return false;
    if (isLegacyBundle && encryptionKey()) {
      console.warn('⚠️ [Nuvem] Foi encontrada uma sessão antiga sem cifragem. Será cifrada na próxima sincronização.');
    }

    // Valida se a sessão no Redis é válida e de facto registrada
    if (bundle['creds.json']) {
      try {
        const creds = JSON.parse(Buffer.from(bundle['creds.json'], 'base64').toString('utf8'));
        if (!creds.registered) {
          console.warn('⚠️ [Nuvem] Sessão no Redis incompleta (registered: false). Ignorando para permitir novo emparelhamento.');
          return false;
        }
      } catch (e) {
        return false;
      }
    } else {
      return false;
    }

    if (!fs.existsSync(AUTH_DIR)) {
      fs.mkdirSync(AUTH_DIR, { recursive: true });
    }

    let restoredCount = 0;
    for (const [filename, base64Content] of Object.entries(bundle)) {
      if (!filename || filename === '.' || filename === '..' || /[\\/]/.test(filename)) {
        throw new Error('Invalid session filename');
      }
      const filePath = path.join(AUTH_DIR, filename);
      fs.writeFileSync(filePath, Buffer.from(base64Content, 'base64'));
      restoredCount++;
    }

    if (restoredCount > 0) {
      console.log(`☁️ [Nuvem] Sessão WhatsApp restaurada com sucesso do Redis (${restoredCount} arquivos).`);
      if (isLegacyBundle && encryptionKey()) await syncSessionToCloud();
      return true;
    }
  } catch (err) {
    console.warn('⚠️ [Nuvem] Não foi possível restaurar sessão do Redis:', err.message);
  }
  return false;
}

export async function syncSessionToCloud() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !fs.existsSync(AUTH_DIR)) return;
  if (!encryptionKey()) {
    if (!warnedMissingEncryptionKey) {
      console.warn('⚠️ [Nuvem] Sessão não sincronizada: configure WHATSAPP_SESSION_ENCRYPTION_KEY (mínimo 32 caracteres).');
      warnedMissingEncryptionKey = true;
    }
    return;
  }

  try {
    const credsPath = path.join(AUTH_DIR, 'creds.json');
    if (!fs.existsSync(credsPath)) return;

    // Só sincroniza na nuvem se a sessão estiver de facto registrada e confirmada
    const credsRaw = fs.readFileSync(credsPath, 'utf8');
    const creds = JSON.parse(credsRaw);
    if (!creds.registered) {
      return; // Evita salvar credenciais provisórias ou não concluídas no Redis
    }

    const files = fs.readdirSync(AUTH_DIR);
    if (files.length === 0) return;

    const bundle = {};
    for (const file of files) {
      const filePath = path.join(AUTH_DIR, file);
      if (fs.statSync(filePath).isFile()) {
        bundle[file] = fs.readFileSync(filePath).toString('base64');
      }
    }

    const encryptedBundle = encryptBundle(JSON.stringify(bundle));
    if (!encryptedBundle) return;

    const response = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([
        ['SET', REDIS_KEY, encryptedBundle, 'EX', SESSION_CLOUD_RETENTION_SECONDS]
      ]),
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);
    const results = await response.json();
    if (results.some(item => item?.error)) throw new Error('Redis session write failed');
  } catch (err) {
    console.warn('⚠️ [Nuvem] Falha ao sincronizar sessão no Redis:', err.message);
  }
}

export async function clearSessionFromCloud() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return;

  try {
    const response = await fetch(`${url}/del/${REDIS_KEY}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);
    console.log('☁️ [Nuvem] Sessão antiga apagada do Redis.');
  } catch (err) {
    console.warn('[Nuvem] Não foi possível apagar a sessão Redis:', err.message);
  }
}

export async function checkSessionStoreHealth() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !encryptionKey()) return 'misconfigured';

  try {
    const response = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([['PING']]),
      signal: AbortSignal.timeout(3000)
    });
    if (!response.ok) return 'offline';
    const results = await response.json();
    return results[0]?.result === 'PONG' ? 'online' : 'offline';
  } catch {
    return 'offline';
  }
}

function rememberMessage(hash, now) {
  if (memoryDedupe.size >= MAX_MEMORY_DEDUPE_ENTRIES) {
    memoryDedupe.delete(memoryDedupe.keys().next().value);
  }
  memoryDedupe.set(hash, now + MESSAGE_DEDUPE_TTL_SECONDS * 1000);
}

// Claim before processing so Baileys redeliveries do not trigger duplicate analyses/replies.
// Redis provides cross-restart deduplication; bounded memory is a temporary fallback.
export async function claimIncomingMessage(remoteJid, messageId) {
  if (!remoteJid || !messageId) return true;
  const hash = crypto.createHash('sha256').update(`${remoteJid}\0${messageId}`).digest('hex');
  const now = Date.now();
  const seenUntil = memoryDedupe.get(hash);
  if (seenUntil && seenUntil > now) return false;
  if (seenUntil) memoryDedupe.delete(hash);

  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) {
    try {
      const key = encodeURIComponent(`zapqueme:wa_message:${hash}`);
      const response = await fetch(`${url}/set/${key}/1/EX/${MESSAGE_DEDUPE_TTL_SECONDS}/NX`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(3000)
      });
      if (response.ok) {
        const data = await response.json();
        if (data.result === null) return false;
        if (data.result === 'OK') {
          rememberMessage(hash, now);
          return true;
        }
      }
      throw new Error(`Redis HTTP ${response.status}`);
    } catch {
      if (now - lastDedupeWarningAt > 60000) {
        console.warn('[WhatsApp] Deduplicação Redis indisponível; a usar cache local temporária.');
        lastDedupeWarningAt = now;
      }
    }
  }

  rememberMessage(hash, now);
  return true;
}

// Per-sender cap controls provider costs and prevents one chat from flooding analysis.
// Sender identifiers are hashed before they are used in Redis keys.
export async function allowWhatsAppMessage(remoteJid, limit = 12) {
  if (!remoteJid) return true;
  const senderHash = crypto.createHash('sha256').update(remoteJid).digest('hex');
  const bucket = Math.floor(Date.now() / (MESSAGE_RATE_WINDOW_SECONDS * 1000));
  const key = `zapqueme:wa_rate:${senderHash}:${bucket}`;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (url && token) {
    try {
      const response = await fetch(`${url}/pipeline`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify([
          ['INCR', key],
          ['EXPIRE', key, MESSAGE_RATE_WINDOW_SECONDS * 2]
        ]),
        signal: AbortSignal.timeout(3000)
      });
      if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);
      const results = await response.json();
      if (results.some(item => item?.error)) throw new Error('Redis rate-limit command failed');
      const count = Number(results[0]?.result);
      if (!Number.isFinite(count)) throw new Error('Redis rate-limit count invalid');
      return count <= limit;
    } catch {
      const now = Date.now();
      if (now - lastDedupeWarningAt > 60000) {
        console.warn('[WhatsApp] Limite Redis indisponível; a usar controlo local temporário.');
        lastDedupeWarningAt = now;
      }
    }
  }

  const now = Date.now();
  for (const [localKey, entry] of memoryRateLimits) {
    if (entry.expiresAt <= now) memoryRateLimits.delete(localKey);
  }
  const entry = memoryRateLimits.get(key) || { count: 0, expiresAt: (bucket + 2) * MESSAGE_RATE_WINDOW_SECONDS * 1000 };
  entry.count++;
  memoryRateLimits.set(key, entry);
  while (memoryRateLimits.size > MAX_MEMORY_DEDUPE_ENTRIES) {
    memoryRateLimits.delete(memoryRateLimits.keys().next().value);
  }
  return entry.count <= limit;
}
