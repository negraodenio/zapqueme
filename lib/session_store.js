// lib/session_store.js — Persistência de Sessão WhatsApp na Nuvem (Upstash Redis)
import fs from 'fs';
import path from 'path';

const AUTH_DIR = './auth_info_baileys';
const REDIS_KEY = 'zapqueme:baileys_auth_bundle';

export async function restoreSessionFromCloud() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return false;

  try {
    const res = await fetch(`${url}/get/${REDIS_KEY}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return false;
    const data = await res.json();
    if (!data.result) return false;

    const bundle = JSON.parse(data.result);
    if (!fs.existsSync(AUTH_DIR)) {
      fs.mkdirSync(AUTH_DIR, { recursive: true });
    }

    let restoredCount = 0;
    for (const [filename, base64Content] of Object.entries(bundle)) {
      const filePath = path.join(AUTH_DIR, filename);
      fs.writeFileSync(filePath, Buffer.from(base64Content, 'base64'));
      restoredCount++;
    }

    if (restoredCount > 0) {
      console.log(`☁️ [Nuvem] Sessão WhatsApp restaurada com sucesso do Redis (${restoredCount} arquivos).`);
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

  try {
    const files = fs.readdirSync(AUTH_DIR);
    if (files.length === 0) return;

    const bundle = {};
    for (const file of files) {
      const filePath = path.join(AUTH_DIR, file);
      if (fs.statSync(filePath).isFile()) {
        bundle[file] = fs.readFileSync(filePath).toString('base64');
      }
    }

    await fetch(`${url}/set/${REDIS_KEY}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'text/plain'
      },
      body: JSON.stringify(bundle)
    });
  } catch (err) {
    console.warn('⚠️ [Nuvem] Falha ao sincronizar sessão no Redis:', err.message);
  }
}

export async function clearSessionFromCloud() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return;

  try {
    await fetch(`${url}/del/${REDIS_KEY}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    console.log('☁️ [Nuvem] Sessão antiga apagada do Redis.');
  } catch (err) {}
}
