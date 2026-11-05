// bot.js — ZapQuemÉ WhatsApp Bot + Painel Web Local (http://localhost:3333)
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import http from 'http';
import fs from 'fs';
import path from 'path';
import makeWASocket, {
  useMultiFileAuthState,
  DisconnectReason,
  downloadMediaMessage,
  fetchLatestBaileysVersion,
  Browsers
} from '@whiskeysockets/baileys';
import qrcode from 'qrcode-terminal';
import QRCodeImage from 'qrcode';
import pino from 'pino';
import { analyzeContent, formatWhatsAppMessage, formatSmsMessage, getEmergencyVictimGuide } from './lib/scanner.js';
import {
  buildDataContract,
  renderWhatsAppResponse,
  renderHelpResponse,
  renderDetailsResponse,
  renderFeedbackResponse,
  renderNoSessionResponse
} from './lib/renderer.js';
import { restoreSessionFromCloud, syncSessionToCloud, clearSessionFromCloud, claimIncomingMessage, allowWhatsAppMessage, checkSessionStoreHealth } from './lib/session_store.js';
import { pruneRedisLeadFallback } from './lib/retention.js';
import { registarFeedbackErroUtilizador } from './lib/golpes_novos.js';
import { checkRateLimit, isAuthorizedSmsWebhook, isConfiguredSmsWebhook, secureEqual } from './lib/security.js';

// Cache de conversação por chat (TTL: 24 horas) para comandos interativos (AJUDA, DETALHES, ÚTIL, ERRO)
const chatSessions = new Map();

function cleanOldSessions() {
  const now = Date.now();
  const ttl = 24 * 60 * 60 * 1000;
  for (const [jid, session] of chatSessions.entries()) {
    if (now - session.timestamp > ttl) {
      chatSessions.delete(jid);
    }
  }
}
setInterval(cleanOldSessions, 30 * 60 * 1000);

const logger = pino({ level: 'silent' });
const AUTH_DIR = './auth_info_baileys';
const PORT = process.env.PORT || 3333;
const configuredMessageLimit = Number(process.env.WHATSAPP_MESSAGES_PER_MINUTE || 12);
const WHATSAPP_MESSAGES_PER_MINUTE = Number.isInteger(configuredMessageLimit) && configuredMessageLimit >= 1 && configuredMessageLimit <= 120
  ? configuredMessageLimit
  : 12;

let currentSock = null;
let currentStatus = {
  version: '2.6.0-gemini20',
  connected: false,
  status: 'starting',
  phone: process.env.WHATSAPP_PHONE || '',
  pairingCode: null,
  pairingExpiresAt: null,
  qrBase64: null,
  lastError: null
};

let lastSupabasePing = null;
let supabaseStatus = 'unknown';
let lastPairingRequestAt = 0;
let qrUpdatedAt = null;
let supabaseHealthCheck = null;
let sessionStoreHealthCheck = null;
let lastSessionStoreHealth = 'unknown';
let lastSessionStoreHealthAt = 0;

function isAdminRequest(req) {
  const configured = process.env.ADMIN_SECRET_KEY;
  const headerKey = req.headers['x-admin-key'];
  const authHeader = req.headers.authorization || '';
  const bearerKey = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
  const supplied = typeof headerKey === 'string' ? headerKey : bearerKey;
  return Boolean(configured && secureEqual(supplied, configured));
}

function sendJson(res, statusCode, value) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  return res.end(JSON.stringify(value));
}

function readRequestBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      data += chunk.toString('utf8');
      if (Buffer.byteLength(data) > maxBytes) tooLarge = true;
    });
    req.on('end', () => tooLarge ? reject(new Error('BODY_TOO_LARGE')) : resolve(data));
    req.on('error', reject);
  });
}

async function checkSupabaseHealth() {
  const sUrl = process.env.SUPABASE_URL;
  const sKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!sUrl || !sKey) {
    supabaseStatus = 'unconfigured';
    lastSupabasePing = new Date().toISOString();
    return { status: supabaseStatus, lastPing: lastSupabasePing };
  }

  try {
    const res = await fetch(`${sUrl}/rest/v1/empresas?select=id&limit=1`, {
      headers: { apikey: sKey, Authorization: `Bearer ${sKey}` },
      signal: AbortSignal.timeout(5000)
    });
    supabaseStatus = res.ok ? 'online' : `error_${res.status}`;
    lastSupabasePing = new Date().toISOString();
    return { status: supabaseStatus, lastPing: lastSupabasePing };
  } catch (err) {
    supabaseStatus = 'offline';
    lastSupabasePing = new Date().toISOString();
    return { status: 'offline', error: err.message, lastPing: lastSupabasePing };
  }
}

function refreshSupabaseHealth() {
  if (!supabaseHealthCheck) {
    supabaseHealthCheck = checkSupabaseHealth().finally(() => { supabaseHealthCheck = null; });
  }
  return supabaseHealthCheck;
}

async function getReadiness() {
  if (!lastSupabasePing || Date.now() - new Date(lastSupabasePing).getTime() > 30000) {
    await refreshSupabaseHealth();
  }

  const production = process.env.NODE_ENV === 'production';
  const sessionStoreConfigured = Boolean(
    process.env.UPSTASH_REDIS_REST_URL
    && process.env.UPSTASH_REDIS_REST_TOKEN
    && process.env.WHATSAPP_SESSION_ENCRYPTION_KEY?.length >= 32
  );
  let sessionPersistence = 'not_required';
  if (production) {
    if (!sessionStoreConfigured) {
      sessionPersistence = 'misconfigured';
    } else {
      if (!lastSessionStoreHealthAt || Date.now() - lastSessionStoreHealthAt > 30000) {
        if (!sessionStoreHealthCheck) {
          sessionStoreHealthCheck = checkSessionStoreHealth()
            .then(status => {
              lastSessionStoreHealth = status;
              lastSessionStoreHealthAt = Date.now();
              return status;
            })
            .finally(() => { sessionStoreHealthCheck = null; });
        }
        await sessionStoreHealthCheck;
      }
      sessionPersistence = lastSessionStoreHealth;
    }
  }
  const whatsapp = currentStatus.connected ? 'connected' : currentStatus.status;
  const ready = currentStatus.connected && supabaseStatus === 'online'
    && (!production || sessionPersistence === 'online');

  return { ready, whatsapp, supabase: supabaseStatus, sessionPersistence };
}

// --------------------------------------------------------------------------
// SERVIDOR WEB LOCAL (http://localhost:3333)
// --------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  // Liveness confirma que o processo HTTP responde, sem depender de serviços externos.
  if (url.pathname === '/ping' || url.pathname === '/health/live') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' });
      return res.end('Method Not Allowed');
    }
    return sendJson(res, 200, { ok: true, service: 'zapqueme-bot' });
  }

  // Readiness confirma que WhatsApp, Supabase e persistência de sessão estão operacionais.
  if (url.pathname === '/health/ready' || url.pathname === '/status') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' });
      return res.end('Method Not Allowed');
    }
    const health = await getReadiness();
    const payload = {
      ok: health.ready,
      service: 'zapqueme-bot',
      whatsapp: health.whatsapp,
      supabase: health.supabase,
      sessionPersistence: health.sessionPersistence
    };
    return sendJson(res, health.ready ? 200 : 503, payload);
  }

  if (url.pathname === '/admin/status') {
    if (req.method !== 'GET') return sendJson(res, 405, { error: 'Método não permitido.' });
    if (!isAdminRequest(req)) return sendJson(res, 401, { error: 'Acesso não autorizado.' });
    if (currentStatus.pairingExpiresAt && Date.now() > currentStatus.pairingExpiresAt) {
      currentStatus.pairingCode = null;
      currentStatus.pairingExpiresAt = null;
    }
    return sendJson(res, 200, {
      connected: currentStatus.connected,
      status: currentStatus.status,
      phone: currentStatus.phone,
      pairingCode: currentStatus.pairingCode,
      pairingExpiresAt: currentStatus.pairingExpiresAt,
      qrUpdatedAt,
      hasQr: Boolean(qrUpdatedAt),
      lastError: currentStatus.lastError
    });
  }

  // Pairing QR material is available only to an operator holding ADMIN_SECRET_KEY.
  if (url.pathname === '/qrcode.png') {
    if (req.method !== 'GET') return sendJson(res, 405, { error: 'Método não permitido.' });
    if (!isAdminRequest(req)) return sendJson(res, 401, { error: 'Acesso não autorizado.' });
    if (!fs.existsSync('./qrcode.png')) return sendJson(res, 404, { error: 'QR ainda não disponível.' });
    const image = fs.readFileSync('./qrcode.png');
    res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-store, no-cache, must-revalidate' });
    return res.end(image);
  }

  if (url.pathname === '/request-code') {
    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' });
      return res.end('Method Not Allowed');
    }
    if (!isAdminRequest(req)) return sendJson(res, 401, { error: 'Acesso não autorizado.' });
    if (Date.now() - lastPairingRequestAt < 30000) {
      return sendJson(res, 429, { error: 'Aguarda 30 segundos antes de pedir outro código.' });
    }

    let body;
    try {
      body = JSON.parse(await readRequestBody(req, 2048) || '{}');
    } catch (error) {
      return sendJson(res, error.message === 'BODY_TOO_LARGE' ? 413 : 400, { error: 'Pedido inválido.' });
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return sendJson(res, 400, { error: 'Pedido inválido.' });
    }
    const phoneParam = typeof body.phone === 'string' ? body.phone : '';
    const cleanPhone = phoneParam.replace(/\D/g, '');
    if (cleanPhone.length < 8 || cleanPhone.length > 15) {
      return sendJson(res, 400, { error: 'Número de telefone inválido.' });
    }
    if (!currentSock || currentStatus.connected) {
      return sendJson(res, 409, { error: 'WhatsApp já conectado ou ainda a inicializar.' });
    }

    lastPairingRequestAt = Date.now();
    currentStatus.phone = cleanPhone;
    try {
      const code = await currentSock.requestPairingCode(cleanPhone);
      const formattedCode = code?.match(/.{1,4}/g)?.join('-') || code;
      currentStatus.pairingCode = formattedCode;
      currentStatus.pairingExpiresAt = Date.now() + 60000;
      return sendJson(res, 200, { success: true, code: formattedCode });
    } catch (error) {
      console.warn('[Pairing] Code request failed:', error.message);
      return sendJson(res, 503, { error: 'Não foi possível pedir o código. Tenta novamente mais tarde.' });
    }
  }

  if (url.pathname === '/test-ai') {
    if (!isAdminRequest(req)) return sendJson(res, 401, { error: 'Acesso não autorizado.' });
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Método não permitido.' });
    let testBody;
    try {
      testBody = JSON.parse(await readRequestBody(req, 4096) || '{}');
    } catch (error) {
      return sendJson(res, error.message === 'BODY_TOO_LARGE' ? 413 : 400, { error: 'Pedido inválido.' });
    }
    if (!testBody || typeof testBody !== 'object' || Array.isArray(testBody)) {
      return sendJson(res, 400, { error: 'Pedido inválido.' });
    }
    const limit = await checkRateLimit(req, 'bot-test-ai', 5, 60);
    if (!limit.allowed) return sendJson(res, 429, { error: 'Limite de análises de diagnóstico atingido.' });
    const q = typeof testBody.text === 'string' ? testBody.text : 'Mensagem demonstrativa para diagnóstico';
    if (q.length > 2000) return sendJson(res, 413, { error: 'Texto demasiado longo.' });
    try {
      const result = await analyzeContent({ texto: q });
      return sendJson(res, 200, { success: true, result, formatted: formatWhatsAppMessage(result) });
    } catch (error) {
      console.warn('[Test AI] Analysis failed:', error.message);
      return sendJson(res, 503, { success: false, error: 'A análise não está disponível.' });
    }
  }

  if (url.pathname === '/api/sms' || url.pathname === '/sms') {
    if (req.method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' });
      return res.end('Method Not Allowed');
    }
    if (!isConfiguredSmsWebhook()) return sendJson(res, 503, { error: 'O webhook SMS não está configurado.' });
    let rawBody;
    try {
      rawBody = await readRequestBody(req, 16 * 1024);
    } catch (error) {
      return sendJson(res, error.message === 'BODY_TOO_LARGE' ? 413 : 400, { error: 'Pedido inválido.' });
    }
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    let body = {};
    try {
      if (contentType.includes('application/x-www-form-urlencoded')) {
        body = Object.fromEntries(new URLSearchParams(rawBody));
      } else if (contentType.includes('application/json')) {
        body = JSON.parse(rawBody || '{}');
      } else {
        return sendJson(res, 415, { error: 'Formato de pedido não suportado.' });
      }
    } catch {
      return sendJson(res, 400, { error: 'Pedido inválido.' });
    }
    if (req.headers['x-twilio-signature'] && !contentType.includes('application/x-www-form-urlencoded')) {
      return sendJson(res, 415, { error: 'Formato de webhook Twilio não suportado.' });
    }
    if (!isAuthorizedSmsWebhook(req, body)) return sendJson(res, 401, { error: 'Webhook não autorizado.' });
    const limit = await checkRateLimit(req, 'bot-sms', 20, 60);
    if (limit.unavailable && process.env.NODE_ENV === 'production') {
      return sendJson(res, 503, { error: 'Análise SMS temporariamente indisponível.' });
    }
    if (!limit.allowed) return sendJson(res, 429, { error: 'Demasiados pedidos. Tenta mais tarde.' });

    const incomingText = String(body.Body || body.text || body.message || '').trim();
    const wantsJson = url.searchParams.get('format') === 'json' || String(req.headers.accept || '').includes('application/json');
    if (incomingText.length > 5000) return sendJson(res, 413, { error: 'Mensagem demasiado longa.' });
    if (!incomingText || ['ajuda', 'help', 'info', 'start', 'zap'].includes(incomingText.toLowerCase())) {
      const help = '[ZAP VERIFICA] Reencaminhe o SMS suspeito para análise. Nunca partilhe códigos ou palavras-passe.';
      if (wantsJson) return sendJson(res, 200, { success: true, sms_resposta: help });
      return sendTwiml(res, help);
    }
    try {
      const result = await analyzeContent({ texto: incomingText, canal: 'sms' });
      const responseText = formatSmsMessage(result);
      if (wantsJson) return sendJson(res, 200, { success: true, canal: 'sms', veredito: result.veredito, risco_score: result.risco_score, sms_resposta: responseText });
      return sendTwiml(res, responseText);
    } catch (error) {
      console.warn('[SMS Gateway] Processing failed:', error.message);
      const failure = '[ZAP ALERTA] Não foi possível analisar este SMS agora. Tenta novamente mais tarde.';
      if (wantsJson) return sendJson(res, 503, { success: false, sms_resposta: failure });
      return sendTwiml(res, failure);
    }
  }

  // 6. Arquivos Estáticos & Painel Admin
  const staticFiles = {
    '/admin': 'admin.html',
    '/admin.html': 'admin.html',
    '/empresas': 'empresas.html',
    '/empresas.html': 'empresas.html',
    '/verificar': 'verificar.html',
    '/verificar.html': 'verificar.html',
    '/index.html': 'index.html',
    '/logo.jpg': 'logo.jpg',
    '/favicon.png': 'favicon.png',
    '/widget.js': 'widget.js'
  };

  if (staticFiles[url.pathname]) {
    const filePath = path.join(process.cwd(), staticFiles[url.pathname]);
    if (fs.existsSync(filePath)) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.json': 'application/json'
      };
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      return res.end(fs.readFileSync(filePath));
    }
  }

  // 6. Página de Emparelhamento QR (HTML)
  if (url.pathname === '/' || url.pathname === '/qr.html' || url.pathname === '/qr') {
    const html = getDashboardHtml();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  res.writeHead(404);
  res.end('Not found');
});

function sendTwiml(res, message) {
  const xml = String(message || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;').replace(/'/g, '&apos;');
  res.writeHead(200, { 'Content-Type': 'text/xml; charset=utf-8' });
  return res.end(`<?xml version="1.0" encoding="UTF-8"?><Response><Message><Body>${xml}</Body></Message></Response>`);
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🌐 PAINEL DE CONEXÃO DISPONÍVEL EM: http://localhost:${PORT}\n`);
  refreshSupabaseHealth();
  const supabaseKeepAlive = setInterval(refreshSupabaseHealth, 10 * 60 * 1000);
  supabaseKeepAlive.unref();
  pruneRedisLeadFallback();
  const retentionTimer = setInterval(pruneRedisLeadFallback, 24 * 60 * 60 * 1000);
  retentionTimer.unref();
});

// --------------------------------------------------------------------------
// HTML DO PAINEL DE CONTROLE
// --------------------------------------------------------------------------
function getDashboardHtml() {
  return `<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Zap, quem é? — Conectar Robô WhatsApp</title>
  <style>
    * { box-sizing: border-box; }
    body {
      background: radial-gradient(circle at 50% 15%, #1e1b4b 0%, #09090b 80%);
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }
    .card {
      background: rgba(18, 18, 27, 0.9);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 24px;
      padding: 32px;
      max-width: 500px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
      text-align: center;
    }
    .logo-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(34, 197, 94, 0.15);
      border: 1px solid rgba(34, 197, 94, 0.3);
      color: #4ade80;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 14px;
    }
    h1 {
      font-size: 24px;
      margin: 0 0 8px 0;
      font-weight: 800;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 14px;
      margin: 0 0 20px 0;
      line-height: 1.4;
    }
    .status-banner {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 10px 16px;
      border-radius: 12px;
      margin-bottom: 20px;
      font-size: 14px;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }
    .status-banner.connected {
      background: rgba(34, 197, 94, 0.2);
      color: #4ade80;
      border-color: rgba(34, 197, 94, 0.4);
      padding: 16px;
      font-size: 16px;
    }
    .box {
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 20px;
      text-align: left;
    }
    .box-title {
      font-size: 13px;
      font-weight: 700;
      color: #38bdf8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .input-row {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }
    input[type="text"] {
      flex: 1;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid #334155;
      color: #fff;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 15px;
      outline: none;
    }
    input[type="text"]:focus {
      border-color: #38bdf8;
    }
    .btn {
      background: #2563eb;
      color: #fff;
      border: none;
      padding: 10px 18px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
      white-space: nowrap;
    }
    .btn:hover { background: #1d4ed8; }
    .btn-green { background: #16a34a; }
    .btn-green:hover { background: #15803d; }
    .code-display {
      background: #0f172a;
      border: 2px dashed #38bdf8;
      border-radius: 12px;
      padding: 16px;
      text-align: center;
      margin-top: 10px;
    }
    .code-digits {
      font-size: 36px;
      font-weight: 900;
      font-family: monospace;
      letter-spacing: 4px;
      color: #38bdf8;
    }
    .code-hint {
      font-size: 12px;
      color: #94a3b8;
      margin-top: 6px;
    }
    .qr-container {
      background: #fff;
      padding: 14px;
      border-radius: 16px;
      display: inline-block;
      margin: 10px 0;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .qr-container img {
      display: block;
      width: 220px;
      height: 220px;
      image-rendering: pixelated;
    }
    ol {
      margin: 0;
      padding-left: 20px;
      color: #cbd5e1;
      font-size: 13px;
      line-height: 1.6;
    }
    .connected-card {
      display: none;
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 16px;
      padding: 24px;
      text-align: center;
    }
    .connected-icon { font-size: 54px; margin-bottom: 12px; }
    .connected-title { font-size: 20px; font-weight: 800; color: #4ade80; margin-bottom: 8px; }
    .connected-desc { font-size: 14px; color: #cbd5e1; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo-badge">🛡️ ZAP, QUEM É?</div>
    <h1>Conectar ao WhatsApp</h1>
    <p class="subtitle">Escolha como prefere conectar seu WhatsApp com o assistente anti-golpe.</p>

    <!-- Banner Conectado -->
    <div id="connectedCard" class="connected-card">
      <div class="connected-icon">🎉</div>
      <div class="connected-title">Robô Conectado com Sucesso!</div>
      <div class="connected-desc">
        O <b>Zap, quem é?</b> está online!<br><br>
        Envie qualquer mensagem suspeita ou print pelo WhatsApp para o número conectado que a IA responderá na hora com o laudo de segurança! 🕵️
      </div>
    </div>

    <div id="setupCards">
      <!-- Status Banner -->
      <div id="statusBanner" class="status-banner">
        <span id="statusIcon">⏳</span>
        <span id="statusText">Aguardando conexão com WhatsApp...</span>
      </div>

      <!-- Opção 1: Código de 8 Dígitos -->
      <div class="box">
        <div class="box-title">⚡ Opção 1: Conectar por Código (Sem Câmera)</div>
        <div class="input-row">
          <input type="text" id="phoneInput" placeholder="Ex: 351927618142 (com DDI e DDD)" value="${String(currentStatus.phone || '').replace(/\D/g, '')}">
          <button class="btn" id="btnRequestCode" onclick="requestCode()">Gerar Código</button>
        </div>

        <div id="codeDisplayArea" class="code-display" style="display: none;">
          <div class="code-hint">DIGITE NO SEU WHATSAPP:</div>
          <div id="codeDigits" class="code-digits">----</div>
          <button class="btn" style="margin-top: 10px; padding: 6px 14px; font-size: 12px;" onclick="copyCode()">📋 Copiar Código</button>
        </div>

        <ol style="margin-top: 12px;">
          <li>No WhatsApp do celular, toque nos <b>3 pontinhos</b> (ou Configurações)</li>
          <li>Acesse <b>Aparelhos Conectados</b> &gt; <b>Conectar um aparelho</b></li>
          <li>Toque em <b>"Conectar com número de telefone"</b></li>
          <li>Digite o código gerado acima</li>
        </ol>
      </div>

      <!-- Opção 2: QR Code -->
      <div class="box" style="text-align: center;">
        <div class="box-title" style="justify-content: center;">📷 Opção 2: Escanear com a Câmera</div>
        <div class="qr-container">
          <img id="qrImg" src="data:," alt="QR Code WhatsApp">
        </div>
        <ol style="text-align: left; margin-top: 8px;">
          <li>No WhatsApp, vá em <b>Aparelhos Conectados</b></li>
          <li>Toque em <b>Conectar um aparelho</b></li>
          <li>Aponte a câmera para o QR Code acima</li>
        </ol>
      </div>
    </div>
  </div>

  <script>
    let botAdminKey = sessionStorage.getItem('zap_bot_admin_key') || '';
    let adminKeyPrompted = false;
    let lastQrObjectUrl = '';
    let lastQrUpdatedAt = null;

    function ensureBotAdminKey() {
      if (!botAdminKey && !adminKeyPrompted) {
        adminKeyPrompted = true;
        botAdminKey = prompt('Introduz a chave de administração do servidor:') || '';
        if (botAdminKey) sessionStorage.setItem('zap_bot_admin_key', botAdminKey);
      }
      return botAdminKey;
    }

    async function adminFetch(url, options = {}) {
      const key = ensureBotAdminKey();
      if (!key) throw new Error('É necessária uma chave de administração. Atualiza a página para tentar novamente.');
      const headers = { ...(options.headers || {}), 'x-admin-key': key };
      const response = await fetch(url, { ...options, headers, cache: 'no-store' });
      if (response.status === 401) {
        sessionStorage.removeItem('zap_bot_admin_key');
        botAdminKey = '';
        throw new Error('Chave inválida. Atualiza a página e tenta novamente.');
      }
      return response;
    }

    async function requestCode() {
      const phone = document.getElementById('phoneInput').value.trim();
      if (!phone) {
        alert('Por favor, informe seu número com código do país (ex: 351927618142 ou 5511999999999)');
        return;
      }
      const btn = document.getElementById('btnRequestCode');
      btn.disabled = true;
      btn.textContent = 'Gerando...';

      try {
        const res = await adminFetch('/request-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone })
        });
        const data = await res.json();
        if (data.success && data.code) {
          showCode(data.code);
        } else {
          alert(data.error || 'Não foi possível gerar o código. Tente usar o QR Code.');
        }
      } catch (e) {
        alert('Erro ao contatar o robô local. Verifique se o terminal está rodando.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Gerar Código';
      }
    }

    function showCode(code) {
      document.getElementById('codeDisplayArea').style.display = 'block';
      document.getElementById('codeDigits').textContent = code;
    }

    function copyCode() {
      const code = document.getElementById('codeDigits').textContent.replace('-', '');
      navigator.clipboard.writeText(code);
      alert('Código copiado!');
    }

    async function pollStatus() {
      try {
        const res = await adminFetch('/admin/status?t=' + Date.now());
        if (!res.ok) return;
        const data = await res.json();

        if (data.connected) {
          document.getElementById('setupCards').style.display = 'none';
          document.getElementById('connectedCard').style.display = 'block';
          return;
        }

        if (data.pairingCode && !document.getElementById('codeDigits').textContent.includes(data.pairingCode)) {
          showCode(data.pairingCode);
        }

        if (data.hasQr && data.qrUpdatedAt !== lastQrUpdatedAt) {
          const qrResponse = await adminFetch('/qrcode.png?t=' + Date.now());
          if (qrResponse.ok) {
            const imageBlob = await qrResponse.blob();
            const nextObjectUrl = URL.createObjectURL(imageBlob);
            const image = document.getElementById('qrImg');
            image.src = nextObjectUrl;
            if (lastQrObjectUrl) URL.revokeObjectURL(lastQrObjectUrl);
            lastQrObjectUrl = nextObjectUrl;
            lastQrUpdatedAt = data.qrUpdatedAt;
          }
        }
      } catch (error) {
        const statusText = document.getElementById('statusText');
        if (statusText) statusText.textContent = error.message;
      }
    }

    setInterval(pollStatus, 3000);
    pollStatus();
  </script>
</body>
</html>`;
}

// --------------------------------------------------------------------------
// CONEXÃO BAILEYS
// --------------------------------------------------------------------------
let isStarting = false;
let credentialsSyncQueue = Promise.resolve();
let reconnectTimer = null;
let reconnectAttempts = 0;

function scheduleBotRestart() {
  if (reconnectTimer) return;
  const baseDelay = 3000;
  const maxDelay = 60000;
  const exponentialDelay = Math.min(maxDelay, baseDelay * (2 ** Math.min(reconnectAttempts, 5)));
  const jitter = Math.floor(Math.random() * 1000);
  const delay = exponentialDelay + jitter;
  reconnectAttempts++;
  currentStatus.status = 'reconnecting';
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    startBot();
  }, delay);
  reconnectTimer.unref?.();
}

async function startBot() {
  if (isStarting) return;
  isStarting = true;

  console.log('\n=============================================');
  console.log('🛡️   CONFIRME, QUEM É? — INICIANDO ROBÔ WHATSAPP');
  console.log('=============================================\n');

  currentStatus.status = 'starting';
  currentStatus.connected = false;

  try {
  // Restaura sessão salva no Redis (se estiver rodando na nuvem como Render)
  await restoreSessionFromCloud();

  // Limpeza de salvaguarda: se houver credenciais locais com registered: false, limpa para evitar loop 408
  const credsPath = path.join(AUTH_DIR, 'creds.json');
  if (fs.existsSync(credsPath)) {
    try {
      const credsRaw = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
      if (credsRaw && credsRaw.registered === false) {
        console.log('🧹 Limpando credenciais locais provisórias (registered: false) para permitir novo emparelhamento limpo...');
        fs.rmSync(AUTH_DIR, { recursive: true, force: true });
      }
    } catch (_) {}
  }

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version } = await fetchLatestBaileysVersion();
  console.log(`📡 WhatsApp Web versão: v${version.join('.')}`);

  const sock = makeWASocket({
    version,
    logger,
    printQRInTerminal: false,
    auth: state,
    browser: Browsers.windows('Chrome'),
    generateHighQualityLinkPreview: true,
    connectTimeoutMs: 60000,
    keepAliveIntervalMs: 25000
  });

  currentSock = sock;

  sock.ev.on('creds.update', () => {
    credentialsSyncQueue = credentialsSyncQueue
      .then(async () => {
        await saveCreds();
        await syncSessionToCloud();
      })
      .catch(() => console.error('[WhatsApp] Falha ao guardar credenciais da sessão.'));
  });

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      currentStatus.status = 'awaiting_connection';
      try {
        await QRCodeImage.toFile('./qrcode.png', qr, { width: 400, margin: 2 });
        qrUpdatedAt = new Date().toISOString();
      } catch (e) {}

      if (process.env.NODE_ENV !== 'production') {
        console.log('\n=============================================================');
        console.log('📲 QR CODE PRONTO!');
        console.log(`👉 Abra no navegador:  http://localhost:${PORT}`);
        console.log('👉 No telemóvel: WhatsApp > Aparelhos conectados > Conectar');
        console.log('=============================================================\n');
        qrcode.generate(qr, { small: true });
      }

      // Se solicitado via flag explícita AUTO_PAIRING, gera o código inicial.
      // Por padrão, deixamos o QR Code livre para evitar bloqueios por excesso de requisições.
      if (process.env.AUTO_PAIRING === 'true' && !sock.authState.creds.registered && !currentStatus.pairingCode && currentStatus.phone) {
        setTimeout(async () => {
          try {
            const code = await sock.requestPairingCode(currentStatus.phone);
            const formattedCode = code?.match(/.{1,4}/g)?.join('-') || code;
            currentStatus.pairingCode = formattedCode;
            currentStatus.pairingExpiresAt = Date.now() + 60000;
          } catch (pairErr) {
            console.warn('Aviso pairing code:', pairErr.message);
          }
        }, 2000);
      }
    }

    if (connection === 'close') {
      isStarting = false;
      currentStatus.connected = false;
      if (currentSock === sock) currentSock = null;
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
      
      console.log(`⚠️ Conexão encerrada (Status: ${statusCode || 'desconhecido'}).`);

      if (statusCode === DisconnectReason.loggedOut || (!sock.authState.creds.registered && (statusCode === 408 || statusCode === 401))) {
        console.log('❌ Sessão desconectada ou não registrada. Limpando credenciais...');
        try {
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        } catch (e) {}
        await clearSessionFromCloud();
        currentStatus.pairingCode = null;
        scheduleBotRestart();
      } else if (shouldReconnect) {
        scheduleBotRestart();
      } else {
        currentStatus.status = 'awaiting_connection';
      }
    } else if (connection === 'open') {
      isStarting = false;
      reconnectAttempts = 0;
      currentStatus.connected = true;
      currentStatus.status = 'connected';
      currentStatus.lastError = null;
      currentStatus.pairingCode = null;

      console.log('\n=============================================================');
      console.log('✅✅✅ ROBÔ ZAP, QUEM É? CONECTADO COM SUCESSO! ✅✅✅');
      console.log('Robô 100% ativo! Recebendo mensagens e prints para análise!');
      console.log('=============================================================\n');
    }
  });

  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;

    for (const msg of messages) {
      if (!msg.message || msg.key.fromMe) continue;
      const remoteJid = msg.key.remoteJid;
      if (!remoteJid || remoteJid.endsWith('@g.us') || remoteJid.endsWith('@broadcast') || remoteJid.endsWith('@newsletter')) continue;
      if (msg.key.id && !(await claimIncomingMessage(remoteJid, msg.key.id))) continue;
      if (!(await allowWhatsAppMessage(remoteJid, WHATSAPP_MESSAGES_PER_MINUTE))) {
        console.warn('[WhatsApp] Mensagem ignorada: limite por remetente atingido.');
        continue;
      }

      try {
        let messageContent = msg.message;
        for (let depth = 0; depth < 4; depth++) {
          const wrapper = messageContent?.ephemeralMessage
            || messageContent?.viewOnceMessage
            || messageContent?.viewOnceMessageV2
            || messageContent?.documentWithCaptionMessage;
          if (!wrapper?.message) break;
          messageContent = wrapper.message;
        }
        const messageType = Object.keys(messageContent || {})[0];
        let incomingText = '';
        let imagemBase64 = null;
        let imagemTipo = null;
        let mediaIssue = null;

        if (messageType === 'conversation') {
          incomingText = messageContent.conversation || '';
        } else if (messageType === 'extendedTextMessage') {
          incomingText = messageContent.extendedTextMessage?.text || '';
        } else if (messageType === 'imageMessage') {
          incomingText = messageContent.imageMessage?.caption || '';
          imagemTipo = messageContent.imageMessage?.mimetype || 'image/jpeg';
          const advertisedSize = Number(messageContent.imageMessage?.fileLength?.toString?.() ?? messageContent.imageMessage?.fileLength);
          if (!Number.isFinite(advertisedSize) || advertisedSize <= 0) {
            mediaIssue = 'image_unavailable';
          } else if (advertisedSize > 8 * 1024 * 1024) {
            mediaIssue = 'image_too_large';
          } else {
            try {
              const buffer = await downloadMediaMessage(
                msg,
                'buffer',
                {},
                { logger, reuploadRequest: sock.updateMediaMessage }
              );
              if (buffer && buffer.length <= 8 * 1024 * 1024) {
                imagemBase64 = buffer.toString('base64');
              } else {
                mediaIssue = 'image_too_large';
              }
            } catch {
              mediaIssue = 'image_unavailable';
            }
          }
        } else {
          await sock.sendMessage(remoteJid, { text: 'Este formato ainda não é suportado. Envie texto ou uma imagem até 8 MB.' }, { quoted: msg });
          continue;
        }

        if (mediaIssue) {
          const text = mediaIssue === 'image_too_large'
            ? 'A imagem excede o limite de 8 MB. Envie uma imagem mais pequena.'
            : 'Não consegui abrir esta imagem. Tente enviá-la novamente ou cole o texto da mensagem.';
          await sock.sendMessage(remoteJid, { text }, { quoted: msg });
          continue;
        }

        incomingText = (incomingText || '').trim();
        const lower = incomingText.toLowerCase();

        // Presença "digitando..."
        await sock.sendPresenceUpdate('composing', remoteJid);

        // Protocolo de Emergência para vítimas (Multilíngue)
        const isEmergencyPt = ['fui vitima', 'fui vítima', 'ja paguei', 'já paguei', 'cai no golpe', 'caí no golpe', 'fiz o pix', 'fiz pix', 'já transferi', 'ja transferi', 'me roubaram', 'perdi dinheiro', 'socorro', 'emergencia', 'emergência'].some(t => lower.includes(t));
        const isEmergencyEn = ['victim', 'i got scammed', 'lost money', 'emergency', 'help victim', 'i was scammed', 'scammed'].some(t => lower.includes(t));
        const isEmergencyFr = ['victime', 'arnaque', 'je me suis fait arnaquer', 'urgence'].some(t => lower.includes(t));
        const isEmergencyIt = ['vittima', 'truffa', 'sono stato truffato', 'emergenza'].some(t => lower.includes(t));

        if ((isEmergencyPt || isEmergencyEn || isEmergencyFr || isEmergencyIt) && !imagemBase64) {
          const lang = isEmergencyEn ? 'en' : (isEmergencyFr ? 'fr' : (isEmergencyIt ? 'it' : 'pt'));
          await sock.sendMessage(remoteJid, { text: getEmergencyVictimGuide(lang) }, { quoted: msg });
          continue;
        }

        // ---------------------------------------------------------------------
        // COMANDOS INTERATIVOS PÓS-ANÁLISE (AJUDA, DETALHES, ÚTIL, ERRO)
        // ---------------------------------------------------------------------
        const cleanCmd = lower.normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
        if (['ajuda', 'detalhes', 'util', 'erro'].includes(cleanCmd) && !imagemBase64) {
          cleanOldSessions();
          const session = chatSessions.get(remoteJid);
          const isExpired = !session || (Date.now() - session.timestamp > 24 * 60 * 60 * 1000);

          if (cleanCmd === 'ajuda') {
            await sock.sendMessage(remoteJid, { text: renderHelpResponse() }, { quoted: msg });
            continue;
          }

          if (isExpired) {
            await sock.sendMessage(remoteJid, { text: renderNoSessionResponse() }, { quoted: msg });
            continue;
          }

          if (cleanCmd === 'detalhes') {
            await sock.sendMessage(remoteJid, { text: renderDetailsResponse(session.contract) }, { quoted: msg });
            continue;
          }

          if (cleanCmd === 'util' || cleanCmd === 'erro') {
            console.log(`[Feedback] Comando ${cleanCmd.toUpperCase()} recebido.`);
            if (cleanCmd === 'erro') {
              registarFeedbackErroUtilizador(session).catch(() => {});
            }
            await sock.sendMessage(remoteJid, { text: renderFeedbackResponse(cleanCmd) }, { quoted: msg });
            continue;
          }
        }

        // Boas-vindas / Menu inicial Multilíngue
        const isGreetingEn = ['hi', 'hello', 'hey', 'help'].includes(lower);
        const isGreetingFr = ['bonjour', 'salut', 'aide'].includes(lower);
        const isGreetingIt = ['ciao', 'buongiorno', 'buonasera', 'aiuto'].includes(lower);
        const isGreetingPt = ['oi', 'olá', 'ola', 'menu', 'iniciar', 'start', 'bom dia', 'boa tarde', 'boa noite'].includes(lower);

        if ((!incomingText && !imagemBase64) || (isGreetingPt || isGreetingEn || isGreetingFr || isGreetingIt) && !imagemBase64) {
          let welcome = '';
          if (isGreetingEn) {
            welcome = `Hello! 👋 I'm *Confirme, Who is it?*\n\nForward me any suspicious text message or send a screenshot and I will analyze immediately whether it contains risk signals!\n\n_You can paste text or send an image directly here._\n\n💡 _If you already paid or clicked, reply *AJUDA* or *victim*._`;
          } else if (isGreetingFr) {
            welcome = `Bonjour ! 👋 Je suis *Confirme, Qui est-ce ?*\n\nTransférez-moi tout message suspect ou capture d'écran et j'analyse immédiatement si le message présente des risques !\n\n_Vous pouvez coller le texte ou envoyer l'image ici._\n\n💡 _Si vous êtes déjà victime, répondez *AJUDA* ou *victime*._`;
          } else if (isGreetingIt) {
            welcome = `Ciao! 👋 Sono *Confirme, Chi è?*\n\nInoltrami qualsiasi messaggio sospetto o invia uno screenshot e analizzerò all'istante la presença di rischi!\n\n_Puoi incollare il testo o inviare l'immagine qui._\n\n💡 _Se sei già vittima, rispondi con *AJUDA* o *vittima*._`;
          } else {
            welcome = `Olá! 👋 Eu sou o *Confirme, Quem É?*\n\nMe encaminhe qualquer mensagem suspeita ou envie um print (foto do SMS ou conversa do WhatsApp) que eu analiso na hora se há indícios de burla!\n\n_Pode colar o texto ou enviar a imagem direto aqui._\n\n💡 _Se já clicou ou fez pagamento, envie *AJUDA* para instruções de emergência._`;
          }
          await sock.sendMessage(remoteJid, { text: welcome }, { quoted: msg });
          continue;
        }

        console.log('[WhatsApp] Mensagem privada recebida; a iniciar análise.');

        const resultado = await analyzeContent({
          texto: incomingText || null,
          imagemBase64,
          imagemTipo,
          canal: 'whatsapp_baileys'
        });

        const contract = buildDataContract(resultado, incomingText);
        chatSessions.set(remoteJid, {
          contract,
          analise_id: resultado.analise_id,
          timestamp: Date.now()
        });

        const resposta = formatWhatsAppMessage(resultado, incomingText);
        await sock.sendMessage(remoteJid, { text: resposta }, { quoted: msg });
        console.log('[WhatsApp] Análise concluída e resposta enviada.');

      } catch {
        console.error('[WhatsApp] Falha ao processar ou responder à mensagem.');
        const erroMsg = renderWhatsAppResponse({ template: 'error', level: 'error' });
        try {
          await sock.sendMessage(remoteJid, { text: erroMsg }, { quoted: msg });
        } catch {
          console.error('[WhatsApp] Não foi possível enviar a resposta de erro.');
        }
      }
    }
  });
  } catch (error) {
    isStarting = false;
    currentStatus.connected = false;
    currentStatus.status = 'startup_error';
    currentStatus.lastError = error?.code || error?.name || 'startup_failed';
    console.error('[WhatsApp] Falha ao iniciar o cliente; será feita nova tentativa.');
    scheduleBotRestart();
  }
}

startBot();
