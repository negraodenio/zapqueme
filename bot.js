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
import { analyzeContent, formatWhatsAppMessage, getEmergencyVictimGuide } from './lib/scanner.js';
import { restoreSessionFromCloud, syncSessionToCloud, clearSessionFromCloud } from './lib/session_store.js';

const logger = pino({ level: 'silent' });
const AUTH_DIR = './auth_info_baileys';
const PORT = process.env.PORT || 3333;

let currentSock = null;
let currentStatus = {
  connected: false,
  status: 'starting',
  phone: process.env.WHATSAPP_PHONE || '351927618142',
  pairingCode: null,
  pairingExpiresAt: null,
  qrBase64: null,
  lastError: null
};

// --------------------------------------------------------------------------
// SERVIDOR WEB LOCAL (http://localhost:3333)
// --------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  // 1. Status JSON
  if (url.pathname === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(currentStatus));
  }

  // 2. Imagem QR Code
  if (url.pathname === '/qrcode.png') {
    if (fs.existsSync('./qrcode.png')) {
      const img = fs.readFileSync('./qrcode.png');
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-cache' });
      return res.end(img);
    } else {
      res.writeHead(404);
      return res.end('QR not ready');
    }
  }

  // 3. Solicitar novo Código de Emparelhamento sob demanda
  if (url.pathname === '/request-code' && (req.method === 'POST' || req.method === 'GET')) {
    const phoneParam = url.searchParams.get('phone') || currentStatus.phone;
    const cleanPhone = phoneParam.replace(/\D/g, '');

    if (!cleanPhone || cleanPhone.length < 8) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Número de telefone inválido' }));
    }

    currentStatus.phone = cleanPhone;

    if (!currentSock || currentStatus.connected) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'WhatsApp já conectado ou inicializando.' }));
    }

    try {
      console.log(`\n⏳ Solicitando Código de Emparelhamento via Painel para +${cleanPhone}...`);
      const code = await currentSock.requestPairingCode(cleanPhone);
      const formattedCode = code?.match(/.{1,4}/g)?.join('-') || code;
      
      currentStatus.pairingCode = formattedCode;
      currentStatus.pairingExpiresAt = Date.now() + 60000; // 60 segundos
      
      console.log(`🔑 NOVO CÓDIGO GERADO: [ ${formattedCode} ] para +${cleanPhone}`);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: true, code: formattedCode }));
    } catch (err) {
      console.error('Erro ao gerar código:', err.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: err.message || 'Falha ao solicitar código' }));
    }
  }

  // 4. Página Principal (HTML)
  if (url.pathname === '/' || url.pathname === '/qr.html') {
    const html = getDashboardHtml();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🌐 PAINEL DE CONEXÃO DISPONÍVEL EM: http://localhost:${PORT}\n`);
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
          <input type="text" id="phoneInput" placeholder="Ex: 351927618142 (com DDI e DDD)" value="${currentStatus.phone || ''}">
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
          <img id="qrImg" src="/qrcode.png" alt="QR Code WhatsApp">
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
        const res = await fetch('/request-code?phone=' + encodeURIComponent(phone));
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
        const res = await fetch('/status?t=' + Date.now());
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

        document.getElementById('qrImg').src = '/qrcode.png?t=' + Date.now();
      } catch (e) {}
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

async function startBot() {
  if (isStarting) return;
  isStarting = true;

  console.log('\n=============================================');
  console.log('🛡️   ZAP, QUEM É? — INICIANDO ROBÔ WHATSAPP');
  console.log('=============================================\n');

  currentStatus.status = 'starting';
  currentStatus.connected = false;

  // Restaura sessão salva no Redis (se estiver rodando na nuvem como Render)
  await restoreSessionFromCloud();

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version } = await fetchLatestBaileysVersion();
  console.log(`📡 WhatsApp Web versão: v${version.join('.')}`);

  const sock = makeWASocket({
    version,
    logger,
    printQRInTerminal: false,
    auth: state,
    browser: Browsers.ubuntu('Chrome'),
    generateHighQualityLinkPreview: true,
    connectTimeoutMs: 60000,
    keepAliveIntervalMs: 25000
  });

  currentSock = sock;

  sock.ev.on('creds.update', async () => {
    await saveCreds();
    await syncSessionToCloud();
  });

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      currentStatus.status = 'awaiting_connection';
      try {
        await QRCodeImage.toFile('./qrcode.png', qr, { width: 400, margin: 2 });
      } catch (e) {}

      console.log('\n=============================================================');
      console.log('📲 QR CODE PRONTO!');
      console.log(`👉 Abra no navegador:  http://localhost:${PORT}`);
      console.log('=============================================================\n');
      qrcode.generate(qr, { small: true });

      // Se tiver número padrão configurado e não estiver pareado, gera pairing code inicial
      if (!sock.authState.creds.registered && !currentStatus.pairingCode && currentStatus.phone) {
        setTimeout(async () => {
          try {
            console.log(`\n⏳ Solicitando Código de Emparelhamento inicial para +${currentStatus.phone}...`);
            const code = await sock.requestPairingCode(currentStatus.phone);
            const formattedCode = code?.match(/.{1,4}/g)?.join('-') || code;
            currentStatus.pairingCode = formattedCode;
            console.log(`🔑 CÓDIGO INICIAL: [ ${formattedCode} ]  (Digite no celular ou veja em http://localhost:${PORT})\n`);
          } catch (pairErr) {
            // normal se já registrado ou se expirar
          }
        }, 2000);
      }
    }

    if (connection === 'close') {
      isStarting = false;
      currentStatus.connected = false;
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
      
      console.log(`⚠️ Conexão encerrada (Status: ${statusCode || 'desconhecido'}).`);

      if (statusCode === DisconnectReason.loggedOut) {
        console.log('❌ Sessão desconectada pelo WhatsApp. Limpando credenciais...');
        try {
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        } catch (e) {}
        await clearSessionFromCloud();
        currentStatus.pairingCode = null;
        setTimeout(startBot, 3000);
      } else if (shouldReconnect) {
        console.log('🔄 Reconectando ao WhatsApp em 5 segundos...');
        currentStatus.status = 'reconnecting';
        setTimeout(startBot, 5000);
      }
    } else if (connection === 'open') {
      isStarting = false;
      currentStatus.connected = true;
      currentStatus.status = 'connected';
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
      if (remoteJid.includes('@broadcast') || remoteJid.includes('status@broadcast')) continue;

      try {
        const messageType = Object.keys(msg.message)[0];
        let incomingText = '';
        let imagemBase64 = null;
        let imagemTipo = null;

        if (messageType === 'conversation') {
          incomingText = msg.message.conversation || '';
        } else if (messageType === 'extendedTextMessage') {
          incomingText = msg.message.extendedTextMessage?.text || '';
        } else if (messageType === 'imageMessage') {
          incomingText = msg.message.imageMessage?.caption || '';
          imagemTipo = msg.message.imageMessage?.mimetype || 'image/jpeg';
          try {
            const buffer = await downloadMediaMessage(
              msg,
              'buffer',
              {},
              { logger, reuploadRequest: sock.updateMediaMessage }
            );
            if (buffer) {
              imagemBase64 = buffer.toString('base64');
            }
          } catch (imgErr) {
            console.warn('[Mídia] Falha ao baixar imagem:', imgErr.message);
          }
        }

        incomingText = (incomingText || '').trim();
        const lower = incomingText.toLowerCase();

        // Presença "digitando..."
        await sock.sendPresenceUpdate('composing', remoteJid);

        // Protocolo de Emergência para vítimas
        const emergencyTriggers = [
          'fui vitima', 'fui vítima', 'ja paguei', 'já paguei', 'cai no golpe', 'caí no golpe',
          'fiz o pix', 'fiz pix', 'já transferi', 'ja transferi', 'me roubaram', 'perdi dinheiro',
          'socorro', 'emergencia', 'emergência'
        ];
        if (emergencyTriggers.some(t => lower.includes(t)) && !imagemBase64) {
          await sock.sendMessage(remoteJid, { text: getEmergencyVictimGuide() }, { quoted: msg });
          continue;
        }

        // Boas-vindas / Menu inicial
        const isGreeting = ['oi', 'olá', 'ola', 'ajuda', 'help', 'menu', 'iniciar', 'start', 'bom dia', 'boa tarde', 'boa noite'].includes(lower);
        if ((!incomingText && !imagemBase64) || (isGreeting && !imagemBase64)) {
          const welcome = `Olá! 👋 Eu sou o *Zap, quem é?*\n\nMe encaminhe qualquer mensagem suspeita ou envie um print (foto do SMS ou conversa do WhatsApp) que eu analiso na hora se é golpe ou legítimo! 🕵️\n\n_Pode colar o texto ou enviar a imagem direto aqui._\n\n💡 _Se você já foi vítima de um golpe e precisa de ajuda imediata, envie *fui vítima*._`;
          await sock.sendMessage(remoteJid, { text: welcome }, { quoted: msg });
          continue;
        }

        console.log(`\n📩 Mensagem recebida de ${remoteJid}: "${incomingText.slice(0, 60)}"`);
        console.log('🤖 Analisando com IA (OpenRouter / Gemini)...');

        const resultado = await analyzeContent({
          texto: incomingText || null,
          imagemBase64,
          imagemTipo
        });

        const resposta = formatWhatsAppMessage(resultado);
        await sock.sendMessage(remoteJid, { text: resposta }, { quoted: msg });
        console.log(`✅ Resposta enviada para ${remoteJid} (Veredito: ${resultado.veredito}, Score: ${resultado.risco_score})`);

      } catch (err) {
        console.error('❌ Erro ao processar mensagem:', err);
        await sock.sendMessage(
          remoteJid,
          { text: '⚠️ Tive um problema momentâneo ao analisar essa mensagem. Por favor, tente enviar novamente em instantes.' },
          { quoted: msg }
        );
      }
    }
  });
}

startBot().catch(console.error);
