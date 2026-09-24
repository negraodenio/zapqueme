// api/whatsapp.js — Twilio WhatsApp Webhook
import { analyzeContent, formatWhatsAppMessage, getEmergencyVictimGuide } from '../lib/scanner.js';

export default async function handler(req, res) {
  console.log(`[WhatsApp Webhook] ${req.method} request received at ${new Date().toISOString()}`);

  if (req.method !== 'POST' && req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }

  try {
    // Parser resiliente que aceita POST (body em objeto, string ou stream) ou GET (query)
    let body = req.body || {};
    if (typeof body === 'string') {
      body = Object.fromEntries(new URLSearchParams(body));
    } else if (Buffer.isBuffer(body)) {
      body = Object.fromEntries(new URLSearchParams(body.toString('utf-8')));
    } else if (typeof body === 'object' && Object.keys(body).length === 0 && req.method === 'GET') {
      body = req.query || {};
    }

    console.log('[WhatsApp Webhook] Received payload:', JSON.stringify(body));

    const incomingText = (body?.Body || '').trim();
    const numMedia = parseInt(body?.NumMedia || '0', 10);
    const mediaUrl = body?.MediaUrl0;
    const mediaContentType = body?.MediaContentType0 || 'image/jpeg';
    const lower = incomingText.toLowerCase();

    // Protocolo de Emergência: se a pessoa já caiu no golpe ou pagou
    const emergencyTriggers = [
      'fui vitima', 'fui vítima', 'ja paguei', 'já paguei', 'cai no golpe', 'caí no golpe',
      'fiz o pix', 'fiz pix', 'já transferi', 'ja transferi', 'me roubaram', 'perdi dinheiro',
      'socorro', 'emergencia', 'emergência'
    ];
    const isEmergency = emergencyTriggers.some(t => lower.includes(t));
    if (isEmergency && numMedia === 0) {
      return sendTwiml(res, getEmergencyVictimGuide());
    }

    // Boas-vindas / Ajuda ou ativação inicial da sandbox ("join...")
    const isGreeting = ['oi', 'olá', 'ola', 'ajuda', 'help', 'menu', 'iniciar', 'start', 'test', 'teste'].includes(lower)
      || lower.startsWith('join ')
      || lower === 'join';

    if ((!incomingText && numMedia === 0) || (isGreeting && numMedia === 0)) {
      const welcome = `Olá! 👋 Eu sou o *Zap, quem é?*\n\nMe encaminhe qualquer mensagem suspeita ou envie um print (foto do SMS ou conversa do WhatsApp) que eu analiso na hora se é golpe ou legítimo! 🕵️\n\n_Pode colar o texto ou enviar a imagem direto aqui._\n\n💡 _Se você já foi vítima de um golpe e precisa de ajuda imediata, envie *fui vítima*._`;
      return sendTwiml(res, welcome);
    }

    let imagemBase64 = null;
    let imagemTipo = null;

    // Se o usuário enviou uma imagem/print
    if (numMedia > 0 && mediaUrl) {
      imagemTipo = mediaContentType;
      const headers = {};
      if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
        const auth = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
        headers['Authorization'] = `Basic ${auth}`;
      }

      try {
        const imgResp = await fetch(mediaUrl, { headers });
        if (imgResp.ok) {
          const arrayBuf = await imgResp.arrayBuffer();
          imagemBase64 = Buffer.from(arrayBuf).toString('base64');
        } else {
          console.warn('[WhatsApp] Falha ao baixar mídia Twilio:', imgResp.status);
        }
      } catch (imgErr) {
        console.warn('[WhatsApp] Erro no download da mídia:', imgErr.message);
      }
    }

    // Executa a análise via Google Gemini
    const resultado = await analyzeContent({
      texto: incomingText || null,
      imagemBase64,
      imagemTipo
    });

    const respostaFormatada = formatWhatsAppMessage(resultado);
    return sendTwiml(res, respostaFormatada);

  } catch (err) {
    console.error('Erro no webhook do WhatsApp:', err);
    return sendTwiml(res, '⚠️ Tive um problema ao analisar essa mensagem agora. Por favor, tente enviar novamente em alguns instantes.');
  }
}

function escapeXml(unsafe) {
  if (!unsafe) return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function sendTwiml(res, messageText) {
  const xmlContent = escapeXml(messageText);
  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Message>
    <Body>${xmlContent}</Body>
  </Message>
</Response>`.trim();

  res.setHeader('Content-Type', 'text/xml');
  return res.status(200).send(twiml);
}
