// SMS webhook for Twilio and explicitly configured partner integrations.
import { analyzeContent, formatSmsMessage } from '../lib/scanner.js';
import { checkRateLimit, isAuthorizedSmsWebhook, isConfiguredSmsWebhook } from '../lib/security.js';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_MESSAGE_LENGTH = 5_000;

function parseBody(req) {
  const raw = req.body || {};
  if (typeof raw === 'string' || Buffer.isBuffer(raw)) {
    const parsed = Object.fromEntries(new URLSearchParams(raw.toString()));
    return parsed;
  }
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader?.('Allow', 'POST');
    return res.status(405).send('Method Not Allowed');
  }
  if (process.env.NODE_ENV === 'production' && !isConfiguredSmsWebhook()) {
    return res.status(503).json({ error: 'O webhook SMS não está configurado.' });
  }

  const body = parseBody(req);
  const contentType = String(req.headers?.['content-type'] || '').toLowerCase();
  const hasTwilioSignature = Boolean(req.headers?.['x-twilio-signature']);
  if (hasTwilioSignature && !contentType.includes('application/x-www-form-urlencoded')) {
    return res.status(415).send('Unsupported Media Type');
  }
  if (isConfiguredSmsWebhook() && !isAuthorizedSmsWebhook(req, body)) {
    return res.status(401).send('Unauthorized');
  }

  const bodySize = Buffer.byteLength(JSON.stringify(body));
  if (bodySize > MAX_BODY_BYTES) {
    return res.status(413).send('Payload Too Large');
  }

  const incomingText = String(body.Body || body.text || body.message || '').trim();
  const sender = String(body.From || body.sender || '').trim() || 'anonimo';
  const formatParam = String(req.query?.format || '').toLowerCase();
  const wantsJson = formatParam === 'json' || String(req.headers?.accept || '').includes('application/json');

  if (incomingText.length > MAX_MESSAGE_LENGTH) {
    return res.status(413).send('Message Too Long');
  }
  if (!incomingText || ['ajuda', 'help', 'info', 'start', 'zap'].includes(incomingText.toLowerCase())) {
    const help = '[ZAP VERIFICA] Reencaminhe para este numero qualquer SMS suspeito. Analisaremos na hora se e golpe ou autentico. zapqueme.vercel.app';
    if (wantsJson) return res.status(200).json({ success: true, sms_resposta: help });
    return sendTwiml(res, help);
  }

  const limit = await checkRateLimit(req, 'sms', 20, 60);
  if (limit.unavailable && process.env.NODE_ENV === 'production') {
    return res.status(503).send('SMS analysis temporarily unavailable');
  }
  if (!limit.allowed) return res.status(429).send('Too Many Requests');

  try {
    const result = await analyzeContent({ texto: incomingText, canal: 'sms' });
    const responseText = formatSmsMessage(result);
    if (wantsJson) {
      return res.status(200).json({
        success: true,
        canal: 'sms',
        from: sender,
        veredito: result.veredito,
        risco_score: result.risco_score,
        sms_resposta: responseText
      });
    }
    return sendTwiml(res, responseText);
  } catch (error) {
    console.error('[SMS Gateway] Processing failed:', error.message);
    const failure = '[ZAP ALERTA] Não foi possível analisar este SMS agora. Tente novamente mais tarde.';
    if (wantsJson) return res.status(503).json({ success: false, sms_resposta: failure });
    return sendTwiml(res, failure);
  }
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function sendTwiml(res, messageText) {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<Response><Message><Body>${escapeXml(messageText)}</Body></Message></Response>`;
  res.setHeader('Content-Type', 'text/xml; charset=utf-8');
  return res.status(200).send(xml);
}
