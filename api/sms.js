// api/sms.js — Webhook & Gateway de SMS (Twilio, Telcos & Parceiros B2B)
import { analyzeContent, formatSmsMessage } from '../lib/scanner.js';

export default async function handler(req, res) {
  console.log(`[SMS Gateway] ${req.method} request received at ${new Date().toISOString()}`);

  if (req.method !== 'POST' && req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }

  try {
    // Parser resiliente que aceita POST (body em objeto, URLSearchParams, buffer) ou GET
    let body = req.body || {};
    if (typeof body === 'string') {
      body = Object.fromEntries(new URLSearchParams(body));
    } else if (Buffer.isBuffer(body)) {
      body = Object.fromEntries(new URLSearchParams(body.toString('utf-8')));
    } else if (typeof body === 'object' && Object.keys(body).length === 0 && req.method === 'GET') {
      body = req.query || {};
    }

    // Identifica texto e remetente (compatível com Twilio, Sinch, Plivo e gateways padrão)
    const incomingText = (body?.Body || body?.text || body?.message || req.query?.Body || req.query?.text || '').trim();
    const sender = (body?.From || body?.sender || req.query?.From || 'anonimo').trim();
    const reqHeaders = req.headers || {};
    const formatParam = (req.query?.format || (reqHeaders['accept']?.includes('application/json') ? 'json' : 'twiml')).toLowerCase();

    console.log(`[SMS Gateway] Mensagem de ${sender}: "${incomingText.slice(0, 80)}"`);

    // Mensagem de boas-vindas / Ajuda se vier vazio ou comando de teste
    if (!incomingText || ['ajuda', 'help', 'info', 'start', 'zap'].includes(incomingText.toLowerCase())) {
      const ajudaSms = '[ZAP VERIFICA] Reencaminhe para este numero qualquer SMS suspeito. Analisaremos na hora se e golpe ou autentico. zapqueme.vercel.app';
      if (formatParam === 'json' || reqHeaders['content-type']?.includes('application/json')) {
        return res.status(200).json({ success: true, sms_resposta: ajudaSms });
      }
      return sendTwiml(res, ajudaSms);
    }

    // Executa análise pelo motor de inteligência e threat radar
    const resultado = await analyzeContent({
      texto: incomingText,
      canal: 'sms',
      remetente: sender
    });

    const respostaSms = formatSmsMessage(resultado);

    // Resposta em JSON para integrações de API B2B (MEO, Galp, etc.)
    if (formatParam === 'json' || reqHeaders['content-type']?.includes('application/json')) {
      return res.status(200).json({
        success: true,
        canal: 'sms',
        from: sender,
        veredito: resultado.veredito,
        risco_score: resultado.risco_score,
        marca_mencionada: resultado.marca_mencionada || null,
        sms_resposta: respostaSms,
        analise: resultado
      });
    }

    // Resposta padrão TwiML / XML para operadoras e Twilio SMS
    return sendTwiml(res, respostaSms);

  } catch (err) {
    console.error('[SMS Gateway] Erro ao processar SMS:', err);
    const erroMsg = '[ZAP ALERTA] Nao foi possivel analisar este SMS agora. Tente novamente em instantes.';
    return sendTwiml(res, erroMsg);
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

  res.setHeader('Content-Type', 'text/xml; charset=utf-8');
  return res.status(200).send(twiml);
}
