// api/whatsapp.js — Twilio WhatsApp Sandbox Webhook
import { analyzeContent, formatWhatsAppMessage } from '../lib/scanner.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  try {
    // Parser resiliente de application/x-www-form-urlencoded (padrão da Twilio)
    let body = req.body;
    if (typeof body === 'string') {
      body = Object.fromEntries(new URLSearchParams(body));
    } else if (!body || typeof body !== 'object') {
      const buffers = [];
      for await (const chunk of req) {
        buffers.push(chunk);
      }
      const raw = Buffer.concat(buffers).toString();
      body = Object.fromEntries(new URLSearchParams(raw));
    }

    const incomingText = (body?.Body || '').trim();
    const numMedia = parseInt(body?.NumMedia || '0', 10);
    const mediaUrl = body?.MediaUrl0;
    const mediaContentType = body?.MediaContentType0 || 'image/jpeg';

    // Boas-vindas / Ajuda ou ativação inicial da sandbox ("join...")
    const lower = incomingText.toLowerCase();
    const isGreeting = ['oi', 'olá', 'ola', 'ajuda', 'help', 'menu', 'iniciar', 'start'].includes(lower)
      || lower.startsWith('join ');

    if ((!incomingText && numMedia === 0) || (isGreeting && numMedia === 0)) {
      const welcome = `Olá! 👋 Eu sou o *Zap, quem é?*\n\nMe encaminhe qualquer mensagem suspeita ou envie um print (foto do SMS ou conversa do WhatsApp) que eu analiso na hora se é golpe ou legítimo! 🕵️\n\n_Pode colar o texto ou enviar a imagem direto aqui._`;
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

      const imgResp = await fetch(mediaUrl, { headers });
      if (!imgResp.ok) {
        return sendTwiml(res, '⚠️ Não consegui carregar a imagem enviada. Tenta enviar o texto copiado ou mandar a foto novamente.');
      }
      const arrayBuf = await imgResp.arrayBuffer();
      imagemBase64 = Buffer.from(arrayBuf).toString('base64');
    }

    // Executa a análise via Google Gemini 2.0 Flash
    const resultado = await analyzeContent({
      texto: incomingText || null,
      imagemBase64,
      imagemTipo
    });

    const respostaFormatada = formatWhatsAppMessage(resultado);
    return sendTwiml(res, respostaFormatada);

  } catch (err) {
    console.error('Erro no webhook do WhatsApp:', err);
    return sendTwiml(res, '⚠️ Tive um problema ao analisar essa mensagem agora. Por favor, tente novamente em alguns instantes.');
  }
}

function sendTwiml(res, messageText) {
  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Message><![CDATA[${messageText}]]></Message>
</Response>`;

  res.setHeader('Content-Type', 'text/xml; charset=utf-8');
  return res.status(200).send(twiml);
}
