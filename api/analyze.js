// api/analyze.js — Vercel Serverless Function (Web & API)
// Recebe { texto, imagemBase64, imagemTipo } e devolve o veredito da IA em JSON.
import { analyzeContent } from '../lib/scanner.js';

async function checkRateLimit(ip) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !ip) return { allowed: true };

  try {
    const key = `ratelimit:analyze:${ip}`;
    // Pipeline INCR + EXPIRE 60s
    const res = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([
        ['INCR', key],
        ['EXPIRE', key, 60]
      ])
    });

    if (!res.ok) return { allowed: true };
    const results = await res.json();
    const count = results[0]?.result || 1;
    if (count > 10) {
      return { allowed: false, count };
    }
    return { allowed: true, count };
  } catch (err) {
    console.warn('[RateLimit] Falha ao verificar limite no Redis:', err.message);
    return { allowed: true }; // Fail-open para não penalizar usuários se o Redis oscilar
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  // Rate limiting por IP (10 requisições / minuto)
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '127.0.0.1';
  const limitCheck = await checkRateLimit(clientIp);
  if (!limitCheck.allowed) {
    return res.status(429).json({
      error: 'Limite de análises excedido. Por favor, aguarda um momento antes de enviar uma nova mensagem.'
    });
  }

  const { texto, imagemBase64, imagemTipo } = req.body || {};
  if (!texto && !imagemBase64) {
    return res.status(400).json({ error: 'Envia um texto ou uma imagem.' });
  }

  try {
    const parsed = await analyzeContent({ texto, imagemBase64, imagemTipo, canal: 'web' });
    return res.status(200).json(parsed);
  } catch (err) {
    console.error('Erro na análise:', err);
    return res.status(500).json({ error: err.message || 'Falha ao analisar a mensagem. Tenta novamente.' });
  }
}

