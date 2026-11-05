// Stores a user's useful/not useful feedback for a specific analysis.
import { checkRateLimit } from '../lib/security.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido.' });
  }

  const limit = await checkRateLimit(req, 'feedback', 10, 60);
  if (limit.unavailable && process.env.NODE_ENV === 'production') {
    return res.status(503).json({ error: 'Feedback temporariamente indisponível.' });
  }
  if (!limit.allowed) return res.status(429).json({ error: 'Limite de feedback excedido.' });

  const { positivo, analise_id: analysisId } = req.body || {};
  if (typeof positivo !== 'boolean' || typeof analysisId !== 'string' || !UUID_RE.test(analysisId)) {
    return res.status(400).json({ error: 'Feedback ou identificador de análise inválido.' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return res.status(200).json({ ok: true, salvo: false });

  try {
    const response = await fetch(`${url}/rest/v1/feedback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: key,
        Authorization: `Bearer ${key}`
      },
      body: JSON.stringify({ positivo, analise_id: analysisId }),
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) {
      console.warn('[Feedback] Supabase insert failed with HTTP', response.status);
      return res.status(200).json({ ok: true, salvo: false });
    }
    return res.status(200).json({ ok: true, salvo: true });
  } catch (error) {
    console.warn('[Feedback] Persistence unavailable:', error.message);
    return res.status(200).json({ ok: true, salvo: false });
  }
}
