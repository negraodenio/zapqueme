// api/feedback.js — Salva o feedback (👍/👎) na tabela `feedback` do Supabase,
// ligado à análise original pelo analise_id devolvido por /api/analyze.

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  const { positivo, analise_id } = req.body || {};
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    // Modo degradado: Supabase não configurado, só loga (comportamento antigo).
    console.log('[feedback]', positivo ? '👍' : '👎', new Date().toISOString());
    return res.status(200).json({ ok: true, salvo: false });
  }

  try {
    const resp = await fetch(`${url}/rest/v1/feedback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: key,
        Authorization: `Bearer ${key}`
      },
      body: JSON.stringify({ positivo: !!positivo, analise_id: analise_id || null })
    });
    if (!resp.ok) {
      console.error('Supabase feedback insert falhou:', await resp.text());
      return res.status(200).json({ ok: true, salvo: false });
    }
    return res.status(200).json({ ok: true, salvo: true });
  } catch (err) {
    console.error('Erro ao salvar feedback:', err);
    return res.status(200).json({ ok: true, salvo: false }); // nunca falha pro usuário por causa disso
  }
}
