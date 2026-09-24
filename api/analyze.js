// api/analyze.js — Vercel Serverless Function (Web & API)
// Recebe { texto, imagemBase64, imagemTipo } e devolve o veredito da IA em JSON.
import { analyzeContent } from '../lib/scanner.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  const { texto, imagemBase64, imagemTipo } = req.body || {};
  if (!texto && !imagemBase64) {
    return res.status(400).json({ error: 'Envia um texto ou uma imagem.' });
  }

  try {
    const parsed = await analyzeContent({ texto, imagemBase64, imagemTipo });
    return res.status(200).json(parsed);
  } catch (err) {
    console.error('Erro na análise:', err);
    return res.status(500).json({ error: err.message || 'Falha ao analisar a mensagem. Tenta novamente.' });
  }
}
