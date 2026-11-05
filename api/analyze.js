// Recebe texto e/ou imagem e devolve a análise de risco.
import { analyzeContent } from '../lib/scanner.js';
import { checkRateLimit } from '../lib/security.js';

const MAX_TEXT_LENGTH = 12_000;
const MAX_IMAGE_BASE64_LENGTH = 4 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido.' });
  }

  const limit = await checkRateLimit(req, 'analyze', 10, 60);
  if (limit.unavailable && process.env.NODE_ENV === 'production') {
    return res.status(503).json({ error: 'Análise temporariamente indisponível. Tenta novamente mais tarde.' });
  }
  if (!limit.allowed) {
    return res.status(429).json({ error: 'Limite de análises excedido. Aguarda um momento antes de tentar novamente.' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Pedido inválido.' });
  }

  let texto = body.texto;
  let imagemBase64 = body.imagemBase64;
  let imagemTipo = body.imagemTipo;

  if (texto !== undefined && typeof texto !== 'string') {
    return res.status(400).json({ error: 'O texto tem um formato inválido.' });
  }
  if (typeof texto === 'string' && texto.length > MAX_TEXT_LENGTH) {
    return res.status(413).json({ error: `O texto excede o limite de ${MAX_TEXT_LENGTH} caracteres.` });
  }

  if (imagemBase64 !== undefined && imagemBase64 !== null && imagemBase64 !== '') {
    if (typeof imagemBase64 !== 'string') {
      return res.status(400).json({ error: 'A imagem tem um formato inválido.' });
    }
    const dataUrl = imagemBase64.match(/^data:(image\/(?:jpeg|png|webp));base64,([\s\S]+)$/i);
    if (dataUrl) {
      imagemTipo = dataUrl[1].toLowerCase();
      imagemBase64 = dataUrl[2];
    }
    imagemTipo = typeof imagemTipo === 'string' ? imagemTipo.toLowerCase() : 'image/jpeg';
    if (!ALLOWED_IMAGE_TYPES.has(imagemTipo)) {
      return res.status(415).json({ error: 'Formato de imagem não suportado. Usa JPEG, PNG ou WebP.' });
    }
    if (imagemBase64.length > MAX_IMAGE_BASE64_LENGTH || !/^[A-Za-z0-9+/]+={0,2}$/.test(imagemBase64) || imagemBase64.length % 4 !== 0) {
      return res.status(413).json({ error: 'A imagem é inválida ou excede o tamanho permitido.' });
    }
    const decodedLength = Buffer.from(imagemBase64, 'base64').length;
    if (decodedLength > 3 * 1024 * 1024) {
      return res.status(413).json({ error: 'A imagem excede o limite de 3 MB.' });
    }
  } else {
    imagemBase64 = undefined;
  }

  if (!(texto?.trim()) && !imagemBase64) {
    return res.status(400).json({ error: 'Envia um texto ou uma imagem.' });
  }

  try {
    const result = await analyzeContent({ texto: texto?.trim() || '', imagemBase64, imagemTipo, canal: 'web' });
    return res.status(200).json(result);
  } catch (error) {
    console.error('[Analyze] Processing failed:', error.message);
    return res.status(500).json({ error: 'Falha ao analisar a mensagem. Tenta novamente.' });
  }
}
