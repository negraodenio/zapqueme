// lib/scanner.js — Núcleo de análise compartilhado entre Web e WhatsApp

const SYSTEM_PROMPT = `És um especialista em fraudes e golpes em Portugal e no Brasil.
Analisa a mensagem de texto e/ou a imagem (print de SMS/WhatsApp/email) fornecida.

Responde APENAS com um JSON válido, sem texto antes ou depois, neste formato exato:
{
  "veredito": "golpe" | "suspeito" | "legitimo",
  "confianca": <número de 0 a 100>,
  "tipo": "falso banco" | "falso parente" | "entrega" | "pix errado" | "premio" | "investimento" | "romance" | "outro",
  "sinais": ["sinal 1", "sinal 2", "sinal 3"],
  "explicacao_simples": "2 frases em português simples, sem jargão",
  "acao_recomendada": "1 a 2 frases práticas e diretas",
  "texto_normalizado": "o texto da mensagem (extraído da imagem se for o caso), em minúsculas, com nomes próprios, números de telefone, valores em dinheiro e links substituídos por marcadores genéricos tipo [nome], [numero], [valor], [link] — mantendo a estrutura da frase igual, para permitir comparar se é o mesmo golpe enviado para pessoas diferentes"
}

Regras importantes:
- Considera golpes comuns: SMS falso de entrega/CTT/correios, falso funcionário de banco,
  PIX/transferência enviada por engano, falso parente pedindo dinheiro urgente, prémio/sorteio falso,
  golpe romântico, investimento com retorno garantido irrealista, phishing de login.
- Nunca atribuas confiança de exatamente 0 ou 100. Usa no máximo 95 e no mínimo 15.
- Se não tiveres certeza suficiente, usa "suspeito" em vez de forçar "golpe" ou "legitimo".
- Nunca peças, sugiras pedir, ou repitas dados pessoais sensíveis (números de cartão, senhas, etc).
- "sinais" deve ter entre 2 e 4 itens, curtos e concretos (ex: "Link encurtado suspeito", "Urgência artificial").
- "acao_recomendada" deve ser prática: ex "Não cliques no link. Liga diretamente para o número oficial do banco. Apaga a mensagem."`;

export async function analyzeContent({ texto, imagemBase64, imagemTipo }) {
  if (!texto && !imagemBase64) {
    throw new Error('Envia um texto ou uma imagem.');
  }

  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY não configurada no servidor.');
  }

  // Monta as partes do conteúdo (imagem opcional + texto)
  const parts = [];
  if (imagemBase64) {
    parts.push({
      inlineData: {
        mimeType: imagemTipo || 'image/jpeg',
        data: imagemBase64
      }
    });
  }
  parts.push({
    text: texto
      ? `Analisa esta mensagem: "${texto}"`
      : 'Analisa o print/imagem enviada. Extrai o texto relevante e avalia se é golpe.'
  });

  const candidateModels = process.env.GEMINI_MODEL
    ? [process.env.GEMINI_MODEL]
    : ['gemini-3.5-flash-lite', 'gemini-3.6-flash', 'gemini-3.5-flash'];

  let lastError = null;
  let parsed = null;

  for (const model of candidateModels) {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            systemInstruction: {
              parts: [{ text: SYSTEM_PROMPT }]
            },
            contents: [
              {
                role: 'user',
                parts
              }
            ],
            generationConfig: {
              responseMimeType: 'application/json',
              temperature: 0.2
            }
          })
        }
      );

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`API Gemini [${model}] error: ${response.status} ${errText}`);
      }

      const data = await response.json();
      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      const clean = rawText.replace(/```json|```/g, '').trim();
      parsed = JSON.parse(clean);
      if (parsed) break;
    } catch (err) {
      console.warn(`Tentativa com ${model} falhou:`, err.message);
      lastError = err;
    }
  }

  if (!parsed) {
    throw lastError || new Error('Falha ao obter análise da IA.');
  }

  // Deduplicação Upstash Redis
  const vezesReportada = await incrementarContador(parsed.texto_normalizado || texto || '');
  delete parsed.texto_normalizado;
  parsed.vezes_reportada = vezesReportada;

  // Registro de auditoria no Supabase
  parsed.analise_id = await salvarAnalise(parsed, !!imagemBase64);

  return parsed;
}

export function formatWhatsAppMessage(data) {
  const icones = {
    golpe: '🚨 *PROVÁVEL GOLPE*',
    suspeito: '⚠️ *MENSAGEM SUSPEITA*',
    legitimo: '✅ *PARECE LEGÍTIMO*'
  };

  const titulo = icones[data.veredito] || `*${data.veredito.toUpperCase()}*`;
  let texto = `${titulo} (${data.confianca}% de certeza)\n`;

  if (data.vezes_reportada && data.vezes_reportada > 1) {
    texto += `\n⚠️ _Esta mensagem já foi verificada ${data.vezes_reportada} vezes por outras pessoas._\n`;
  }

  if (data.explicacao_simples) {
    texto += `\n📝 *Por que:* ${data.explicacao_simples}\n`;
  }

  if (data.sinais && data.sinais.length > 0) {
    texto += `\n🔍 *Sinais de alerta:*\n`;
    data.sinais.forEach(s => {
      texto += `• ${s}\n`;
    });
  }

  if (data.acao_recomendada) {
    texto += `\n💡 *O que fazer:*\n${data.acao_recomendada}\n`;
  }

  texto += `\n---\n_⚡ Zap, quem é? — Verificador instantâneo de golpes_`;
  return texto;
}

async function salvarAnalise(parsed, teveImagem) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;

  try {
    const resp = await fetch(`${url}/rest/v1/analises`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: key,
        Authorization: `Bearer ${key}`,
        Prefer: 'return=representation'
      },
      body: JSON.stringify({
        veredito: parsed.veredito,
        confianca: parsed.confianca,
        tipo: parsed.tipo,
        vezes_reportada: parsed.vezes_reportada,
        teve_imagem: teveImagem
      })
    });
    if (!resp.ok) return null;
    const rows = await resp.json();
    return rows?.[0]?.id || null;
  } catch (err) {
    console.error('Erro ao salvar no Supabase:', err);
    return null;
  }
}

async function gerarHash(texto) {
  const crypto = await import('node:crypto');
  return crypto.createHash('sha256').update(texto.trim().toLowerCase()).digest('hex');
}

async function incrementarContador(texto) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !texto) return 1;

  try {
    const hash = await gerarHash(texto);
    const key = `msg:${hash}`;
    const resp = await fetch(`${url}/incr/${key}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!resp.ok) return 1;
    const data = await resp.json();
    return data.result || 1;
  } catch (err) {
    console.error('Erro no contador Redis:', err);
    return 1;
  }
}
