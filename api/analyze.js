// api/analyze.js — Vercel Serverless Function
// Recebe { texto, imagemBase64, imagemTipo } e devolve o veredito da IA.

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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  const { texto, imagemBase64, imagemTipo } = req.body || {};
  if (!texto && !imagemBase64) {
    return res.status(400).json({ error: 'Envia um texto ou uma imagem.' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY não configurada no servidor.' });
  }

  // Monta o conteúdo da mensagem (texto + imagem opcional)
  const content = [];
  if (imagemBase64) {
    content.push({
      type: 'image',
      source: {
        type: 'base64',
        media_type: imagemTipo || 'image/jpeg',
        data: imagemBase64
      }
    });
  }
  content.push({
    type: 'text',
    text: texto
      ? `Analisa esta mensagem: "${texto}"`
      : 'Analisa o print/imagem enviada. Extrai o texto relevante e avalia se é golpe.'
  });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 500,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content }]
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`API error: ${response.status} ${errText}`);
    }

    const data = await response.json();
    const rawText = data.content?.find(b => b.type === 'text')?.text || '';

    // Remove eventuais fences de markdown antes de fazer parse
    const clean = rawText.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    // Deduplicação: conta quantas vezes essa mesma mensagem (normalizada) já foi checada.
    // Usa o texto_normalizado devolvido pela IA (nomes/números/links já removidos),
    // para pegar o mesmo golpe mesmo quando o número ou o valor muda de vítima pra vítima.
    const vezesReportada = await incrementarContador(parsed.texto_normalizado || texto || '');
    delete parsed.texto_normalizado; // não precisa ir pro frontend
    parsed.vezes_reportada = vezesReportada;

    // Salva a análise no Supabase (se configurado) para métricas depois.
    // Devolve o id da linha para o frontend poder ligar o feedback 👍/👎 a esta análise específica.
    parsed.analise_id = await salvarAnalise(parsed, !!imagemBase64);

    return res.status(200).json(parsed);
  } catch (err) {
    console.error('Erro na análise:', err);
    return res.status(500).json({ error: 'Falha ao analisar a mensagem. Tenta novamente.' });
  }
}

// Salva a análise na tabela `analises` do Supabase e devolve o id gerado.
// Se as variáveis de ambiente do Supabase não estiverem configuradas, devolve null
// (modo degradado: a análise continua funcionando, só sem histórico/métricas).
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
    if (!resp.ok) {
      console.error('Supabase insert falhou:', await resp.text());
      return null;
    }
    const rows = await resp.json();
    return rows?.[0]?.id || null;
  } catch (err) {
    console.error('Erro ao salvar no Supabase:', err);
    return null; // nunca deixa o Supabase quebrar a análise principal
  }
}
async function gerarHash(texto) {
  const crypto = await import('node:crypto');
  return crypto.createHash('sha256').update(texto.trim().toLowerCase()).digest('hex');
}

// Incrementa o contador desse hash no Upstash Redis e devolve o novo valor.
// Se as variáveis de ambiente do Upstash não estiverem configuradas, devolve 1
// (modo degradado: a análise continua funcionando, só sem o contador social).
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
    return 1; // nunca deixa o contador quebrar a análise principal
  }
}
