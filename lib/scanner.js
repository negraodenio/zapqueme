// lib/scanner.js — Núcleo de análise compartilhado entre Web e WhatsApp

const SYSTEM_PROMPT = `És um especialista em fraudes e golpes em Portugal e no Brasil.
Analisa a mensagem de texto e/ou a imagem (print de SMS/WhatsApp/email) fornecida.

Responde APENAS com um JSON válido, sem texto antes ou depois, neste formato exato:
{
  "veredito": "golpe" | "suspeito" | "legitimo",
  "confianca": <número de 0 a 100>,
  "risco_score": <número de 0 a 100, onde 0 é risco nulo e 100 é perigo extremo de fraude>,
  "tipo": "falso banco" | "falso parente" | "entrega" | "pix errado" | "premio" | "investimento" | "romance" | "outro",
  "alerta_link": <string curta alertando sobre domínio falso/typosquatting ou link encurtado suspeito, ou null se não houver link suspeito>,
  "sinais": ["sinal 1", "sinal 2", "sinal 3"],
  "explicacao_simples": "2 frases em português simples, sem jargão",
  "acao_recomendada": "1 a 2 frases práticas e diretas",
  "texto_normalizado": "o texto da mensagem (extraído da imagem se for o caso), em minúsculas, com nomes próprios, números de telefone, valores em dinheiro e links substituídos por marcadores genéricos tipo [nome], [numero], [valor], [link] — mantendo a estrutura da frase igual, para permitir comparar se é o mesmo golpe enviado para pessoas diferentes"
}

Regras importantes:
- Considera golpes comuns: SMS falso de entrega/CTT/correios, falso funcionário de banco,
  PIX/transferência enviada por engano, falso parente pedindo dinheiro urgente, prémio/sorteio falso,
  golpe romântico, investimento com retorno garantido irrealista, phishing de login.
- "risco_score": para golpe atribui entre 80 e 99; para suspeito entre 45 e 79; para legítimo entre 5 e 25.
- Nunca atribuas confiança de exatamente 0 ou 100. Usa no máximo 95 e no mínimo 15.
- Se houver links na mensagem, analisa se o domínio tenta imitar marcas oficiais (ex: bancos, CTT, Correios, Netflix, Finanças/Receita) com pequenas alterações ou domínios genéricos (.top, .xyz, traços extras) e detalha em "alerta_link".
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

  // Deduplicação Upstash Redis:
  // Usa o texto enviado (se houver) ou o texto normalizado da IA.
  const textoParaHash = texto && texto.trim().length > 5
    ? texto
    : (parsed.texto_normalizado || texto || '');
  const vezesReportada = await incrementarContador(textoParaHash);
  delete parsed.texto_normalizado;
  parsed.vezes_reportada = vezesReportada;

  // Registro de auditoria no Supabase
  parsed.analise_id = await salvarAnalise(parsed, !!imagemBase64);

  // Radar Corporativo B2B: detecta uso indevido de marcas parceiras
  verificarMarcasEGravarAmeacas(parsed, textoParaHash).catch(() => {});

  return parsed;
}

export function getRiscoBar(score) {
  const blocks = Math.round(score / 10);
  const color = score >= 75 ? '🟥' : score >= 40 ? '🟨' : '🟩';
  const filled = color.repeat(Math.min(10, Math.max(0, blocks)));
  const empty = '⬜'.repeat(Math.max(0, 10 - blocks));
  return `[${filled}${empty}]`;
}

export function formatWhatsAppMessage(data) {
  const score = data.risco_score !== undefined
    ? data.risco_score
    : (data.veredito === 'golpe' ? data.confianca : (data.veredito === 'suspeito' ? 55 : Math.max(5, 100 - data.confianca)));

  const icones = {
    golpe: '🚨 *PROVÁVEL GOLPE*',
    suspeito: '⚠️ *MENSAGEM SUSPEITA*',
    legitimo: '✅ *PARECE LEGÍTIMO*'
  };

  const nivelTexto = score >= 80 ? 'CRÍTICO' : score >= 65 ? 'ALTO' : score >= 40 ? 'MODERADO' : 'BAIXO';
  const barra = getRiscoBar(score);

  const titulo = icones[data.veredito] || `*${data.veredito.toUpperCase()}*`;
  let texto = `${titulo}\n\n`;
  texto += `📊 *Nível de Risco:* ${score}/100 [${nivelTexto}]\n${barra}\n`;

  if (data.vezes_reportada && data.vezes_reportada > 1) {
    texto += `\n🔥 *ALERTA DE MENSAGEM REPETIDA:*\n⚠️ Esta mensagem exata já foi pesquisada *${data.vezes_reportada} vezes* por outras pessoas! Golpistas frequentemente disparam a mesma mensagem em massa.\n`;
  } else {
    texto += `\n🛡️ *Verificação:* 1ª vez que esta mensagem é verificada no nosso sistema.\n`;
  }

  if (data.explicacao_simples) {
    texto += `\n📝 *Por que:* ${data.explicacao_simples}\n`;
  }

  if (data.alerta_link) {
    texto += `\n🔗 *Alerta de Link:* ${data.alerta_link}\n`;
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

  if (data.veredito === 'golpe' || score >= 60) {
    texto += `\n🆘 _Já caiu ou fez o pagamento? Responda com *fui vítima* para ver o protocolo de emergência imediato._\n`;
  }

  texto += `\n---\n_⚡ Zap, quem é? — Verificador instantâneo de golpes_`;
  return texto;
}

export function getEmergencyVictimGuide() {
  return `🆘 *PROTOCOLO DE EMERGÊNCIA — FUI VÍTIMA DE GOLPE* 🆘

Se você já realizou pagamento, PIX ou forneceu senhas/cartão, *AJA AGORA MESMO (CADA MINUTO CONTA)*:

1️⃣ *LIGUE PARA O SEU BANCO IMEDIATAMENTE:*
• *Brasil:* Exija a abertura do *MED (Mecanismo Especial de Devolução do PIX)*. O banco pode rastrear e bloquear o valor na conta do golpista em até 80 dias. Peça também o bloqueio imediato do cartão.
• *Portugal:* Contacte a linha de emergência 24h do seu banco ou da SIBS para cancelar cartões e tentar estornar transferências imediatas.

2️⃣ *NÃO APAGUE A CONVERSA (PRESERVE PROVAS):*
• Tire prints da conversa inteira, do número do golpista, links recebidos, chaves PIX/IBAN e do comprovante com o código de autenticação da transferência.

3️⃣ *REGISTE O BOLETIM DE OCORRÊNCIA / QUEIXA:*
• *Brasil:* Registre online na *Delegacia Eletrônica* da Polícia Civil do seu Estado por estelionato virtual / fraude.
• *Portugal:* Apresente queixa no portal do *Ministério Público / Polícia Judiciária* ou no posto da PSP/GNR.

4️⃣ *BLINDE SUAS CONTAS:*
• Mude senhas do seu e-mail e ative a *Confirmação em Duas Etapas com PIN* no WhatsApp (Configurações → Conta → Confirmação em duas etapas).

---
_⚡ Zap, quem é? — Estamos aqui para ajudar a te proteger!_`;
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
  const normalizado = texto
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w\s]/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
  return crypto.createHash('sha256').update(normalizado || texto.trim().toLowerCase()).digest('hex');
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

async function verificarMarcasEGravarAmeacas(parsed, textoRecebido) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key || !textoRecebido) return;

  try {
    const resp = await fetch(`${url}/rest/v1/empresas_verificadas?status=eq.ativo&select=id,nome,dominio,whatsapp_oficial`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (!resp.ok) return;
    const empresas = await resp.json();
    if (!empresas || empresas.length === 0) return;

    const textoLower = textoRecebido.toLowerCase();

    for (const emp of empresas) {
      const nomeLower = (emp.nome || '').toLowerCase().trim();
      const domainBase = (emp.dominio || '').toLowerCase().split('.')[0];
      const matchName = nomeLower.length >= 3 && textoLower.includes(nomeLower);
      const matchDomain = domainBase && domainBase.length >= 3 && textoLower.includes(domainBase);

      if (matchName || matchDomain) {
        if (parsed.veredito === 'golpe' || parsed.veredito === 'suspeito') {
          await fetch(`${url}/rest/v1/ameacas_detectadas`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              apikey: key,
              Authorization: `Bearer ${key}`
            },
            body: JSON.stringify({
              empresa_id: emp.id,
              canal: 'WhatsApp/Web',
              link_suspeito: parsed.alerta_link || null,
              mensagem_trecho: textoRecebido.slice(0, 300),
              tipo_golpe: parsed.tipo || 'uso indevido de marca',
              score_risco: parsed.risco_score || parsed.confianca || 85,
              notificado: false
            })
          });
        }
      }
    }
  } catch (err) {
    console.debug('Radar de marcas error:', err.message);
  }
}

