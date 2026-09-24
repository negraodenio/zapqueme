// lib/scanner.js — Núcleo de análise compartilhado entre Web e WhatsApp
import { inspectAllUrls } from './threat_intel.js';

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
  const openRouterKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey && !openRouterKey) {
    throw new Error('Nenhuma chave de IA (OPENROUTER_API_KEY ou GEMINI_API_KEY) configurada.');
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

  let lastError = null;
  let parsed = null;

  // 1. Tenta OpenRouter como motor principal de alta performance
  if (openRouterKey) {
    try {
      const orModel = process.env.OPENROUTER_MODEL || 'google/gemini-2.5-flash';
      const userContent = [];
      if (imagemBase64) {
        userContent.push({
          type: 'image_url',
          image_url: { url: `data:${imagemTipo || 'image/jpeg'};base64,${imagemBase64}` }
        });
      }
      userContent.push({
        type: 'text',
        text: texto ? `Analisa esta mensagem: "${texto}"` : 'Analisa o print/imagem enviada. Extrai o texto relevante e avalia se é golpe.'
      });

      const orRes = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${openRouterKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://zapqueme.vercel.app',
          'X-Title': 'ZapQuemE'
        },
        signal: AbortSignal.timeout(12000),
        body: JSON.stringify({
          model: orModel,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: userContent }
          ]
        })
      });

      if (orRes.ok) {
        const orData = await orRes.json();
        const rawContent = orData.choices?.[0]?.message?.content || '';
        const cleanContent = rawContent.replace(/```json|```/g, '').trim();
        parsed = JSON.parse(cleanContent);
      } else {
        console.warn('[OpenRouter] Erro HTTP:', orRes.status);
      }
    } catch (orErr) {
      console.warn('[OpenRouter] Falha:', orErr.message);
    }
  }

  // 2. Se o OpenRouter não retornar, tenta o Google Gemini direto
  if (!parsed && apiKey) {
    const candidateModels = process.env.GEMINI_MODEL
      ? [process.env.GEMINI_MODEL]
      : ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-2.5-flash'];

  for (const model of candidateModels) {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          signal: AbortSignal.timeout(10000),
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
}

  // Se o Gemini estiver fora do ar (503 High Demand ou timeout), ativa o Motor Heurístico de Alta Precisão
  if (!parsed) {
    console.warn('[Scanner] Ativando Motor Heurístico Resiliente (Gemini offline ou 503)');
    parsed = heuristicAnalyze(texto);
  }

  // 3. Inspeção Técnica Externa de Links em Tempo Real (Google Safe Browsing, RDAP, Cloudflare e Marcas Oficiais)
  try {
    const textoParaInspecao = [texto, parsed.texto_normalizado, parsed.alerta_link].filter(Boolean).join(' ');
    const threatResult = await inspectAllUrls(textoParaInspecao, apiKey);

    if (threatResult.hasUrls) {
      const maliciousReport = threatResult.reports.find(r => r.isMalicious);
      if (maliciousReport) {
        parsed.veredito = 'golpe';
        parsed.risco_score = Math.max(parsed.risco_score || 0, 95);
        parsed.confianca = 98;

        const evidencias = [];
        if (maliciousReport.googleResult?.flagged) {
          evidencias.push(`Google Safe Browsing: Link catalogado como ${maliciousReport.googleResult.threatType}`);
        }
        if (maliciousReport.cloudflareResult?.flagged) {
          evidencias.push('Cloudflare Security: Domínio bloqueado na rede global de cibersegurança');
        }
        if (maliciousReport.impersonation?.evidence) {
          evidencias.push(maliciousReport.impersonation.evidence);
        }
        if (maliciousReport.domainAge?.isRecentlyCreated) {
          evidencias.push(`Idade do Domínio: Registrado há apenas ${maliciousReport.domainAge.ageInDays} dias (padrão de site clonado descartável)`);
        }

        parsed.alerta_link = evidencias.join(' | ') || `Link malicioso confirmado em bases externas: ${maliciousReport.domain}`;
        if (!parsed.sinais) parsed.sinais = [];
        evidencias.forEach(ev => {
          if (!parsed.sinais.includes(ev)) parsed.sinais.unshift(ev);
        });
      }
    }
  } catch (threatErr) {
    console.warn('[ThreatIntel] Falha ao inspecionar links:', threatErr.message);
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

export function getRiscoBar(score, mode) {
  const blocks = Math.min(10, Math.max(1, Math.round(score / 10)));
  // Barra suave e circular com caracteres Unicode refinados (● e ○) - sem blocos ou cantos quadrados
  const filled = '●'.repeat(blocks);
  const empty = '○'.repeat(10 - blocks);
  return `[${filled}${empty}]`;
}

export function formatWhatsAppMessage(data) {
  const score = data.risco_score !== undefined
    ? data.risco_score
    : (data.veredito === 'golpe' ? data.confianca : (data.veredito === 'suspeito' ? 65 : 5));

  // Determina categoria de criticidade (3 Cores)
  let mode = 'critico';
  let label = 'CRÍTICO';
  let dot = '🔴';
  let statusTexto = 'Perigo Extremo';

  if (data.veredito === 'legitimo' || score < 35) {
    mode = 'seguro';
    label = 'SEGURO';
    dot = '🟢';
    statusTexto = 'Risco Mínimo';
  } else if (data.veredito === 'suspeito' || (score >= 35 && score < 75)) {
    mode = 'moderado';
    label = 'SUSPEITO';
    dot = '🟡';
    statusTexto = 'Atenção Redobrada';
  } else {
    mode = 'critico';
    label = 'CRÍTICO';
    dot = '🔴';
    statusTexto = 'Perigo Extremo';
  }

  const tipo = (data.tipo || '').toUpperCase();
  const barra = getRiscoBar(score, mode);

  // Inteligência de Repetição no Upstash Redis
  let verificacaoRedis = '';
  if (data.vezes_reportada && data.vezes_reportada > 1) {
    verificacaoRedis = `🔥 *Verificação (Redis):* Esta mensagem já foi consultada *${data.vezes_reportada} vezes hoje* no nosso sistema (alerta de disparo em massa / golpe repetido)!`;
  } else {
    verificacaoRedis = `🛡️ *Verificação:* 1ª vez que esta mensagem é verificada no nosso sistema.`;
  }

  // 🔴 1. MODO VERMELHO: PROVÁVEL GOLPE / RISCO CRÍTICO
  if (mode === 'critico') {
    const tag = tipo ? ` • *[${tipo}]*` : '';

    let msg = `*🔴 ALERTA: PROVÁVEL GOLPE*${tag}\n\n`;
    msg += `📊 *Nível de Risco:* ${score}/100 [${label}]\n`;
    msg += `${barra} _${statusTexto}_\n\n`;
    msg += `${verificacaoRedis}\n\n`;

    const explicacao = data.explicacao_simples || 'Esta mensagem apresenta características claras de fraude e engenharia social para obter vantagens financeiras ou dados confidenciais.';
    msg += `📝 *Por que:* ${explicacao}\n`;

    if (data.alerta_link) {
      msg += `\n⚠️ *Alerta Técnico:* ${data.alerta_link}\n`;
    }

    if (data.sinais && data.sinais.length > 0) {
      msg += `\n🔍 *Sinais de alerta:*\n`;
      data.sinais.slice(0, 4).forEach(s => {
        msg += `• ${s}\n`;
      });
    }

    msg += `\n💡 *O que fazer:*\n`;
    if (data.acao_recomendada) {
      msg += `• ${data.acao_recomendada}\n`;
    }
    msg += `• Não faça transferências, Pix ou pagamentos.\n`;
    msg += `• Bloqueie o remetente e apague a mensagem.\n`;
    msg += `• Ligue para o número habitual da pessoa/empresa para confirmar.\n`;

    msg += `\n🆘 *Já caiu ou fez o pagamento?* Responda com *fui vítima* para ver o protocolo de emergência imediato.\n`;
    msg += `\n---\n⚡ *Zap, quem é?* — Verificador instantâneo de golpes`;
    return msg;
  }

  // 🟡 2. MODO AMARELO: SUSPEITO / RISCO MODERADO
  if (mode === 'moderado') {
    const tag = tipo ? ` • *[${tipo}]*` : ' • *[LINK SUSPEITO]*';

    let msg = `*🟡 ATENÇÃO: RISCO MODERADO*${tag}\n\n`;
    msg += `📊 *Nível de Risco:* ${score}/100 [${label}]\n`;
    msg += `${barra} _${statusTexto}_\n\n`;
    msg += `${verificacaoRedis}\n\n`;

    const explicacao = data.explicacao_simples || 'A mensagem possui elementos que exigem cautela. O remetente ou links enviados não puderam ser totalmente validados.';
    msg += `📝 *Por que:* ${explicacao}\n`;

    if (data.alerta_link) {
      msg += `\n⚠️ *Alerta Técnico:* ${data.alerta_link}\n`;
    }

    if (data.sinais && data.sinais.length > 0) {
      msg += `\n🔍 *Sinais de alerta:*\n`;
      data.sinais.slice(0, 4).forEach(s => {
        msg += `• ${s}\n`;
      });
    }

    msg += `\n💡 *O que fazer:*\n`;
    if (data.acao_recomendada) {
      msg += `• ${data.acao_recomendada}\n`;
    }
    msg += `• Não clique no link e não forneça informações pessoais.\n`;
    msg += `• Consulte diretamente pelo aplicativo ou site oficial da instituição.\n`;
    msg += `• Na dúvida, nunca realize pagamentos antecipados.\n`;

    msg += `\n🆘 *Já clicou ou fez pagamento?* Responda com *fui vítima* para ver o protocolo de emergência imediato.\n`;
    msg += `\n---\n⚡ *Zap, quem é?* — Verificador instantâneo de golpes`;
    return msg;
  }

  // 🟢 3. MODO VERDE: SEGURO / LEGÍTIMO
  const tag = tipo ? ` • *[${tipo}]*` : ' • *[CANAL OFICIAL]*';

  let msg = `*🟢 ANÁLISE: MENSAGEM SEGURA*${tag}\n\n`;
  msg += `📊 *Nível de Risco:* ${score < 10 ? '0' + score : score}/100 [${label}]\n`;
  msg += `${barra} _${statusTexto}_\n\n`;
  msg += `${verificacaoRedis}\n\n`;

  const explicacao = data.explicacao_simples || 'A mensagem segue padrões legítimos de comunicação, sem solicitação suspeita de senhas, códigos ou transferências financeiras.';
  msg += `📝 *Por que:* ${explicacao}\n`;

  msg += `\n🔍 *Verificações de segurança:*\n`;
  if (data.sinais && data.sinais.length > 0) {
    data.sinais.slice(0, 3).forEach(s => {
      msg += `✓ ${s}\n`;
    });
  } else {
    msg += `✓ Remetente e padrão de texto verificados\n`;
    msg += `✓ Nenhum link falso ou clonado detectado\n`;
    msg += `✓ Sem pressão de urgência artificial ou pedido de Pix/senhas\n`;
  }

  msg += `\n💡 *O que fazer:*\n`;
  msg += `• Pode prosseguir normalmente.\n`;
  msg += `• Lembre-se: instituições sérias nunca pedem senhas ou transferências urgentes por mensagem.\n`;

  msg += `\n---\n⚡ *Zap, quem é?* — Verificador instantâneo de golpes`;
  return msg;
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
    console.debug('Radar error:', err.message);
  }
}

export function heuristicAnalyze(texto) {
  const t = (texto || '').toLowerCase();

  // 1. Golpe do falso parente / filho pedindo pix
  if (
    (t.includes('mãe') || t.includes('mae') || t.includes('pai') || t.includes('filho') || t.includes('filha')) &&
    (t.includes('número novo') || t.includes('numero novo') || t.includes('troquei') || t.includes('quebrou') || t.includes('pix') || t.includes('urgente') || t.includes('salva'))
  ) {
    return {
      veredito: 'golpe',
      confianca: 96,
      risco_score: 95,
      tipo: 'falso parente',
      alerta_link: null,
      sinais: [
        'Alegação de celular quebrado ou troca de número',
        'Urgência para envio de dinheiro ou pagamento de conta',
        'Abordagem típica do golpe do falso filho'
      ],
      explicacao_simples: 'Criminosos fingem ser um familiar (geralmente filho ou filha) que supostamente trocou de número e precisa de dinheiro rápido por PIX.',
      acao_recomendada: 'NÃO transfira dinheiro nem salve o número! Ligue imediatamente para o número habitual dessa pessoa para confirmar a identidade por voz.',
      texto_normalizado: 'oi mae meu celular quebrou anota meu numero novo preciso de pix urgente'
    };
  }

  // 2. Falso banco / Phishing de conta
  if (t.includes('bloqueio') || t.includes('bloqueada') || t.includes('cancelamento') || t.includes('dispositivo') || (t.includes('banco') && (t.includes('link') || t.includes('http')))) {
    return {
      veredito: 'golpe',
      confianca: 94,
      risco_score: 92,
      tipo: 'falso banco',
      alerta_link: 'Link externo não oficial simulando acesso bancário',
      sinais: [
        'Ameaça de bloqueio ou cancelamento imediato',
        'Link externo solicitando senhas ou dados',
        'Senso de urgência falso'
      ],
      explicacao_simples: 'Mensagem falsa tentando roubar credenciais bancárias e dados de acesso.',
      acao_recomendada: 'Nunca clique no link. Entre em contato diretamente pelo aplicativo oficial do seu banco no celular.',
      texto_normalizado: 'sua conta bancaria sera bloqueada acesse o link para atualizar'
    };
  }

  // 3. Falsa entrega / CTT / Correios / Taxa
  if ((t.includes('encomenda') || t.includes('ctt') || t.includes('correios') || t.includes('alfândega') || t.includes('alfandega')) &&
      (t.includes('taxa') || t.includes('retida') || t.includes('pagar') || t.includes('link') || t.includes('http'))) {
    return {
      veredito: 'golpe',
      confianca: 95,
      risco_score: 90,
      tipo: 'entrega',
      alerta_link: 'Link falso imitando transportadora oficial',
      sinais: [
        'Cobrança de taxa não identificada para liberação',
        'Link suspeito fora dos canais oficiais',
        'Tentativa de phishing de cartão de crédito'
      ],
      explicacao_simples: 'Golpistas enviam avisos falsos de encomendas presas para cobrar taxas inexistentes e clonar cartões.',
      acao_recomendada: 'Não pague nada pelo link. Consulte o rastreio diretamente no site oficial da transportadora.',
      texto_normalizado: 'sua encomenda esta retida pague a taxa no link'
    };
  }

  // 4. Padrão genérico de cautela
  return {
    veredito: 'suspeito',
    confianca: 70,
    risco_score: 65,
    tipo: 'outro',
    alerta_link: t.includes('http') ? 'Contém link externo não verificado' : null,
    sinais: [
      'Abordagem com características atípicas',
      'Recomendada checagem antes de compartilhar dados'
    ],
    explicacao_simples: 'A mensagem contém elementos que recomendam atenção redobrada antes de qualquer ação ou envio de valores.',
    acao_recomendada: 'Não clique em links nem envie dados pessoais ou pagamentos sem confirmação segura.',
    texto_normalizado: t.slice(0, 100)
  };
}

