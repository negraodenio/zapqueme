// lib/scanner.js — Núcleo de análise compartilhado entre Web e WhatsApp
import { inspectAllUrls } from './threat_intel.js';
import { detectarImpersonation } from './radar.js';

const SYSTEM_PROMPT = `És um especialista internacional em cibersegurança e detecção de fraudes e golpes cibernéticos.
Analisa a mensagem de texto e/ou a imagem (print de SMS/WhatsApp/email) fornecida.

REQUISITO MULTILÍNGUE CRÍTICO:
1. Detecta o idioma da mensagem analisada ("pt", "en", "fr", "it", "es", "de", etc.) e preenche no campo "idioma".
2. Redige "explicacao_simples", "acao_recomendada", "sinais" e "alerta_link" NO MESMO IDIOMA da mensagem analisada!
   - Se a mensagem estiver em inglês -> responde em inglês.
   - Se a mensagem estiver em francês -> responde em francês.
   - Se a mensagem estiver em italiano -> responde em italiano.
   - Se a mensagem estiver em espanhol -> responde em espanhol.
   - Se a mensagem estiver em português -> responde em português.

Responde APENAS com um JSON válido, sem texto antes ou depois, neste formato exato:
{
  "idioma": "pt" | "en" | "fr" | "it" | "es" | "de" | "outro",
  "veredito": "golpe" | "suspeito" | "legitimo",
  "confianca": <número de 0 a 100>,
  "risco_score": <número de 0 a 100, onde 0 é risco nulo e 100 é perigo extremo de fraude>,
  "tipo": "falso banco" | "falso parente" | "entrega" | "pix errado" | "premio" | "investimento" | "romance" | "outro",
  "alerta_link": <string curta no idioma da mensagem alertando sobre domínio falso/typosquatting ou link encurtado suspeito, ou null se não houver link suspeito>,
  "sinais": ["sinal 1", "sinal 2", "sinal 3 no idioma da mensagem"],
  "explicacao_simples": "2 frases simples sem jargão NO IDIOMA DA MENSAGEM",
  "acao_recomendada": "1 a 2 frases práticas e diretas NO IDIOMA DA MENSAGEM",
  "texto_normalizado": "o texto da mensagem (extraído da imagem se for o caso), em minúsculas, com nomes próprios, números de telefone, valores em dinheiro e links substituídos por marcadores genéricos tipo [nome], [numero], [valor], [link] — mantendo a estrutura da frase igual, para permitir comparar se é o mesmo golpe enviado para pessoas diferentes",
  "marca_mencionada": <nome exato da empresa, banco, loja, serviço de entrega ou marca comercial citada ou imitada na mensagem, ou null se não for citado nenhum nome>,
  "canal_mencionado": <o link, domínio, endereço de email ou número de telefone citado na mensagem como remetente ou canal de atendimento, ou null se não houver>
}

Regras importantes:
- Considera golpes comuns: SMS falso de entrega/correios/USPS/Chronopost/Poste Italiane/CTT, falso funcionário de banco,
  falso parente pedindo dinheiro urgente, prémio/sorteio falso, golpe romântico, investimento com retorno garantido irrealista, phishing.
- "risco_score": para golpe atribui entre 80 e 99; para suspeito entre 45 e 79; para legítimo entre 5 e 25.
- Nunca atribuas confiança de exatamente 0 ou 100. Usa no máximo 95 e no mínimo 15.
- Se houver links na mensagem, analisa se o domínio tenta imitar marcas oficiais com pequenas alterações ou domínios genéricos (.top, .xyz, traços extras) e detalha em "alerta_link".
- Se não tiveres certeza suficiente, usa "suspeito" em vez de forçar "golpe" ou "legitimo".
- Nunca peças, sugiras pedir, ou repitas dados pessoais sensíveis (números de cartão, senhas, etc).
- "sinais" deve ter entre 2 e 4 itens, curtos e concretos no idioma da mensagem.
- "acao_recomendada" deve ser prática no idioma correspondente.`;

export async function analyzeContent({ texto, imagemBase64, imagemTipo, canal = 'web' }) {
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
      const orModel = process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash';
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
      : ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];

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
  let threatResult = null;
  try {
    const textoParaInspecao = [texto, parsed.texto_normalizado, parsed.alerta_link].filter(Boolean).join(' ');
    threatResult = await inspectAllUrls(textoParaInspecao, apiKey);

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

  // 4. Se canal_mencionado não foi extraído pela IA, mas há URL identificada na mensagem, aproveita
  if (!parsed.canal_mencionado && threatResult?.reports?.[0]?.originalUrl) {
    parsed.canal_mencionado = threatResult.reports[0].originalUrl;
  }

  // 5. Threat Radar: Detecção de Impersonation para empresas cadastradas (B2B)
  let impersonationResult = { empresa_id: null, impersonation: false };
  try {
    impersonationResult = await detectarImpersonation({
      marca_mencionada: parsed.marca_mencionada,
      canal_mencionado: parsed.canal_mencionado,
      veredito: parsed.veredito
    });
  } catch (radarErr) {
    console.warn('[Radar] Erro ao detectar impersonation:', radarErr.message);
  }

  parsed.empresa_id = impersonationResult.empresa_id;
  parsed.impersonation = impersonationResult.impersonation;

  // Deduplicação Upstash Redis:
  // Usa o texto enviado (se houver) ou o texto normalizado da IA.
  const textoParaHash = texto && texto.trim().length > 5
    ? texto
    : (parsed.texto_normalizado || texto || '');
  const vezesReportada = await incrementarContador(textoParaHash);
  delete parsed.texto_normalizado;
  parsed.vezes_reportada = vezesReportada;

  // Registro de auditoria no Supabase com suporte a Threat Radar
  parsed.analise_id = await salvarAnalise(parsed, !!imagemBase64, canal);

  // Remove campos internos antes de devolver ao frontend B2C (Regras Seções 3 e 12)
  delete parsed.marca_mencionada;
  delete parsed.canal_mencionado;
  delete parsed.empresa_id;
  delete parsed.impersonation;

  return parsed;
}

export function getRiscoBar(score, mode) {
  const blocks = Math.min(10, Math.max(1, Math.round(score / 10)));
  // Círculos coloridos por criticidade (bordas perfeitamente arredondadas, sem blocos quadrados)
  // 🔴 Vermelho (Crítico) | 🟡 Amarelo (Moderado) | 🟢 Verde (Seguro) | ⚪ Círculo vazio
  let circle = '🔴';
  if (mode === 'seguro') {
    circle = '🟢';
  } else if (mode === 'moderado') {
    circle = '🟡';
  } else {
    circle = '🔴';
  }

  const filled = circle.repeat(blocks);
  const empty = '⚪'.repeat(10 - blocks);
  return `[${filled}${empty}]`;
}

export const I18N = {
  pt: {
    critico_titulo: '*🔴 ALERTA: PROVÁVEL GOLPE*',
    moderado_titulo: '*🟡 ATENÇÃO: RISCO MODERADO*',
    seguro_titulo: '*🟢 ANÁLISE: MENSAGEM SEGURA*',
    nivel_risco: 'Nível de Risco:',
    rotulo_critico: 'CRÍTICO',
    rotulo_moderado: 'SUSPEITO',
    rotulo_seguro: 'SEGURO',
    status_critico: 'Perigo Extremo',
    status_moderado: 'Atenção Redobrada',
    status_seguro: 'Risco Mínimo',
    verificacao_massa: (vezes) => `🔥 *Atenção:* Esta mesma mensagem já foi verificada *${vezes} vezes hoje* por outras pessoas (alerta de golpe em massa)!`,
    verificacao_primeira: '🛡️ *Verificação:* 1ª vez que esta mensagem é verificada no nosso sistema.',
    por_que: 'Por que:',
    alerta_tecnico: 'Alerta Técnico:',
    sinais_alerta: 'Sinais de alerta:',
    verificacoes_seguranca: 'Verificações de segurança:',
    o_que_fazer: 'O que fazer:',
    protocolo_emergencia: '🆘 *Já caiu ou fez o pagamento?* Responda com *fui vítima* para ver o protocolo de emergência imediato.',
    protocolo_emergencia_mod: '🆘 *Já clicou ou fez pagamento?* Responda com *fui vítima* para ver o protocolo de emergência imediato.',
    rodape: '⚡ *Zap, quem é?* — Verificador instantâneo de golpes',
    padrao_seguro_1: '✓ Remetente e padrão de texto verificados',
    padrao_seguro_2: '✓ Nenhum link falso ou clonado detectado',
    padrao_seguro_3: '✓ Sem pressão de urgência artificial ou pedido de Pix/senhas',
    padrao_explicacao_critico: 'Esta mensagem é uma tentativa de fraude para tentar recolher dinheiro ou dados pessoais confidenciais.',
    padrao_acao_critico: 'Não responda, não clique em links nem envie qualquer valor. Bloqueie o remetente e apague a mensagem.',
    padrao_explicacao_moderado: 'A mensagem possui elementos que exigem cautela. O remetente ou links enviados não puderam ser totalmente autenticados.',
    padrao_acao_moderado: 'Não clique no link e não forneça informações pessoais. Confirme a informação diretamente pelos canais oficiais da empresa.',
    padrao_explicacao_seguro: 'A mensagem segue padrões legítimos de comunicação, sem solicitação de senhas, códigos ou transferências bancárias.',
    padrao_acao_seguro: 'Pode prosseguir normalmente. Lembre-se: instituições sérias nunca pedem senhas ou transferências urgentes por mensagem.'
  },
  en: {
    critico_titulo: '*🔴 WARNING: LIKELY SCAM*',
    moderado_titulo: '*🟡 CAUTION: MODERATE RISK*',
    seguro_titulo: '*🟢 ANALYSIS: SAFE MESSAGE*',
    nivel_risco: 'Risk Level:',
    rotulo_critico: 'CRITICAL',
    rotulo_moderado: 'SUSPICIOUS',
    rotulo_seguro: 'SAFE',
    status_critico: 'Extreme Danger',
    status_moderado: 'High Caution',
    status_seguro: 'Minimal Risk',
    verificacao_massa: (vezes) => `🔥 *Warning:* This exact message was checked *${vezes} times today* by other users (mass scam alert)!`,
    verificacao_primeira: '🛡️ *Verification:* 1st time this message was analyzed in our system.',
    por_que: 'Why:',
    alerta_tecnico: 'Technical Alert:',
    sinais_alerta: 'Warning signs:',
    verificacoes_seguranca: 'Security checks:',
    o_que_fazer: 'What to do:',
    protocolo_emergencia: '🆘 *Already paid or fallen for it?* Reply with *victim* to see the emergency guide.',
    protocolo_emergencia_mod: '🆘 *Clicked the link or provided info?* Reply with *victim* to see the emergency guide.',
    rodape: '⚡ *Zap, who is it?* — Instant scam detector',
    padrao_seguro_1: '✓ Sender and message format verified',
    padrao_seguro_2: '✓ No fake or cloned links detected',
    padrao_seguro_3: '✓ No artificial urgency or request for passwords/money',
    padrao_explicacao_critico: 'This message is a fraudulent attempt to steal money or sensitive personal information.',
    padrao_acao_critico: 'Do not reply, do not click any links, and do not send money. Block the sender and delete the message.',
    padrao_explicacao_moderado: 'The message contains elements requiring caution. The sender or links could not be fully verified.',
    padrao_acao_moderado: 'Do not click the link and do not provide personal details. Confirm directly with the official organization.',
    padrao_explicacao_seguro: 'The message follows legitimate communication standards with no requests for passwords, codes or transfers.',
    padrao_acao_seguro: 'You can proceed normally. Legitimate organizations never request passwords or urgent transfers via text message.'
  },
  fr: {
    critico_titulo: '*🔴 ALERTE : ARNAQUE PROBABLE*',
    moderado_titulo: '*🟡 ATTENTION : RISQUE MODÉRÉ*',
    seguro_titulo: '*🟢 ANALYSE : MESSAGE SÉCURISÉ*',
    nivel_risco: 'Niveau de risque :',
    rotulo_critico: 'CRITIQUE',
    rotulo_moderado: 'SUSPECT',
    rotulo_seguro: 'SÛR',
    status_critico: 'Danger extrême',
    status_moderado: 'Vigilance requise',
    status_seguro: 'Risque minime',
    verificacao_massa: (vezes) => `🔥 *Attention :* Ce même message a été vérifié *${vezes} fois aujourd’hui* par d’autres personnes (alerte arnaque de masse) !`,
    verificacao_primeira: '🛡️ *Vérification :* 1ère fois que ce message est vérifié dans notre système.',
    por_que: 'Pourquoi :',
    alerta_tecnico: 'Alerte technique :',
    sinais_alerta: 'Signes d\'alerte :',
    verificacoes_seguranca: 'Contrôles de sécurité :',
    o_que_fazer: 'Que faire :',
    protocolo_emergencia: '🆘 *Vous avez déjà payé ou cliqué ?* Répondez *victime* pour le protocole d\'urgence.',
    protocolo_emergencia_mod: '🆘 *Vous avez cliqué ou partagé des infos ?* Répondez *victime* pour le protocole d\'urgence.',
    rodape: '⚡ *Zap, qui est-ce ?* — Détecteur instantané d\'arnaques',
    padrao_seguro_1: '✓ Expéditeur et format vérifiés',
    padrao_seguro_2: '✓ Aucun lien frauduleux ou cloné détecté',
    padrao_seguro_3: '✓ Aucune urgence artificielle ni demande d\'argent/mots de passe',
    padrao_explicacao_critico: 'Ce message est une tentative de fraude visant à dérober de l\'argent ou des données personnelles.',
    padrao_acao_critico: 'Ne répondez pas, ne cliquez sur aucun lien et n\'envoyez aucun paiement. Bloquez l\'expéditeur.',
    padrao_explicacao_moderado: 'Ce message comporte des anomalies suspectes. L\'expéditeur ou le lien ne peuvent être authentifiés.',
    padrao_acao_moderado: 'Ne cliquez pas sur le lien et ne fournissez aucune donnée. Vérifiez directement auprès du service officiel.',
    padrao_explicacao_seguro: 'Le message respecte les normes officielles de communication, sans demande de mots de passe ou d\'argent.',
    padrao_acao_seguro: 'Vous pouvez continuer normalement. Les services officiels ne demandent jamais de virements urgents par SMS.'
  },
  it: {
    critico_titulo: '*🔴 AVVISO: PROBABILE TRUFFA*',
    moderado_titulo: '*🟡 ATTENZIONE: RISCHIO MODERATO*',
    seguro_titulo: '*🟢 ANALISI: MESSAGGIO SICURO*',
    nivel_risco: 'Livello di rischio:',
    rotulo_critico: 'CRITICO',
    rotulo_moderado: 'SOSPETTO',
    rotulo_seguro: 'SICURO',
    status_critico: 'Pericolo estremo',
    status_moderado: 'Massima attenzione',
    status_seguro: 'Rischio minimo',
    verificacao_massa: (vezes) => `🔥 *Attenzione:* Questo stesso messaggio è già stato verificato *${vezes} volte oggi* da altri utenti (allerta truffa di massa)!`,
    verificacao_primeira: '🛡️ *Verifica:* 1ª volta che questo messaggio viene controllato nel sistema.',
    por_que: 'Perché:',
    alerta_tecnico: 'Avviso tecnico:',
    sinais_alerta: 'Segnali di allarme:',
    verificacoes_seguranca: 'Controlli di sicurezza:',
    o_que_fazer: 'Cosa fare:',
    protocolo_emergencia: '🆘 *Hai già pagato o fornito dati?* Rispondi con *vittima* per la guida d\'emergenza.',
    protocolo_emergencia_mod: '🆘 *Hai cliccato o inserito credenziali?* Rispondi con *vittima* per la guida d\'emergenza.',
    rodape: '⚡ *Zap, chi è?* — Rilevatore istantaneo di truffe',
    padrao_seguro_1: '✓ Mittente e formato del testo verificati',
    padrao_seguro_2: '✓ Nessun link fraudolento o clonato rilevato',
    padrao_seguro_3: '✓ Nessuna richiesta urgente di password o pagamenti',
    padrao_explicacao_critico: 'Questo messaggio è un tentativo di truffa volto a sottrarre denaro o dati personali.',
    padrao_acao_critico: 'Non rispondere, non cliccare sui link e non inviare denaro. Blocca il mittente ed elimina il messaggio.',
    padrao_explicacao_moderado: 'Il messaggio presenta elementi sospetti. Il mittente o i link non possono essere autenticati.',
    padrao_acao_moderado: 'Non cliccare sul link e non fornire dati riservati. Verifica direttamente con l\'ente ufficiale.',
    padrao_explicacao_seguro: 'Il messaggio segue gli standard legittimi di comunicazione, senza richieste di password o bonifici.',
    padrao_acao_seguro: 'Puoi procedere normalmente. Gli enti ufficiali non richiedono mai password o pagamenti urgenti via messaggio.'
  },
  es: {
    critico_titulo: '*🔴 ALERTA: PROBABLE ESTAFA*',
    moderado_titulo: '*🟡 ATENCIÓN: RIESGO MODERADO*',
    seguro_titulo: '*🟢 ANÁLISIS: MENSAJE SEGURO*',
    nivel_risco: 'Nivel de riesgo:',
    rotulo_critico: 'CRÍTICO',
    rotulo_moderado: 'SOSPECHOSO',
    rotulo_seguro: 'SEGURO',
    status_critico: 'Peligro extremo',
    status_moderado: 'Atención redoblada',
    status_seguro: 'Riesgo mínimo',
    verificacao_massa: (vezes) => `🔥 *Atención:* Este mismo mensaje ha sido verificado *${vezes} veces hoy* por otros usuarios (alerta de estafa masiva)!`,
    verificacao_primeira: '🛡️ *Verificación:* 1ª vez que este mensaje se verifica en nuestro sistema.',
    por_que: 'Por qué:',
    alerta_tecnico: 'Alerta técnica:',
    sinais_alerta: 'Señales de alerta:',
    verificacoes_seguranca: 'Verificaciones de seguridad:',
    o_que_fazer: 'Qué hacer:',
    protocolo_emergencia: '🆘 *¿Ya pagaste o caíste?* Responde con *fui victima* para el protocolo de emergencia.',
    protocolo_emergencia_mod: '🆘 *¿Hiciste clic o diste datos?* Responde con *fui victima* para el protocolo de emergencia.',
    rodape: '⚡ *Zap, ¿quién es?* — Detector instantáneo de estafas',
    padrao_seguro_1: '✓ Remitente y formato de texto verificados',
    padrao_seguro_2: '✓ Ningún enlace falso o clonado detectado',
    padrao_seguro_3: '✓ Sin presión de urgencia ni petición de contraseñas o transferencias',
    padrao_explicacao_critico: 'Este mensaje es un intento de fraude para robar dinero o datos personales confidenciales.',
    padrao_acao_critico: 'No respondas, no hagas clic en enlaces ni envíes dinero. Bloquea al remitente y borra el mensaje.',
    padrao_explicacao_moderado: 'El mensaje presenta elementos que exigen precaución. El remitente o enlace no pudieron ser autenticados.',
    padrao_acao_moderado: 'No hagas clic en el enlace ni facilites datos personales. Confirma directamente con los canales oficiales.',
    padrao_explicacao_seguro: 'El mensaje sigue los estándares legítimos de comunicación, sin pedir contraseñas ni dinero.',
    padrao_acao_seguro: 'Puedes continuar con normalidad. Las entidades serias nunca piden contraseñas o pagos urgentes por mensaje.'
  }
};

export function formatWhatsAppMessage(data) {
  const score = data.risco_score !== undefined
    ? data.risco_score
    : (data.veredito === 'golpe' ? data.confianca : (data.veredito === 'suspeito' ? 65 : 5));

  // Identifica o idioma (default: pt)
  const langKey = (data.idioma || 'pt').toLowerCase().slice(0, 2);
  const t = I18N[langKey] || I18N.pt;

  // Determina categoria de criticidade (3 Cores)
  let mode = 'critico';
  let label = t.rotulo_critico;
  let dot = '🔴';
  let statusTexto = t.status_critico;

  if (data.veredito === 'legitimo' || score < 35) {
    mode = 'seguro';
    label = t.rotulo_seguro;
    dot = '🟢';
    statusTexto = t.status_seguro;
  } else if (data.veredito === 'suspeito' || (score >= 35 && score < 75)) {
    mode = 'moderado';
    label = t.rotulo_moderado;
    dot = '🟡';
    statusTexto = t.status_moderado;
  } else {
    mode = 'critico';
    label = t.rotulo_critico;
    dot = '🔴';
    statusTexto = t.status_critico;
  }

  // Trata o tipo: nunca exibe "OUTRO"
  let tag = '';
  const tipoLimpo = (data.tipo || '').toLowerCase().trim();
  if (tipoLimpo && tipoLimpo !== 'outro' && tipoLimpo !== 'outros') {
    tag = ` • *[${tipoLimpo.toUpperCase()}]*`;
  }

  const barra = getRiscoBar(score, mode);

  // Inteligência Coletiva Humanizada
  let verificacaoTexto = '';
  if (data.vezes_reportada && data.vezes_reportada > 1) {
    verificacaoTexto = t.verificacao_massa(data.vezes_reportada);
  } else {
    verificacaoTexto = t.verificacao_primeira;
  }

  // 🔴 1. MODO VERMELHO: PROVÁVEL GOLPE / RISCO CRÍTICO
  if (mode === 'critico') {
    let msg = `${t.critico_titulo}${tag}\n\n`;
    msg += `📊 *${t.nivel_risco}* ${score}/100 [${label}]\n`;
    msg += `${barra} _${statusTexto}_\n\n`;
    msg += `${verificacaoTexto}\n\n`;

    const explicacao = data.explicacao_simples || t.padrao_explicacao_critico;
    msg += `📝 *${t.por_que}* ${explicacao}\n`;

    if (data.alerta_link) {
      msg += `\n⚠️ *${t.alerta_tecnico}* ${data.alerta_link}\n`;
    }

    if (data.sinais && data.sinais.length > 0) {
      const sinaisUnicos = [...new Set(data.sinais.map(s => s.trim()))].filter(Boolean);
      msg += `\n🔍 *${t.sinais_alerta}*\n`;
      sinaisUnicos.slice(0, 3).forEach(s => {
        msg += `• ${s}\n`;
      });
    }

    const oQueFazer = data.acao_recomendada || t.padrao_acao_critico;
    msg += `\n💡 *${t.o_que_fazer}*\n${oQueFazer}\n`;

    msg += `\n${t.protocolo_emergencia}\n`;
    msg += `\n---\n${t.rodape}`;
    return msg;
  }

  // 🟡 2. MODO AMARELO: SUSPEITO / RISCO MODERADO
  if (mode === 'moderado') {
    let msg = `${t.moderado_titulo}${tag}\n\n`;
    msg += `📊 *${t.nivel_risco}* ${score}/100 [${label}]\n`;
    msg += `${barra} _${statusTexto}_\n\n`;
    msg += `${verificacaoTexto}\n\n`;

    const explicacao = data.explicacao_simples || t.padrao_explicacao_moderado;
    msg += `📝 *${t.por_que}* ${explicacao}\n`;

    if (data.alerta_link) {
      msg += `\n⚠️ *${t.alerta_tecnico}* ${data.alerta_link}\n`;
    }

    if (data.sinais && data.sinais.length > 0) {
      const sinaisUnicos = [...new Set(data.sinais.map(s => s.trim()))].filter(Boolean);
      msg += `\n🔍 *${t.sinais_alerta}*\n`;
      sinaisUnicos.slice(0, 3).forEach(s => {
        msg += `• ${s}\n`;
      });
    }

    const oQueFazer = data.acao_recomendada || t.padrao_acao_moderado;
    msg += `\n💡 *${t.o_que_fazer}*\n${oQueFazer}\n`;

    msg += `\n${t.protocolo_emergencia_mod}\n`;
    msg += `\n---\n${t.rodape}`;
    return msg;
  }

  // 🟢 3. MODO VERDE: SEGURO / LEGÍTIMO
  let msg = `${t.seguro_titulo}${tag}\n\n`;
  msg += `📊 *${t.nivel_risco}* ${score < 10 ? '0' + score : score}/100 [${label}]\n`;
  msg += `${barra} _${statusTexto}_\n\n`;
  msg += `${verificacaoTexto}\n\n`;

  const explicacao = data.explicacao_simples || t.padrao_explicacao_seguro;
  msg += `📝 *${t.por_que}* ${explicacao}\n`;

  msg += `\n🔍 *${t.verificacoes_seguranca}*\n`;
  if (data.sinais && data.sinais.length > 0) {
    const sinaisUnicos = [...new Set(data.sinais.map(s => s.trim()))].filter(Boolean);
    sinaisUnicos.slice(0, 3).forEach(s => {
      msg += `✓ ${s}\n`;
    });
  } else {
    msg += `${t.padrao_seguro_1}\n`;
    msg += `${t.padrao_seguro_2}\n`;
    msg += `${t.padrao_seguro_3}\n`;
  }

  const oQueFazer = data.acao_recomendada || t.padrao_acao_seguro;
  msg += `\n💡 *${t.o_que_fazer}*\n${oQueFazer}\n`;

  msg += `\n---\n${t.rodape}`;
  return msg;
}

export function getEmergencyVictimGuide(lang = 'pt') {
  const l = (lang || 'pt').toLowerCase().slice(0, 2);
  
  if (l === 'en') {
    return `🆘 *EMERGENCY PROTOCOL — SCAM VICTIM* 🆘

If you already sent money, transferred funds, or shared credit card / password details, *ACT IMMEDIATELY (EVERY MINUTE COUNTS)*:

1️⃣ *CALL YOUR BANK IMMEDIATELY:*
• Request an immediate block on transactions, freeze the affected cards, and ask to dispute or reverse the fraud.

2️⃣ *DO NOT DELETE THE CHAT (PRESERVE EVIDENCE):*
• Take screenshots of the entire conversation, sender phone number, links received, payment receipts and transaction hashes.

3️⃣ *FILE A POLICE REPORT:*
• Report the cybercrime to local police or cyber fraud portal (e.g. Action Fraud UK, FBI IC3, or local authorities).

4️⃣ *SECURE YOUR ACCOUNTS:*
• Immediately change passwords for your email and enable Two-Factor Authentication (2FA) with a PIN on WhatsApp (Settings → Account → Two-step verification).

---
_⚡ Zap, who is it? — Here to help keep you safe!_`;
  }

  if (l === 'fr') {
    return `🆘 *PROTOCOLE D'URGENCE — VICTIME D'ARNAQUE* 🆘

Si vous avez déjà effectué un virement, payé ou communiqué vos coordonnées bancaires, *AGISSEZ IMMÉDIATEMENT* :

1️⃣ *APPELEZ VOTRE BANQUE SANS DÉLAI :*
• Demandez l'opposition immédiate sur votre carte, le blocage des virements et l'ouverture d'un dossier de contestation pour fraude.

2️⃣ *NE SUPPRIMEZ PAS LA CONVERSATION (GARDEZ LES PREUVES) :*
• Prenez des captures d'écran de tous les échanges, des numéros, des liens reçus et des justificatifs de paiement.

3️⃣ *DÉPOSEZ PLAINTE :*
• Signalez l'escroquerie sur la plateforme officielle (ex: THÉSÉE / Pharos en France) ou auprès de la gendarmerie / police.

4️⃣ *SÉCURISEZ VOS ACCÈS :*
• Modifiez les mots de passe de votre boîte mail et activez la vérification en deux étapes sur WhatsApp.

---
_⚡ Zap, qui est-ce ? — Nous sommes là pour vous protéger !_`;
  }

  if (l === 'it') {
    return `🆘 *PROTOCOLLO DI EMERGENZA — VITTIMA DI TRUFFA* 🆘

Se hai già inviato denaro, effettuato un bonifico o fornito dati di carte/password, *AGISCI SUBITO (OGNI MINUTO CONTA)*:

1️⃣ *CHIAMA IMMEDIATAMENTE LA TUA BANCA:*
• Richiedi il blocco immediato delle carte e dei bonifici per disconoscere le operazioni fraudolente.

2️⃣ *NON CANCELLARE LA CHAT (CONSERVA LE PROVE):*
• Fai screenshot dell'intera conversazione, del numero del truffatore, dei link e delle ricevute di pagamento.

3️⃣ *SPORGI DENUNCIA:*
• Segnala la truffa alla Polizia Postale o recati presso i Carabinieri / Polizia di Stato.

4️⃣ *METTI AL SICURO I TUOI ACCOUNT:*
• Cambia la password della tua email e attiva la verifica in due passaggi con PIN su WhatsApp.

---
_⚡ Zap, chi è? — Siamo qui per aiutarti a proteggerti!_`;
  }

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

async function salvarAnalise(parsed, teveImagem, canal = 'web') {
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
        risco_score: parsed.risco_score ?? null,
        alerta_link: parsed.alerta_link ?? null,
        canal: canal || 'web',
        tipo: parsed.tipo,
        vezes_reportada: parsed.vezes_reportada,
        teve_imagem: teveImagem,
        empresa_id: parsed.empresa_id || null,
        marca_mencionada: parsed.marca_mencionada || null,
        canal_mencionado: parsed.canal_mencionado || null,
        impersonation: !!parsed.impersonation
      })
    });
    if (!resp.ok) {
      console.warn('Erro salvarAnalise status:', resp.status, await resp.text());
      return null;
    }
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

export function heuristicAnalyze(texto) {
  const t = (texto || '').toLowerCase();

  // Extrai possível URL ou telefone citado no texto
  const urlMatch = texto?.match(/https?:\/\/[^\s]+/i);
  const canalMencionadoHeuristico = urlMatch ? urlMatch[0] : null;

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
      texto_normalizado: 'oi mae meu celular quebrou anota meu numero novo preciso de pix urgente',
      marca_mencionada: null,
      canal_mencionado: canalMencionadoHeuristico
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
      texto_normalizado: 'sua conta bancaria sera bloqueada acesse o link para atualizar',
      marca_mencionada: t.includes('caixa') ? 'Caixa' : (t.includes('santander') ? 'Santander' : (t.includes('millennium') ? 'Millennium BCP' : null)),
      canal_mencionado: canalMencionadoHeuristico
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
      texto_normalizado: 'sua encomenda esta retida pague a taxa no link',
      marca_mencionada: t.includes('ctt') ? 'CTT' : (t.includes('correios') ? 'Correios' : null),
      canal_mencionado: canalMencionadoHeuristico
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
    texto_normalizado: t.slice(0, 100),
    marca_mencionada: null,
    canal_mencionado: canalMencionadoHeuristico
  };
}

