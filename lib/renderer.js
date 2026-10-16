// lib/renderer.js
// Camada de Apresentação Exclusiva para WhatsApp (Confirme, Quem É?)
// Regras: ≤ 600 caracteres, ≤ 12 linhas, níveis em vez de números, blindagem jurídica.

const BRAND_NAME = process.env.BRAND_NAME || 'Confirme, Quem É?';
const BRAND_URL = process.env.BRAND_URL || 'confirmequeme.pt';

// Lista estrita de termos proibidos nas respostas
export const PROHIBITED_TERMS = [
  'é um golpe',
  'trata-se de uma burla',
  'legítimo',
  'seguro',
  '100%',
  'domínio é falso',
  'fraudulento'
];

/**
 * Mapeia o score numérico (0-100) para os 4 níveis de risco
 */
export function scoreToLevel(score, isError = false) {
  if (isError) return 'error';
  const num = Number(score) || 0;
  if (num >= 75) return 'high';
  if (num >= 40) return 'medium';
  return 'low';
}

/**
 * Higieniza uma frase de explicação garantindo 1 frase concisa e sem alegações absolutas proibidas
 */
export function sanitizeExplanation(text) {
  if (!text) return '';
  let clean = text.trim();
  // Pega a primeira oração/frase se houver quebras ou múltiplos pontos
  const match = clean.match(/^([^.!?\n]+[.!?]?)/);
  if (match && match[1]) {
    clean = match[1].trim();
  }
  // Remove termos proibidos de alegação absoluta
  clean = clean
    .replace(/\bé um golpe\b/gi, 'apresenta indícios de risco')
    .replace(/\btrata-se de uma burla\b/gi, 'apresenta características de alerta')
    .replace(/\bdomínio é falso\b/gi, 'domínio não é oficial')
    .replace(/\bfraudulento\b/gi, 'suspeito')
    .replace(/\b100%\b/gi, 'elevada probabilidade')
    .replace(/\blegítimo\b/gi, 'sem sinais de risco')
    .replace(/\bseguro\b/gi, 'sem alertas');

  if (!/[.!?]$/.test(clean)) {
    clean += '.';
  }
  if (clean.length > 150) {
    clean = clean.slice(0, 147) + '...';
  }
  return clean.charAt(0).toLowerCase() + clean.slice(1);
}

/**
 * Constrói o contrato de dados estruturado a partir da análise interna
 */
export function buildDataContract(parsed, originalText = '') {
  const text = (originalText || '').trim();
  const lower = text.toLowerCase();
  const score = parsed.risco_score !== undefined
    ? parsed.risco_score
    : (parsed.veredito === 'golpe' ? (parsed.confianca || 90) : (parsed.veredito === 'suspeito' ? 60 : 10));

  const isError = parsed.isError || parsed.veredito === 'erro';
  const level = scoreToLevel(score, isError);

  // Extrai domínio e marca
  let brand = parsed.marca || parsed.marca_mencionada || null;
  let domain = parsed.dominio || parsed.canal_mencionado || null;
  let officialDomain = parsed.dominio_oficial || null;

  // Se o scanner identificou no alerta_link ou sinais
  if (!domain && text) {
    const urlMatch = text.match(/https?:\/\/([^\s/$.?#].[^\s]*)/i) || text.match(/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?/);
    if (urlMatch) {
      try {
        const raw = urlMatch[0].startsWith('http') ? urlMatch[0] : `https://${urlMatch[0]}`;
        const u = new URL(raw);
        domain = u.hostname.replace(/^www\./, '');
      } catch (e) {
        domain = urlMatch[0];
      }
    }
  }

  // Identificação de Marca comum em Portugal se não preenchida
  if (!brand && text) {
    if (/ctt/i.test(text)) { brand = 'CTT'; officialDomain = officialDomain || 'ctt.pt'; }
    else if (/via\s*verde/i.test(text)) { brand = 'Via Verde'; officialDomain = officialDomain || 'viaverde.pt'; }
    else if (/edp/i.test(text)) { brand = 'EDP'; officialDomain = officialDomain || 'edp.pt'; }
    else if (/galp/i.test(text)) { brand = 'Galp'; officialDomain = officialDomain || 'galp.pt'; }
    else if (/santander/i.test(text)) { brand = 'Santander'; officialDomain = officialDomain || 'santander.pt'; }
    else if (/millennium|bcp/i.test(text)) { brand = 'Millennium BCP'; officialDomain = officialDomain || 'millenniumbcp.pt'; }
    else if (/caixadirecta|cgd/i.test(text)) { brand = 'CGD'; officialDomain = officialDomain || 'cgd.pt'; }
    else if (/novobanco|novo\s*banco/i.test(text)) { brand = 'Novo Banco'; officialDomain = officialDomain || 'novobanco.pt'; }
    else if (/nos/i.test(text)) { brand = 'NOS'; officialDomain = officialDomain || 'nos.pt'; }
    else if (/meo/i.test(text)) { brand = 'MEO'; officialDomain = officialDomain || 'meo.pt'; }
    else if (/vodafone/i.test(text)) { brand = 'Vodafone'; officialDomain = officialDomain || 'vodafone.pt'; }
    else if (/autoridade\s*tribut[aá]ria|finan[cç]as/i.test(text)) { brand = 'Autoridade Tributária'; officialDomain = officialDomain || 'portaldasfinancas.gov.pt'; }
    else if (/seguran[cç]a\s*social/i.test(text)) { brand = 'Segurança Social'; officialDomain = officialDomain || 'seg-social.pt'; }
  }

  // Deteção Universal dos Mais de 50 Tipos de Golpe
  let template = 'none';

  if (isError) {
    template = 'error';
  } else if (level === 'low' || parsed.veredito === 'sem sinais de risco' || parsed.veredito === 'legitimo') {
    template = 'none';
  } else {
    // 1. Familiar ("Olá mãe / pai", perda de telemóvel)
    const isFamiliar = /ol[aá]\s+(m[aã]e|pai|filh[oa])|perdi\s+o\s+telem[oó]vel|ecr[aã]\s+partiu|n[uú]mero\s+(tempor[aá]rio|provis[oó]rio|novo)/i.test(lower) || parsed.tipo === 'falso parente';
    
    // 2. MB WAY em compras/vendas (OLX, Vinted, Multibanco)
    const isMbwaySeller = /(ir\s+ao\s+multibanco|caixa\s+multibanco|outras\s+opera[cç][oõ]es|associar\s+(o\s+)?(meu\s+)?n[uú]mero|c[oó]digo\s+mb\s*way)/i.test(lower) || (/mb\s*way/i.test(lower) && /olx|vinted|comprar\s+o\s+artigo|an[uú]ncio/i.test(lower));

    // 3. Criptomoedas, Forex, Investimento milagroso
    const isCrypto = /(cripto|crypto|bitcoin|forex|lucro\s+garantido|retorno\s+garantido|\b\d+%\s+ao\s+dia|rendimento\s+di[aá]rio|ganh(os?|ar)\s+\d+€|grupo\s+vip|sinais\s+vip)/i.test(lower) || parsed.tipo === 'investimento';

    // 4. Emprego falso / Tarefas pagas online
    const isJobOffer = /(avaliar\s+(v[ií]deos?|produtos?|hot[eé]is)|tarefas?\s+online|comiss[aã]o\s+di[aá]ria|ganhe\s+\d+€\s*(a\s*\d+€)?\s*(\/|por)\s*dia|recrutamento\s+(amazon|tiktok|booking|youtube|google)|tempo\s+parcial)/i.test(lower);

    // 5. Falso apoio bancário / Spoofing telefónico sem link
    const isFakeBank = (/(alerta\s+de\s+seguran[cç]a|acesso\s+indevido|cart[aã]o\s+bloqueado|conta\s+suspensa|ligue\s+(j[aá]\s+)?para|contacte\s+o\s+n[uú]mero\s+\d+)/i.test(lower) && !domain) || parsed.tipo === 'falso banco';

    // 6. Falsa notificação policial / judicial (Europol, PJ, Penhoras)
    const isPoliceLegal = /(pol[ií]cia\s+judici[aá]ria|europol|interpol|mandado\s+de\s+deten[cç][aã]o|convocat[oó]ria\s+judicial|processo\s+crime|penhora\s+urgente)/i.test(lower);

    // 7. Falso arrendamento / Caução adiantada
    const isRental = /(arrendamento|aluguer|cau[cç][aã]o\s+para\s+visita|sinal\s+para\s+reserva|apartamento\s+t[0-9]|enviar\s+cau[cç][aã]o)/i.test(lower);

    // 8. Falso empréstimo / Crédito fácil
    const isCredit = /(empr[eé]stimo\s+r[aá]pido|cr[eé]dito\s+(f[aá]cil|imediato|urgente)|sem\s+consulta|taxa\s+de\s+abertura\s+de\s+processo)/i.test(lower);

    // 9. Lotaria / Sorteio / Prémios fictícios
    const isLottery = /(parab[eé]ns\s+ganhou|foi\s+selecionado|pr[eé]mio|sorteio|ganhou\s+um\s+(iphone|samsung|vale))/i.test(lower) || parsed.tipo === 'premio';

    // 10. Referência Multibanco pura (neutro)
    const hasMultibanco = /entidade|refer[eê]ncia|sub-?entidade/i.test(lower) || parsed.tipo === 'cobranca_multibanco';
    const hasSuspectLink = domain && (level === 'high' || level === 'medium');

    if (isFamiliar) {
      template = 'familiar';
    } else if (isMbwaySeller) {
      template = 'mbway_seller';
    } else if (isCrypto) {
      template = 'crypto_investment';
    } else if (isJobOffer) {
      template = 'job_offer';
    } else if (isFakeBank) {
      template = 'fake_bank_support';
    } else if (isPoliceLegal) {
      template = 'fake_police_legal';
    } else if (isRental) {
      template = 'fake_rental';
    } else if (isCredit) {
      template = 'fake_credit';
    } else if (isLottery) {
      template = 'lottery_gift';
    } else if (hasMultibanco && !hasSuspectLink) {
      template = 'reference';
    } else if (hasSuspectLink || domain || (brand && level === 'high')) {
      template = 'link_brand';
    } else {
      // Qualquer outro dos mais de 50 tipos de golpe detectados por IA / heurísticas
      template = 'general_scam';
    }
  }

  return {
    level,
    template,
    brand,
    domain,
    official_domain: officialDomain,
    signals: parsed.sinais || [],
    explanation: parsed.explicacao_simples || (parsed.sinais && parsed.sinais[0]) || '',
    checks: ['domínio', 'listas de ameaças', 'idade do domínio', 'padrão da mensagem'],
    vezes_reportada: parsed.vezes_reportada || 0,
    original_text: text,
    internal: {
      score,
      model: parsed.modelo_utilizado || 'google/gemini-3.8-flash',
      source: parsed.origem_veredito || 'ia'
    }
  };
}

/**
 * Renderizador Universal de Mensagens de Resposta para WhatsApp
 * Garante rigorosamente: ≤ 600 caracteres, ≤ 12 linhas, blindagem jurídica.
 */
export function renderWhatsAppResponse(contract, options = {}) {
  const brandName = options.brandName || BRAND_NAME;
  const brandUrl = options.brandUrl || BRAND_URL;
  const n = contract.vezes_reportada || 0;

  let headerCounter = '';
  if (n >= 3) {
    headerCounter = `_Esta mensagem já foi verificada ${n} vezes._\n\n`;
  }

  const rodape = [
    '_Análise automática: confirme sempre por canal oficial._',
    `_ÚTIL / ERRO / DETALHES · ${brandName} (${brandUrl})_`
  ].join('\n');

  // T5: Erro / Não foi possível analisar
  if (contract.template === 'error' || contract.level === 'error') {
    return [
      '⚪ *Não foi possível analisar esta mensagem agora.*',
      '',
      'Até confirmar, não clique em links nem envie dinheiro ou códigos. Confirme por um canal oficial e tente novamente dentro de alguns minutos.',
      `_${brandName} (${brandUrl})_`
    ].join('\n');
  }

  // T4: Sem sinais de risco
  if (contract.template === 'none' || contract.level === 'low') {
    return [
      '🟢 *Sem sinais de risco encontrados.*',
      '',
      'Isto não garante que a mensagem seja segura. Se pede dinheiro, dados ou códigos, confirme por um canal oficial antes de agir.',
      rodape
    ].join('\n');
  }

  // T2: "Olá mãe / pai"
  if (contract.template === 'familiar') {
    const text = (contract.original_text || '').toLowerCase();
    const asksMoney = /mbway|mb\s*way|transfer[eê]ncia|dinheiro|euros?|\d+\s*€|pagar\s+uma\s+conta/i.test(text);

    let title = asksMoney
      ? '🔴 *Provável golpe: não envie dinheiro.*'
      : '🟠 *Suspeito: parece o golpe do "Olá mãe/pai".*';

    return [
      title,
      '',
      '*Porquê:* este tipo de mensagem costuma ser o primeiro passo de um pedido de dinheiro por MB WAY ou transferência.',
      '',
      '*O que fazer:*',
      '1. Não envie dinheiro nem códigos.',
      '2. Ligue para o número habitual do seu familiar, não para este.',
      '3. Se não conseguir falar com ele, faça uma pergunta que só ele saiba responder.',
      '',
      '*Já enviou dinheiro?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // T3: Referência Multibanco (sempre neutro)
  if (contract.template === 'reference') {
    const marca = contract.brand;
    const passo1 = marca
      ? `Confirme na app ou no site oficial de ${marca} que a entidade e a referência estão corretas.`
      : 'Confirme na app ou no site oficial da entidade que espera que a entidade e a referência estão corretas.';

    return [
      '🟠 *Atenção: confirme antes de pagar.*',
      '',
      '*Porquê:* a mensagem traz dados de pagamento por referência, e não conseguimos confirmar a origem do pedido.',
      '',
      '*O que fazer:*',
      `1. ${passo1}`,
      '2. Se não esperava esta cobrança, não pague.',
      rodape
    ].join('\n');
  }

  // Criptomoedas / Investimento Pirâmide
  if (contract.template === 'crypto_investment') {
    const title = contract.level === 'high'
      ? '🔴 *Provável golpe: não envie dinheiro.*'
      : '🟠 *Suspeito: promessa de lucros irreais.*';

    return [
      title,
      '',
      '*Porquê:* promete ganhos rápidos ou retornos garantidos, padrão clássico para induzir transferências sem retorno.',
      '',
      '*O que fazer:*',
      '1. Não transfira dinheiro nem compre criptoativos.',
      '2. Desconfie sempre de promessas de lucros fáceis ou garantidos.',
      '3. Guarde uma captura de ecrã para prova e bloqueie o contacto.',
      '',
      '*Já enviou dinheiro?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falso Emprego / Tarefas online
  if (contract.template === 'job_offer') {
    const title = contract.level === 'high'
      ? '🔴 *Provável golpe: não faça pagamentos.*'
      : '🟠 *Suspeito: oferta de tarefas pagas.*';

    return [
      title,
      '',
      '*Porquê:* ofertas de trabalho fácil com pagamento por tarefas costumam exigir adiantamentos que não são devolvidos.',
      '',
      '*O que fazer:*',
      '1. Não pague taxas de adesão nem forneça dados bancários.',
      '2. Pedir pagamento antecipado para trabalhar costuma ser um sinal de alerta.',
      '3. Guarde uma captura de ecrã para prova e bloqueie o remetente.',
      '',
      '*Já enviou dinheiro ou dados?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Burla MB WAY no Multibanco (vendedor OLX / Vinted)
  if (contract.template === 'mbway_seller') {
    return [
      '🔴 *Provável golpe: não vá ao Multibanco.*',
      '',
      '*Porquê:* o suposto comprador tenta fazê-lo ir a um Multibanco ou autorizar débitos em vez de lhe pagar.',
      '',
      '*O que fazer:*',
      '1. Para receber por MB WAY só precisa de dar o seu número de telemóvel.',
      '2. Não é necessário aceder a uma caixa Multibanco nem fornecer códigos.',
      '3. Guarde uma captura de ecrã para prova e cancele o negócio.',
      '',
      '*Já autorizou alguma operação?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falso Apoio Bancário / Spoofing de SMS ou chamada
  if (contract.template === 'fake_bank_support') {
    return [
      '🔴 *Provável golpe: não ligue para este número.*',
      '',
      '*Porquê:* a mensagem simula um alerta de segurança bancária para o levar a telefonar e ceder códigos de autorização.',
      '',
      '*O que fazer:*',
      '1. Não ligue para o número indicado nem responda à mensagem.',
      '2. Ligue diretamente para o seu banco através do número no verso do cartão.',
      '3. Guarde uma captura de ecrã para prova e bloqueie o remetente.',
      '',
      '*Já forneceu códigos ou dados?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falsa Notificação Policial / Judicial
  if (contract.template === 'fake_police_legal') {
    return [
      '🔴 *Provável golpe: não responda nem pague.*',
      '',
      '*Porquê:* utiliza falsas ameaças judiciais ou policiais para coagir ao pagamento rápido de supostas multas.',
      '',
      '*O que fazer:*',
      '1. Não faça nenhum pagamento nem forneça dados pessoais.',
      '2. Confirme sempre diretamente com a entidade, pelos contactos oficiais.',
      '3. Guarde uma captura de ecrã para prova e bloqueie o remetente.',
      '',
      '*Já efetuou algum pagamento?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falso Arrendamento / Caução
  if (contract.template === 'fake_rental') {
    return [
      '🔴 *Provável golpe: não transfira sinal.*',
      '',
      '*Porquê:* exige o pagamento de caução antes da visita presencial ao imóvel, sem garantias de existência.',
      '',
      '*O que fazer:*',
      '1. Evite enviar cauções antes de visitar o imóvel e confirmar o proprietário.',
      '2. Desconfie de rendas muito abaixo dos preços de mercado.',
      '3. Guarde uma captura de ecrã para prova e não envie documentos.',
      '',
      '*Já transferiu algum valor?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falso Crédito / Empréstimo
  if (contract.template === 'fake_credit') {
    return [
      '🔴 *Provável golpe: não pague comissões.*',
      '',
      '*Porquê:* promete aprovação de crédito imediato mas exige pagamento adiantado de supostas taxas de abertura.',
      '',
      '*O que fazer:*',
      '1. Evite pagar qualquer valor adiantado para ter acesso a empréstimos.',
      '2. Confirme se a entidade está registada em bportugal.pt/entidades-autorizadas.',
      '3. Guarde uma captura de ecrã para prova e bloqueie o remetente.',
      '',
      '*Já pagou taxas adiantadas?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Falso Prémio / Lotaria / Sorteio
  if (contract.template === 'lottery_gift') {
    return [
      '🔴 *Provável golpe: não introduza dados.*',
      '',
      '*Porquê:* promete prémios em sorteios em que não participou para recolher dados de pagamento sob pretexto de portes.',
      '',
      '*O que fazer:*',
      '1. Não pague despesas de envio nem introduza dados do seu cartão.',
      '2. Desconfie de prémios de sorteios em que não participou.',
      '3. Guarde uma captura de ecrã para prova e apague a mensagem.',
      '',
      '*Já forneceu dados do cartão?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // T1: Link a imitar uma marca
  if (contract.template === 'link_brand') {
    const marca = contract.brand;
    const dominio = contract.domain || 'indicado';
    const dominioOficial = contract.official_domain;

    let porque = '';
    let passo2 = '';

    if (marca && dominioOficial) {
      porque = `o link (${dominio}) não é o site oficial de ${marca} (${dominioOficial}) e a mensagem pede um pagamento urgente.`;
      passo2 = `Se espera algo de ${marca}, confirme no site ou na app oficial.`;
    } else if (marca) {
      porque = `o link (${dominio}) não corresponde aos canais oficiais de ${marca} e a mensagem pede um pagamento urgente.`;
      passo2 = `Se espera algo de ${marca}, confirme no site ou na app oficial.`;
    } else {
      porque = `o link (${dominio}) tem sinais de imitação ou de risco e a mensagem pede um pagamento urgente.`;
      passo2 = 'Se espera algo desta entidade, confirme no site ou na app oficial.';
    }

    return [
      '🔴 *Provável golpe: não clique nem pague.*',
      '',
      `*Porquê:* ${porque}`,
      '',
      '*O que fazer:*',
      '1. Não clique no link nem introduza dados do cartão.',
      `2. ${passo2}`,
      '3. Guarde uma captura de ecrã para prova e apague a mensagem.',
      '',
      '*Já clicou ou pagou?* Responda *AJUDA*.',
      rodape
    ].join('\n');
  }

  // Motor Universal Dinâmico: frase fixa e segura para os 50+ tipos restantes
  const title = contract.level === 'high'
    ? '🔴 *Provável golpe: não pague nem aceda.*'
    : '🟠 *Suspeito: confirme antes de agir.*';

  return [
    title,
    '',
    '*Porquê:* esta mensagem apresenta sinais de risco e pede uma ação urgente.',
    '',
    '*O que fazer:*',
    '1. Não clique em links, não forneça códigos nem transfira dinheiro.',
    '2. Confirme sempre diretamente com a entidade, pelos contactos oficiais.',
    '3. Guarde uma captura de ecrã para prova e bloqueie o remetente.',
    '',
    '*Já clicou ou pagou?* Responda *AJUDA*.',
    rodape
  ].join('\n');
}

/**
 * Resposta ao comando AJUDA
 */
export function renderHelpResponse() {
  return [
    '*Já clicou ou pagou? Faça isto agora:*',
    '',
    '1. *Banco:* ligue já ao seu banco (número no verso do cartão) e peça para bloquear o cartão ou a operação.',
    '2. *MB WAY:* se partilhou códigos ou associou números, desative o serviço na app MB WAY ou na app do seu banco.',
    '3. *Credenciais:* altere de imediato as palavras-passe das contas que possam ter sido expostas.',
    '4. *Provas:* guarde capturas de ecrã da mensagem, do contacto e dos comprovativos. Não apague nada.',
    '5. *Queixa formal:* apresente queixa na PSP, GNR, PJ ou no Sistema Queixa Eletrónica (queixaselectronicas.mai.gov.pt). Para apoio confidencial e gratuito, contacte a Linha de Apoio à Vítima da APAV (116 006).',
    '',
    'Quanto mais depressa agir, maiores as hipóteses de travar a operação.'
  ].join('\n');
}

/**
 * Resposta ao comando DETALHES
 */
export function renderDetailsResponse(contract) {
  const sinais = (contract.signals || []).filter(Boolean);
  let sinaisTexto = '';

  if (sinais.length > 0) {
    sinaisTexto = sinais.slice(0, 3).map(s => `• ${s.replace(/\|/g, '').trim()}`).join('\n');
  } else {
    sinaisTexto = '• Nenhum sinal de alarme detetado na estrutura da mensagem.';
  }

  return [
    '*Detalhes da análise:*',
    '',
    '• *Sinais encontrados:*',
    sinaisTexto,
    '',
    '• *Verificações efetuadas:*',
    '- Verificação de domínio e canais oficiais',
    '- Consulta a listas de ameaças e inteligência de segurança',
    '- Análise de idade do domínio e reputação',
    '- Deteção de padrões de engenharia social e urgência',
    '',
    '_Esta análise é automática e pode errar._'
  ].join('\n');
}

/**
 * Resposta aos comandos ÚTIL e ERRO
 */
export function renderFeedbackResponse(tipo) {
  if (tipo === 'util') {
    return 'Obrigado!';
  }
  return 'Obrigado. Vamos rever esta análise.';
}

/**
 * Resposta quando não há análise nas últimas 24h
 */
export function renderNoSessionResponse() {
  return 'Não encontrei uma análise recente nas últimas 24 horas. Envie-me a mensagem ou link que deseja verificar.';
}
