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
  let brand = parsed.marca || null;
  let domain = parsed.dominio || null;
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

  // Deteção do Template
  let template = 'none';

  if (isError) {
    template = 'error';
  } else {
    // 1. Caso T2: "Olá mãe / pai"
    const isFamiliar = /ol[aá]\s+(m[aã]e|pai|filh[oa])|perdi\s+o\s+telem[oó]vel|ecr[aã]\s+partiu|n[uú]mero\s+(tempor[aá]rio|provis[oó]rio|novo)/i.test(lower);
    const asksMoney = /mbway|mb\s*way|transfer[eê]ncia|dinheiro|euros?|\d+\s*€|pagar\s+uma\s+conta/i.test(lower);

    if (isFamiliar) {
      template = 'familiar';
    } else {
      // 2. Caso T3: Referência Multibanco
      const hasMultibanco = /entidade|refer[eê]ncia|sub-?entidade/i.test(lower) || parsed.tipo === 'cobranca_multibanco';
      const hasSuspectLink = domain && (level === 'high' || level === 'medium');

      if (hasMultibanco && !hasSuspectLink) {
        template = 'reference';
      } else if (hasSuspectLink || domain || (brand && level === 'high')) {
        // 3. Caso T1: Link a imitar marca ou link de risco
        template = 'link_brand';
      } else if (level === 'low' || parsed.veredito === 'sem sinais de risco' || parsed.veredito === 'legitimo') {
        // 4. Caso T4: Sem sinais de risco
        template = 'none';
      } else {
        template = 'link_brand';
      }
    }
  }

  return {
    level,
    template,
    brand,
    domain,
    official_domain: officialDomain,
    signals: parsed.sinais || [],
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
 * Renderizador Único de Mensagens de Resposta (T1 a T5)
 */
export function renderWhatsAppResponse(contract, options = {}) {
  const brandName = options.brandName || BRAND_NAME;
  const brandUrl = options.brandUrl || BRAND_URL;
  const n = contract.vezes_reportada || 0;

  let headerCounter = '';
  if (n >= 3) {
    headerCounter = `_Esta mensagem já foi verificada ${n} vezes._\n\n`;
  }

  // T5: Erro / Não foi possível analisar
  if (contract.template === 'error' || contract.level === 'error') {
    return [
      '⚪ *Não foi possível analisar esta mensagem agora.*',
      '',
      'Até confirmar, não clique em links nem envie dinheiro ou códigos. Confirme por um canal oficial e tente novamente dentro de alguns minutos.',
      '',
      `_${brandName} · ${brandUrl}_`
    ].join('\n');
  }

  // T4: Sem sinais de risco
  if (contract.template === 'none' || contract.level === 'low') {
    return [
      '🟢 *Sem sinais de risco encontrados.*',
      '',
      'Isto não garante que a mensagem seja segura. Se pede dinheiro, dados ou códigos, confirme por um canal oficial antes de agir.',
      '',
      '_Análise automática._',
      '_Foi útil? Responda ÚTIL ou ERRO · Mais informação: DETALHES_',
      `_${brandName} · ${brandUrl}_`
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
      '',
      '_Análise automática: confirme sempre por um canal oficial._',
      '_Foi útil? Responda ÚTIL ou ERRO · Mais informação: DETALHES_',
      `_${brandName} · ${brandUrl}_`
    ].join('\n');
  }

  // T3: Referência Multibanco (sempre neutro)
  if (contract.template === 'reference') {
    const marca = contract.brand;
    const passo1 = marca
      ? `Confirme na app ou no site oficial de ${marca} (ou da entidade que espera) que a entidade, a referência e o montante estão corretos.`
      : 'Confirme na app ou no site oficial da entidade que espera que a entidade, a referência e o montante estão corretos.';

    return [
      '🟠 *Atenção: confirme antes de pagar.*',
      '',
      '*Porquê:* a mensagem traz dados de pagamento por referência, e não conseguimos confirmar a origem do pedido.',
      '',
      '*O que fazer:*',
      `1. ${passo1}`,
      '2. Se não esperava esta cobrança, não pague.',
      '',
      '_Análise automática: confirme sempre por um canal oficial._',
      '_Foi útil? Responda ÚTIL ou ERRO · Mais informação: DETALHES_',
      `_${brandName} · ${brandUrl}_`
    ].join('\n');
  }

  // T1: Link a imitar uma marca
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
    '3. Apague a mensagem.',
    '',
    '*Já clicou ou pagou?* Responda *AJUDA*.',
    '',
    '_Análise automática: confirme sempre por um canal oficial._',
    '_Foi útil? Responda ÚTIL ou ERRO · Mais informação: DETALHES_',
    `_${brandName} · ${brandUrl}_`
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
    '2. *MB WAY:* se partilhou dados do MB WAY, desative-o na app e altere o código de acesso.',
    '3. *Palavras-passe:* altere as que possa ter introduzido num site suspeito.',
    '4. *Provas:* guarde capturas de ecrã da mensagem, do link e dos comprovativos. Não apague nada.',
    '5. *Queixa:* apresente queixa às autoridades em queixaselectronicas.mai.gov.pt ou contacte a Linha de Apoio à Vítima (116 006).',
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
