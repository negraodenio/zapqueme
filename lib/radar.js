// lib/radar.js — Motor de Detecção de Impersonation & Threat Radar
// Especificação Fechada ZAP, QUEM É? — B2B

import crypto from 'node:crypto';

/**
 * Normaliza strings para comparação de marcas (lowercase, sem acentos, sem pontuação, espaços normalizados)
 * Conforme Seção 10 da especificação.
 */
export function normalizarTexto(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // remove acentos
    .toLowerCase()
    .replace(/[^\w\s]/gi, ' ') // remove pontuação básica
    .replace(/\s+/g, ' ') // normaliza espaços
    .trim();
}

/**
 * Extrai o hostname limpo de uma URL, domínio ou endereço de email
 * Conforme Seção 11 da especificação.
 */
export function extrairHostname(str) {
  if (!str || typeof str !== 'string') return '';
  let clean = str.toLowerCase().trim();

  // Se tiver formato de email (ex: user@dominio.com), pega o domínio após o @
  if (clean.includes('@')) {
    clean = clean.split('@')[1] || clean;
  }

  // Remove protocolo http://, https://
  clean = clean.replace(/^[a-z0-9]+:\/\//, '');

  // Remove caminho /... e parâmetros ?...
  clean = clean.split('/')[0].split('?')[0].split('#')[0];

  // Remove porta :8080
  clean = clean.split(':')[0];

  return clean.trim();
}

/**
 * Verifica se um canal mencionado corresponde a algum canal oficial cadastrado da empresa.
 * Conforme Seção 11 da especificação.
 */
export function isCanalOficial(canalMencionado, empresa) {
  if (!canalMencionado || !empresa) return false;

  const canalLimpo = canalMencionado.trim();
  const canalLower = canalLimpo.toLowerCase();

  // 1. TELEFONE: comparar apenas os dígitos numéricos
  const canalDigitos = canalLimpo.replace(/\D/g, '');
  if (canalDigitos.length >= 8 && empresa.telefone_oficial) {
    const telOficialDigitos = empresa.telefone_oficial.replace(/\D/g, '');
    if (telOficialDigitos.length >= 8) {
      if (
        canalDigitos === telOficialDigitos ||
        canalDigitos.endsWith(telOficialDigitos) ||
        telOficialDigitos.endsWith(canalDigitos)
      ) {
        return true;
      }
    }
  }

  // 2. EMAIL: comparar email exato, domínio do email ou domínio oficial
  if (canalLower.includes('@')) {
    const canalEmailDomain = canalLower.split('@')[1];

    if (empresa.email_oficial) {
      const emailOficialLower = empresa.email_oficial.toLowerCase().trim();
      // Email exato
      if (canalLower === emailOficialLower) return true;

      // Domínio do email oficial
      const oficialEmailDomain = emailOficialLower.split('@')[1];
      if (oficialEmailDomain && canalEmailDomain === oficialEmailDomain) return true;
    }

    if (empresa.dominio_oficial) {
      const oficialHost = extrairHostname(empresa.dominio_oficial);
      if (oficialHost && (canalEmailDomain === oficialHost || canalEmailDomain.endsWith('.' + oficialHost))) {
        return true;
      }
    }
  }

  // 3. DOMÍNIO / HOSTNAME
  const canalHost = extrairHostname(canalLimpo);
  if (canalHost && empresa.dominio_oficial) {
    const oficialHost = extrairHostname(empresa.dominio_oficial);
    if (oficialHost) {
      // Aceita xpto.pt e subdomínio app.xpto.pt. Não aceita xpto.pt.fake.com
      if (canalHost === oficialHost || canalHost.endsWith('.' + oficialHost)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Busca empresas ativas no Supabase
 */
export async function getEmpresasAtivasFromDB() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return [];

  try {
    const resp = await fetch(`${url}/rest/v1/empresas?status=eq.ativo&select=*`, {
      headers: {
        'Content-Type': 'application/json',
        apikey: key,
        Authorization: `Bearer ${key}`
      }
    });
    if (!resp.ok) return [];
    return await resp.json();
  } catch (err) {
    console.warn('[Radar] Erro ao buscar empresas ativas:', err.message);
    return [];
  }
}

/**
 * Regras de detecção de Impersonation
 * Conforme Seção 9, 10, 11 da especificação.
 *
 * impersonation=true SOMENTE quando TODAS as 4 condições forem verdadeiras:
 * 1. marca_mencionada corresponde a exatamente UMA empresa ativa;
 * 2. veredito é: golpe OU suspeito;
 * 3. existe canal_mencionado;
 * 4. canal_mencionado NÃO corresponde a nenhum canal oficial cadastrado.
 * Se qualquer condição falhar: impersonation=false
 * Se houver ambiguidade entre empresas: não associar.
 */
export async function detectarImpersonation({
  marca_mencionada,
  canal_mencionado,
  veredito,
  empresasList = null
}) {
  // Condição 2: veredito deve ser 'golpe' ou 'suspeito'
  const isSuspeitoOuGolpe = veredito === 'golpe' || veredito === 'suspeito';

  // Se não houver marca mencionada, não há correspondência
  if (!marca_mencionada || typeof marca_mencionada !== 'string' || !marca_mencionada.trim()) {
    return { empresa_id: null, impersonation: false };
  }

  const normMarca = normalizarTexto(marca_mencionada);
  if (!normMarca) {
    return { empresa_id: null, impersonation: false };
  }

  // Lista de empresas ativas (passada explicitamente em testes ou buscada do banco)
  const empresas = empresasList !== null ? empresasList : await getEmpresasAtivasFromDB();

  // Condição 1: Correspondência de marca com exatamente UMA empresa ativa
  const matchingEmpresas = empresas.filter(emp => {
    if (emp.status && emp.status !== 'ativo') return false;

    // Compara nome oficial
    const normNome = normalizarTexto(emp.nome);
    if (normNome === normMarca) return true;

    // Compara apelidos / aliases da marca
    if (Array.isArray(emp.apelidos_marca)) {
      for (const alias of emp.apelidos_marca) {
        if (normalizarTexto(alias) === normMarca) return true;
      }
    }

    return false;
  });

  // Se nenhuma empresa ou ambiguidade (mais de uma empresa): não associar
  if (matchingEmpresas.length !== 1) {
    return { empresa_id: null, impersonation: false };
  }

  const matchedEmpresa = matchingEmpresas[0];

  // Se o veredito não for golpe nem suspeito, não é impersonation (mesmo que haja marca)
  if (!isSuspeitoOuGolpe) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Condição 3: existe canal_mencionado
  if (!canal_mencionado || typeof canal_mencionado !== 'string' || !canal_mencionado.trim()) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Condição 4: canal_mencionado NÃO corresponde a nenhum canal oficial cadastrado
  const ehOficial = isCanalOficial(canal_mencionado, matchedEmpresa);
  if (ehOficial) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Todas as 4 condições satisfeitas!
  return {
    empresa_id: matchedEmpresa.id,
    impersonation: true
  };
}

/**
 * Gera código de selo de alta entropia e imprevisível
 * Formato exemplo: ZQV-7K4M9X2P8R6T1 (Conforme Seção 4.3)
 */
export function gerarCodigoSelo() {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const bytes = crypto.randomBytes(13);
  let randomStr = '';
  for (let i = 0; i < bytes.length; i++) {
    randomStr += chars[bytes[i] % chars.length];
  }
  return `ZQV-${randomStr}`;
}

/**
 * Classifica o setor institucional de uma marca para priorização Enterprise
 * (SIBS / MB WAY, Banca, Seguradoras, DECO / Consumidor, Logística, Utilities, Estado)
 */
export function classificarSetorMarca(marca = '') {
  const m = normalizarTexto(marca);
  if (!m) return 'Geral / Outros';

  if (/(sibs|mb\s*way|mbway|multibanco|paypal|revolut|stripe|easypay|ifthenpay|eupago)/.test(m)) {
    return 'SIBS / Pagamentos';
  }
  if (/(cgd|caixa geral|millennium|bcp|novo banco|novobanco|santander|bpi|activobank|montepio|bankinter|banco|itau|bradesco|nubank|credito agricola)/.test(m)) {
    return 'Banca & Financeiro';
  }
  if (/(fidelidade|ageas|tranquilidade|generali|allianz|mapfre|zurich|ok\s*teleseguros|seguro|seguradora|logo\s*seguros|caravela|real\s*vida|una\s*seguros)/.test(m)) {
    return 'Seguradoras';
  }
  if (/(deco|proteste|continente|worten|pingo doce|auchan|fnac|amazon|olx|vinted|wallapop)/.test(m)) {
    return 'DECO / Retalho & E-Commerce';
  }
  if (/(edp|galp|endesa|iberdrola|meo|nos|vodafone|digi|via\s*verde|viaverde|epal|aguas)/.test(m)) {
    return 'Energia, Telecom & Via Verde';
  }
  if (/(ctt|dpd|gls|dhl|ups|fedex|correios|chronopost|Nacex|mrw|seur)/.test(m)) {
    return 'Logística & Entregas';
  }
  if (/(financas|autoridade tributaria|at|seguranca social|sns| sns24|cuf|hospital da luz|lusiadas|gov|estado)/.test(m)) {
    return 'Estado & Saúde';
  }
  return 'Empresas & Serviços';
}

/**
 * Extrai Indicadores de Compromisso (IOCs) Financeiros e de Telecomunicações
 * desenhados para o ecossistema SIBS / MB WAY, Banca, Seguradoras, DECO Proteste e CERT.PT.
 */
export function extrairIOCsFinanceiros(texto = '', canalMencionado = '', alertaLink = '', tipo = '') {
  const combinado = [texto, canalMencionado, alertaLink, tipo].filter(Boolean).join(' \n ');
  const lower = combinado.toLowerCase();

  // 1. Entidade Multibanco (5 dígitos precedidos por "entidade", "ent", "ent.mb" ou contexto MB)
  const entidadesSet = new Set();
  const entRegex = /(?:entidade(?:\s*mb)?|ent\.?\s*mb|ent\.?|multibanco\s+entidade)[\s:.-]*(\d{5})\b/gi;
  let match;
  while ((match = entRegex.exec(combinado)) !== null) {
    entidadesSet.add(match[1]);
  }

  // 2. Referência Multibanco (9 dígitos: XXX XXX XXX ou XXXXXXXXX precedido por "ref", "ref.mb", "referência")
  const referenciasSet = new Set();
  const refRegex = /(?:refer[eê]ncia(?:\s*mb)?|ref\.?\s*mb|ref\.?)[\s:.-]*(\d{3}[\s.-]?\d{3}[\s.-]?\d{3})\b/gi;
  while ((match = refRegex.exec(combinado)) !== null) {
    const digits = match[1].replace(/\D/g, '');
    if (digits.length === 9) {
      referenciasSet.add(`${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6, 9)}`);
      referenciasSet.add(digits);
    }
  }

  // 3. IBAN (PT50 ou internacional)
  const ibansSet = new Set();
  const ibanRegex = /\b(PT50(?:[\s.-]*\d){21}|[A-Z]{2}\d{2}(?:[\s.-]*[A-Z0-9]){11,30})\b/gi;
  while ((match = ibanRegex.exec(combinado)) !== null) {
    const cleanIban = match[1].replace(/[\s.-]+/g, '').toUpperCase();
    if (cleanIban.startsWith('PT50') && cleanIban.length === 25) {
      ibansSet.add(cleanIban);
    } else if (/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(cleanIban) && /\d{8,}/.test(cleanIban)) {
      ibansSet.add(cleanIban);
    }
  }

  // 4. Números de Telemóvel / WhatsApp / MB WAY do burlão (PT +351 9xx/2xx ou BR +55)
  const telefonesSet = new Set();
  const telRegex = /(?:\+?351[\s.-]*)?\b(9[1236]\d[\s.-]*\d{3}[\s.-]*\d{3}|2\d{2}[\s.-]*\d{3}[\s.-]*\d{3})\b/g;
  while ((match = telRegex.exec(combinado)) !== null) {
    const dig = match[1].replace(/\D/g, '');
    // Evita confundir uma referência MB já extraída com um telefone
    const fmtRef = `${dig.slice(0, 3)} ${dig.slice(3, 6)} ${dig.slice(6, 9)}`;
    if (dig.length === 9 && !referenciasSet.has(fmtRef)) {
      telefonesSet.add(`+351 ${dig.slice(0, 3)} ${dig.slice(3, 6)} ${dig.slice(6, 9)}`);
      telefonesSet.add(`+351${dig}`);
    }
  }

  // 5. Domínios e URLs suspeitos
  const dominiosSet = new Set();
  const urlsSet = new Set();
  const urlCandidates = [canalMencionado, texto].filter(Boolean).join(' ');
  const urlMatchRegex = /(?:https?:\/\/[^\s<>"'{}|\\^`]+|www\.[^\s<>"'{}|\\^`]+|\b[a-zA-Z0-9-]+\.(?:pt|com|net|org|top|xyz|site|online|shop|info|live|click|vip|work|buzz|com\.br)\b[^\s<>"'{}|\\^`]*)/gi;
  while ((match = urlMatchRegex.exec(urlCandidates)) !== null) {
    let raw = match[0].replace(/[.,;!?)]+$/, '');
    if (raw.includes('@')) continue; // ignora emails aqui
    const host = extrairHostname(raw);
    if (host && host.includes('.')) {
      dominiosSet.add(host);
      urlsSet.add(raw.startsWith('http') ? raw : `https://${raw}`);
    }
  }

  const entidades_mb = [...entidadesSet];
  const referencias_mb = [...referenciasSet];
  const ibans = [...ibansSet];
  const telefones = [...telefonesSet];
  const dominios = [...dominiosSet];
  const urls = [...urlsSet];

  // 6. Classificação Tática (Modus Operandi)
  let tatica_codigo = 'IMPERSONATION_MARCA';
  let tatica_nome = 'Usurpação de Marca / Canal Falso';

  if (/(ol[aá]\s+pai|ol[aá]\s+m[aã]e|oi\s+m[aã]e|oi\s+pai|n[uú]mero\s+novo|falso\s+parente|falso\s+filho)/i.test(lower)) {
    tatica_codigo = 'BURLA_OLA_PAI_MAE';
    tatica_nome = 'Falso Familiar WhatsApp (Olá Pai/Mãe)';
  } else if (entidades_mb.length > 0 || referencias_mb.length > 0 || /(entidade\s*:?\s*\d{5}|refer[eê]ncia\s*:?\s*\d{3})/i.test(combinado)) {
    tatica_codigo = 'SMISHING_ENTIDADE_MB';
    tatica_nome = 'Cobrança Fraudulenta (Entidade/Ref MB)';
  } else if (/(mb\s*way|mbway|c[oó]digo\s+mb|autoriza[cç][aã]o\s+mb|olx.*mb)/i.test(lower)) {
    tatica_codigo = 'FRAUDE_MBWAY';
    tatica_nome = 'Burla / Engenharia Social MB WAY';
  } else if (/(ap[oó]lice|carta\s+verde|sinistro|seguro|fidelidade|ageas|tranquilidade|allianz|generali)/i.test(lower)) {
    tatica_codigo = 'FALSA_SEGURADORA';
    tatica_nome = 'Falsa Cobrança Apólice / Sinistro Seguradora';
  } else if (/(via\s*verde|portagem|edp|galp|endesa|fatura\s+em\s+atraso|corte\s+de\s+fornecimento)/i.test(lower)) {
    tatica_codigo = 'FALSA_PORTAGEM_UTILITY';
    tatica_nome = 'Falsa Portagem / Fatura Energia & Telecom';
  } else if (/(encomenda|alf[aâ]ndega|desalfandegamento|ctt|dpd|dhl|correios|entrega\s+suspensa)/i.test(lower)) {
    tatica_codigo = 'FALSA_ENTREGA';
    tatica_nome = 'Falsa Encomenda / Taxa de Alfândega';
  } else if (/(banco|conta\s+bloqueada|acesso\s+suspenso|cart[aã]o\s+bloqueado|homebanking|caixadirecta)/i.test(lower)) {
    tatica_codigo = 'PHISHING_BANCO';
    tatica_nome = 'Phishing Bancário / Roubo de Credenciais';
  }

  // 7. Construir resumo determinístico de IOC (para persistência em canal_mencionado quando não há URL)
  let resumo_ioc = null;
  if (entidades_mb.length > 0 || referencias_mb.length > 0) {
    const entPart = entidades_mb.length ? `Ent: ${entidades_mb[0]}` : '';
    const refPart = referencias_mb.length ? `Ref: ${referencias_mb[0]}` : '';
    resumo_ioc = `MB ${[entPart, refPart].filter(Boolean).join(' / ')}`.trim();
  } else if (ibans.length > 0) {
    resumo_ioc = `IBAN ${ibans[0]}`;
  } else if (dominios.length > 0) {
    resumo_ioc = urls[0] || dominios[0];
  } else if (telefones.length > 0) {
    resumo_ioc = telefones[0];
  }

  return {
    entidades_mb,
    referencias_mb,
    ibans,
    telefones,
    dominios,
    urls,
    tatica_codigo,
    tatica_nome,
    resumo_ioc,
    tem_ioc_financeiro: entidades_mb.length > 0 || referencias_mb.length > 0 || ibans.length > 0 || tatica_codigo === 'FRAUDE_MBWAY'
  };
}

/**
 * Compila a Inteligência Enterprise do Threat Radar:
 * 1. Detetor de Surtos / Campanhas Ativas (Outbreak Clustering por IOC ou Marca+Tática)
 * 2. Feed Estruturado de IOCs Financeiros & Telecom (SIBS / MB WAY / Banca / CERT.PT)
 * 3. Shadow Radar Unificado (Clientes Ativos + Pipeline + Marcas Vigiadas Não-Clientes)
 */
export function compilarIntelligenceRadar({
  empresas = [],
  radar = [],
  ocorrencias = [],
  sinais = [],
  marcas = []
} = {}) {
  const agora = Date.now();
  const vinteQuatroHorasMs = 24 * 60 * 60 * 1000;
  const seteDiasMs = 7 * 24 * 60 * 60 * 1000;

  // Unifica ocorrências e sinais sem duplicar IDs exatos
  const vistos = new Set();
  const todosEventos = [];
  let idxSeq = 0;
  for (const ev of [...(sinais || []), ...(ocorrencias || [])]) {
    if (!ev) continue;
    idxSeq++;
    const key = ev.id || `ev_${idxSeq}_${ev.criado_em || ev.data || ''}_${ev.marca_mencionada || ev.marca || ev.empresa || ''}`;
    if (vistos.has(key)) continue;
    vistos.add(key);
    todosEventos.push(ev);
  }

  // Mapa de clusters de surtos e agregação de IOCs
  const clustersMap = new Map();
  const iocsMap = new Map();

  const addIocEntry = (tipoCode, valor, marcaAlvo, setorAlvo, empresaId, iocObj, tsIso, peso) => {
    if (!valor) return;
    const k = `${tipoCode}::${valor}`;
    if (!iocsMap.has(k)) {
      iocsMap.set(k, {
        id: crypto.randomUUID(),
        tipo: tipoCode,
        tipo_ioc: tipoCode,
        valor,
        indicador: valor,
        marca: marcaAlvo,
        marca_alvo: marcaAlvo,
        empresa_id: empresaId || null,
        setor: setorAlvo,
        setor_alvo: setorAlvo,
        tatica_codigo: iocObj.tatica_codigo,
        tatica_nome: iocObj.tatica_nome,
        ocorrencias: 0,
        vezes_reportada: 0,
        primeira_deteccao: tsIso,
        ultima_deteccao: tsIso
      });
    }
    const entry = iocsMap.get(k);
    entry.ocorrencias += peso;
    entry.vezes_reportada += peso;
    if (tsIso < entry.primeira_deteccao) entry.primeira_deteccao = tsIso;
    if (tsIso > entry.ultima_deteccao) entry.ultima_deteccao = tsIso;
  };

  for (const ev of todosEventos) {
    const canalTexto = ev.canal_mencionado || ev.canal || '';
    const ioc = extrairIOCsFinanceiros(
      ev.texto_original || '',
      canalTexto,
      ev.alerta_link || '',
      ev.tipo || ''
    );
    const marcaAlvo = (ev.marca_mencionada || ev.empresa || ev.marca || ev.empresa_nome || 'Não especificada').trim();
    const setorAlvo = classificarSetorMarca(marcaAlvo);
    const tsIso = ev.criado_em || ev.data || new Date().toISOString();
    const ts = new Date(tsIso).getTime() || agora;
    const is24h = (agora - ts) <= vinteQuatroHorasMs;
    const is7d = (agora - ts) <= seteDiasMs;
    const pesoReportes = Math.max(1, parseInt(ev.vezes_reportada, 10) || 1);

    // Regista cada IOC individualmente no Feed Financeiro & Técnico (SIBS / MB WAY / CERT.PT)
    for (const ent of ioc.entidades_mb) {
      addIocEntry('ENTIDADE_MB', ent, marcaAlvo, setorAlvo, ev.empresa_id, ioc, tsIso, pesoReportes);
    }
    for (const ref of ioc.referencias_mb.filter(r => r.includes(' '))) {
      addIocEntry('REFERENCIA_MB', ref, marcaAlvo, setorAlvo, ev.empresa_id, ioc, tsIso, pesoReportes);
    }
    for (const ib of ioc.ibans) {
      addIocEntry('IBAN', ib, marcaAlvo, setorAlvo, ev.empresa_id, ioc, tsIso, pesoReportes);
    }
    for (const tel of ioc.telefones.filter(t => t.includes(' '))) {
      addIocEntry('TELEFONE_BURLA', tel, marcaAlvo, setorAlvo, ev.empresa_id, ioc, tsIso, pesoReportes);
    }
    for (const dom of ioc.dominios) {
      addIocEntry('DOMINIO_PHISHING', dom, marcaAlvo, setorAlvo, ev.empresa_id, ioc, tsIso, pesoReportes);
    }

    // Determina o indicador primário para o Detetor de Surtos
    let indicador = canalTexto.trim();
    let tipoIoc = 'CANAL / LINK';

    if (ioc.entidades_mb.length > 0 || ioc.referencias_mb.length > 0) {
      indicador = ioc.resumo_ioc;
      tipoIoc = 'ENTIDADE / REF MB';
    } else if (ioc.ibans.length > 0) {
      indicador = `IBAN ${ioc.ibans[0]}`;
      tipoIoc = 'IBAN (CONTA MULA)';
    } else if (ioc.dominios.length > 0) {
      indicador = ioc.dominios[0];
      tipoIoc = 'DOMINIO_PHISHING';
    } else if (ioc.telefones.length > 0) {
      indicador = ioc.telefones[0];
      tipoIoc = 'TELEFONE_BURLA';
    } else if (!indicador) {
      indicador = `Campanha ${ioc.tatica_nome} (${marcaAlvo})`;
      tipoIoc = 'PADRAO_MENSAGEM';
    }

    // Agrupa para deteção de Surtos (Outbreak Clustering)
    const clusterKey = `${tipoIoc}::${indicador.toLowerCase()}::${normalizarTexto(marcaAlvo)}`;
    if (!clustersMap.has(clusterKey)) {
      clustersMap.set(clusterKey, {
        cluster_id: Buffer.from(clusterKey).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 16),
        empresa_id: ev.empresa_id || null,
        indicador,
        ioc_principal: indicador,
        tipo_ioc: tipoIoc,
        marca: marcaAlvo,
        marca_alvo: marcaAlvo,
        setor: setorAlvo,
        setor_alvo: setorAlvo,
        tatica_codigo: ioc.tatica_codigo,
        tatica_nome: ioc.tatica_nome,
        eventos_count: 0,
        ocorrencias: 0,
        total_reportes: 0,
        reportes_24h: 0,
        reportes_7d: 0,
        canais_origem: new Set(),
        primeira_deteccao: tsIso,
        ultima_deteccao: tsIso,
        confianca_max: ev.confianca || 85,
        alerta_amostra: ev.alerta_link || ''
      });
    }

    const c = clustersMap.get(clusterKey);
    c.eventos_count += 1;
    c.ocorrencias += pesoReportes;
    c.total_reportes += pesoReportes;
    if (is24h) c.reportes_24h += pesoReportes;
    if (is7d) c.reportes_7d += pesoReportes;
    c.canais_origem.add(ev.canal || 'whatsapp');
    if (tsIso < c.primeira_deteccao) c.primeira_deteccao = tsIso;
    if (tsIso > c.ultima_deteccao) c.ultima_deteccao = tsIso;
    if ((ev.confianca || 0) > c.confianca_max) c.confianca_max = ev.confianca;
  }

  // Formata surtos ativos ordenados por criticidade e volume
  const surtos_ativos = [...clustersMap.values()]
    .map(c => {
      let severidade = 'monitorar';
      let status_surto = 'SINAL_ISOLADO';
      if (c.total_reportes >= 3 || c.reportes_24h >= 3 || (c.tipo_ioc === 'ENTIDADE / REF MB' && c.total_reportes >= 2)) {
        severidade = 'critica';
        status_surto = 'SURTO_CRITICO';
      } else if (c.total_reportes >= 2 || c.tipo_ioc === 'ENTIDADE / REF MB' || c.tipo_ioc === 'IBAN (CONTA MULA)') {
        severidade = 'suspeita';
        status_surto = 'CAMPANHA_ATIVA';
      }
      return {
        ...c,
        canais_origem: [...c.canais_origem],
        severidade,
        status_surto
      };
    })
    .sort((a, b) => {
      const sevOrder = { critica: 3, suspeita: 2, monitorar: 1 };
      if (sevOrder[b.severidade] !== sevOrder[a.severidade]) {
        return sevOrder[b.severidade] - sevOrder[a.severidade];
      }
      return b.total_reportes - a.total_reportes;
    });

  const iocs_financeiros = [...iocsMap.values()].sort((a, b) => b.ocorrencias - a.ocorrencias);

  // 3. Construir Shadow Radar Unificado (Clientes Ativos + Pipeline + Marcas Não-Clientes)
  const empresasAtivas = (empresas || []).filter(e => !e.arquivado_em);
  const shadowMap = new Map();

  // A) Adiciona empresas registadas que estão no radar_ameacas
  for (const r of (radar || [])) {
    const emp = empresasAtivas.find(e => e.id === r.empresa_id);
    if (emp && emp.arquivado_em) continue;
    const norm = normalizarTexto(r.empresa);
    const relacao = emp?.estado === 'ativo' || emp?.status === 'ativo' ? 'cliente_ativo' : 'pipeline_lead';
    shadowMap.set(norm, {
      empresa: r.empresa,
      marca: r.empresa,
      empresa_id: r.empresa_id,
      relacao_comercial: relacao,
      status_comercial: relacao,
      estado_empresa: emp?.estado || emp?.status || 'ativo',
      is_teste: !!emp?.is_teste,
      setor: classificarSetorMarca(r.empresa),
      ocorrencias: parseInt(r.ocorrencias, 10) || 0,
      golpes_confirmados: parseInt(r.ocorrencias, 10) || 0,
      canais_distintos: parseInt(r.canais_distintos, 10) || 0,
      primeira_deteccao: r.primeira_deteccao,
      ultima_deteccao: r.ultima_deteccao,
      severidade: r.severidade || 'monitorar'
    });
  }

  // B) Adiciona marcas de sinais e marcas mencionadas (Shadow Radar para SIBS, MB WAY, Seguradoras, Bancos ainda não clientes)
  const marcasCombinadas = [...(marcas || [])];
  for (const s of (sinais || [])) {
    const nomeSinal = (s.marca || s.marca_mencionada || '').trim();
    if (nomeSinal) {
      marcasCombinadas.push({
        marca: nomeSinal,
        denuncias: 1,
        golpe: 1,
        canais_distintos: 1,
        primeira_denuncia: s.data || s.criado_em,
        ultima_denuncia: s.data || s.criado_em
      });
    }
  }

  for (const m of marcasCombinadas) {
    const nomeMarca = (m.marca || m.marca_norm || '').trim();
    if (!nomeMarca) continue;
    const norm = normalizarTexto(nomeMarca);
    if (!norm) continue;

    const empMatch = empresasAtivas.find(e => {
      if (normalizarTexto(e.nome) === norm || normalizarTexto(e.nome_comercial) === norm) return true;
      const aliases = [...(e.apelidos_marca || []), ...(e.marca_aliases || [])];
      return aliases.some(a => normalizarTexto(a) === norm);
    });

    const denuncias = parseInt(m.denuncias, 10) || 1;
    const golpes = parseInt(m.golpe, 10) || 1;
    const canaisDist = parseInt(m.canais_distintos, 10) || 1;

    if (shadowMap.has(norm)) {
      const existing = shadowMap.get(norm);
      if (!existing.empresa_id) {
        existing.ocorrencias += denuncias;
      } else {
        existing.ocorrencias = Math.max(existing.ocorrencias, denuncias);
      }
      existing.golpes_confirmados = Math.max(existing.golpes_confirmados, golpes);
      existing.canais_distintos = Math.max(existing.canais_distintos, canaisDist);
    } else {
      let relacao = 'oportunidade_shadow';
      if (empMatch) {
        relacao = (empMatch.estado === 'ativo' || empMatch.status === 'ativo') ? 'cliente_ativo' : 'pipeline_lead';
      }
      const nomeExibicao = empMatch ? (empMatch.nome_comercial || empMatch.nome) : nomeMarca;
      shadowMap.set(norm, {
        empresa: nomeExibicao,
        marca: nomeExibicao,
        empresa_id: empMatch ? empMatch.id : null,
        relacao_comercial: relacao,
        status_comercial: relacao,
        estado_empresa: empMatch ? (empMatch.estado || empMatch.status) : 'nao_cadastrada',
        is_teste: !!empMatch?.is_teste,
        setor: classificarSetorMarca(nomeMarca),
        ocorrencias: denuncias,
        golpes_confirmados: golpes,
        canais_distintos: canaisDist,
        primeira_deteccao: m.primeira_denuncia || null,
        ultima_deteccao: m.ultima_denuncia || null,
        severidade: denuncias >= 10 ? 'critica' : (denuncias >= 2 ? 'suspeita' : 'monitorar')
      });
    }
  }

  const shadow_radar = [...shadowMap.values()].sort((a, b) => b.ocorrencias - a.ocorrencias);

  // Resumo executivo para o topo da aba Radar
  const resumo = {
    total_surtos_ativos: surtos_ativos.length,
    total_surtos_criticos: surtos_ativos.filter(s => s.severidade === 'critica').length,
    total_campanhas_ativas: surtos_ativos.filter(s => s.severidade !== 'monitorar').length,
    entidades_mb_detetadas: iocs_financeiros.filter(i => i.tipo === 'ENTIDADE_MB' || i.tipo === 'REFERENCIA_MB').length,
    ibans_detetados: iocs_financeiros.filter(i => i.tipo === 'IBAN').length,
    telefones_burla_detetados: iocs_financeiros.filter(i => i.tipo === 'TELEFONE_BURLA').length,
    dominios_phishing_detetados: iocs_financeiros.filter(i => i.tipo === 'DOMINIO_PHISHING').length,
    marcas_shadow_nao_clientes: shadow_radar.filter(s => s.relacao_comercial === 'oportunidade_shadow').length
  };

  return {
    resumo,
    surtos_ativos: surtos_ativos.slice(0, 50),
    iocs_financeiros: iocs_financeiros.slice(0, 100),
    shadow_radar
  };
}

/**
 * Gera um Pacote Pericial de Takedown & Notificação de Abuso (SIBS / CERT.PT / Seguradoras / DECO)
 * com Hash SHA-256 e zero dados pessoais de vítimas.
 */
export function gerarPacoteTakedown({
  marca = 'Marca Alvo',
  indicador = '',
  tipo_ioc = 'DOMÍNIO / CANAL',
  tatica_nome = 'Usurpação de Marca',
  ocorrencias_total = 1,
  primeira_deteccao = null,
  ultima_deteccao = null,
  exemplos_limpos = [],
  ocorrencias = [],
  sinais = []
} = {}) {
  const agoraIso = new Date().toISOString();
  const setor = classificarSetorMarca(marca);

  // Extrai automaticamente IOCs de ocorrencias/sinais se indicador não foi passado explicitamente
  let indFinal = indicador;
  const todosSinais = [...(ocorrencias || []), ...(sinais || [])];
  if (!indFinal && todosSinais.length > 0) {
    const textos = todosSinais.map(s => s.canal_mencionado || s.canal || s.texto_original || '').join(' | ');
    const extraido = extrairIOCsFinanceiros(textos, textos, '', '');
    const partes = [
      ...extraido.entidades_mb.map(e => `Ent.MB: ${e}`),
      ...extraido.referencias_mb.filter(r => r.includes(' ')).map(r => `Ref.MB: ${r}`),
      ...extraido.ibans.map(i => `IBAN: ${i}`),
      ...extraido.dominios
    ];
    indFinal = partes.length ? partes.join(' | ') : (todosSinais[0].canal_mencionado || todosSinais[0].canal || 'Indicador em análise');
  }
  if (!indFinal) indFinal = 'Indicador em análise';

  const totalCount = Math.max(ocorrencias_total, todosSinais.length, 1);

  const payloadHash = JSON.stringify({
    marca,
    indicador: indFinal,
    tipo_ioc,
    tatica_nome,
    ocorrencias_total: totalCount,
    gerado_em: agoraIso.slice(0, 13)
  });
  const hashForense = crypto.createHash('sha256').update(payloadHash).digest('hex');

  const destRecomendado = (tipo_ioc.includes('MB') || tipo_ioc.includes('IBAN') || indFinal.includes('MB') || setor.includes('SIBS') || setor.includes('Banca'))
    ? 'SIBS Fraud Desk / Equipa de Prevenção de Fraude Bancária & CERT.PT'
    : 'CERT.PT (CNCS) / DNS.PT / Equipa de Segurança (CSIRT) da Marca';

  const destinatarios_sugeridos = [
    destRecomendado,
    `CISO / DPO (${marca})`,
    'DECO Proteste (Defesa do Consumidor)'
  ];

  const assunto = `[ALERTA TÉCNICO DE FRAUDE & IOC] ${marca.toUpperCase()} — Indicador Ativo (${indFinal}) [Ref: ${hashForense.slice(0, 10).toUpperCase()}]`;

  const relatorio = `======================================================================
NOTIFICAÇÃO TÉCNICA DE THREAT INTELLIGENCE & TAKEDOWN (RGPD-COMPLIANT)
CONFIRME, QUEM É? — SISTEMA DE DETEÇÃO PRE-TRANSACTION
======================================================================
Data/Hora de Emissão (UTC): ${agoraIso}
Hash Forense SHA-256:       ${hashForense}
Destinatário Recomendado:   ${destRecomendado}
Setor Impactado:            ${setor}

1. SUMÁRIO EXECUTIVO DO INCIDENTE
----------------------------------------------------------------------
• Marca / Entidade Visada:  ${marca}
• Indicador Malicioso (IOC): ${indFinal}
• Classificação do Vetor:   ${tipo_ioc}
• Modus Operandi (Tática):  ${tatica_nome}
• Volume de Submissões:     ${totalCount} deteção(ões) pré-transação na rede
• Primeira Deteção (UTC):   ${primeira_deteccao || agoraIso}
• Última Deteção (UTC):     ${ultima_deteccao || agoraIso}

2. EVIDÊNCIAS DESPERSONALIZADAS (ART. 5.º RGPD — SEM DADOS DE VÍTIMAS)
----------------------------------------------------------------------
${exemplos_limpos.length > 0 ? exemplos_limpos.map((e, i) => `[Amostra #${i + 1}] "${e}"`).join('\n') : '[Amostra #1] "Mensagem fraudulenta intercetada em canal fechado (SMS/WhatsApp) induzindo pagamento urgente ou recolha de credenciais em nome da marca."'}

3. AÇÕES TÉCNICAS RECOMENDADAS (MITIGAÇÃO IMEDIATA)
----------------------------------------------------------------------
${tipo_ioc.includes('MB') || tipo_ioc.includes('IBAN') || indFinal.includes('MB')
    ? `• [SIBS / SUB-ACQUIRER / BANCA]: Bloqueio preventivo de liquidação para a Entidade/Referência ou IBAN indicado e auditoria ao sub-comerciante originador.\n• [COMUNICAÇÃO]: Alerta preventivo nos canais digitais sobre cobranças falsas por SMS.`
    : `• [CERT.PT / REGISTRAR / CLOUDFLARE]: Solicitação de suspensão imediata de resolução DNS (Takedown) e inclusão na blacklist Google Web Risk / Cloudflare Radar.\n• [OPERADORES TELECOM]: Filtro de Sender ID / URL nos gateways SMS nacionais.`}

======================================================================
Emitido por: Confirme, Quem É? — Threat Intelligence & Brand Protection
Verificação de Integridade: https://confirmequeme.pt
======================================================================`;

  return {
    assunto,
    destinatario_recomendado: destRecomendado,
    destinatarios_sugeridos,
    hash_sha256: hashForense,
    hash_evidencia: hashForense,
    setor,
    relatorio_texto: relatorio,
    corpo_forense: relatorio
  };
}


