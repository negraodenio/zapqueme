// lib/threat_intel.js — Módulo de Inteligência de Ameaças em Tempo Real
// Verifica links contra:
// 1. Google Safe Browsing (Phishing & Malware)
// 2. Cloudflare Security DNS (Detecção de ameaças ativas em tempo real)
// 3. RDAP Oficial (Idade do Domínio — detecta domínios registrados recentemente)
// 4. Base Oficial de Marcas e Typosquatting (Bancos, CTT, Correios e Governo)
// 5. Expansor de Links Encurtados (desmascara bit.ly, tinyurl, etc.)

// Base de domínios oficiais protegidos (Portugal e Brasil)
export const OFFICIAL_DOMAINS = {
  // Bancos Portugal
  cgd: ['cgd.pt', 'caixadirecta.cgd.pt'],
  millennium: ['millenniumbcp.pt', 'ind.millenniumbcp.pt'],
  novobanco: ['novobanco.pt'],
  santander_pt: ['santander.pt'],
  bpi: ['bancobpi.pt'],
  activobank: ['activobank.pt'],
  montepio: ['bancomontepio.pt'],
  mbway: ['mbway.pt', 'sibs.pt'],

  // Entregas Portugal
  ctt: ['ctt.pt'],
  dpd: ['dpd.com', 'dpd.pt'],
  gls: ['gls-portugal.pt', 'gls-group.com'],

  // Saúde Portugal (Clínicas e Hospitais)
  cuf: ['cuf.pt', 'saude.cuf.pt'],
  luz: ['hospitaldaluz.pt', 'luzsaude.pt'],
  lusiadas: ['lusiadas.pt'],
  joaquim_chaves: ['jcs.pt', 'joaquimchaves.pt'],
  trofa: ['trofasaude.pt'],

  // Ordens e Associações Profissionais Portugal
  ordem_medicos: ['ordemdosmedicos.pt'],
  ordem_advogados: ['oa.pt', 'portal.oa.pt'],
  ordem_dentistas: ['omd.pt'],
  apemip: ['apemip.pt'],

  // Telecomunicações & Utilities Portugal (alvos frequentes de smishing)
  meo: ['meo.pt'],
  nos: ['nos.pt'],
  vodafone_pt: ['vodafone.pt'],
  edp: ['edp.pt', 'edpcomercial.pt'],
  galp: ['galp.pt', 'galpenergia.com'],
  endesa: ['endesa.pt'],
  viaverde: ['viaverde.pt'],

  // Retalho e Supermercados Portugal
  continente: ['continente.pt', 'cartao.continente.pt', 'feed.continente.pt', 'zu.pt'],
  worten: ['worten.pt'],
  pingo_doce: ['pingodoce.pt'],
  auchan: ['auchan.pt'],
  fnac: ['fnac.pt'],

  // Governo Portugal
  financas: ['portaldasfinancas.gov.pt', 'at.gov.pt'],
  seguranca_social: ['seg-social.pt'],
  sns: ['sns.gov.pt', 'sns24.gov.pt'],

  // Bancos Brasil
  itau: ['itau.com.br'],
  bradesco: ['bradesco.com.br', 'banco.bradesco'],
  bb: ['bb.com.br'],
  caixa_br: ['caixa.gov.br'],
  santander_br: ['santander.com.br'],
  nubank: ['nubank.com.br'],
  inter: ['inter.co', 'bancointer.com.br'],
  c6: ['c6bank.com.br'],
  mercado_pago: ['mercadopago.com.br', 'mercadolivre.com.br'],

  // Entregas & Governo Brasil
  correios: ['correios.com.br'],
  gov_br: ['gov.br'],
  receita_federal: ['gov.br/receitafederal'],

  // Entregas Internacionais (França, Itália, Reino Unido, EUA e Global)
  chronopost: ['chronopost.fr', 'chronopost.com'],
  laposte: ['laposte.fr', 'colissimo.fr'],
  posteitaliane: ['poste.it', 'posteitaliane.it'],
  usps: ['usps.com'],
  royalmail: ['royalmail.com'],
  dhl: ['dhl.com', 'dhl.de', 'dhl.fr', 'dhl.it', 'dhl.pt'],
  ups: ['ups.com'],
  fedex: ['fedex.com'],

  // Bancos Internacionais (França, Itália, EUA, Reino Unido)
  bnp: ['mabanque.bnpparibas', 'bnpparibas.com', 'bnpparibas.fr'],
  credit_agricole: ['credit-agricole.fr'],
  societe_generale: ['societegenerale.fr', 'societegenerale.com'],
  intesa: ['intesasanpaolo.com'],
  unicredit: ['unicredit.it', 'unicreditgroup.eu'],
  chase: ['chase.com'],
  bankofamerica: ['bankofamerica.com'],
  wells_fargo: ['wellsfargo.com'],
  barclays: ['barclays.co.uk', 'barclays.com'],

  // Serviços Globais Frequentes de Phishing
  netflix: ['netflix.com'],
  amazon: ['amazon.com', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.uk', 'amazon.com.br'],
  paypal: ['paypal.com'],
  apple: ['apple.com', 'icloud.com']
};

// TLDs de altíssimo risco frequentemente usados em golpes
const HIGH_RISK_TLDS = ['.top', '.xyz', '.work', '.click', '.buzz', '.shop', '.site', '.live', '.info', '.online', '.vip', '.rest'];

// Encurtadores conhecidos (comparação por hostname exato ou subdomínio, nunca por substring)
const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'linktr.ee', 'v.gd', 'abre.ai', 'shorte.st', 'rb.gy',
  'shorturl.at', 't.ly', 'ow.ly', 'goo.gl', 'tiny.cc', 'buff.ly', 'rebrand.ly', 'bit.do', 'cutt.us',
  's.id', 'gg.gg', 'lnkd.in', 'encurtador.com.br', 'tr.ee', 'qrco.de'
];

export function isShortenerHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^www\./, '');
  return SHORTENERS.some(s => h === s || h.endsWith('.' + s));
}

/**
 * Extrai todas as URLs válidas de um texto
 */
export function extractUrls(text) {
  if (!text) return [];
  // TLDs ambíguos de 2 letras (it, de, es, me, co, us...) ficam de fora para não tratar "ok.es" como link
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+|www\.[^\s<>"'{}|\\^`]+|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com\.br|com\.pt|com|pt|net|org|eu|cc|ly|gl|at|app|link|click|top|xyz|site|online|shop|info|live|vip|icu|buzz|work|rest|store|club|life|cfd|sbs|help|bond|cyou|today|biz|website)\b(?:\/[^\s<>"'{}|\\^`]*)?)/gi;
  // Remove endereços de email antes de procurar links (joao@gmail.com não é um link)
  const textoSemEmails = text.replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, ' ');
  const matches = textoSemEmails.match(urlRegex) || [];
  
  return Array.from(new Set(matches.map(u => {
    let clean = u.replace(/[.,;!?)]+$/, '');
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = 'https://' + clean;
    }
    return clean;
  })));
}

export function isPrivateIpOrHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().trim().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '0.0.0.0' || h === '::1' || h === '::') return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.onion') || h.endsWith('.localhost')) return true;
  // Qualquer IPv6 literal (inclui ::ffff:127.0.0.1, fc00::/7, fe80::/10) é tratado como não seguro
  if (h.includes(':')) return true;
  // IPv4 literal em qualquer notação (decimal, hex, octal, pontos): nunca seguimos encurtadores para IPs
  if (/^[0-9a-fx.]+$/.test(h) && /\d/.test(h) && !/[g-wyz]/.test(h)) return true;
  // Bloqueia IPs privados (RFC 1918), loopback, CGNAT e Link-Local / Cloud Metadata (169.254.169.254)
  if (/^127\.\d+\.\d+\.\d+$/.test(h)) return true;
  if (/^0\.\d+\.\d+\.\d+$/.test(h)) return true;
  if (/^10\.\d+\.\d+\.\d+$/.test(h)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(h)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$/.test(h)) return true;
  if (/^169\.254\.\d+\.\d+$/.test(h)) return true;
  return false;
}

/**
 * Expande links encurtados seguindo redirecionamentos com proteção rigorosa contra SSRF.
 * Cada salto é validado ANTES de ser pedido (redirect manual, máx. 5 saltos).
 */
export async function unshortenUrl(rawUrl) {
  try {
    let current = new URL(rawUrl);
    if (!/^https?:$/.test(current.protocol)) return rawUrl;
    if (isPrivateIpOrHost(current.hostname)) return rawUrl;
    if (!isShortenerHost(current.hostname)) return rawUrl;

    for (let hop = 0; hop < 5; hop++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      let res;
      try {
        res = await fetch(current.href, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });
      } finally {
        clearTimeout(timeout);
      }

      const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
      if (!location) return current.href;

      const next = new URL(location, current);
      if (!/^https?:$/.test(next.protocol) || isPrivateIpOrHost(next.hostname)) return rawUrl;
      current = next;
      // Só continua a seguir enquanto o destino ainda for um encurtador; o destino final nunca é pedido
      if (!isShortenerHost(current.hostname)) return current.href;
    }
    return current.href;
  } catch (e) {
    return rawUrl;
  }
}

/**
 * Consulta a Google Web Risk API (Google Cloud — suporte comercial)
 * Em conformidade com os termos para produtos comerciais e serviços corporativos B2B.
 * Endpoint: https://webrisk.googleapis.com/v1/uris:search
 */
export async function checkGoogleWebRisk(url, apiKey) {
  const key = process.env.GOOGLE_WEB_RISK_KEY || process.env.WEB_RISK_API_KEY || apiKey;
  if (!key) return null;
  try {
    const encodedUrl = encodeURIComponent(url);
    const endpoint = `https://webrisk.googleapis.com/v1/uris:search?uri=${encodedUrl}&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&key=${key}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(endpoint, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();
    if (data.threat && data.threat.threatTypes && data.threat.threatTypes.length > 0) {
      return {
        flagged: true,
        threatType: data.threat.threatTypes.join(', '),
        source: 'Google Web Risk (Commercial)'
      };
    }
    return { flagged: false, source: 'Google Web Risk (Commercial)' };
  } catch (e) {
    return null;
  }
}

/**
 * Consulta a Google Safe Browsing API v4 (uso não-comercial / desenvolvimento)
 */
export async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(endpoint, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'zapqueme', clientVersion: '2.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      return {
        flagged: true,
        threatType: match.threatType,
        source: 'Google Safe Browsing'
      };
    }
    return { flagged: false, source: 'Google Safe Browsing' };
  } catch (e) {
    return null;
  }
}

/**
 * Consulta unificada Google Threat Intelligence:
 * Utiliza Web Risk API se configurada chave comercial (GOOGLE_WEB_RISK_KEY), ou Safe Browsing como fallback de desenvolvimento.
 */
export async function checkGoogleThreat(url, apiKey) {
  if (process.env.GOOGLE_WEB_RISK_KEY || process.env.WEB_RISK_API_KEY || process.env.USE_WEB_RISK === 'true') {
    const webRisk = await checkGoogleWebRisk(url, apiKey);
    if (webRisk !== null) return webRisk;
  }
  return checkGoogleSafeBrowsing(url, apiKey);
}

/**
 * Consulta o Cloudflare Security DNS (1.1.1.2 DoH - bloqueio de malware e phishing)
 * Se retornar 0.0.0.0, a Cloudflare bloqueou o domínio como ameaça ativa.
 */
export async function checkCloudflareSecurity(domain) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(`https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      signal: controller.signal,
      headers: { 'Accept': 'application/dns-json' }
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();
    const isBlocked = data.Answer?.some(ans => ans.data === '0.0.0.0');

    if (isBlocked) {
      return {
        flagged: true,
        threat: 'Bloqueado por segurança (Cloudflare Threat Intelligence)',
        source: 'Cloudflare Radar'
      };
    }
    return { flagged: false, source: 'Cloudflare Radar' };
  } catch (e) {
    return null;
  }
}

/**
 * Consulta a base global aberta de inteligência URLhaus (abuse.ch - Universidade de Berna)
 * Detecta novos domínios de malware e phishing ativos antes da indexação em blacklists comerciais.
 */
export async function checkUrlhaus(url) {
  const authKey = process.env.URLHAUS_AUTH_KEY;
  // Exige chave de autenticação conforme termos de serviço da abuse.ch
  if (!url || !authKey) return null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);

    const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': authKey
      },
      body: new URLSearchParams({ url })
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();

    if (data.query_status === 'ok') {
      return {
        flagged: true,
        threat: data.threat || 'Ameaça ativa catalogada na base de inteligência URLhaus (abuse.ch)',
        urlStatus: data.url_status,
        source: 'URLhaus (abuse.ch)'
      };
    }
    return { flagged: false, source: 'URLhaus (abuse.ch)' };
  } catch (e) {
    return null;
  }
}

// ----------------------------------------------------------------------------
// RDAP (idade do domínio) via bootstrap oficial da IANA
// ----------------------------------------------------------------------------
// Sufixos públicos de 2 níveis mais comuns (o domínio registável tem 3 etiquetas)
const SUFIXOS_2_NIVEIS = new Set([
  'com.br', 'net.br', 'org.br', 'gov.br', 'com.pt', 'org.pt', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'com.mx', 'com.ar', 'com.co', 'co.za', 'co.in', 'com.tr', 'co.jp'
]);

let ianaRdapCache = { at: 0, services: null };
const IANA_CACHE_MS = 24 * 60 * 60 * 1000;

async function getRdapBaseForTld(tld) {
  if (!ianaRdapCache.services || Date.now() - ianaRdapCache.at > IANA_CACHE_MS) {
    try {
      const res = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(3500) });
      if (res.ok) {
        const data = await res.json();
        ianaRdapCache = { at: Date.now(), services: data.services || [] };
      }
    } catch (_e) { /* mantém cache anterior, se existir */ }
  }
  const services = ianaRdapCache.services || [];
  const svc = services.find(entry => Array.isArray(entry[0]) && entry[0].includes(tld));
  return svc?.[1]?.[0] || null;
}

export function dominioRegistavel(domain) {
  const parts = String(domain || '').toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length < 2) return null;
  const ult2 = parts.slice(-2).join('.');
  return SUFIXOS_2_NIVEIS.has(ult2) && parts.length >= 3 ? parts.slice(-3).join('.') : ult2;
}

/**
 * Consulta RDAP para obter a data de registo (idade) do domínio.
 * Usa o bootstrap oficial da IANA para escolher o servidor RDAP de cada TLD.
 * Nota: o TLD `.pt` (DNS.PT) não publica RDAP aberto, por isso devolve null (sem dados) em vez de inventar.
 */
export async function checkDomainAge(domain) {
  try {
    const baseDomain = dominioRegistavel(domain);
    if (!baseDomain) return null;
    const tld = baseDomain.split('.').pop();
    const rdapBase = await getRdapBaseForTld(tld);
    if (!rdapBase) return null;

    const res = await fetch(`${rdapBase.replace(/\/?$/, '/')}domain/${encodeURIComponent(baseDomain)}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(3500),
      headers: { 'Accept': 'application/rdap+json, application/json' }
    });
    if (!res.ok) return null;
    const data = await res.json();

    const registrationEvent = data.events?.find(e => e.eventAction === 'registration');
    if (registrationEvent?.eventDate) {
      const regDate = new Date(registrationEvent.eventDate);
      const diffDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
      return {
        domain: baseDomain,
        registeredAt: registrationEvent.eventDate,
        ageInDays: diffDays,
        isRecentlyCreated: diffDays <= 60
      };
    }
    return null;
  } catch (e) {
    return null;
  }
}

// ----------------------------------------------------------------------------
// OpenPhish (feed comunitário gratuito, sem chave): URLs de phishing ativos
// ----------------------------------------------------------------------------
let openPhishCache = { at: 0, urls: new Set(), hosts: new Set(), erro: null };
const OPENPHISH_CACHE_MS = 6 * 60 * 60 * 1000;

async function carregarOpenPhish() {
  if (openPhishCache.urls.size > 0 && Date.now() - openPhishCache.at < OPENPHISH_CACHE_MS) return openPhishCache;
  try {
    const res = await fetch('https://openphish.com/feed.txt', { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const txt = await res.text();
    const urls = new Set();
    const hosts = new Set();
    for (const linha of txt.split(/\r?\n/)) {
      const u = linha.trim();
      if (!u) continue;
      urls.add(u.toLowerCase().replace(/\/$/, ''));
      try { hosts.add(new URL(u).hostname.toLowerCase()); } catch (_e) { /* linha inválida */ }
    }
    openPhishCache = { at: Date.now(), urls, hosts, erro: null };
  } catch (e) {
    openPhishCache = { ...openPhishCache, erro: e.message };
    return openPhishCache.urls.size > 0 ? openPhishCache : null;
  }
  return openPhishCache;
}

export async function checkOpenPhish(url) {
  const feed = await carregarOpenPhish();
  if (!feed) return null;
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const completo = url.toLowerCase().replace(/\/$/, '');
    if (feed.urls.has(completo) || feed.hosts.has(host)) {
      return { flagged: true, threat: 'URL ativo na lista de phishing OpenPhish', source: 'OpenPhish' };
    }
    return { flagged: false, source: 'OpenPhish' };
  } catch (_e) {
    return null;
  }
}

/**
 * Diagnóstico ativo das fontes de ameaça: testa cada fonte com um alvo conhecido e diz se está mesmo a funcionar.
 * Não depende de ficar à espera de um caso real para descobrir que uma fonte está inativa.
 */
export async function diagnosticarFontesAmeaca(apiKey = null) {
  const resultados = [];
  const add = (fonte, estado, detalhe) => resultados.push({ fonte, estado, detalhe });
  const key = apiKey || process.env.GEMINI_API_KEY || null;

  // Cloudflare 1.1.1.2
  const cf = await checkCloudflareSecurity('malware.testcategory.com');
  if (cf === null) add('Cloudflare Security DNS', 'erro', 'Sem resposta do serviço DNS-over-HTTPS');
  else add('Cloudflare Security DNS', cf.flagged ? 'ok' : 'erro', cf.flagged ? 'A bloquear o domínio de teste' : 'Não bloqueou o domínio de teste');

  // Google Web Risk / Safe Browsing
  const usaWebRisk = !!(process.env.GOOGLE_WEB_RISK_KEY || process.env.WEB_RISK_API_KEY || process.env.USE_WEB_RISK === 'true');
  const testeGoogle = 'https://testsafebrowsing.appspot.com/s/phishing.html';
  const g = await checkGoogleThreat(testeGoogle, key);
  const nomeG = usaWebRisk ? 'Google Web Risk' : 'Google Safe Browsing';
  if (g === null) add(nomeG, 'inativa', 'Pedido recusado: ative a API na chave Google Cloud (Safe Browsing API ou Web Risk API) ou defina GOOGLE_WEB_RISK_KEY');
  else add(nomeG, g.flagged ? 'ok' : 'erro', g.flagged ? 'A detetar o URL de teste' : 'Respondeu mas não detetou o URL de teste');

  // URLhaus
  if (!process.env.URLHAUS_AUTH_KEY) add('URLhaus (abuse.ch)', 'inativa', 'Falta URLHAUS_AUTH_KEY (gratuita em auth.abuse.ch)');
  else {
    const u = await checkUrlhaus('http://example.com/diagnostico');
    add('URLhaus (abuse.ch)', u === null ? 'erro' : 'ok', u === null ? 'Chave definida mas a API não respondeu' : 'A responder');
  }

  // OpenPhish
  const op = await carregarOpenPhish();
  if (!op || op.urls.size === 0) add('OpenPhish', 'erro', `Feed indisponível${openPhishCache.erro ? ': ' + openPhishCache.erro : ''}`);
  else add('OpenPhish', 'ok', `${op.urls.size} URLs de phishing carregados`);

  // RDAP (idade do domínio)
  const rdap = await checkDomainAge('google.com');
  add('RDAP (idade do domínio)', rdap ? 'ok' : 'erro', rdap ? `Cobre .com, .net, .org e a maioria dos TLDs (via IANA). Limitação: .pt não publica RDAP` : 'Sem resposta do bootstrap IANA / servidor RDAP');

  // Dicionário de marcas
  add('Dicionário de marcas oficiais', 'ok', `${Object.keys(getEffectiveOfficialDomains()).length} marcas protegidas`);
  return resultados;
}
// ============================================================================
// FASE 3: DICIONÁRIO DE MARCAS E DOMÍNIOS COM APROVAÇÃO HUMANA (Secção 3.5)
// Estado inicial idêntico a OFFICIAL_DOMAINS; apenas propostas com estado === 'aprovado'
// e aprovado_por preenchido entram em vigor quando o interruptor está ativo.
// ============================================================================
let approvedDictionaryEnabled = process.env.USE_APPROVED_DICTIONARY !== 'false';
let approvedAlterationsCache = [];
let lastDictionarySyncMs = 0;
const DICTIONARY_CACHE_TTL_MS = 5 * 60 * 1000;

export function isApprovedDictionaryEnabled() {
  return approvedDictionaryEnabled && process.env.USE_APPROVED_DICTIONARY !== 'false';
}

export function setApprovedDictionaryEnabled(enabled) {
  approvedDictionaryEnabled = Boolean(enabled);
}

function normalizarChaveMarca(marca = '') {
  return String(marca || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function normalizarDominioOficial(dom = '') {
  return String(dom || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split(':')[0]
    .trim();
}

/**
 * Atualiza a cache local do dicionário apenas com alterações APROVADAS por um humano (Critério 4).
 * Qualquer registo 'pendente' ou 'rejeitado' é estritamente ignorado.
 */
export function setApprovedDictionaryAlterations(alterations = []) {
  if (!Array.isArray(alterations)) {
    approvedAlterationsCache = [];
    return approvedAlterationsCache;
  }
  approvedAlterationsCache = alterations
    .filter(item => item && item.estado === 'aprovado' && item.aprovado_por && String(item.aprovado_por).trim())
    .sort((a, b) => new Date(a.aprovado_em || a.criado_em || 0).getTime() - new Date(b.aprovado_em || b.criado_em || 0).getTime());
  lastDictionarySyncMs = Date.now();
  return approvedAlterationsCache;
}

export function getApprovedDictionaryAlterations() {
  return [...approvedAlterationsCache];
}

export async function syncApprovedDictionaryFromDb(force = false) {
  if (!isApprovedDictionaryEnabled()) return approvedAlterationsCache;
  const now = Date.now();
  if (!force && lastDictionarySyncMs > 0 && (now - lastDictionarySyncMs) < DICTIONARY_CACHE_TTL_MS) {
    return approvedAlterationsCache;
  }
  const sUrl = process.env.SUPABASE_URL;
  const sKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!sUrl || !sKey) {
    lastDictionarySyncMs = now;
    return approvedAlterationsCache;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);
    const res = await fetch(
      `${sUrl}/rest/v1/dicionario_alteracoes?estado=eq.aprovado&order=criado_em.asc&limit=500`,
      {
        headers: { apikey: sKey, Authorization: `Bearer ${sKey}` },
        signal: controller.signal
      }
    );
    clearTimeout(timer);
    if (res.ok) {
      const rows = await res.json();
      setApprovedDictionaryAlterations(rows);
    } else {
      lastDictionarySyncMs = now;
    }
  } catch (_err) {
    lastDictionarySyncMs = now;
  }
  return approvedAlterationsCache;
}

export function getEffectiveOfficialDomains() {
  if (!isApprovedDictionaryEnabled() || approvedAlterationsCache.length === 0) {
    return OFFICIAL_DOMAINS;
  }
  const effective = {};
  for (const [k, list] of Object.entries(OFFICIAL_DOMAINS)) {
    effective[k] = [...list];
  }
  for (const alt of approvedAlterationsCache) {
    const key = normalizarChaveMarca(alt.marca);
    const dom = normalizarDominioOficial(alt.dominio_oficial);
    if (!key || !dom) continue;
    if (alt.acao === 'adicionar') {
      if (!effective[key]) effective[key] = [];
      if (!effective[key].includes(dom)) effective[key].push(dom);
    } else if (alt.acao === 'alterar') {
      effective[key] = [dom];
    } else if (alt.acao === 'remover') {
      if (effective[key]) {
        effective[key] = effective[key].filter(d => d !== dom);
        if (effective[key].length === 0) delete effective[key];
      }
    }
  }
  return effective;
}

// --- Correspondência de marcas (palavra inteira / token de hostname) -----------------------------
// Evita falsos positivos como "anos" -> NOS, "azul" -> ZU, "groups" -> UPS, "purchase" -> CHASE.
const HOST_PREFIX_OK = new Set(['ctt', 'dpd', 'dhl', 'galp']);

function normalizeForMatch(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

function textMentionsName(contextNorm, name) {
  const n = normalizeForMatch(name).trim();
  if (!n) return false;
  const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`(?<![a-z0-9])${esc}(?![a-z0-9])`).test(contextNorm);
}

function hostMentionsName(hostname, name) {
  const compact = normalizeForMatch(name).replace(/\s+/g, '');
  if (!compact) return false;
  const tokens = hostname.split(/[.\-_]/);
  if (tokens.includes(compact)) return true;
  // Nomes longos e distintivos podem aparecer colados no domínio (ex: millennium-bcp-seguro.top)
  if (compact.length >= 6 && hostname.includes(compact)) return true;
  if (HOST_PREFIX_OK.has(compact) && tokens.some(tk => tk.startsWith(compact))) return true;
  return false;
}
/**
 * Verifica se a mensagem menciona uma marca oficial, mas o link usa um domínio não oficial (Typosquatting / Falso Site)
 */
export function checkBrandImpersonation(url, textContext) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const context = (textContext || '').toLowerCase();
    const contextNorm = normalizeForMatch(context);
    const hostTokens = hostname.split(/[.\-_]/);
    const effectiveDomains = getEffectiveOfficialDomains();

    // Dicionário de termos de marcas e palavras-chave
    const brandChecks = [
      { key: 'ctt', names: ['ctt', 'correios de portugal'], official: effectiveDomains.ctt || OFFICIAL_DOMAINS.ctt },
      { key: 'dpd', names: ['dpd', 'dpd portugal'], official: effectiveDomains.dpd || OFFICIAL_DOMAINS.dpd },
      { key: 'gls', names: ['gls', 'gls portugal'], official: effectiveDomains.gls || OFFICIAL_DOMAINS.gls },
      { key: 'correios', names: ['correios', 'sedex', 'taxa correios'], official: effectiveDomains.correios || OFFICIAL_DOMAINS.correios },
      { key: 'cgd', names: ['caixa geral', 'cgd', 'caixadirecta'], official: effectiveDomains.cgd || OFFICIAL_DOMAINS.cgd },
      { key: 'millennium', names: ['millennium', 'millennium bcp'], official: effectiveDomains.millennium || OFFICIAL_DOMAINS.millennium },
      { key: 'novobanco', names: ['novo banco', 'novobanco'], official: effectiveDomains.novobanco || OFFICIAL_DOMAINS.novobanco },
      { key: 'santander', names: ['santander'], official: [...(effectiveDomains.santander_pt || OFFICIAL_DOMAINS.santander_pt), ...(effectiveDomains.santander_br || OFFICIAL_DOMAINS.santander_br)] },
      { key: 'itau', names: ['itau', 'itaú'], official: effectiveDomains.itau || OFFICIAL_DOMAINS.itau },
      { key: 'bradesco', names: ['bradesco'], official: effectiveDomains.bradesco || OFFICIAL_DOMAINS.bradesco },
      { key: 'nubank', names: ['nubank', 'nu pagamentos'], official: effectiveDomains.nubank || OFFICIAL_DOMAINS.nubank },
      { key: 'financas', names: ['autoridade tributaria', 'autoridade tributária', 'reembolso at'], official: effectiveDomains.financas || OFFICIAL_DOMAINS.financas },
      { key: 'receita', names: ['receita federal', 'restituição', 'leilao receita', 'leilão receita'], official: effectiveDomains.receita_federal || OFFICIAL_DOMAINS.receita_federal },

      // Entregas Internacionais
      { key: 'chronopost', names: ['chronopost', 'colis chronopost', 'relais chronopost'], official: effectiveDomains.chronopost || OFFICIAL_DOMAINS.chronopost },
      { key: 'laposte', names: ['la poste', 'laposte', 'colissimo', 'lettre suivie'], official: effectiveDomains.laposte || OFFICIAL_DOMAINS.laposte },
      { key: 'posteitaliane', names: ['poste italiane', 'poste info', 'pacco postale'], official: effectiveDomains.posteitaliane || OFFICIAL_DOMAINS.posteitaliane },
      { key: 'usps', names: ['usps', 'us postal service', 'united states postal'], official: effectiveDomains.usps || OFFICIAL_DOMAINS.usps },
      { key: 'royalmail', names: ['royal mail', 'royalmail'], official: effectiveDomains.royalmail || OFFICIAL_DOMAINS.royalmail },
      { key: 'dhl', names: ['dhl', 'dhl express'], official: effectiveDomains.dhl || OFFICIAL_DOMAINS.dhl },
      { key: 'ups', names: ['united parcel service', 'ups parcel', 'ups tracking'], hostTokens: ['ups'], official: effectiveDomains.ups || OFFICIAL_DOMAINS.ups },
      { key: 'fedex', names: ['fedex', 'federal express'], official: effectiveDomains.fedex || OFFICIAL_DOMAINS.fedex },

      // Bancos Internacionais
      { key: 'bnp', names: ['bnp paribas', 'bnpparibas', 'bnp'], official: effectiveDomains.bnp || OFFICIAL_DOMAINS.bnp },
      { key: 'credit_agricole', names: ['credit agricole', 'crédit agricole'], official: effectiveDomains.credit_agricole || OFFICIAL_DOMAINS.credit_agricole },
      { key: 'societe_generale', names: ['societe generale', 'société générale'], official: effectiveDomains.societe_generale || OFFICIAL_DOMAINS.societe_generale },
      { key: 'intesa', names: ['intesa sanpaolo', 'intesasanpaolo', 'banca intesa'], official: effectiveDomains.intesa || OFFICIAL_DOMAINS.intesa },
      { key: 'unicredit', names: ['unicredit', 'banca unicredit'], official: effectiveDomains.unicredit || OFFICIAL_DOMAINS.unicredit },
      { key: 'chase', names: ['chase bank', 'jpmorgan chase'], hostTokens: ['chase'], official: effectiveDomains.chase || OFFICIAL_DOMAINS.chase },
      { key: 'barclays', names: ['barclays', 'barclays bank'], official: effectiveDomains.barclays || OFFICIAL_DOMAINS.barclays },

      // Serviços Globais
      { key: 'netflix', names: ['netflix', 'sua assinatura netflix', 'votre abonnement netflix'], official: effectiveDomains.netflix || OFFICIAL_DOMAINS.netflix },
      { key: 'amazon', names: ['amazon', 'pedido amazon', 'commande amazon'], official: effectiveDomains.amazon || OFFICIAL_DOMAINS.amazon },
      { key: 'paypal', names: ['paypal', 'sua conta paypal', 'compte paypal'], official: effectiveDomains.paypal || OFFICIAL_DOMAINS.paypal },

      // Saúde Portugal
      { key: 'cuf', names: ['cuf', 'hospital cuf', 'clinica cuf', 'consulta cuf'], official: effectiveDomains.cuf || OFFICIAL_DOMAINS.cuf },
      { key: 'hospital_da_luz', names: ['hospital da luz', 'luz saude', 'luz saúde'], official: effectiveDomains.luz || OFFICIAL_DOMAINS.luz },
      { key: 'lusiadas', names: ['lusiadas', 'lusíadas', 'hospital lusiadas'], official: effectiveDomains.lusiadas || OFFICIAL_DOMAINS.lusiadas },
      { key: 'joaquim_chaves', names: ['joaquim chaves', 'clinica joaquim chaves'], official: effectiveDomains.joaquim_chaves || OFFICIAL_DOMAINS.joaquim_chaves },

      // Utilities & Telecomunicações Portugal
      { key: 'edp', names: ['edp', 'edp comercial', 'fatura edp'], official: effectiveDomains.edp || OFFICIAL_DOMAINS.edp },
      { key: 'galp', names: ['galp', 'galp energia', 'fatura galp'], official: effectiveDomains.galp || OFFICIAL_DOMAINS.galp },
      { key: 'meo', names: ['meo', 'fatura meo', 'telecomunicacoes meo'], official: effectiveDomains.meo || OFFICIAL_DOMAINS.meo },
      { key: 'nos', names: ['fatura nos', 'operadora nos', 'nos comunicacoes'], hostTokens: ['nos'], official: effectiveDomains.nos || OFFICIAL_DOMAINS.nos },
      { key: 'vodafone', names: ['vodafone', 'fatura vodafone'], official: effectiveDomains.vodafone_pt || OFFICIAL_DOMAINS.vodafone_pt },
      { key: 'via_verde', names: ['via verde', 'identificador via verde'], official: effectiveDomains.viaverde || OFFICIAL_DOMAINS.viaverde },

      // Retalho e Supermercados Portugal
      { key: 'continente', names: ['continente', 'cartao continente', 'cartão continente', 'zu pet'], hostTokens: ['zu'], official: effectiveDomains.continente || OFFICIAL_DOMAINS.continente },
      { key: 'worten', names: ['worten'], official: effectiveDomains.worten || OFFICIAL_DOMAINS.worten },
      { key: 'pingo_doce', names: ['pingo doce'], official: effectiveDomains.pingo_doce || OFFICIAL_DOMAINS.pingo_doce },

      // Ordens Profissionais
      { key: 'ordem_advogados', names: ['ordem dos advogados'], official: effectiveDomains.ordem_advogados || OFFICIAL_DOMAINS.ordem_advogados },
      { key: 'ordem_medicos', names: ['ordem dos medicos', 'ordem dos médicos'], official: effectiveDomains.ordem_medicos || OFFICIAL_DOMAINS.ordem_medicos }
    ];

    // Se o dicionário aprovado estiver ativo, acrescenta novas marcas aprovadas que não existiam na lista inicial
    if (isApprovedDictionaryEnabled() && approvedAlterationsCache.length > 0) {
      const existingKeys = new Set(brandChecks.map(b => b.key));
      for (const alt of approvedAlterationsCache) {
        const key = normalizarChaveMarca(alt.marca);
        if (!key || !effectiveDomains[key] || effectiveDomains[key].length === 0) continue;
        if (!existingKeys.has(key)) {
          existingKeys.add(key);
          const nomeLimpo = String(alt.marca || key).toLowerCase().trim();
          const nomes = Array.from(new Set([nomeLimpo, key.replace(/_/g, ' ')])).filter(Boolean);
          brandChecks.push({
            key,
            names: nomes,
            official: effectiveDomains[key]
          });
        }
      }
    }

    for (const b of brandChecks) {
      // Se o texto da mensagem menciona a marca OU o próprio domínio usa o nome da marca (ex: ctt-pagamentos.com)
      const mentionsBrand = b.names.some(n => textMentionsName(contextNorm, n) || hostMentionsName(hostname, n)) ||
        (b.hostTokens || []).some(tok => hostTokens.includes(tok));
      if (mentionsBrand) {
        const isOfficial = b.official.some(off => hostname === off || hostname.endsWith('.' + off));
        if (!isOfficial) {
          return {
            impersonated: true,
            brand: b.key.toUpperCase(),
            hostname,
            officialDomains: b.official,
            evidence: `A mensagem faz referência a [${b.key.toUpperCase()}], mas o site [${hostname}] NÃO é o domínio oficial verificado (${b.official.join(', ')}).`
          };
        }
      }
    }

    // Checa TLDs de alto risco
    const hasHighRiskTld = HIGH_RISK_TLDS.some(tld => hostname.endsWith(tld));
    if (hasHighRiskTld) {
      return {
        impersonated: false,
        highRiskTld: true,
        hostname,
        evidence: `O link utiliza terminação de domínio de alto risco (${hostname}), comumente usada para hospedar páginas clonadas temporárias.`
      };
    }

    return null;
  } catch (e) {
    return null;
  }
}

export function isOfficialDomain(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase().replace(/^www\./, '').split(':')[0].trim();
  const effectiveDomains = getEffectiveOfficialDomains();
  for (const list of Object.values(effectiveDomains)) {
    if (list.some(off => h === off || h.endsWith('.' + off))) {
      return true;
    }
  }
  return false;
}

/**
 * Executa inspeção profunda e multi-camadas em todas as URLs encontradas
 */
export async function inspectAllUrls(text, apiKey) {
  await syncApprovedDictionaryFromDb();
  const rawUrls = extractUrls(text);
  if (!rawUrls || rawUrls.length === 0) return { hasUrls: false, reports: [] };

  const reports = [];

  for (const rawUrl of rawUrls.slice(0, 3)) { // Analisa até 3 links
    try {
      // 1. Expande link se for encurtador
      const finalUrl = await unshortenUrl(rawUrl);
      const urlObj = new URL(finalUrl);
      const domain = urlObj.hostname;

      // Executa checagens paralelas (Google Threat Intel / Web Risk, Cloudflare Radar, URLhaus e RDAP)
      const [googleResult, cloudflareResult, urlhausResult, openPhishResult, domainAge, impersonation] = await Promise.all([
        checkGoogleThreat(finalUrl, apiKey),
        checkCloudflareSecurity(domain),
        checkUrlhaus(finalUrl),
        checkOpenPhish(finalUrl),
        checkDomainAge(domain),
        Promise.resolve(checkBrandImpersonation(finalUrl, text))
      ]);

      const isOfficial = isOfficialDomain(domain);

      // Malicioso confirmado: base de ameaças ou usurpação direta de identidade de marca oficial
      const isMalicious = !isOfficial && !!(
        googleResult?.flagged ||
        cloudflareResult?.flagged ||
        urlhausResult?.flagged ||
        openPhishResult?.flagged ||
        impersonation?.impersonated
      );

      // Suspeito / Risco Moderado: indicador heurístico (domínio recém-criado ou TLD incomum), não um veredito fatal
      const isSuspicious = !isOfficial && !isMalicious && !!(
        (domainAge?.isRecentlyCreated && impersonation?.highRiskTld) ||
        impersonation?.highRiskTld ||
        domainAge?.isRecentlyCreated
      );

      reports.push({
        originalUrl: rawUrl,
        finalUrl,
        domain,
        isOfficial,
        isMalicious,
        isSuspicious,
        googleResult,
        cloudflareResult,
        urlhausResult,
        openPhishResult,
        domainAge,
        impersonation
      });
    } catch (e) {}
  }

  return {
    hasUrls: reports.length > 0,
    reports
  };
}
