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

// Encurtadores conhecidos
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'linktr.ee', 'v.gd', 'abre.ai', 'shorte.st', 'rb.gy'];

/**
 * Extrai todas as URLs válidas de um texto
 */
export function extractUrls(text) {
  if (!text) return [];
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+|www\.[^\s<>"'{}|\\^`]+|[a-zA-Z0-9-]+\.(?:com\.br|com|pt|net|org|top|xyz|site|online|shop|info|live)\b[^\s<>"'{}|\\^`]*)/gi;
  const matches = text.match(urlRegex) || [];
  
  return Array.from(new Set(matches.map(u => {
    let clean = u.replace(/[.,;!?)]+$/, '');
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = 'https://' + clean;
    }
    return clean;
  })));
}

function isPrivateIpOrHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().trim();
  if (h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0' || h === '::1') return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.onion')) return true;
  // Bloqueia IPs privados (RFC 1918) e Link-Local / Cloud Metadata (169.254.169.254)
  if (/^10\.\d+\.\d+\.\d+$/.test(h)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(h)) return true;
  if (/^169\.254\.\d+\.\d+$/.test(h)) return true;
  return false;
}

/**
 * Expande links encurtados seguindo redirecionamentos com proteção rigorosa contra SSRF
 */
export async function unshortenUrl(rawUrl) {
  try {
    const urlObj = new URL(rawUrl);
    if (isPrivateIpOrHost(urlObj.hostname)) return rawUrl;

    const isShortener = SHORTENERS.some(s => urlObj.hostname.toLowerCase().includes(s));
    if (!isShortener) return rawUrl;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(rawUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    clearTimeout(timeout);

    if (res.url) {
      const destUrl = new URL(res.url);
      if (isPrivateIpOrHost(destUrl.hostname)) return rawUrl;
      return res.url;
    }
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

/**
 * Consulta oficial RDAP para checar a data de registro / idade do domínio
 */
export async function checkDomainAge(domain) {
  try {
    const parts = domain.toLowerCase().split('.');
    if (parts.length < 2) return null;

    let baseDomain = domain;
    if (domain.endsWith('.com.br') || domain.endsWith('.gov.br') || domain.endsWith('.org.br')) {
      baseDomain = parts.slice(-3).join('.');
    } else {
      baseDomain = parts.slice(-2).join('.');
    }

    let rdapUrl = `https://rdap-bootstrap.arin.net/bootstrap/domain/${encodeURIComponent(baseDomain)}`;
    if (baseDomain.endsWith('.com.br') || baseDomain.endsWith('.br')) {
      rdapUrl = `https://rdap.registro.br/domain/${encodeURIComponent(baseDomain)}`;
    } else if (baseDomain.endsWith('.com') || baseDomain.endsWith('.net')) {
      rdapUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(baseDomain)}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(rdapUrl, {
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();

    const registrationEvent = data.events?.find(e => e.eventAction === 'registration');
    if (registrationEvent?.eventDate) {
      const regDate = new Date(registrationEvent.eventDate);
      const diffMs = Date.now() - regDate.getTime();
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

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

/**
 * Verifica se a mensagem menciona uma marca oficial, mas o link usa um domínio não oficial (Typosquatting / Falso Site)
 */
export function checkBrandImpersonation(url, textContext) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const context = (textContext || '').toLowerCase();

    // Dicionário de termos de marcas e palavras-chave
    const brandChecks = [
      { key: 'ctt', names: ['ctt', 'correios de portugal'], official: OFFICIAL_DOMAINS.ctt },
      { key: 'dpd', names: ['dpd', 'dpd portugal'], official: OFFICIAL_DOMAINS.dpd },
      { key: 'gls', names: ['gls', 'gls portugal'], official: OFFICIAL_DOMAINS.gls },
      { key: 'correios', names: ['correios', 'sedex', 'taxa correios', 'alfandega'], official: OFFICIAL_DOMAINS.correios },
      { key: 'cgd', names: ['caixa geral', 'cgd', 'caixadirecta'], official: OFFICIAL_DOMAINS.cgd },
      { key: 'millennium', names: ['millennium', 'millennium bcp'], official: OFFICIAL_DOMAINS.millennium },
      { key: 'novobanco', names: ['novo banco', 'novobanco'], official: OFFICIAL_DOMAINS.novobanco },
      { key: 'santander', names: ['santander'], official: [...OFFICIAL_DOMAINS.santander_pt, ...OFFICIAL_DOMAINS.santander_br] },
      { key: 'itau', names: ['itau', 'itaú'], official: OFFICIAL_DOMAINS.itau },
      { key: 'bradesco', names: ['bradesco'], official: OFFICIAL_DOMAINS.bradesco },
      { key: 'nubank', names: ['nubank', 'nu pagamentos'], official: OFFICIAL_DOMAINS.nubank },
      { key: 'financas', names: ['autoridade tributaria', 'autoridade tributária', 'financas', 'finanças', 'reembolso at'], official: OFFICIAL_DOMAINS.financas },
      { key: 'receita', names: ['receita federal', 'restituição', 'leilao receita', 'leilão receita'], official: OFFICIAL_DOMAINS.receita_federal },

      // Entregas Internacionais
      { key: 'chronopost', names: ['chronopost', 'colis chronopost', 'relais chronopost'], official: OFFICIAL_DOMAINS.chronopost },
      { key: 'laposte', names: ['la poste', 'laposte', 'colissimo', 'lettre suivie'], official: OFFICIAL_DOMAINS.laposte },
      { key: 'posteitaliane', names: ['poste italiane', 'poste info', 'pacco postale', 'poste'], official: OFFICIAL_DOMAINS.posteitaliane },
      { key: 'usps', names: ['usps', 'us postal service', 'united states postal'], official: OFFICIAL_DOMAINS.usps },
      { key: 'royalmail', names: ['royal mail', 'royalmail'], official: OFFICIAL_DOMAINS.royalmail },
      { key: 'dhl', names: ['dhl', 'dhl express'], official: OFFICIAL_DOMAINS.dhl },
      { key: 'ups', names: ['ups', 'united parcel service'], official: OFFICIAL_DOMAINS.ups },
      { key: 'fedex', names: ['fedex', 'federal express'], official: OFFICIAL_DOMAINS.fedex },

      // Bancos Internacionais
      { key: 'bnp', names: ['bnp paribas', 'bnpparibas', 'bnp'], official: OFFICIAL_DOMAINS.bnp },
      { key: 'credit_agricole', names: ['credit agricole', 'crédit agricole'], official: OFFICIAL_DOMAINS.credit_agricole },
      { key: 'societe_generale', names: ['societe generale', 'société générale'], official: OFFICIAL_DOMAINS.societe_generale },
      { key: 'intesa', names: ['intesa sanpaolo', 'intesasanpaolo', 'banca intesa'], official: OFFICIAL_DOMAINS.intesa },
      { key: 'unicredit', names: ['unicredit', 'banca unicredit'], official: OFFICIAL_DOMAINS.unicredit },
      { key: 'chase', names: ['chase bank', 'jpmorgan chase', 'chase'], official: OFFICIAL_DOMAINS.chase },
      { key: 'barclays', names: ['barclays', 'barclays bank'], official: OFFICIAL_DOMAINS.barclays },

      // Serviços Globais
      { key: 'netflix', names: ['netflix', 'sua assinatura netflix', 'votre abonnement netflix'], official: OFFICIAL_DOMAINS.netflix },
      { key: 'amazon', names: ['amazon', 'pedido amazon', 'commande amazon'], official: OFFICIAL_DOMAINS.amazon },
      { key: 'paypal', names: ['paypal', 'sua conta paypal', 'compte paypal'], official: OFFICIAL_DOMAINS.paypal },

      // Saúde Portugal
      { key: 'cuf', names: ['cuf', 'hospital cuf', 'clinica cuf', 'consulta cuf'], official: OFFICIAL_DOMAINS.cuf },
      { key: 'hospital_da_luz', names: ['hospital da luz', 'luz saude', 'luz saúde'], official: OFFICIAL_DOMAINS.luz },
      { key: 'lusiadas', names: ['lusiadas', 'lusíadas', 'hospital lusiadas'], official: OFFICIAL_DOMAINS.lusiadas },
      { key: 'joaquim_chaves', names: ['joaquim chaves', 'clinica joaquim chaves'], official: OFFICIAL_DOMAINS.joaquim_chaves },

      // Utilities & Telecomunicações Portugal
      { key: 'edp', names: ['edp', 'edp comercial', 'fatura edp', 'eletricidade'], official: OFFICIAL_DOMAINS.edp },
      { key: 'galp', names: ['galp', 'galp energia', 'fatura galp'], official: OFFICIAL_DOMAINS.galp },
      { key: 'meo', names: ['meo', 'fatura meo', 'telecomunicacoes meo'], official: OFFICIAL_DOMAINS.meo },
      { key: 'nos', names: ['nos', 'fatura nos', 'operadora nos'], official: OFFICIAL_DOMAINS.nos },
      { key: 'vodafone', names: ['vodafone', 'fatura vodafone'], official: OFFICIAL_DOMAINS.vodafone_pt },
      { key: 'via_verde', names: ['via verde', 'portagem', 'identificador via verde'], official: OFFICIAL_DOMAINS.viaverde },

      // Ordens Profissionais
      { key: 'ordem_advogados', names: ['ordem dos advogados', 'advogado', 'honorarios'], official: OFFICIAL_DOMAINS.ordem_advogados },
      { key: 'ordem_medicos', names: ['ordem dos medicos', 'ordem dos médicos'], official: OFFICIAL_DOMAINS.ordem_medicos }
    ];

    for (const b of brandChecks) {
      // Se o texto da mensagem menciona a marca OU o próprio domínio usa o nome da marca (ex: ctt-pagamentos.com)
      const mentionsBrand = b.names.some(n => context.includes(n) || hostname.includes(n.replace(/\s+/g, '')));
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

/**
 * Executa inspeção profunda e multi-camadas em todas as URLs encontradas
 */
export async function inspectAllUrls(text, apiKey) {
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
      const [googleResult, cloudflareResult, urlhausResult, domainAge, impersonation] = await Promise.all([
        checkGoogleThreat(finalUrl, apiKey),
        checkCloudflareSecurity(domain),
        checkUrlhaus(finalUrl),
        checkDomainAge(domain),
        Promise.resolve(checkBrandImpersonation(finalUrl, text))
      ]);

      // Malicioso confirmado: base de ameaças ou usurpação direta de identidade de marca oficial
      const isMalicious = !!(
        googleResult?.flagged ||
        cloudflareResult?.flagged ||
        urlhausResult?.flagged ||
        impersonation?.impersonated
      );

      // Suspeito / Risco Moderado: indicador heurístico (domínio recém-criado ou TLD incomum), não um veredito fatal
      const isSuspicious = !isMalicious && !!(
        (domainAge?.isRecentlyCreated && impersonation?.highRiskTld) ||
        impersonation?.highRiskTld ||
        domainAge?.isRecentlyCreated
      );

      reports.push({
        originalUrl: rawUrl,
        finalUrl,
        domain,
        isMalicious,
        isSuspicious,
        googleResult,
        cloudflareResult,
        urlhausResult,
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
