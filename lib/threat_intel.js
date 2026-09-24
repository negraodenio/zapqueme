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
  receita_federal: ['gov.br/receitafederal']
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

/**
 * Expande links encurtados seguindo redirecionamentos (HTTP HEAD/GET rápido)
 */
export async function unshortenUrl(rawUrl) {
  try {
    const urlObj = new URL(rawUrl);
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
    return res.url || rawUrl;
  } catch (e) {
    return rawUrl;
  }
}

/**
 * Consulta a Google Safe Browsing API v4
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
        threatType: match.threatType, // e.g. SOCIAL_ENGINEERING (phishing)
        source: 'Google Safe Browsing'
      };
    }
    return { flagged: false, source: 'Google Safe Browsing' };
  } catch (e) {
    return null;
  }
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
      { key: 'ctt', names: ['ctt', 'encomenda', 'alfandega', 'alfândega', 'objeto postal'], official: OFFICIAL_DOMAINS.ctt },
      { key: 'correios', names: ['correios', 'sedex', 'taxa correios', 'alfandega'], official: OFFICIAL_DOMAINS.correios },
      { key: 'cgd', names: ['caixa geral', 'cgd', 'caixadirecta'], official: OFFICIAL_DOMAINS.cgd },
      { key: 'millennium', names: ['millennium', 'millennium bcp'], official: OFFICIAL_DOMAINS.millennium },
      { key: 'novobanco', names: ['novo banco', 'novobanco'], official: OFFICIAL_DOMAINS.novobanco },
      { key: 'santander', names: ['santander'], official: [...OFFICIAL_DOMAINS.santander_pt, ...OFFICIAL_DOMAINS.santander_br] },
      { key: 'itau', names: ['itau', 'itaú'], official: OFFICIAL_DOMAINS.itau },
      { key: 'bradesco', names: ['bradesco'], official: OFFICIAL_DOMAINS.bradesco },
      { key: 'nubank', names: ['nubank', 'nu pagamentos'], official: OFFICIAL_DOMAINS.nubank },
      { key: 'financas', names: ['autoridade tributaria', 'autoridade tributária', 'financas', 'finanças', 'reembolso at'], official: OFFICIAL_DOMAINS.financas },
      { key: 'receita', names: ['receita federal', 'restituição', 'leilao receita', 'leilão receita'], official: OFFICIAL_DOMAINS.receita_federal }
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

      // Executa checagens paralelas
      const [googleResult, cloudflareResult, domainAge, impersonation] = await Promise.all([
        checkGoogleSafeBrowsing(finalUrl, apiKey),
        checkCloudflareSecurity(domain),
        checkDomainAge(domain),
        Promise.resolve(checkBrandImpersonation(finalUrl, text))
      ]);

      const isMalicious = !!(
        googleResult?.flagged ||
        cloudflareResult?.flagged ||
        impersonation?.impersonated ||
        (domainAge?.isRecentlyCreated && impersonation?.highRiskTld)
      );

      reports.push({
        originalUrl: rawUrl,
        finalUrl,
        domain,
        isMalicious,
        googleResult,
        cloudflareResult,
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
