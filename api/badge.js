// api/badge.js — ZAP VERIFIED Dynamic Badge SVG Generator
// Especificação Fechada ZAP, QUEM É? — Kit Comercial de Badges
// Formatos: principal (vertical), horizontal (website/email), circular (perfil/whatsapp)

function escapeXml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Gera SVG para o Badge Horizontal (Formato para Websites, Rodapés e Assinatura de Email)
 */
export function generateHorizontalBadge({ codigo, empresaNome, status, statusTexto }) {
  const isAtivo = status === 'ativo';
  const isSuspenso = status === 'suspenso';
  const isExpirado = status === 'expirado';

  const primaryColor = isAtivo ? '#10b981' : (isSuspenso ? '#ef4444' : '#f59e0b');
  const glowColor = isAtivo ? 'rgba(16, 185, 129, 0.25)' : (isSuspenso ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)');
  const statusLabel = isAtivo ? 'CANAIS CONFIRMADOS' : (isSuspenso ? 'VERIFICAÇÃO SUSPENSA' : 'VERIFICAÇÃO EXPIRADA');
  const safeCodigo = escapeXml(codigo || 'ZAP VERIFIED');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="310" height="64" viewBox="0 0 310 64" fill="none">
  <defs>
    <linearGradient id="bgGrad" x1="0" y1="0" x2="310" y2="64" gradientUnits="userSpaceOnUse">
      <stop stop-color="#0f172a" />
      <stop offset="1" stop-color="#090d16" />
    </linearGradient>
    <linearGradient id="shieldGrad" x1="0" y1="0" x2="36" y2="36" gradientUnits="userSpaceOnUse">
      <stop stop-color="${primaryColor}" />
      <stop offset="1" stop-color="${isAtivo ? '#059669' : (isSuspenso ? '#b91c1c' : '#d97706')}" />
    </linearGradient>
    <filter id="glow" x="4" y="8" width="48" height="48" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="${glowColor}" />
    </filter>
  </defs>

  <!-- Container -->
  <rect width="310" height="64" rx="12" fill="url(#bgGrad)" stroke="#ffffff" stroke-opacity="0.12" stroke-width="1" />

  <!-- Shield Icon -->
  <g filter="url(#glow)" transform="translate(14, 14)">
    <path d="M18 2L5 7.5V17.5C5 25.5 10.5 32.8 18 35C25.5 32.8 31 25.5 31 17.5V7.5L18 2Z" fill="url(#shieldGrad)" />
    <!-- Checkmark inside Shield -->
    <path d="M13 18L16.5 21.5L23 14" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
  </g>

  <!-- Typography -->
  <g transform="translate(58, 24)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="14" font-weight="800" fill="#ffffff" letter-spacing="0.08em">ZAP VERIFIED</text>
  </g>
  <g transform="translate(58, 41)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="10.5" font-weight="600" fill="${primaryColor}" letter-spacing="0.04em">${statusLabel}</text>
  </g>

  <!-- Code Tag -->
  <g transform="translate(58, 54)">
    <text x="0" y="0" font-family="'JetBrains Mono', monospace, Courier" font-size="8.5" font-weight="500" fill="#64748b" letter-spacing="0.06em">${safeCodigo}</text>
  </g>

  <!-- Verification Pill -->
  <rect x="236" y="16" width="60" height="20" rx="10" fill="${primaryColor}" fill-opacity="0.15" stroke="${primaryColor}" stroke-opacity="0.4" stroke-width="1" />
  <circle cx="246" cy="26" r="3" fill="${primaryColor}" />
  <text x="254" y="29.5" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9" font-weight="700" fill="${primaryColor}">${isAtivo ? 'OFICIAL' : (isSuspenso ? 'SUSP' : 'EXP')}</text>
</svg>`;
}

/**
 * Gera SVG para o Badge Principal (Emblema Vertical / Selo Institucional)
 */
export function generatePrincipalBadge({ codigo, empresaNome, status, statusTexto }) {
  const isAtivo = status === 'ativo';
  const isSuspenso = status === 'suspenso';

  const primaryColor = isAtivo ? '#10b981' : (isSuspenso ? '#ef4444' : '#f59e0b');
  const safeEmpresa = escapeXml(empresaNome || 'Empresa Certificada');
  const safeCodigo = escapeXml(codigo || 'ZAP VERIFIED');
  const statusLabel = isAtivo ? 'VERIFICAÇÃO ATIVA' : (isSuspenso ? 'VERIFICAÇÃO SUSPENSA' : 'VERIFICAÇÃO EXPIRADA');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="250" viewBox="0 0 220 250" fill="none">
  <defs>
    <linearGradient id="pBg" x1="110" y1="0" x2="110" y2="250" gradientUnits="userSpaceOnUse">
      <stop stop-color="#0f172a" />
      <stop offset="1" stop-color="#090d16" />
    </linearGradient>
    <linearGradient id="pShield" x1="30" y1="20" x2="80" y2="80" gradientUnits="userSpaceOnUse">
      <stop stop-color="${primaryColor}" />
      <stop offset="1" stop-color="${isAtivo ? '#059669' : (isSuspenso ? '#b91c1c' : '#d97706')}" />
    </linearGradient>
  </defs>

  <!-- Background Card -->
  <rect width="220" height="250" rx="18" fill="url(#pBg)" stroke="#ffffff" stroke-opacity="0.12" stroke-width="1.5" />

  <!-- Shield Icon Centered -->
  <g transform="translate(85, 24)">
    <path d="M25 2L5 10.5V26C5 38 13.5 48.8 25 52C36.5 48.8 45 38 45 26V10.5L25 2Z" fill="url(#pShield)" />
    <path d="M17 26.5L22.5 32L33 20" stroke="#ffffff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" />
  </g>

  <!-- Title -->
  <text x="110" y="104" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="14.5" font-weight="900" fill="#ffffff" letter-spacing="0.1em">ZAP VERIFIED</text>
  <text x="110" y="122" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9" font-weight="700" fill="${primaryColor}" letter-spacing="0.08em">CANAIS OFICIAIS CONFIRMADOS</text>

  <!-- Divider -->
  <line x1="30" y1="138" x2="190" y2="138" stroke="#ffffff" stroke-opacity="0.1" stroke-width="1" />

  <!-- Empresa -->
  <text x="110" y="160" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="700" fill="#f8fafc">${safeEmpresa}</text>

  <!-- Status Pill -->
  <g transform="translate(30, 178)">
    <rect width="160" height="24" rx="12" fill="${primaryColor}" fill-opacity="0.12" stroke="${primaryColor}" stroke-opacity="0.35" stroke-width="1" />
    <circle cx="44" cy="12" r="3.5" fill="${primaryColor}" />
    <text x="54" y="15.5" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9" font-weight="800" fill="${primaryColor}" letter-spacing="0.04em">${statusLabel}</text>
  </g>

  <!-- Code -->
  <text x="110" y="226" text-anchor="middle" font-family="'JetBrains Mono', monospace" font-size="9" font-weight="600" fill="#64748b" letter-spacing="0.08em">${safeCodigo}</text>
</svg>`;
}

/**
 * Gera SVG para o Badge Circular (Selo / Avatar para WhatsApp, Redes e Materiais)
 */
export function generateCircularBadge({ codigo, empresaNome, status, statusTexto }) {
  const isAtivo = status === 'ativo';
  const isSuspenso = status === 'suspenso';
  const primaryColor = isAtivo ? '#10b981' : (isSuspenso ? '#ef4444' : '#f59e0b');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="160" viewBox="0 0 160 160" fill="none">
  <defs>
    <linearGradient id="cBg" x1="0" y1="0" x2="160" y2="160" gradientUnits="userSpaceOnUse">
      <stop stop-color="#0f172a" />
      <stop offset="1" stop-color="#090d16" />
    </linearGradient>
    <linearGradient id="cShield" x1="15" y1="10" x2="50" y2="50" gradientUnits="userSpaceOnUse">
      <stop stop-color="${primaryColor}" />
      <stop offset="1" stop-color="${isAtivo ? '#059669' : (isSuspenso ? '#b91c1c' : '#d97706')}" />
    </linearGradient>
  </defs>

  <!-- Outer Circles -->
  <circle cx="80" cy="80" r="78" fill="url(#cBg)" stroke="#ffffff" stroke-opacity="0.12" stroke-width="2" />
  <circle cx="80" cy="80" r="70" fill="none" stroke="${primaryColor}" stroke-opacity="0.3" stroke-width="1.5" stroke-dasharray="4 3" />

  <!-- Shield Centered -->
  <g transform="translate(55, 38)">
    <path d="M25 2L6 10V25C6 36.5 14 46.5 25 50C36 46.5 44 36.5 44 25V10L25 2Z" fill="url(#cShield)" />
    <path d="M17 25L22 30L33 19" stroke="#ffffff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
  </g>

  <!-- Texts -->
  <text x="80" y="112" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="900" fill="#ffffff" letter-spacing="0.08em">ZAP VERIFIED</text>
  <text x="80" y="126" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="8" font-weight="700" fill="${primaryColor}" letter-spacing="0.06em">CANAIS OFICIAIS</text>
  <circle cx="80" cy="138" r="3" fill="${primaryColor}" />
</svg>`;
}

export default async function handler(req, res) {
  const codigo = (req.query.codigo || req.query.c || '').trim();
  const formato = (req.query.formato || req.query.f || 'horizontal').toLowerCase().trim();

  // Cache headers para performance global em CDN
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=60, s-maxage=300');

  let status = 'ativo';
  let statusTexto = 'Verificação ativa';
  let empresaNome = 'Empresa Verificada';

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (url && key && codigo) {
    try {
      const headers = { 'Content-Type': 'application/json', apikey: key, Authorization: `Bearer ${key}` };
      const seloRes = await fetch(`${url}/rest/v1/selos?codigo=eq.${encodeURIComponent(codigo)}&select=*,empresas(*)&limit=1`, { headers });
      if (seloRes.ok) {
        const selos = await seloRes.json();
        if (selos && selos.length > 0) {
          const selo = selos[0];
          const emp = selo.empresas || {};
          empresaNome = emp.nome || empresaNome;

          const agora = new Date();
          const expirado = selo.valido_ate ? new Date(selo.valido_ate) < agora : false;

          if (emp.status === 'suspenso') {
            status = 'suspenso';
            statusTexto = 'Verificação suspensa';
          } else if (emp.status !== 'ativo') {
            status = 'inativo';
            statusTexto = 'Verificação inativa';
          } else if (expirado) {
            status = 'expirado';
            statusTexto = 'Verificação expirada';
          }
        }
      }
    } catch (err) {
      console.warn('[Badge] Erro ao buscar selo:', err.message);
    }
  }

  let svg = '';
  if (formato === 'principal' || formato === 'vertical') {
    svg = generatePrincipalBadge({ codigo, empresaNome, status, statusTexto });
  } else if (formato === 'circular') {
    svg = generateCircularBadge({ codigo, empresaNome, status, statusTexto });
  } else {
    svg = generateHorizontalBadge({ codigo, empresaNome, status, statusTexto });
  }

  return res.status(200).send(svg);
}
