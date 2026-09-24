// api/verify.js — Página Pública ZAP VERIFIED (/verify/[codigo])
// Especificação Fechada ZAP, QUEM É? — B2B
// Seções 5, 15, 16, 17, 18

/**
 * Escapa strings para prevenir injeção XSS (Seção 18)
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Determina o status do selo conforme Seção 16
 * Estados públicos:
 * - Válido: "✓ Verificação ativa"
 * - Suspenso: "⚠️ Verificação suspensa"
 * - Expirado: "⚠️ Verificação expirada"
 * - Empresa inativa: "⚠️ Verificação inativa"
 */
export function calcularStatusPublico({ selo, empresa, agora = new Date() }) {
  const expirado = selo?.valido_ate ? new Date(selo.valido_ate) < agora : false;
  let statusPublico = '✓ Verificação ativa';
  let statusClasse = 'status-valido';
  let statusRaw = 'valido';

  if (empresa?.status === 'suspenso') {
    statusPublico = '⚠️ Verificação suspensa';
    statusClasse = 'status-suspenso';
    statusRaw = 'suspenso';
  } else if (empresa?.status !== 'ativo') {
    statusPublico = '⚠️ Verificação inativa';
    statusClasse = 'status-inativo';
    statusRaw = 'inativo';
  } else if (expirado) {
    statusPublico = '⚠️ Verificação expirada';
    statusClasse = 'status-expirado';
    statusRaw = 'expirado';
  }

  return { statusPublico, statusClasse, statusRaw, expirado };
}

export default async function handler(req, res) {
  // Seção 18: Cache-Control: no-store obrigatório
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  const codigo = (req.query.codigo || req.query.c || '').trim();

  if (!codigo) {
    if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
      return res.status(400).json({ error: 'Código de selo não fornecido.' });
    }
    return res.status(400).send(renderErrorHtml('Código Inválido', 'Nenhum código de selo foi fornecido na URL.'));
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
      return res.status(500).json({ error: 'Configuração de banco indisponível.' });
    }
    return res.status(500).send(renderErrorHtml('Erro de Configuração', 'Serviço temporariamente indisponível.'));
  }

  const dbHeaders = {
    'Content-Type': 'application/json',
    apikey: key,
    Authorization: `Bearer ${key}`
  };

  try {
    // 1. Consultar o selo pelo código
    const seloResp = await fetch(
      `${url}/rest/v1/selos?codigo=eq.${encodeURIComponent(codigo)}&select=*&limit=1`,
      { headers: dbHeaders }
    );

    if (!seloResp.ok) {
      throw new Error(`Erro ao consultar selo: ${seloResp.status}`);
    }

    const selos = await seloResp.json();
    if (!selos || selos.length === 0) {
      if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
        return res.status(404).json({ error: 'Selo não encontrado.', status_selo: 'nao_encontrado' });
      }
      return res.status(404).send(renderErrorHtml('Selo Não Encontrado', 'O código de selo consultado não existe no registro oficial ZAP VERIFIED.'));
    }

    const selo = selos[0];

    // 2. Consultar a empresa associada ao selo
    const empResp = await fetch(
      `${url}/rest/v1/empresas?id=eq.${encodeURIComponent(selo.empresa_id)}&select=*&limit=1`,
      { headers: dbHeaders }
    );

    if (!empResp.ok) {
      throw new Error(`Erro ao consultar empresa: ${empResp.status}`);
    }

    const empresas = await empResp.json();
    if (!empresas || empresas.length === 0) {
      if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
        return res.status(404).json({ error: 'Empresa associada não encontrada.' });
      }
      return res.status(404).send(renderErrorHtml('Empresa Não Encontrada', 'A empresa associada a este selo não foi localizada.'));
    }

    const empresa = empresas[0];

    // 3. Determinar o status do selo conforme Seção 16
    const { statusPublico, statusClasse, statusRaw } = calcularStatusPublico({ selo, empresa });

    // Se solicitado formato JSON
    if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
      return res.status(200).json({
        selo: {
          codigo: selo.codigo,
          tipo: selo.tipo,
          valido_ate: selo.valido_ate,
          criado_em: selo.criado_em
        },
        empresa: {
          nome: empresa.nome,
          status: empresa.status,
          dominio_oficial: empresa.dominio_oficial,
          email_oficial: empresa.email_oficial,
          telefone_oficial: empresa.telefone_oficial,
          dominio_verificado: !!empresa.dominio_verificado,
          email_verificado: !!empresa.email_verificado,
          telefone_verificado: !!empresa.telefone_verificado
        },
        status_publico: statusPublico,
        status_raw: statusRaw,
        valido: statusRaw === 'valido'
      });
    }

    // 4. Renderizar página HTML segura com escapeHtml e disclaimers obrigatórios
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(renderVerifyHtml({ selo, empresa, statusPublico, statusClasse }));

  } catch (err) {
    console.error('[Verify] Erro:', err);
    if (req.headers.accept?.includes('application/json') || req.query.format === 'json') {
      return res.status(500).json({ error: 'Erro ao processar verificação.' });
    }
    return res.status(500).send(renderErrorHtml('Erro de Verificação', 'Ocorreu um erro ao carregar o certificado. Tente novamente.'));
  }
}

/**
 * Renderiza página pública oficial do selo
 */
export function renderVerifyHtml({ selo, empresa, statusPublico, statusClasse }) {
  const nomeEmpresa = escapeHtml(empresa.nome);
  const codigoSelo = escapeHtml(selo.codigo);

  // Formatação de validade
  let validadeTexto = 'Indeterminada';
  if (selo.valido_ate) {
    try {
      const d = new Date(selo.valido_ate);
      validadeTexto = d.toLocaleDateString('pt-PT', { day: '2-digit', month: 'long', year: 'numeric' });
    } catch {
      validadeTexto = escapeHtml(selo.valido_ate);
    }
  }

  // Seção 5: Verificação dos Canais
  // DOMÍNIO
  let domHtml = '';
  if (empresa.dominio_verificado && empresa.dominio_oficial) {
    domHtml = `
      <div class="channel-badge badge-verified">
        <img src="/badges/canal-dominio-verificado.png" alt="Verificado" style="width: 28px; height: 28px; object-fit: contain; flex-shrink: 0;" />
        <div class="channel-detail">
          <span class="channel-type">Canal verificado</span>
          <span class="channel-val">${escapeHtml(empresa.dominio_oficial)}</span>
        </div>
      </div>`;
  } else if (empresa.dominio_oficial) {
    domHtml = `
      <div class="channel-badge badge-registered">
        <span class="icon">–</span>
        <div class="channel-detail">
          <span class="channel-type">Canal registado, ainda não verificado</span>
          <span class="channel-val">${escapeHtml(empresa.dominio_oficial)}</span>
        </div>
      </div>`;
  } else {
    domHtml = `<div class="channel-empty">– Nenhum domínio registado</div>`;
  }

  // EMAIL
  let emailHtml = '';
  if (empresa.email_verificado && empresa.email_oficial) {
    emailHtml = `
      <div class="channel-badge badge-verified">
        <img src="/badges/canal-email-verificado.png" alt="Verificado" style="width: 28px; height: 28px; object-fit: contain; flex-shrink: 0;" />
        <div class="channel-detail">
          <span class="channel-type">Canal verificado</span>
          <span class="channel-val">${escapeHtml(empresa.email_oficial)}</span>
        </div>
      </div>`;
  } else if (empresa.email_oficial) {
    emailHtml = `
      <div class="channel-badge badge-registered">
        <span class="icon">–</span>
        <div class="channel-detail">
          <span class="channel-type">Canal registado, ainda não verificado</span>
          <span class="channel-val">${escapeHtml(empresa.email_oficial)}</span>
        </div>
      </div>`;
  } else {
    emailHtml = `<div class="channel-empty">– Nenhum e-mail registado</div>`;
  }

  // TELEFONE
  let telHtml = '';
  if (empresa.telefone_verificado && empresa.telefone_oficial) {
    telHtml = `
      <div class="channel-badge badge-verified">
        <img src="/badges/canal-telefone-verificado.png" alt="Verificado" style="width: 28px; height: 28px; object-fit: contain; flex-shrink: 0;" />
        <div class="channel-detail">
          <span class="channel-type">Canal verificado</span>
          <span class="channel-val">${escapeHtml(empresa.telefone_oficial)}</span>
        </div>
      </div>`;
  } else if (empresa.telefone_oficial) {
    telHtml = `
      <div class="channel-badge badge-registered">
        <span class="icon">–</span>
        <div class="channel-detail">
          <span class="channel-type">Canal registado, ainda não verificado</span>
          <span class="channel-val">${escapeHtml(empresa.telefone_oficial)}</span>
        </div>
      </div>`;
  } else {
    telHtml = `<div class="channel-empty">– Nenhum telefone registado</div>`;
  }

  return `<!DOCTYPE html>
<html lang="pt-PT">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZAP VERIFIED — ${nomeEmpresa}</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(15, 23, 42, 0.85);
      --card-border: rgba(255, 255, 255, 0.1);
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #25d366;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --radius: 16px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
    body {
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 32px 20px 60px;
      background-image: radial-gradient(circle at 50% 0%, rgba(37, 211, 102, 0.1) 0%, transparent 50%);
    }
    .container {
      max-width: 680px;
      width: 100%;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand-title {
      font-size: 1.1rem;
      font-weight: 800;
      letter-spacing: 0.05em;
      color: #25d366;
      text-transform: uppercase;
    }
    .cert-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 32px 28px;
      backdrop-filter: blur(12px);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }
    .cert-header {
      text-align: center;
      margin-bottom: 28px;
    }
    .zap-verified-tag {
      display: inline-block;
      font-size: 0.75rem;
      font-weight: 800;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--primary);
      background: rgba(37, 211, 102, 0.12);
      border: 1px solid rgba(37, 211, 102, 0.3);
      padding: 6px 14px;
      border-radius: 999px;
      margin-bottom: 14px;
    }
    .company-name {
      font-size: 1.85rem;
      font-weight: 800;
      margin-bottom: 8px;
      color: #fff;
    }
    .company-desc {
      font-size: 0.95rem;
      color: var(--text-muted);
      max-width: 480px;
      margin: 0 auto;
      line-height: 1.5;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 0.95rem;
      font-weight: 700;
      padding: 8px 18px;
      border-radius: 999px;
      margin-top: 18px;
    }
    .status-valido {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .status-suspenso, .status-expirado, .status-inativo {
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.4);
    }
    .section-title {
      font-size: 0.8rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin: 28px 0 12px;
    }
    .channel-box {
      margin-bottom: 16px;
    }
    .channel-label {
      font-size: 0.85rem;
      font-weight: 700;
      color: #cbd5e1;
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
    }
    .channel-badge {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 10px;
      background: #090d16;
      border: 1px solid var(--card-border);
    }
    .badge-verified {
      border-color: rgba(16, 185, 129, 0.35);
      background: rgba(16, 185, 129, 0.05);
    }
    .badge-registered {
      border-color: rgba(255, 255, 255, 0.12);
    }
    .icon {
      font-weight: 900;
      font-size: 1.1rem;
    }
    .badge-verified .icon { color: #10b981; }
    .badge-registered .icon { color: #94a3b8; }
    .channel-detail {
      display: flex;
      flex-direction: column;
    }
    .channel-type {
      font-size: 0.72rem;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
    }
    .channel-val {
      font-size: 0.95rem;
      font-weight: 600;
      color: #fff;
    }
    .channel-empty {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-style: italic;
      padding: 6px 0;
    }
    .meta-box {
      display: flex;
      justify-content: space-between;
      padding: 16px 0;
      margin-top: 24px;
      border-top: 1px solid var(--card-border);
      font-size: 0.82rem;
      color: var(--text-muted);
    }
    .meta-item strong {
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
    }
    .disclaimer-box {
      background: rgba(255, 255, 255, 0.03);
      border-left: 3px solid #f59e0b;
      padding: 14px 16px;
      border-radius: 0 8px 8px 0;
      font-size: 0.82rem;
      line-height: 1.5;
      color: #cbd5e1;
      margin-top: 24px;
    }
    .actions-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 28px;
    }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 12px 18px;
      border-radius: 10px;
      font-size: 0.88rem;
      font-weight: 700;
      text-decoration: none;
      transition: all 0.2s;
    }
    .btn-primary {
      background: var(--primary);
      color: #042f2e;
    }
    .btn-primary:hover {
      background: #1eb956;
      transform: translateY(-1px);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.12);
    }
    @media (max-width: 600px) {
      .actions-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand-title">ZAP VERIFIED</div>
      <a href="/" class="btn btn-secondary" style="padding: 6px 14px; font-size: 0.8rem;">Página Inicial</a>
    </div>

    <article class="cert-card">
      <div class="cert-header">
        <div style="display: flex; justify-content: center; margin-bottom: 16px;">
          <img src="/badges/badge-principal.png" alt="ZAP VERIFIED Selo Oficial" style="width: 140px; height: auto; filter: drop-shadow(0 10px 20px rgba(0, 0, 0, 0.5)); border-radius: 8px;" />
        </div>
        <span class="zap-verified-tag">ZAP VERIFIED</span>
        <h1 class="company-name">${nomeEmpresa}</h1>
        <p class="company-desc">Esta página confirma os canais oficiais associados a esta empresa.</p>
        <div>
          <span class="status-badge ${statusClasse}">${statusPublico}</span>
        </div>
      </div>

      <div class="section-title">Canais Oficiais Registados</div>

      <div class="channel-box">
        <div class="channel-label">DOMÍNIO OFICIAL</div>
        ${domHtml}
      </div>

      <div class="channel-box">
        <div class="channel-label">EMAIL OFICIAL</div>
        ${emailHtml}
      </div>

      <div class="channel-box">
        <div class="channel-label">TELEFONE OFICIAL</div>
        ${telHtml}
      </div>

      <div class="meta-box">
        <div class="meta-item">CÓDIGO: <strong>${codigoSelo}</strong></div>
        <div class="meta-item">VALIDADE: <strong>${validadeTexto}</strong></div>
      </div>

      <!-- Texto Público Obrigatório (Seção 17) -->
      <div class="disclaimer-box">
        ⚠️ <strong>Aviso Importante:</strong> Este selo confirma a associação dos canais apresentados à organização. Não significa que toda mensagem recebida em nome da empresa seja legítima.
      </div>

      <!-- Botões Obrigatórios (Seção 17) -->
      <div class="actions-grid">
        <a href="/" class="btn btn-primary">Verificar uma mensagem suspeita</a>
        <a href="/?denuncia=true" class="btn btn-secondary">Denunciar possível fraude</a>
      </div>
    </article>
  </div>
</body>
</html>`;
}

function renderErrorHtml(titulo, mensagem) {
  return `<!DOCTYPE html>
<html lang="pt-PT">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZAP VERIFIED — ${escapeHtml(titulo)}</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    body {
      background: #090d16;
      color: #f8fafc;
      font-family: system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .box {
      max-width: 480px;
      text-align: center;
      background: #0f172a;
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 40px 32px;
      border-radius: 16px;
    }
    .icon { font-size: 3rem; margin-bottom: 16px; }
    h1 { font-size: 1.4rem; margin-bottom: 12px; }
    p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 24px; line-height: 1.5; }
    a {
      display: inline-block;
      background: #25d366;
      color: #042f2e;
      padding: 10px 20px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">⚠️</div>
    <h1>${escapeHtml(titulo)}</h1>
    <p>${escapeHtml(mensagem)}</p>
    <a href="/">Ir para o Início</a>
  </div>
</body>
</html>`;
}
