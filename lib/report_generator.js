// lib/report_generator.js — Resumos mensais de sinais B2B
// Confirme, Quem É? (confirmequeme.pt)
// Resumos automáticos não autenticam a origem dos sinais nem substituem revisão humana.

import crypto from 'node:crypto';

/**
 * Remove alguns padrões comuns de identificadores.
 * Esta limpeza é uma ajuda e não garante anonimização completa.
 */
export function limparTextoVitima(texto) {
  if (!texto || typeof texto !== 'string') return '';
  return texto
    // Emails
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, '[EMAIL REMOVIDO]')
    // IBAN internacional e português (ex: PT50 0035...)
    .replace(/\b[A-Z]{2}\d{2}[A-Z0-9\s]{11,30}\b/gi, '[IBAN REMOVIDO]')
    // Cartões bancários (sequências de 13 a 19 dígitos)
    .replace(/\b(?:\d[ -]*?){13,19}\b/g, '[CARTÃO REMOVIDO]')
    // Telefones com indicativo internacional (+351, 00351, +55, etc.)
    .replace(/(?:\+|00)\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}/g, '[TELEFONE REMOVIDO]')
    // Telefones locais PT / telemóveis (9 dígitos começando por 9 ou 2)
    .replace(/\b[29]\d{2}[\s.-]?\d{3}[\s.-]?\d{3}\b/g, '[TELEFONE REMOVIDO]')
    // NIF / NIPC português (9 dígitos isolados)
    .replace(/\b\d{9}\b/g, '[NIF REMOVIDO]')
    // Valores monetários com nomes pessoais
    .replace(/\b(sr\.|sra\.|dr\.|dra\.|dona|senhor|senhora)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)*/gi, '[NOME REMOVIDO]')
    .trim();
}

/**
 * Calcula um checksum SHA-256 do conteúdo do resumo (não valida a origem dos registos).
 */
export function calcularHashRelatorio(conteudoHtmlOuJson) {
  const str = typeof conteudoHtmlOuJson === 'string' ? conteudoHtmlOuJson : JSON.stringify(conteudoHtmlOuJson);
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Estrutura um resumo mensal a partir dos sinais disponíveis no período.
 */
export function estruturarRelatorioMensal({
  empresa,
  periodo,
  ocorrencias = [],
  metricasSelo = {},
  versao = '1.0',
  geradoPor = 'admin'
}) {
  const brandName = empresa.nome_comercial || empresa.nome;
  const plano = empresa.plano || 'selo';
  const isPlanoRadar = plano === 'radar';

  // 1. Filtrar ocorrências com menção à marca no período
  const sinaisPeriodo = (ocorrencias || []).filter(o => {
    const dataOcorr = o.criado_em ? o.criado_em.slice(0, 7) : '';
    return !periodo || dataOcorr === periodo;
  });

  // 2. Extrair domínios para revisão manual; não atribuir titularidade nem recomendar bloqueio automático.
  const dominiosRevisao = new Set();
  const casosFormatados = [];

  for (const s of sinaisPeriodo) {
    // Domínio malicioso (impostor)
    if (s.alerta_link) {
      try {
        const urlObj = new URL(s.alerta_link.startsWith('http') ? s.alerta_link : `https://${s.alerta_link}`);
      dominiosRevisao.add(urlObj.hostname.toLowerCase());
      } catch {
        dominiosRevisao.add(String(s.alerta_link).toLowerCase().trim());
      }
    }

    casosFormatados.push({
      data: s.criado_em ? s.criado_em.slice(0, 10) : 'N/D',
      canal: s.canal || 'WhatsApp / SMS',
      tipo: s.tipo || 'Tentativa de Impersonation',
      impostor: s.alerta_link || 'Indicador não disponível',
      nivel: (s.risco_score >= 75 || s.veredito === 'golpe') ? 'Alto (automático)' : 'Revisão necessária',
      excerto: 'Conteúdo da mensagem omitido neste resumo.'
    });
  }

  const dadosRelatorio = {
    cabecalho: {
      titulo: 'Resumo Mensal de Sinais Submetidos & Integridade de Marca',
      empresa_nome: brandName,
      empresa_legal: empresa.nome_legal || empresa.nome,
      nif: empresa.nif || 'Em verificação',
      codigo_selo: empresa.codigo_selo || 'Não disponibilizado',
      periodo: periodo || new Date().toISOString().slice(0, 7),
      data_geracao: new Date().toISOString().slice(0, 10),
      versao,
      gerado_por: geradoPor,
      plano: isPlanoRadar ? 'Plano Radar (sinais submetidos e selo)' : 'Plano Selo (canais submetidos para revisão)'
    },
    resumo: {
      visitas_pagina: metricasSelo.visitas_pagina || 0,
      verificacoes_widget: metricasSelo.verificacoes_widget || 0,
      total_sinais: sinaisPeriodo.length,
      variacao_periodo_anterior: metricasSelo.variacao || 'Primeiro período auditado',
      tem_dados: sinaisPeriodo.length > 0
    },
    casos: isPlanoRadar ? casosFormatados : (sinaisPeriodo.length > 0 ? casosFormatados.slice(0, 5) : []),
    indicadores_para_revisao: {
      dominios: Array.from(dominiosRevisao),
      contactos: []
    },
    recomendacoes: {
      aviso_clientes: `A ${brandName} recomenda confirmar pedidos de pagamento nos seus canais oficiais antes de agir.`,
      medidas_mitigacao: [
        'Rever a fonte, o contexto e a atualidade dos indicadores antes de qualquer ação.',
        'Confirmar os canais oficiais da empresa por uma fonte independente.',
        'Se houver base suficiente, seguir o processo do fornecedor ou autoridade competente.'
      ]
    },
    metodologia: {
      nota_legal: 'Este resumo agrega registos submetidos ao serviço e classificações automáticas. Não confirma fraude, autoria, titularidade de contas ou identidade; a ausência de registos não prova que uma empresa está livre de risco. O excerto de texto é omitido e os contactos não são incluídos automaticamente.',
      revisao: 'Os indicadores exigem revisão humana e confirmação independente antes de partilha, bloqueio ou comunicação a terceiros. O hash SHA-256 identifica os dados deste resumo e não autentica a fonte original.'
    },
    suporte: {
      email: 'sales@confirmequeme.pt',
      portal: 'https://confirmequeme.pt'
    }
  };

  const hash = calcularHashRelatorio(dadosRelatorio);
  dadosRelatorio.hash_sha256 = hash;

  return dadosRelatorio;
}

/**
 * Renderiza o resumo HTML para pré-visualização ou impressão.
 * Pronto para exportar em PDF vetorial cristalino via browser
 */
export function renderRelatorioHtml(dados) {
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  const c = dados.cabecalho;
  const r = dados.resumo;
  const casos = dados.casos || [];
  const dominios = dados.indicadores_para_revisao?.dominios || dados.bloqueios?.dominios || [];

  return `<!DOCTYPE html>
<html lang="pt-PT">
<head>
  <meta charset="UTF-8">
  <title>Resumo de Sinais — ${esc(c.empresa_nome)} (${esc(c.periodo)})</title>
  <style>
    @page {
      size: A4;
      margin: 16mm 14mm 16mm 14mm;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    body {
      background: #ffffff;
      color: #0f172a;
      line-height: 1.45;
      font-size: 10pt;
    }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 12px;
      margin-bottom: 20px;
    }
    .logo-badge {
      font-weight: 800;
      font-size: 14pt;
      color: #059669;
      letter-spacing: -0.02em;
    }
    .meta-audit {
      text-align: right;
      font-size: 8pt;
      color: #64748b;
    }
    .title-section {
      margin-bottom: 20px;
    }
    .report-title {
      font-size: 18pt;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 4px;
    }
    .report-subtitle {
      font-size: 10pt;
      color: #475569;
    }
    .kpi-row {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    .kpi-box {
      flex: 1;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 10px 12px;
    }
    .kpi-lbl {
      font-size: 7.5pt;
      font-weight: 700;
      color: #64748b;
      text-transform: uppercase;
      margin-bottom: 4px;
    }
    .kpi-val {
      font-size: 16pt;
      font-weight: 800;
      color: #0f172a;
    }
    .section-title {
      font-size: 11pt;
      font-weight: 800;
      color: #0f172a;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
      margin: 18px 0 10px 0;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 8.5pt;
      margin-bottom: 14px;
    }
    th {
      background: #f1f5f9;
      color: #334155;
      text-align: left;
      padding: 6px 8px;
      border-bottom: 1px solid #cbd5e1;
      font-weight: 700;
    }
    td {
      padding: 6px 8px;
      border-bottom: 1px solid #e2e8f0;
      color: #1e293b;
      vertical-align: top;
    }
    .badge-nivel {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 7pt;
      font-weight: 700;
    }
    .nivel-alto { background: #fee2e2; color: #991b1b; }
    .nivel-medio { background: #fef3c7; color: #92400e; }
    .empty-state {
      background: #f8fafc;
      border: 1px dashed #cbd5e1;
      padding: 16px;
      border-radius: 6px;
      text-align: center;
      color: #64748b;
      font-style: italic;
      font-size: 9pt;
      margin: 10px 0;
    }
    .box-aviso {
      background: #eff6ff;
      border-left: 3px solid #2563eb;
      padding: 10px 14px;
      border-radius: 0 6px 6px 0;
      font-size: 8.5pt;
      color: #1e3a8a;
      margin: 10px 0;
    }
    .footer-audit {
      margin-top: 30px;
      padding-top: 10px;
      border-top: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      font-size: 7.5pt;
      color: #94a3b8;
    }
    .hash-code {
      font-family: monospace;
      color: #475569;
    }
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>

  <!-- CABEÇALHO OFICIAL -->
  <div class="header-bar">
    <div>
      <div class="logo-badge">🛡️ CONFIRME, QUEM É?</div>
      <div style="font-size: 8pt; color: #64748b;">Resumo automático de sinais submetidos; requer revisão humana</div>
    </div>
    <div class="meta-audit">
      <div>Código do Selo: <strong>${esc(c.codigo_selo)}</strong></div>
      <div>Período: <strong>${esc(c.periodo)}</strong> | Versão: <strong>${esc(c.versao)}</strong></div>
      <div>Data de Emissão: <strong>${esc(c.data_geracao)}</strong></div>
    </div>
  </div>

  <!-- TÍTULO -->
  <div class="title-section">
    <h1 class="report-title">${esc(c.empresa_nome)}</h1>
    <div class="report-subtitle">${esc(c.empresa_legal)} · NIF: ${esc(c.nif)} · Plano: ${esc(c.plano)}</div>
  </div>

  <!-- RESUMO EXECUTIVO (KPIS) -->
  <div class="kpi-row">
    <div class="kpi-box">
      <div class="kpi-lbl">Sinais Detetados</div>
      <div class="kpi-val" style="color: ${r.total_sinais > 0 ? '#b91c1c' : '#059669'};">${esc(r.total_sinais)}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Consultas à Página Pública</div>
      <div class="kpi-val">${esc(r.visitas_pagina)}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Verificações no Widget</div>
      <div class="kpi-val">${esc(r.verificacoes_widget)}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Tendência vs. Mês Anterior</div>
      <div class="kpi-val" style="font-size: 11pt; padding-top: 6px;">${esc(r.variacao_periodo_anterior)}</div>
    </div>
  </div>

  <!-- SEÇÃO 2: CASOS DE SINAIS DETETADOS -->
  <div class="section-title">1. Registos Submetidos no Período (classificação automática)</div>
  ${r.tem_dados ? `
  <table>
    <thead>
      <tr>
        <th style="width: 12%;">Data</th>
        <th style="width: 14%;">Canal</th>
        <th style="width: 20%;">Tipo de Abordagem</th>
        <th style="width: 10%;">Nível</th>
        <th style="width: 44%;">Nota</th>
      </tr>
    </thead>
    <tbody>
      ${casos.map(cs => `
      <tr>
        <td>${esc(cs.data)}</td>
        <td>${esc(cs.canal)}</td>
        <td>${esc(cs.tipo)}</td>
        <td><span class="badge-nivel ${String(cs.nivel).startsWith('Alto') ? 'nivel-alto' : 'nivel-medio'}">${esc(cs.nivel)}</span></td>
        <td>${esc(cs.excerto)}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>
  ` : `
  <div class="empty-state">
    Sem registos submetidos neste período; isto não prova ausência de fraude.
  </div>
  `}

  <!-- SEÇÃO 3: INDICADORES PARA REVISÃO -->
  <div class="section-title">2. Indicadores extraídos para revisão humana</div>
  ${(dominios.length > 0) ? `
  <div style="display: flex; gap: 16px; margin-bottom: 12px;">
    <div style="flex: 1;">
      <div style="font-size: 8pt; font-weight: 700; color: #475569; margin-bottom: 4px;">DOMÍNIOS SUBMETIDOS (NÃO VALIDADOS):</div>
      <ul style="font-size: 8pt; padding-left: 18px; color: #0f172a;">
        ${dominios.map(d => `<li><code>${esc(d)}</code></li>`).join('')}
      </ul>
    </div>
  </div>
  ` : `
  <div class="empty-state">
    Nenhum domínio submetido para revisão neste período.
  </div>
  `}

  <!-- SEÇÃO 4: RECOMENDAÇÕES AOS CLIENTES -->
  <div class="section-title">3. Recomendações e Modelo de Aviso para Clientes</div>
  <div class="box-aviso">
    <strong>Texto-Modelo Sugerido para Redes e Email:</strong><br>
    "${esc(dados.recomendacoes.aviso_clientes)}"
  </div>

  <!-- SEÇÃO 5: METODOLOGIA E LIMITES -->
  <div class="section-title">4. Metodologia e limites</div>
  <p style="font-size: 7.5pt; color: #64748b; line-height: 1.4;">
    ${esc(dados.metodologia.nota_legal)}
    ${esc(dados.metodologia.revisao)}
  </p>

  <!-- CHECKSUM DO RESUMO -->
  <div class="footer-audit">
    <div>Confirme, Quem É? · resumo automatizado; não é relatório pericial</div>
    <div>SHA-256 do resumo: <span class="hash-code">${esc((dados.hash_sha256 || '').slice(0, 32))}...</span></div>
  </div>

</body>
</html>`;
}
