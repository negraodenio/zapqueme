// lib/report_generator.js — Gerador de Relatórios Mensais Periciais B2B & Sanitização
// Confirme, Quem É? (confirmequeme.pt)
// Regras: Anonimização absoluta de vítimas, linguagem pericial ("sinais detetados"), Hash SHA-256

import crypto from 'node:crypto';

/**
 * Remove com rigor absoluto qualquer dado identificador de vítimas
 * (Telefones, NIF, IBAN, Emails, Números longos de cartões/contas)
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
 * Normaliza e calcula o Hash SHA-256 criptográfico para prova forense do relatório
 */
export function calcularHashRelatorio(conteudoHtmlOuJson) {
  const str = typeof conteudoHtmlOuJson === 'string' ? conteudoHtmlOuJson : JSON.stringify(conteudoHtmlOuJson);
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Estrutura os dados periciais do relatório mensal garantindo todas as seções obrigatórias
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

  // 2. Extrair domínios e contactos maliciosos a bloquear
  const dominiosBloquear = new Set();
  const contactosBloquear = new Set();
  const casosFormatados = [];

  for (const s of sinaisPeriodo) {
    // Domínio malicioso (impostor)
    if (s.alerta_link) {
      try {
        const urlObj = new URL(s.alerta_link.startsWith('http') ? s.alerta_link : `https://${s.alerta_link}`);
        dominiosBloquear.add(urlObj.hostname.toLowerCase());
      } catch {
        dominiosBloquear.add(String(s.alerta_link).toLowerCase().trim());
      }
    }

    // Canal malicioso (número remetente do impostor, NÃO da vítima)
    if (s.canal_mencionado && !s.canal_mencionado.includes('@') && s.canal_mencionado.replace(/\D/g, '').length >= 8) {
      contactosBloquear.add(s.canal_mencionado.trim());
    }

    const textoLimpo = limparTextoVitima(s.texto_original || s.resumo || '');
    const excerto = textoLimpo.length > 120 ? textoLimpo.slice(0, 117) + '...' : textoLimpo;

    casosFormatados.push({
      data: s.criado_em ? s.criado_em.slice(0, 10) : 'N/D',
      canal: s.canal || 'WhatsApp / SMS',
      tipo: s.tipo || 'Tentativa de Impersonation',
      impostor: s.alerta_link || s.canal_mencionado || 'Canal não verificado',
      nivel: (s.risco_score >= 75 || s.veredito === 'golpe') ? 'Alto' : 'Médio',
      excerto: excerto || 'Indícios de abordagem com pretexto urgente ou financeiro.'
    });
  }

  const dadosRelatorio = {
    cabecalho: {
      titulo: 'Relatório Mensal de Sinais de Ameaça & Integridade de Marca',
      empresa_nome: brandName,
      empresa_legal: empresa.nome_legal || empresa.nome,
      nif: empresa.nif || 'Em verificação',
      codigo_selo: empresa.codigo_selo || 'ZQV-OFICIAL',
      periodo: periodo || new Date().toISOString().slice(0, 7),
      data_geracao: new Date().toISOString().slice(0, 10),
      versao,
      gerado_por: geradoPor,
      plano: isPlanoRadar ? 'Plano Radar (Inteligência & Selo)' : 'Plano Selo (Contacto Verificado)'
    },
    resumo: {
      visitas_pagina: metricasSelo.visitas_pagina || 0,
      verificacoes_widget: metricasSelo.verificacoes_widget || 0,
      total_sinais: sinaisPeriodo.length,
      variacao_periodo_anterior: metricasSelo.variacao || 'Primeiro período auditado',
      tem_dados: sinaisPeriodo.length > 0
    },
    casos: isPlanoRadar ? casosFormatados : (sinaisPeriodo.length > 0 ? casosFormatados.slice(0, 5) : []),
    bloqueios: {
      dominios: Array.from(dominiosBloquear),
      contactos: Array.from(contactosBloquear)
    },
    recomendacoes: {
      aviso_clientes: `A ${brandName} alerta todos os seus clientes que nunca solicita pagamentos imediatos via referências desconhecidas ou links recebidos por SMS. Confirme sempre no site oficial ou na app antes de pagar.`,
      medidas_mitigacao: [
        'Solicitar o encerramento dos domínios fraudulentos identificados junto dos respetivos registrars.',
        'Divulgar o certificado oficial Confirme, Quem É? em canais de atendimento e faturação.',
        'Reportar números de envio não oficiais às operadoras móveis para bloqueio de smishing.'
      ]
    },
    metodologia: {
      nota_legal: 'Este relatório é compilado com base em sinais detetados e submetidos à rede descentralizada de sensores Confirme, Quem É?. A deteção de um sinal indica tráfego atípico ou personificação de canais, não constituindo condenação jurídica nem garantia de ausência de fraudes.',
      revisao: 'Para submeter correções ou auditar um sinal específico, contacte o suporte oficial pericial.'
    },
    suporte: {
      email: 'suporte@confirmequeme.pt',
      portal: 'https://confirmequeme.pt'
    }
  };

  const hash = calcularHashRelatorio(dadosRelatorio);
  dadosRelatorio.hash_sha256 = hash;

  return dadosRelatorio;
}

/**
 * Renderiza o HTML Pericial de Alta Qualidade Gráfica com CSS @media print
 * Pronto para exportar em PDF vetorial cristalino via browser
 */
export function renderRelatorioHtml(dados) {
  const c = dados.cabecalho;
  const r = dados.resumo;
  const casos = dados.casos || [];
  const dominios = dados.bloqueios?.dominios || [];
  const contactos = dados.bloqueios?.contactos || [];

  return `<!DOCTYPE html>
<html lang="pt-PT">
<head>
  <meta charset="UTF-8">
  <title>Relatório Pericial — ${c.empresa_nome} (${c.periodo})</title>
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
      <div style="font-size: 8pt; color: #64748b;">Relatório Pericial de Inteligência & Integridade de Marca</div>
    </div>
    <div class="meta-audit">
      <div>Código do Selo: <strong>${c.codigo_selo}</strong></div>
      <div>Período: <strong>${c.periodo}</strong> | Versão: <strong>${c.versao}</strong></div>
      <div>Data de Emissão: <strong>${c.data_geracao}</strong></div>
    </div>
  </div>

  <!-- TÍTULO -->
  <div class="title-section">
    <h1 class="report-title">${c.empresa_nome}</h1>
    <div class="report-subtitle">${c.empresa_legal} · NIF: ${c.nif} · Plano: ${c.plano}</div>
  </div>

  <!-- RESUMO EXECUTIVO (KPIS) -->
  <div class="kpi-row">
    <div class="kpi-box">
      <div class="kpi-lbl">Sinais Detetados</div>
      <div class="kpi-val" style="color: ${r.total_sinais > 0 ? '#b91c1c' : '#059669'};">${r.total_sinais}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Consultas à Página Pública</div>
      <div class="kpi-val">${r.visitas_pagina}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Verificações no Widget</div>
      <div class="kpi-val">${r.verificacoes_widget}</div>
    </div>
    <div class="kpi-box">
      <div class="kpi-lbl">Tendência vs. Mês Anterior</div>
      <div class="kpi-val" style="font-size: 11pt; padding-top: 6px;">${r.variacao_periodo_anterior}</div>
    </div>
  </div>

  <!-- SEÇÃO 2: CASOS DE SINAIS DETETADOS -->
  <div class="section-title">1. Sinais Detetados no Período (Anonimizados)</div>
  ${r.tem_dados ? `
  <table>
    <thead>
      <tr>
        <th style="width: 12%;">Data</th>
        <th style="width: 14%;">Canal</th>
        <th style="width: 20%;">Tipo de Abordagem</th>
        <th style="width: 10%;">Nível</th>
        <th style="width: 44%;">Excerto Limpo (Sem Dados de Vítimas)</th>
      </tr>
    </thead>
    <tbody>
      ${casos.map(cs => `
      <tr>
        <td>${cs.data}</td>
        <td>${cs.canal}</td>
        <td>${cs.tipo}</td>
        <td><span class="badge-nivel ${cs.nivel === 'Alto' ? 'nivel-alto' : 'nivel-medio'}">${cs.nivel}</span></td>
        <td>${cs.excerto}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>
  ` : `
  <div class="empty-state">
    ✓ Sem sinais detetados neste período.
  </div>
  `}

  <!-- SEÇÃO 3: DOMÍNIOS E CONTACTOS PARA BLOQUEIO -->
  <div class="section-title">2. Indicadores para Bloqueio Preventivo</div>
  ${(dominios.length > 0 || contactos.length > 0) ? `
  <div style="display: flex; gap: 16px; margin-bottom: 12px;">
    <div style="flex: 1;">
      <div style="font-size: 8pt; font-weight: 700; color: #475569; margin-bottom: 4px;">DOMÍNIOS SUSPEITOS IDENTIFICADOS:</div>
      <ul style="font-size: 8pt; padding-left: 18px; color: #0f172a;">
        ${dominios.map(d => `<li><code>${d}</code></li>`).join('')}
      </ul>
    </div>
    <div style="flex: 1;">
      <div style="font-size: 8pt; font-weight: 700; color: #475569; margin-bottom: 4px;">REMETENTES NÃO OFICIAIS:</div>
      <ul style="font-size: 8pt; padding-left: 18px; color: #0f172a;">
        ${contactos.map(c => `<li><code>${c}</code></li>`).join('')}
      </ul>
    </div>
  </div>
  ` : `
  <div class="empty-state">
    Nenhum domínio ou canal para bloqueio detetado neste período.
  </div>
  `}

  <!-- SEÇÃO 4: RECOMENDAÇÕES AOS CLIENTES -->
  <div class="section-title">3. Recomendações e Modelo de Aviso para Clientes</div>
  <div class="box-aviso">
    <strong>Texto-Modelo Sugerido para Redes e Email:</strong><br>
    "${dados.recomendacoes.aviso_clientes}"
  </div>

  <!-- SEÇÃO 5: METODOLOGIA E LIMITES -->
  <div class="section-title">4. Metodologia Pericial e Limites Jurídicos</div>
  <p style="font-size: 7.5pt; color: #64748b; line-height: 1.4;">
    ${dados.metodologia.nota_legal}
    ${dados.metodologia.revisao}
  </p>

  <!-- RODAPÉ FORENSE COM HASH SHA-256 -->
  <div class="footer-audit">
    <div>Confirme, Quem É? · Auditoria Forense Digital (confirmequeme.pt)</div>
    <div>Hash SHA-256: <span class="hash-code">${dados.hash_sha256.slice(0, 32)}...</span></div>
  </div>

</body>
</html>`;
}
