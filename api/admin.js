// api/admin.js — Dashboard & Gestão B2B (Empresas, Selos & Threat Radar)
// Especificação Fechada ZAP, QUEM É? — B2B
// Seções 6, 7, 8, 19, 20, 21

import {
  gerarCodigoSelo,
  compilarIntelligenceRadar,
  gerarPacoteTakedown
} from '../lib/radar.js';
import {
  limparTextoVitima,
  estruturarRelatorioMensal,
  renderRelatorioHtml
} from '../lib/report_generator.js';
import {
  compilarEstadoFase1,
  aplicarDecisaoHumanaFila,
  aplicarDecisaoHumanaCluster,
  criarItemFilaRevisao,
  agruparEventosEmClusters,
  getMemoriaGolpesNovos,
  sanitizarCampoAnonimizado,
  verificarFonteAlertaOficial,
  criarOuAtualizarEsquema,
  reverAlertaOficial,
  FONTES_ALERTA_INICIAIS,
  proporAlteracaoDicionario,
  decidirAlteracaoDicionario,
  compilarDicionarioAprovado,
  isApprovedDictionaryEnabled,
  setApprovedDictionaryEnabled,
  criarAmostraTeste,
  classificarAmostraTeste,
  promoverAmostraParaRegressao,
  validarConjuntoBenchmarkRotativo,
  executarBenchmarkRotativo
} from '../lib/golpes_novos.js';

// Campos de verificação comercial e CRM (migração 20261016, 20261015 e 20261019).
const CAMPOS_VERIFICACAO = [
  'nif', 'nif_verificado', 'iban', 'iban_verificado', 'verificacao_notas', 'verificado_em',
  'nome_legal', 'nome_comercial', 'email_contacto', 'representante_nome', 'representante_cargo',
  'plano', 'estado', 'codigo_selo', 'data_emissao', 'data_validade', 'preco_acordado', 'notas', 'marca_aliases',
  'is_teste', 'arquivado_em', 'arquivado_motivo', 'arquivado_por'
];

function extrairCamposVerificacao(body) {
  const out = {};
  if (body.nif !== undefined) out.nif = body.nif ? String(body.nif).replace(/\s+/g, '').toUpperCase() : null;
  if (body.nif_verificado !== undefined) out.nif_verificado = !!body.nif_verificado;
  if (body.iban !== undefined) out.iban = body.iban ? String(body.iban).replace(/\s+/g, '').toUpperCase() : null;
  if (body.iban_verificado !== undefined) out.iban_verificado = !!body.iban_verificado;
  if (body.verificacao_notas !== undefined) out.verificacao_notas = body.verificacao_notas ? String(body.verificacao_notas).trim() : null;
  if (out.nif_verificado || out.iban_verificado) out.verificado_em = new Date().toISOString();

  // Campos CRM 20261016
  if (body.nome_legal !== undefined) out.nome_legal = body.nome_legal ? String(body.nome_legal).trim() : null;
  if (body.nome_comercial !== undefined) out.nome_comercial = body.nome_comercial ? String(body.nome_comercial).trim() : null;
  if (body.email_contacto !== undefined) out.email_contacto = body.email_contacto ? String(body.email_contacto).trim().toLowerCase() : null;
  if (body.representante_nome !== undefined) out.representante_nome = body.representante_nome ? String(body.representante_nome).trim() : null;
  if (body.representante_cargo !== undefined) out.representante_cargo = body.representante_cargo ? String(body.representante_cargo).trim() : null;
  if (body.plano !== undefined) out.plano = body.plano;
  if (body.estado !== undefined) out.estado = body.estado;
  if (body.codigo_selo !== undefined) out.codigo_selo = body.codigo_selo;
  if (body.data_emissao !== undefined) out.data_emissao = body.data_emissao;
  if (body.data_validade !== undefined) out.data_validade = body.data_validade;
  if (body.preco_acordado !== undefined) out.preco_acordado = Number(body.preco_acordado) || (body.plano === 'radar' ? 290.00 : 49.00);
  if (body.notas !== undefined) out.notas = body.notas ? String(body.notas).trim() : null;
  if (body.marca_aliases !== undefined) {
    out.marca_aliases = Array.isArray(body.marca_aliases)
      ? body.marca_aliases.map(a => String(a).trim()).filter(Boolean)
      : (typeof body.marca_aliases === 'string' ? body.marca_aliases.split(',').map(a => a.trim()).filter(Boolean) : []);
  }

  // Campos Fase 1 (20261019)
  if (body.is_teste !== undefined) out.is_teste = !!body.is_teste;
  if (body.arquivado_em !== undefined) out.arquivado_em = body.arquivado_em;
  if (body.arquivado_motivo !== undefined) out.arquivado_motivo = body.arquivado_motivo ? String(body.arquivado_motivo).trim() : null;
  if (body.arquivado_por !== undefined) out.arquivado_por = body.arquivado_por ? String(body.arquivado_por).trim() : null;

  return out;
}

async function registrarHistorico(supabaseUrl, headers, { empresa_id, acao, antes, depois, por = 'admin', motivo = null }) {
  try {
    await fetch(`${supabaseUrl}/rest/v1/historico`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        empresa_id,
        acao,
        antes: antes || null,
        depois: depois || null,
        por,
        motivo: motivo || null
      })
    });
  } catch (err) {
    console.warn('[Admin Historico] Falha ao registar histórico:', err.message);
  }
}

async function inicializarQuatroPilares(supabaseUrl, headers, empresa_id) {
  const pilares = ['nif', 'dominio', 'telefone', 'representante'];
  try {
    await fetch(`${supabaseUrl}/rest/v1/verificacoes`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=ignore-duplicates' },
      body: JSON.stringify(
        pilares.map(tipo => ({
          empresa_id,
          tipo,
          estado: 'pendente'
        }))
      )
    });
  } catch (err) {
    console.warn('[Admin Verificacoes] Aviso ao inicializar pilares:', err.message);
  }
}

async function validarTravaAtivacao4Pilares(supabaseUrl, headers, empresa_id) {
  // A) Checar 4 verificações
  const verifResp = await fetch(`${supabaseUrl}/rest/v1/verificacoes?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
  const verifs = verifResp.ok ? await verifResp.json() : [];
  const tiposOk = new Set(verifs.filter(v => v.estado === 'ok').map(v => v.tipo));
  const obrigatorios = ['nif', 'dominio', 'telefone', 'representante'];
  const faltantes = obrigatorios.filter(t => !tiposOk.has(t));

  if (faltantes.length > 0) {
    return {
      permitido: false,
      error: `Bloqueio de ativação (Critério 1): as 4 verificações obrigatórias devem estar OK no Dossiê B2B. Faltam: ${faltantes.join(', ')}.`
    };
  }

  // B) Checar pagamento válido ou isenção justificada
  const pagResp = await fetch(`${supabaseUrl}/rest/v1/pagamentos?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
  const pags = pagResp.ok ? await pagResp.json() : [];
  const temPagamentoValido = pags.some(
    p => p.estado === 'pago' || (p.estado === 'isento' && p.motivo_isencao && p.motivo_isencao.trim().length >= 4)
  );

  if (!temPagamentoValido) {
    return {
      permitido: false,
      error: 'Bloqueio de ativação (Critério 1): é obrigatório registar pelo menos um pagamento "pago" ou uma isenção justificada no Dossiê B2B antes de ativar.'
    };
  }

  return { permitido: true };
}

function normalizarRelatorioRow(r) {
  if (!r) return r;
  const per = r.periodo || '';
  const partes = per.split('-');
  const ano = r.ano || (partes[0] ? parseInt(partes[0], 10) : new Date().getFullYear());
  const mes = r.mes || (partes[1] ? parseInt(partes[1], 10) : (new Date().getMonth() + 1));
  const estado = r.enviado_em ? 'enviado' : (r.aprovado_em ? 'aprovado' : (r.estado || 'rascunho'));
  return {
    ...r,
    ano,
    mes,
    hash_sha256: r.hash_sha256 || r.hash_ficheiro || '',
    hash_ficheiro: r.hash_ficheiro || r.hash_sha256 || '',
    estado
  };
}

async function fetchComFallback(fetchUrl, options, payload) {
  let resp = await fetch(fetchUrl, { ...options, body: JSON.stringify(payload) });
  if (!resp.ok) {
    const errText = await resp.text();
    const temCamposNovos = CAMPOS_VERIFICACAO.some(c => c in payload);
    if (temCamposNovos && /column|schema cache/i.test(errText)) {
      console.warn('[Admin] Migração pendente; a gravar com fallback retrocompatível.');
      const semNovos = { ...payload };
      CAMPOS_VERIFICACAO.forEach(c => delete semNovos[c]);
      resp = await fetch(fetchUrl, { ...options, body: JSON.stringify(semNovos) });
      if (resp.ok) resp.migracaoPendente = true;
      return resp;
    }
    return { ok: false, text: async () => errText };
  }
  return resp;
}

export default async function handler(req, res) {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';

  // Autenticação: aceita apenas header x-admin-key, Authorization Bearer ou campo secret no body (não via query string)
  let secret = req.headers['x-admin-key'] || (req.body && req.body.secret);
  if (!secret && req.headers['authorization']) {
    const authHeader = req.headers['authorization'];
    if (authHeader.toLowerCase().startsWith('bearer ')) {
      secret = authHeader.slice(7).trim();
    }
  }

  if (!secret || secret !== adminSecret) {
    return res.status(401).json({ error: 'Acesso não autorizado. Chave administrativa inválida.' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    return res.status(500).json({ error: 'Supabase não configurado no servidor.' });
  }

  const headers = {
    'Content-Type': 'application/json',
    apikey: key,
    Authorization: `Bearer ${key}`
  };

  // 1. DADOS DO DASHBOARD (GET)
  if (req.method === 'GET') {
    let empresas = [];
    let selos = [];
    let radar = [];
    let ocorrencias = [];
    let leads = [];
    let marcas = [];
    let sinais = [];
    let verificacoes = [];
    let pagamentos = [];
    let historico = [];
    let contactosComerciais = [];
    let relatorios = [];
    let usoSelo = [];
    let clustersDb = [];
    let filaDb = [];
    let fontesDb = [];
    let alertasDb = [];
    let esquemasDb = [];
    let dicionarioDb = [];
    let amostrasDb = [];
    let corridasDb = [];
    let analisesRevisao = [];
    let isDbOnline = true;
    let dbErrorMessage = null;

    try {
      // 1. Buscar empresas
      const empresasResp = await fetch(`${url}/rest/v1/empresas?select=*&order=criado_em.desc`, { headers });
      empresas = empresasResp.ok ? await empresasResp.json() : [];

      // 2. Buscar selos com nome da empresa
      const selosResp = await fetch(`${url}/rest/v1/selos?select=*&order=criado_em.desc`, { headers });
      const selosRaw = selosResp.ok ? await selosResp.json() : [];

      const empMap = new Map(empresas.map(e => [e.id, e]));
      selos = selosRaw.map(s => {
        const emp = empMap.get(s.empresa_id);
        return {
          ...s,
          empresa_nome: emp ? emp.nome : 'Empresa não encontrada',
          empresa_status: emp ? emp.status : 'inativo',
          empresa_is_teste: emp ? !!emp.is_teste : !!s.is_teste,
          empresa_arquivada: emp ? !!emp.arquivado_em : !!s.arquivado_em
        };
      });

      // 3. Buscar view Threat Radar (Seção 8 e 14)
      const radarResp = await fetch(`${url}/rest/v1/radar_ameacas?select=*&order=ocorrencias.desc`, { headers });
      radar = radarResp.ok ? await radarResp.json() : [];

      // 4. Buscar ocorrências de impersonation para o detalhe (Seção 21)
      const ocorrenciasResp = await fetch(
        `${url}/rest/v1/analises?impersonation=eq.true&select=id,criado_em,veredito,confianca,risco_score,tipo,canal,canal_mencionado,marca_mencionada,alerta_link,vezes_reportada,empresa_id&order=criado_em.desc&limit=100`,
        { headers }
      );
      const ocorrenciasRaw = ocorrenciasResp.ok ? await ocorrenciasResp.json() : [];
      ocorrencias = ocorrenciasRaw.map(o => ({
        ...o,
        empresa_nome: empMap.get(o.empresa_id)?.nome || o.marca_mencionada || 'Empresa desconhecida'
      }));

      // 5. Buscar leads comerciais do Supabase
      try {
        const leadsResp = await fetch(`${url}/rest/v1/leads?select=*&order=criado_em.desc&limit=50`, { headers });
        if (leadsResp.ok) leads = await leadsResp.json();
      } catch {}

      // 6. Marcas mencionadas em denúncias (inclui não-clientes) — base do alerta gratuito e Shadow Radar
      try {
        const marcasResp = await fetch(`${url}/rest/v1/marcas_mencionadas?select=*&order=denuncias.desc&limit=200`, { headers });
        if (marcasResp.ok) marcas = await marcasResp.json();
      } catch {}

      // 7. Denúncias individuais com marca (evidência para os relatórios e IOCs, últimos 90 dias)
      try {
        const desde = new Date(Date.now() - 90 * 24 * 3600 * 1000).toISOString();
        const sinaisResp = await fetch(
          `${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&criado_em=gte.${desde}` +
          `&select=id,criado_em,veredito,confianca,tipo,canal,canal_mencionado,marca_mencionada,alerta_link,vezes_reportada,empresa_id,impersonation` +
          `&order=criado_em.desc&limit=1000`,
          { headers }
        );
        if (sinaisResp.ok) sinais = await sinaisResp.json();
      } catch {}

      // 8. Buscar verificações de empresas (Checklist 4 pilares)
      try {
        const verifResp = await fetch(`${url}/rest/v1/verificacoes?select=*&order=criado_em.asc`, { headers });
        if (verifResp.ok) verificacoes = await verifResp.json();
      } catch {}

      // 9. Buscar registos financeiros de pagamentos e normalizar campos
      try {
        const pagResp = await fetch(`${url}/rest/v1/pagamentos?select=*&order=data.desc&limit=100`, { headers });
        if (pagResp.ok) {
          const pagRaw = await pagResp.json();
          pagamentos = pagRaw.map(p => {
            let periodoMeses = p.periodo_meses || 12;
            if (p.periodo_inicio && p.periodo_fim) {
              const d1 = new Date(p.periodo_inicio);
              const d2 = new Date(p.periodo_fim);
              const diffM = Math.round((d2 - d1) / (1000 * 60 * 60 * 24 * 30));
              if (diffM > 0) periodoMeses = diffM;
            }
            return {
              ...p,
              periodo_meses: periodoMeses,
              notas: p.notas || p.motivo_isencao || p.fatura_numero || ''
            };
          });
        }
      } catch {}

      // 10. Buscar histórico de auditoria
      try {
        const histResp = await fetch(`${url}/rest/v1/historico?select=*&order=em.desc&limit=150`, { headers });
        if (histResp.ok) historico = await histResp.json();
      } catch {}

      // 11. Buscar contactos comerciais do funil e normalizar campos para o frontend
      try {
        const contResp = await fetch(`${url}/rest/v1/contactos_comerciais?select=*&order=data.desc&limit=100`, { headers });
        if (contResp.ok) {
          const contRaw = await contResp.json();
          contactosComerciais = contRaw.map(c => ({
            ...c,
            data: c.data || c.criado_em,
            por: c.por || c.registado_por || 'admin',
            notas: c.notas || c.resumo || '',
            proximo_passo: c.proximo_passo || c.resposta || ''
          }));
        }
      } catch {}

      // 12. Buscar relatórios periciais gerados e normalizar colunas (periodo -> mes/ano, hash_ficheiro -> hash_sha256, estado)
      try {
        const relResp = await fetch(`${url}/rest/v1/relatorios_gerados?select=*&order=gerado_em.desc&limit=50`, { headers });
        if (relResp.ok) {
          const relRaw = await relResp.json();
          relatorios = relRaw.map(normalizarRelatorioRow);
        }
      } catch {}

      // 13. Buscar métricas agregadas de uso do selo (uso_selo)
      try {
        const usoResp = await fetch(`${url}/rest/v1/uso_selo?select=*&order=data.desc&limit=500`, { headers });
        if (usoResp.ok) usoSelo = await usoResp.json();
      } catch {}

      // 14. Módulo Golpes Novos (Fases 1, 2 e 3): Buscar clusters, fila_revisao, fontes_alerta, alertas_oficiais, esquemas, dicionario_alteracoes e análises recentes sem texto bruto
      try {
        const clResp = await fetch(`${url}/rest/v1/clusters?select=*&order=ultima_vez.desc&limit=200`, { headers });
        if (clResp.ok) clustersDb = await clResp.json();
      } catch {}

      try {
        const frResp = await fetch(`${url}/rest/v1/fila_revisao?select=*&order=criado_em.desc&limit=300`, { headers });
        if (frResp.ok) filaDb = await frResp.json();
      } catch {}

      try {
        const faResp = await fetch(`${url}/rest/v1/fontes_alerta?select=*&order=criado_em.asc&limit=100`, { headers });
        if (faResp.ok) fontesDb = await faResp.json();
      } catch {}

      try {
        const aoResp = await fetch(`${url}/rest/v1/alertas_oficiais?select=*&order=detetado_em.desc&limit=200`, { headers });
        if (aoResp.ok) alertasDb = await aoResp.json();
      } catch {}

      try {
        const esqResp = await fetch(`${url}/rest/v1/esquemas?select=*&order=criado_em.desc&limit=200`, { headers });
        if (esqResp.ok) esquemasDb = await esqResp.json();
      } catch {}

      try {
        const dicResp = await fetch(`${url}/rest/v1/dicionario_alteracoes?select=*&order=criado_em.desc&limit=300`, { headers });
        if (dicResp.ok) dicionarioDb = await dicResp.json();
      } catch {}

      try {
        const amResp = await fetch(`${url}/rest/v1/amostras_teste?select=*&order=criado_em.desc&limit=300`, { headers });
        if (amResp.ok) amostrasDb = await amResp.json();
      } catch {}

      try {
        const cbResp = await fetch(`${url}/rest/v1/corridas_benchmark?select=*&order=data_hora.desc&limit=50`, { headers });
        if (cbResp.ok) corridasDb = await cbResp.json();
      } catch {}

      try {
        const anResp = await fetch(
          `${url}/rest/v1/analises?select=id,criado_em,veredito,confianca,risco_score,tipo,canal,canal_mencionado,marca_mencionada,alerta_link,vezes_reportada&order=criado_em.desc&limit=200`,
          { headers }
        );
        if (anResp.ok) analisesRevisao = await anResp.json();
      } catch {}

    } catch (err) {
      isDbOnline = false;
      dbErrorMessage = err.message || 'Falha ao conectar ao banco de dados Supabase.';
      console.warn('[Admin] Supabase offline ou pausado:', err.message);
    }

    // Se Supabase não retornou leads ou está offline, busca leads persistidos no Upstash Redis
    if (!leads.length) {
      const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
      const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
      if (redisUrl && redisToken) {
        try {
          const redisResp = await fetch(`${redisUrl}/lrange/zapqueme:leads/0/50`, {
            headers: { Authorization: `Bearer ${redisToken}` }
          });
          if (redisResp.ok) {
            const rData = await redisResp.json();
            if (Array.isArray(rData.result)) {
              leads = rData.result.map(item => {
                try { return typeof item === 'string' ? JSON.parse(item) : item; }
                catch { return null; }
              }).filter(Boolean);
            }
          }
        } catch (rErr) {
          console.warn('[Admin] Erro ao buscar leads no Redis:', rErr.message);
        }
      }
    }

    // Compila Inteligência Enterprise do Threat Radar (Surtos, IOCs SIBS/MBWAY, Shadow Radar)
    const radarIntel = compilarIntelligenceRadar({
      empresas,
      radar,
      ocorrencias,
      sinais,
      marcas
    });

    // Compila Estado das Fases 1, 2, 3 e 4 do Módulo de Golpes Novos
    const estadoFase1 = compilarEstadoFase1({
      clustersDb,
      filaDb,
      fontesDb,
      alertasDb,
      esquemasDb,
      dicionarioDb,
      amostrasDb,
      corridasDb,
      analisesRecentes: analisesRevisao.length ? analisesRevisao : [...sinais, ...ocorrencias]
    });

    // Filtra empresas/selos reais (não arquivados e não de teste) para não poluir KPIs de produção
    const empresasReais = empresas.filter(e => !e.arquivado_em && !e.is_teste);
    const selosReais = selos.filter(s => !s.arquivado_em && !s.is_teste && !s.empresa_is_teste && !s.empresa_arquivada);

    // 5. Total de ocorrências
    const totalOcorrencias = radar.reduce((acc, r) => acc + (parseInt(r.ocorrencias, 10) || 0), 0);

    // KPIs Obrigatórios (Seção 19) + Métricas de Higiene + Golpes Novos:
    const kpis = {
      totalEmpresas: empresasReais.length,
      totalEmpresasTeste: empresas.filter(e => e.is_teste && !e.arquivado_em).length,
      totalArquivados: empresas.filter(e => !!e.arquivado_em).length + selos.filter(s => !!s.arquivado_em).length,
      totalSelos: selosReais.filter(s => s.ativo !== false).length,
      totalThreatRadar: radarIntel.shadow_radar.length || radar.length,
      totalOcorrencias: totalOcorrencias || ocorrencias.length || sinais.length,
      totalLeads: leads.length,
      totalPagamentos: (pagamentos || []).filter(p => p.estado === 'pago').length,
      totalSinais: sinais.length,
      totalSurtosAtivos: radarIntel.resumo.total_surtos_criticos,
      totalIocsFinanceiros: radarIntel.resumo.total_iocs_financeiros,
      totalFilaRevisao: estadoFase1.resumo_modulo.fila_pendentes,
      totalPossiveisCampanhas: estadoFase1.resumo_modulo.possiveis_campanhas,
      totalAlertasOficiaisNovos: estadoFase1.resumo_modulo.alertas_novos,
      totalEsquemasAtivos: estadoFase1.resumo_modulo.esquemas_ativos,
      totalDicionarioPendentes: estadoFase1.resumo_modulo.dicionario_pendentes,
      totalDicionarioAprovados: estadoFase1.resumo_modulo.dicionario_aprovados,
      totalAmostrasRotativas: estadoFase1.resumo_modulo.amostras_rotativas,
      totalAmostrasRegressao: estadoFase1.resumo_modulo.amostras_regressao,
      totalAmostrasSemClassificacao: estadoFase1.resumo_modulo.amostras_sem_classificacao,
      benchmarkPronto: estadoFase1.resumo_modulo.benchmark_pronto_a_executar,
      ultimaTaxaAcertoBenchmark: estadoFase1.resumo_modulo.ultima_corrida_taxa_acerto
    };

    return res.status(200).json({
      kpis,
      empresas,
      selos,
      radar,
      radar_intel: radarIntel,
      ocorrencias,
      leads,
      marcas,
      sinais,
      verificacoes: verificacoes || [],
      pagamentos: pagamentos || [],
      historico: historico || [],
      contactos_comerciais: contactosComerciais || [],
      relatorios: relatorios || [],
      uso_selo: usoSelo || [],
      clusters: estadoFase1.clusters,
      fila_revisao: estadoFase1.fila_revisao,
      fontes_alerta: estadoFase1.fontes_alerta,
      alertas_oficiais: estadoFase1.alertas_oficiais,
      esquemas: estadoFase1.esquemas,
      dicionario_alteracoes: estadoFase1.dicionario_alteracoes,
      dicionario_ativo: estadoFase1.dicionario_ativo,
      amostras_teste: estadoFase1.amostras_teste,
      corridas_benchmark: estadoFase1.corridas_benchmark,
      golpes_novos_resumo: estadoFase1.resumo_modulo,
      database_online: isDbOnline,
      database_warning: isDbOnline ? null : `Supabase inacessível (${dbErrorMessage}). Verifique se o projeto está pausado em supabase.com.`
    });
  }

  // 2. AÇÕES ADMINISTRATIVAS (POST)
  if (req.method === 'POST') {
    const { action } = req.body || {};

    // 2.1 CRIAR EMPRESA (Seção 6.1 & Respeito Estrito ao Critério 1)
    if (action === 'create_empresa') {
      const {
        nome,
        dominio_oficial,
        email_oficial,
        telefone_oficial,
        apelidos_marca,
        dominio_verificado,
        email_verificado,
        telefone_verificado,
        plano,
        status,
        estado,
        monitorizacao_impersonation,
        criar_selo
      } = req.body;

      if (!nome || !nome.trim()) {
        return res.status(400).json({ error: 'O nome da empresa é obrigatório.' });
      }

      // Normaliza apelidos para array de strings
      let apelidosArray = [];
      if (Array.isArray(apelidos_marca)) {
        apelidosArray = apelidos_marca.map(a => String(a).trim()).filter(Boolean);
      } else if (typeof apelidos_marca === 'string' && apelidos_marca.trim()) {
        apelidosArray = apelidos_marca.split(',').map(a => a.trim()).filter(Boolean);
      }

      // CRITÉRIO 1: Nenhuma empresa real recém-criada pode nascer com selo ativo sem os 4 pilares OK + pagamento.
      const isTesteFlag = !!req.body.is_teste;
      const estadoInicialSolicitado = estado || status || 'lead';
      const estadoInicialSeguro = (!isTesteFlag && estadoInicialSolicitado === 'ativo')
        ? 'em_verificacao'
        : (['lead', 'contactado', 'proposta', 'em_verificacao', 'suspenso'].includes(estadoInicialSolicitado) ? estadoInicialSolicitado : 'lead');
      const statusInicialSeguro = isTesteFlag && status === 'ativo' ? 'ativo' : 'inativo';
      const planoNormalizado = plano || 'selo';

      try {
        const camposExtras = extrairCamposVerificacao(req.body);
        camposExtras.estado = estadoInicialSeguro;
        camposExtras.plano = planoNormalizado;
        if (!req.body.marca_aliases && apelidosArray.length > 0) {
          camposExtras.marca_aliases = apelidosArray;
        }

        const empInsert = await fetchComFallback(`${url}/rest/v1/empresas`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
            nome: nome.trim(),
            dominio_oficial: dominio_oficial ? dominio_oficial.trim().toLowerCase() : null,
            email_oficial: email_oficial ? email_oficial.trim().toLowerCase() : null,
            telefone_oficial: telefone_oficial ? telefone_oficial.trim() : null,
            apelidos_marca: apelidosArray,
            dominio_verificado: !!dominio_verificado,
            email_verificado: !!email_verificado,
            telefone_verificado: !!telefone_verificado,
            plano: planoNormalizado,
            status: statusInicialSeguro,
            ...camposExtras
        });

        if (!empInsert.ok) {
          const errText = await empInsert.text();
          throw new Error('Erro ao cadastrar empresa: ' + errText);
        }

        const novaEmpresaRows = await empInsert.json();
        const novaEmpresa = novaEmpresaRows[0];

        // Inicializa os 4 pilares da checklist em 'verificacoes' (estado: 'pendente')
        await inicializarQuatroPilares(url, headers, novaEmpresa.id);

        // Se solicitado criação de selo inicial: fica com ativo=false até aprovação dos 4 pilares + pagamento (exceto teste explícito)
        let novoSelo = null;
        if (criar_selo !== false) {
          const codigoSelo = gerarCodigoSelo();
          const validoAte = new Date();
          validoAte.setFullYear(validoAte.getFullYear() + 1);

          const seloInsert = await fetch(`${url}/rest/v1/selos`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'return=representation' },
            body: JSON.stringify({
              empresa_id: novaEmpresa.id,
              codigo: codigoSelo,
              tipo: 'canal_verificado',
              valido_ate: validoAte.toISOString(),
              monitorizacao_impersonation: monitorizacao_impersonation !== false,
              ativo: statusInicialSeguro === 'ativo',
              is_teste: !!novaEmpresa.is_teste
            })
          });

          if (seloInsert.ok) {
            const seloRows = await seloInsert.json();
            novoSelo = seloRows[0];
          }
        }

        await registrarHistorico(url, headers, {
          empresa_id: novaEmpresa.id,
          acao: 'criacao_empresa',
          depois: {
            nome: novaEmpresa.nome,
            plano: novaEmpresa.plano,
            estado: estadoInicialSeguro,
            status: statusInicialSeguro,
            is_teste: !!novaEmpresa.is_teste
          },
          por: req.body.por || 'admin',
          motivo: 'Registo de nova empresa no pipeline B2B (aguarda 4 pilares + pagamento para ativação)'
        });

        return res.status(200).json({
          success: true,
          empresa: novaEmpresa,
          selo: novoSelo,
          migracao_pendente: !!empInsert.migracaoPendente
        });
      } catch (err) {
        console.error('[Admin] Erro create_empresa:', err);
        return res.status(500).json({ error: err.message || 'Falha ao cadastrar empresa.' });
      }
    }

    // 2.2 EDITAR EMPRESA (com proteção da trava de ativação Critério 1)
    if (action === 'update_empresa') {
      const {
        id,
        nome,
        dominio_oficial,
        email_oficial,
        telefone_oficial,
        apelidos_marca,
        dominio_verificado,
        email_verificado,
        telefone_verificado,
        plano,
        status,
        estado,
        motivo
      } = req.body;

      if (!id) {
        return res.status(400).json({ error: 'id da empresa é obrigatório.' });
      }

      let apelidosArray = [];
      if (Array.isArray(apelidos_marca)) {
        apelidosArray = apelidos_marca.map(a => String(a).trim()).filter(Boolean);
      } else if (typeof apelidos_marca === 'string') {
        apelidosArray = apelidos_marca.split(',').map(a => a.trim()).filter(Boolean);
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        const empresaAtual = emps[0] || {};

        const querAtivar = (status === 'ativo' || estado === 'ativo') && empresaAtual.status !== 'ativo' && empresaAtual.estado !== 'ativo';
        if (querAtivar) {
          const validacao = await validarTravaAtivacao4Pilares(url, headers, id);
          if (!validacao.permitido) {
            return res.status(400).json({ error: validacao.error });
          }
        }

        if ((status === 'suspenso' || estado === 'suspenso' || estado === 'revogado') &&
            empresaAtual.status !== 'suspenso' &&
            (!motivo || String(motivo).trim().length < 4)) {
          return res.status(400).json({
            error: 'A alteração para suspenso ou revogado exige obrigatoriamente um motivo escrito.'
          });
        }

        const extras = extrairCamposVerificacao(req.body);
        if (!req.body.marca_aliases && apelidosArray.length > 0) {
          extras.marca_aliases = apelidosArray;
        }

        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
            nome: nome ? nome.trim() : undefined,
            dominio_oficial: dominio_oficial !== undefined ? (dominio_oficial ? dominio_oficial.trim().toLowerCase() : null) : undefined,
            email_oficial: email_oficial !== undefined ? (email_oficial ? email_oficial.trim().toLowerCase() : null) : undefined,
            telefone_oficial: telefone_oficial !== undefined ? (telefone_oficial ? telefone_oficial.trim() : null) : undefined,
            apelidos_marca: apelidosArray,
            dominio_verificado: !!dominio_verificado,
            email_verificado: !!email_verificado,
            telefone_verificado: !!telefone_verificado,
            plano: plano || undefined,
            status: status || undefined,
            ...extras
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());

        await registrarHistorico(url, headers, {
          empresa_id: id,
          acao: 'atualizacao_empresa',
          antes: { nome: empresaAtual.nome, plano: empresaAtual.plano, status: empresaAtual.status, estado: empresaAtual.estado },
          depois: { nome, plano, status, estado },
          por: req.body.por || 'admin',
          motivo: motivo || 'Dados comerciais atualizados no painel'
        });

        return res.status(200).json({ success: true, migracao_pendente: !!updateResp.migracaoPendente });
      } catch (err) {
        console.error('[Admin] Erro update_empresa:', err);
        return res.status(500).json({ error: err.message || 'Falha ao atualizar dados da empresa.' });
      }
    }

    // 2.3 SUSPENDER / REATIVAR EMPRESA (com respeito estrito ao Critério 1)
    if (action === 'set_empresa_status') {
      const { id, status: novoStatus, motivo, por = 'admin' } = req.body;
      if (!id || !novoStatus) {
        return res.status(400).json({ error: 'id e status são obrigatórios.' });
      }

      // Suspender ou revogar exige motivo escrito (Seção 2.3)
      if ((novoStatus === 'suspenso' || novoStatus === 'revogado') && (!motivo || motivo.trim().length < 4)) {
        return res.status(400).json({ error: 'A suspensão de uma empresa exige obrigatoriamente um motivo escrito para arquivo no histórico.' });
      }

      try {
        // Se tentar ativar, exige cumprimento da trava dos 4 pilares + pagamento (Critério 1)
        if (novoStatus === 'ativo') {
          const validacao = await validarTravaAtivacao4Pilares(url, headers, id);
          if (!validacao.permitido) {
            return res.status(400).json({ error: validacao.error });
          }
        }

        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        const empresaAtual = emps[0] || {};

        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
          status: novoStatus,
          estado: novoStatus === 'ativo' ? 'ativo' : (novoStatus === 'suspenso' ? 'suspenso' : (empresaAtual.estado || 'em_verificacao'))
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());

        // Se suspender empresa, desativar selos associados
        if (novoStatus === 'suspenso' || novoStatus === 'revogado' || novoStatus === 'inativo') {
          await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(id)}&ativo=eq.true`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
              ativo: false,
              desativado_em: new Date().toISOString(),
              motivo_desativacao: `Empresa ${novoStatus}: ${motivo || 'Alteração administrativa'}`
            })
          });
        }

        await registrarHistorico(url, headers, {
          empresa_id: id,
          acao: `alterar_status_${novoStatus}`,
          antes: { status: empresaAtual.status, estado: empresaAtual.estado },
          depois: { status: novoStatus },
          por,
          motivo: motivo || `Status alterado para ${novoStatus}`
        });

        return res.status(200).json({ success: true });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao alterar status da empresa: ' + err.message });
      }
    }

    // 2.4 CRIAR SELO (Seção 7 & Prevenção de Duplicados Ativos)
    if (action === 'create_selo') {
      const { empresa_id, valido_ate, monitorizacao_impersonation, is_teste, forcar_duplicado, motivo, por = 'admin' } = req.body;
      if (!empresa_id) {
        return res.status(400).json({ error: 'empresa_id é obrigatório.' });
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresa = emps[0];

        // 1. Verificar selos ativos da mesma empresa
        const selosAtivosResp = await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}&ativo=eq.true&select=*`, { headers });
        const selosAtivos = selosAtivosResp.ok ? await selosAtivosResp.json() : [];

        // 2. Verificar selos ativos para empresas com o mesmo domínio oficial
        let selosMesmoDominio = [];
        if (empresa.dominio_oficial) {
          const domResp = await fetch(`${url}/rest/v1/empresas?dominio_oficial=eq.${encodeURIComponent(empresa.dominio_oficial)}&id=neq.${encodeURIComponent(empresa_id)}&select=id`, { headers });
          const outras = domResp.ok ? await domResp.json() : [];
          if (outras.length > 0) {
            const outIds = outras.map(o => o.id);
            const selosOutResp = await fetch(`${url}/rest/v1/selos?empresa_id=in.(${outIds.join(',')})&ativo=eq.true&select=*`, { headers });
            selosMesmoDominio = selosOutResp.ok ? await selosOutResp.json() : [];
          }
        }

        const temDuplicado = selosAtivos.length > 0 || selosMesmoDominio.length > 0;
        if (temDuplicado && (!forcar_duplicado || !motivo || motivo.trim().length < 4)) {
          return res.status(400).json({
            error: 'Já existe um selo ativo para esta empresa ou domínio. Para criar outro selo ativo, confirme explicitamente com motivo por escrito.',
            requer_confirmacao: true
          });
        }

        // Se for substituição normal (sem forçar múltiplos ativos simultâneos), desativa os anteriores
        if (!forcar_duplicado && selosAtivos.length > 0) {
          await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}&ativo=eq.true`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
              ativo: false,
              desativado_em: new Date().toISOString(),
              motivo_desativacao: motivo || 'Substituído por novo selo'
            })
          });
        }

        const codigoSelo = gerarCodigoSelo();
        const seloIsTeste = is_teste !== undefined ? !!is_teste : !!empresa.is_teste;

        const insertResp = await fetch(`${url}/rest/v1/selos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            codigo: codigoSelo,
            tipo: 'canal_verificado',
            valido_ate: valido_ate || null,
            monitorizacao_impersonation: monitorizacao_impersonation !== false,
            ativo: true,
            is_teste: seloIsTeste
          })
        });

        if (!insertResp.ok) throw new Error(await insertResp.text());
        const rows = await insertResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'criacao_selo',
          depois: { codigo: codigoSelo, is_teste: seloIsTeste, forcar_duplicado: !!forcar_duplicado },
          por,
          motivo: motivo || 'Criação de novo selo'
        });

        return res.status(200).json({ success: true, selo: rows[0] });
      } catch (err) {
        console.error('[Admin] Erro create_selo:', err);
        return res.status(500).json({ error: 'Falha ao criar selo: ' + err.message });
      }
    }

    // 2.5 REGENERAR SELO (Seção 2.3 — Avisa que código anterior deixa de funcionar e regista histórico)
    if (action === 'regenerar_selo') {
      const { selo_id, motivo, por = 'admin' } = req.body;
      if (!selo_id) {
        return res.status(400).json({ error: 'selo_id é obrigatório.' });
      }

      if (!motivo || motivo.trim().length < 3) {
        return res.status(400).json({ error: 'Regenerar o selo exige obrigatoriamente a indicação do motivo por escrito.' });
      }

      try {
        const seloResp = await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}&select=*&limit=1`, { headers });
        if (!seloResp.ok) throw new Error(await seloResp.text());
        const selos = await seloResp.json();
        if (!selos || selos.length === 0) {
          return res.status(404).json({ error: 'Selo não encontrado.' });
        }
        const seloAntigo = selos[0];

        // 2. Desativar/invalidar o selo antigo
        await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            ativo: false,
            desativado_em: new Date().toISOString(),
            motivo_desativacao: `Regenerado pelo admin: ${motivo}`
          })
        });

        // 3. Criar novo registro de selo com novo código
        const novoCodigo = gerarCodigoSelo();
        const insertResp = await fetch(`${url}/rest/v1/selos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id: seloAntigo.empresa_id,
            codigo: novoCodigo,
            tipo: seloAntigo.tipo || 'canal_verificado',
            valido_ate: seloAntigo.valido_ate,
            monitorizacao_impersonation: seloAntigo.monitorizacao_impersonation !== false,
            ativo: true,
            is_teste: !!seloAntigo.is_teste
          })
        });

        if (!insertResp.ok) throw new Error(await insertResp.text());
        const rows = await insertResp.json();

        // 4. Registar no histórico
        await registrarHistorico(url, headers, {
          empresa_id: seloAntigo.empresa_id,
          acao: 'regenerar_selo',
          antes: { codigo: seloAntigo.codigo, id: seloAntigo.id },
          depois: { codigo: novoCodigo, id: rows[0].id },
          por,
          motivo: `Código anterior ${seloAntigo.codigo} revogado e substituído por ${novoCodigo}. Motivo: ${motivo}`
        });

        return res.status(200).json({ success: true, selo: rows[0], codigo_anterior: seloAntigo.codigo });
      } catch (err) {
        console.error('[Admin] Erro regenerar_selo:', err);
        return res.status(500).json({ error: 'Falha ao regenerar código do selo.' });
      }
    }

    // 2.6 SOFT-DELETE / ARQUIVAR SELO (Seção 2.3 — Nunca apaga de facto)
    if (action === 'delete_selo' || action === 'archive_selo') {
      const { selo_id, motivo, por = 'admin' } = req.body;
      if (!selo_id) {
        return res.status(400).json({ error: 'selo_id é obrigatório.' });
      }

      if (!motivo || motivo.trim().length < 3) {
        return res.status(400).json({ error: 'Arquivar o selo exige a indicação de um motivo por escrito.' });
      }

      try {
        const seloResp = await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}&select=*&limit=1`, { headers });
        const selos = seloResp.ok ? await seloResp.json() : [];
        if (!selos.length) return res.status(404).json({ error: 'Selo não encontrado.' });
        const selo = selos[0];

        const agoraIso = new Date().toISOString();
        const updateResp = await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            ativo: false,
            arquivado_em: agoraIso,
            arquivado_motivo: motivo,
            arquivado_por: por,
            desativado_em: agoraIso,
            motivo_desativacao: `Arquivado: ${motivo}`
          })
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());

        await registrarHistorico(url, headers, {
          empresa_id: selo.empresa_id,
          acao: 'arquivar_selo',
          antes: { codigo: selo.codigo, ativo: selo.ativo },
          depois: { ativo: false, arquivado_em: agoraIso },
          por,
          motivo: `Selo arquivado (soft-delete): ${motivo}`
        });

        return res.status(200).json({ success: true, message: 'Selo arquivado com sucesso.' });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao arquivar selo: ' + err.message });
      }
    }

    // 2.6.1 SOFT-DELETE / ARQUIVAR EMPRESA (Seção 2.3 — Nunca apaga de facto)
    if (action === 'delete_empresa' || action === 'archive_empresa') {
      const { empresa_id, motivo, por = 'admin' } = req.body;
      if (!empresa_id) {
        return res.status(400).json({ error: 'empresa_id é obrigatório.' });
      }

      if (!motivo || motivo.trim().length < 3) {
        return res.status(400).json({ error: 'Arquivar a empresa exige a indicação de um motivo por escrito.' });
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresa = emps[0];

        const agoraIso = new Date().toISOString();
        const updateResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            status: 'arquivado',
            estado: 'arquivado',
            arquivado_em: agoraIso,
            arquivado_motivo: motivo,
            arquivado_por: por
          })
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());

        // Desativa selos ativos da empresa arquivada
        await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}&ativo=eq.true`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            ativo: false,
            desativado_em: agoraIso,
            motivo_desativacao: `Empresa arquivada: ${motivo}`
          })
        });

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'arquivar_empresa',
          antes: { status: empresa.status, estado: empresa.estado },
          depois: { status: 'arquivado', arquivado_em: agoraIso },
          por,
          motivo: `Empresa arquivada (soft-delete): ${motivo}`
        });

        return res.status(200).json({ success: true, message: 'Empresa arquivada com sucesso.' });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao arquivar empresa: ' + err.message });
      }
    }

    // 2.7 ATUALIZAR CHECKLIST DE VERIFICAÇÃO (4 Pilares)
    if (action === 'update_verificacao') {
      const { empresa_id, tipo, estado, prova, verificado_por = 'admin' } = req.body;
      if (!empresa_id || !tipo || !estado) {
        return res.status(400).json({ error: 'empresa_id, tipo e estado são obrigatórios.' });
      }
      if (!['nif', 'dominio', 'telefone', 'representante'].includes(tipo)) {
        return res.status(400).json({ error: 'Tipo inválido. Permitidos: nif, dominio, telefone, representante.' });
      }
      if (!['pendente', 'ok', 'falhou'].includes(estado)) {
        return res.status(400).json({ error: 'Estado inválido. Permitidos: pendente, ok, falhou.' });
      }

      try {
        const verifResp = await fetch(`${url}/rest/v1/verificacoes`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'resolution=merge-duplicates,return=representation' },
          body: JSON.stringify({
            empresa_id,
            tipo,
            estado,
            prova: prova ? String(prova).trim() : null,
            verificado_por,
            verificado_em: new Date().toISOString()
          })
        });

        if (!verifResp.ok) throw new Error(await verifResp.text());
        const verifRows = await verifResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: `verificacao_${tipo}`,
          depois: { tipo, estado, prova },
          por: verificado_por,
          motivo: `Checklist ${tipo.toUpperCase()} atualizada para ${estado.toUpperCase()}`
        });

        return res.status(200).json({ success: true, verificacao: verifRows[0] });
      } catch (err) {
        console.error('[Admin] Erro update_verificacao:', err);
        return res.status(500).json({ error: 'Falha ao atualizar verificação: ' + err.message });
      }
    }

    // 2.8 ALTERAR ESTADO DA EMPRESA COM TRAVA ESTRITA DE ATIVAÇÃO (Critério 1)
    if (action === 'set_empresa_estado') {
      const { empresa_id, estado: novoEstado, motivo, por = 'admin' } = req.body;
      if (!empresa_id || !novoEstado) {
        return res.status(400).json({ error: 'empresa_id e estado são obrigatórios.' });
      }

      const estadosValidos = ['lead', 'contactado', 'proposta', 'em_verificacao', 'ativo', 'suspenso', 'revogado', 'expirado'];
      if (!estadosValidos.includes(novoEstado)) {
        return res.status(400).json({ error: `Estado inválido. Permitidos: ${estadosValidos.join(', ')}` });
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresaAtual = emps[0];
        const estadoAnterior = empresaAtual.estado || empresaAtual.status;

        // CRITÉRIO 1 DE ACEITAÇÃO: Não é possível ativar selo sem 4 verificações OK e pagamento (ou isenção justificada)
        if (novoEstado === 'ativo') {
          // A) Checar 4 verificações
          const verifResp = await fetch(`${url}/rest/v1/verificacoes?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
          const verifs = verifResp.ok ? await verifResp.json() : [];
          const tiposOk = new Set(verifs.filter(v => v.estado === 'ok').map(v => v.tipo));
          const obrigatorios = ['nif', 'dominio', 'telefone', 'representante'];
          const faltantes = obrigatorios.filter(t => !tiposOk.has(t));

          if (faltantes.length > 0) {
            return res.status(400).json({
              error: `Bloqueio de ativação: as 4 verificações obrigatórias devem estar OK. Faltam: ${faltantes.join(', ')}.`
            });
          }

          // B) Checar pagamento válido ou isenção justificada
          const pagResp = await fetch(`${url}/rest/v1/pagamentos?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
          const pags = pagResp.ok ? await pagResp.json() : [];
          const temPagamentoValido = pags.some(p => p.estado === 'pago' || (p.estado === 'isento' && p.motivo_isencao && p.motivo_isencao.trim().length >= 4));

          if (!temPagamentoValido) {
            return res.status(400).json({
              error: 'Bloqueio de ativação: é obrigatório registrar pelo menos um pagamento "pago" ou uma isenção com motivo escrito antes de ativar o selo.'
            });
          }
        }

        // Suspensão ou revogação exige motivo escrito obrigatório
        if ((novoEstado === 'suspenso' || novoEstado === 'revogado') && (!motivo || motivo.trim().length < 4)) {
          return res.status(400).json({
            error: `A transição para ${novoEstado} exige obrigatoriamente um motivo escrito para arquivo no histórico de auditoria.`
          });
        }

        let codigoSelo = empresaAtual.codigo_selo;
        if (novoEstado === 'ativo' && !codigoSelo) {
          codigoSelo = gerarCodigoSelo();
        }

        const dataEmissao = novoEstado === 'ativo' ? (empresaAtual.data_emissao || new Date().toISOString()) : empresaAtual.data_emissao;
        let dataValidade = empresaAtual.data_validade;
        if (novoEstado === 'ativo' && !dataValidade) {
          const v = new Date();
          v.setFullYear(v.getFullYear() + 1);
          dataValidade = v.toISOString();
        }

        const patchPayload = {
          estado: novoEstado,
          status: novoEstado === 'ativo' ? 'ativo' : (novoEstado === 'suspenso' ? 'suspenso' : 'inativo'),
          codigo_selo: codigoSelo,
          data_emissao: dataEmissao,
          data_validade: dataValidade
        };

        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, patchPayload);

        if (!updateResp.ok) throw new Error(await updateResp.text());

        // Atualizar selos
        if (novoEstado === 'ativo') {
          await fetch(`${url}/rest/v1/selos`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'resolution=merge-duplicates,return=representation' },
            body: JSON.stringify({
              empresa_id,
              codigo: codigoSelo,
              tipo: 'canal_verificado',
              valido_ate: dataValidade,
              ativo: true
            })
          });
        } else if (novoEstado === 'suspenso' || novoEstado === 'revogado' || novoEstado === 'expirado') {
          await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
              ativo: false,
              desativado_em: new Date().toISOString(),
              motivo_desativacao: motivo || `Empresa em estado ${novoEstado}`
            })
          });
        }

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: `mudanca_estado_${novoEstado}`,
          antes: { estado: estadoAnterior },
          depois: { estado: novoEstado, codigo_selo: codigoSelo },
          por,
          motivo: motivo || `Transição de estado para ${novoEstado}`
        });

        return res.status(200).json({ success: true, estado: novoEstado, codigo_selo: codigoSelo });
      } catch (err) {
        console.error('[Admin] Erro set_empresa_estado:', err);
        return res.status(500).json({ error: 'Falha ao alterar estado: ' + err.message });
      }
    }

    // 2.9 REGISTAR PAGAMENTO (Compatível com periodo_meses/notas do Admin UI e periodo_inicio/fim do banco)
    if (action === 'add_pagamento') {
      const {
        empresa_id,
        valor,
        data,
        metodo,
        referencia,
        fatura_numero,
        periodo_inicio,
        periodo_fim,
        periodo_meses,
        notas,
        estado,
        motivo_isencao
      } = req.body;

      const estadoFinal = estado || (motivo_isencao ? 'isento' : 'pago');
      if (!empresa_id) {
        return res.status(400).json({ error: 'empresa_id é obrigatório.' });
      }
      if (estadoFinal === 'isento' && (!motivo_isencao || String(motivo_isencao).trim().length < 4)) {
        return res.status(400).json({ error: 'A isenção exige obrigatoriamente um motivo justificado por escrito (mínimo 4 caracteres).' });
      }

      let pInicio = periodo_inicio || new Date().toISOString().slice(0, 10);
      let pFim = periodo_fim || null;
      if (!pFim && periodo_meses) {
        const dt = new Date();
        dt.setMonth(dt.getMonth() + (parseInt(periodo_meses, 10) || 12));
        pFim = dt.toISOString().slice(0, 10);
      }

      try {
        const pagResp = await fetch(`${url}/rest/v1/pagamentos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            valor: Number(valor) || 0.00,
            data: data || new Date().toISOString(),
            metodo: metodo || (estadoFinal === 'isento' ? 'isencao' : 'transferencia'),
            referencia: referencia ? String(referencia).trim() : null,
            fatura_numero: fatura_numero ? String(fatura_numero).trim() : (notas ? String(notas).trim() : null),
            periodo_inicio: pInicio,
            periodo_fim: pFim,
            estado: estadoFinal,
            motivo_isencao: motivo_isencao ? String(motivo_isencao).trim() : (notas && estadoFinal === 'isento' ? String(notas).trim() : null)
          })
        });

        if (!pagResp.ok) throw new Error(await pagResp.text());
        const pagRows = await pagResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: estadoFinal === 'isento' ? 'registo_isencao' : 'registo_pagamento',
          depois: { valor: Number(valor) || 0, estado: estadoFinal, metodo, periodo_meses: periodo_meses || 12 },
          motivo: estadoFinal === 'isento'
            ? `Isenção justificada: ${motivo_isencao}`
            : `Pagamento registado: ${estadoFinal} (${Number(valor) || 0}€)`
        });

        return res.status(200).json({ success: true, pagamento: pagRows[0] });
      } catch (err) {
        console.error('[Admin] Erro add_pagamento:', err);
        return res.status(500).json({ error: 'Falha ao registar pagamento: ' + err.message });
      }
    }

    // 2.10 REGISTAR CONTACTO COMERCIAL (Compatível com notas/proximo_passo do UI e resumo/resposta do banco)
    if (action === 'add_contacto_comercial') {
      const { empresa_id, tipo, canal, data, resumo, resposta, notas, proximo_passo, por = 'admin' } = req.body;
      if (!empresa_id) {
        return res.status(400).json({ error: 'empresa_id é obrigatório.' });
      }

      const tipoFinal = tipo || 'seguimento';
      const resumoFinal = (resumo !== undefined ? resumo : notas) || '';
      const respostaFinal = (resposta !== undefined ? resposta : proximo_passo) || null;

      try {
        const contResp = await fetch(`${url}/rest/v1/contactos_comerciais`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            tipo: tipoFinal,
            canal: canal || 'email',
            data: data || new Date().toISOString(),
            resumo: String(resumoFinal).trim(),
            resposta: respostaFinal ? String(respostaFinal).trim() : null
          })
        });

        if (!contResp.ok) throw new Error(await contResp.text());
        const contRows = await contResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'contacto_comercial',
          depois: { canal: canal || 'email', tipo: tipoFinal, resumo: String(resumoFinal).slice(0, 80) },
          por,
          motivo: `Contacto via ${canal || 'email'}: ${String(resumoFinal).slice(0, 60)}`
        });

        return res.status(200).json({
          success: true,
          contacto: {
            ...contRows[0],
            notas: contRows[0]?.resumo || '',
            proximo_passo: contRows[0]?.resposta || '',
            por
          }
        });
      } catch (err) {
        console.error('[Admin] Erro add_contacto_comercial:', err);
        return res.status(500).json({ error: 'Falha ao registar contacto comercial: ' + err.message });
      }
    }

    // 2.11 GERAR ALERTA GRATUITO (Radar -> Empresa)
    if (action === 'gerar_alerta_gratuito') {
      const { empresa_id, marca } = req.body;
      if (!empresa_id && !marca) {
        return res.status(400).json({ error: 'empresa_id ou marca é obrigatório.' });
      }

      try {
        let empresa = null;
        let marcaNome = marca;
        if (empresa_id) {
          const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
          const emps = empResp.ok ? await empResp.json() : [];
          if (emps.length) {
            empresa = emps[0];
            marcaNome = empresa.nome_comercial || empresa.nome;
          }
        }

        const marcasFiltro = empresa?.marca_aliases?.length
          ? [marcaNome, ...empresa.marca_aliases]
          : (empresa?.apelidos_marca?.length ? [marcaNome, ...empresa.apelidos_marca] : [marcaNome]);
        const sinaisResp = await fetch(
          `${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&order=criado_em.desc&limit=100`,
          { headers }
        );
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const sinaisMarca = allSinais.filter(s => {
          const m = (s.marca_mencionada || '').toLowerCase();
          return marcasFiltro.some(al => al && m.includes(al.toLowerCase()));
        });

        const totalSinais = sinaisMarca.length;
        const canais = [...new Set(sinaisMarca.map(s => s.canal || 'SMS/WhatsApp'))].join(', ') || 'SMS / WhatsApp';
        const vetoresDetectados = [...new Set(sinaisMarca.map(s => s.canal_mencionado).filter(Boolean))].slice(0, 3);

        const exemplos = sinaisMarca.slice(0, 3).map(s => {
          const limpo = limparTextoVitima(s.texto_original || s.alerta_link || s.resumo || `Tentativa de fraude (${s.tipo || 'phishing'}) com canal não oficial (${s.canal_mencionado || 'link externo'}).`);
          return limpo.length > 110 ? limpo.slice(0, 107) + '...' : limpo;
        });

        const draftAssunto = `Alerta Preventivo de Segurança: Sinais de personificação da marca ${marcaNome}`;
        const draftCorpo = `Exma. Equipa de Segurança / CSIRT / Comunicação de ${marcaNome},

No âmbito da monitorização contínua do Threat Radar da rede Confirme, Quem É? (confirmequeme.pt), detetámos recentemente ${totalSinais || 1} sinal(is) de mensagens fraudulentas em circulação utilizando o nome da vossa marca antes da consumação de transações.

Resumo da inteligência intercetada:
• Total de ocorrências detetadas: ${totalSinais || 1}
• Canais de propagação: ${canais}
${vetoresDetectados.length ? `• Indicadores / Canais não oficiais (IOCs): ${vetoresDetectados.join(' | ')}\n` : ''}• Exemplos higienizados (Art. 5.º RGPD — zero dados pessoais de cidadãos):
${exemplos.map(e => `  - "${e}"`).join('\n') || '  - "Mensagem simulando comunicação oficial com link ou referência de pagamento externa."'}

Recomendação preventiva:
Sugerimos avaliar a publicação de um aviso preventivo nos vossos canais oficiais e a submissão dos indicadores acima para bloqueio técnico (Takedown / SIBS / CERT.PT).

Nota de integridade e utilidade pública:
Este alerta é estritamente informativo e faz parte da nossa missão de proteção do ecossistema digital português. Caso desejem receber o Dossiê Pericial completo (com Hash SHA-256) ou ativar a monitorização contínua da vossa marca, estamos inteiramente ao dispor.

Atenciosamente,
Equipa de Threat Intelligence & Verificação — Confirme, Quem É?
https://confirmequeme.pt`;

        const draftTextoCompleto = `Assunto: ${draftAssunto}\n\n${draftCorpo}`;

        if (empresa_id) {
          await fetch(`${url}/rest/v1/contactos_comerciais`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              empresa_id,
              tipo: 'alerta_gratuito',
              canal: 'email',
              resumo: `Alerta gratuito gerado com ${totalSinais} sinais detetados`,
              resposta: 'Rascunho preparado para envio executivo'
            })
          });

          await registrarHistorico(url, headers, {
            empresa_id,
            acao: 'geracao_alerta_gratuito',
            depois: { total_sinais: totalSinais, marca: marcaNome },
            motivo: 'Alerta preventivo gratuito gerado pelo operador'
          });
        }

        return res.status(200).json({
          success: true,
          total_sinais: totalSinais,
          alerta_texto: draftTextoCompleto,
          draft: {
            assunto: draftAssunto,
            texto: draftCorpo
          }
        });
      } catch (err) {
        console.error('[Admin] Erro gerar_alerta_gratuito:', err);
        return res.status(500).json({ error: 'Falha ao gerar alerta gratuito: ' + err.message });
      }
    }

    // 2.12 GERAR RELATÓRIO MENSAL EM HTML/PDF (Aceita periodo="YYYY-MM" ou mes + ano)
    if (action === 'gerar_relatorio_mensal') {
      const { empresa_id, mes, ano, versao = '1.0' } = req.body;
      let { periodo } = req.body;
      if (!empresa_id) return res.status(400).json({ error: 'empresa_id é obrigatório.' });

      if (!periodo) {
        const y = ano || new Date().getFullYear();
        const m = mes || (new Date().getMonth() + 1);
        periodo = `${y}-${String(m).padStart(2, '0')}`;
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresa = emps[0];

        const marcaNome = empresa.nome_comercial || empresa.nome;
        const aliases = [...(empresa.marca_aliases || []), ...(empresa.apelidos_marca || [])];
        const allMarcas = [marcaNome, ...aliases].filter(Boolean).map(m => m.toLowerCase());

        const sinaisResp = await fetch(`${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&limit=300`, { headers });
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const ocorrencias = allSinais.filter(s => {
          if (s.empresa_id === empresa_id) return true;
          const m = (s.marca_mencionada || '').toLowerCase();
          return allMarcas.some(al => m.includes(al));
        });

        const usoResp = await fetch(`${url}/rest/v1/uso_selo?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
        const usos = usoResp.ok ? await usoResp.json() : [];
        const metricas = {
          visitas_pagina: usos.reduce((a, b) => a + (b.visitas_pagina || 0), 0),
          verificacoes_widget: usos.reduce((a, b) => a + (b.verificacoes_widget || 0), 0)
        };

        const dadosRelatorio = estruturarRelatorioMensal({
          empresa,
          periodo,
          ocorrencias,
          metricasSelo: metricas,
          versao,
          geradoPor: 'admin'
        });

        const html = renderRelatorioHtml(dadosRelatorio);

        const relInsert = await fetch(`${url}/rest/v1/relatorios_gerados`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            periodo,
            versao,
            hash_ficheiro: dadosRelatorio.hash_sha256,
            gerado_por: 'admin'
          })
        });

        const relRows = relInsert.ok ? await relInsert.json() : [];
        const relNormalizado = relRows[0]
          ? { ...normalizarRelatorioRow(relRows[0]), html }
          : normalizarRelatorioRow({ id: 'temp-' + Date.now(), empresa_id, periodo, versao, hash_ficheiro: dadosRelatorio.hash_sha256, html });

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'geracao_relatorio_mensal',
          depois: { periodo, versao, hash: dadosRelatorio.hash_sha256 },
          motivo: `Relatório mensal pericial gerado para ${periodo}`
        });

        return res.status(200).json({
          success: true,
          relatorio: relNormalizado,
          hash_sha256: dadosRelatorio.hash_sha256,
          dados: dadosRelatorio,
          html
        });
      } catch (err) {
        console.error('[Admin] Erro gerar_relatorio_mensal:', err);
        return res.status(500).json({ error: 'Falha ao compilar relatório mensal: ' + err.message });
      }
    }

    // 2.12.1 OBTER HTML DE RELATÓRIO JÁ GERADO (Para visualização/impressão no histórico)
    if (action === 'obter_relatorio_html') {
      const { relatorio_id } = req.body;
      if (!relatorio_id) return res.status(400).json({ error: 'relatorio_id é obrigatório.' });

      try {
        const relResp = await fetch(`${url}/rest/v1/relatorios_gerados?id=eq.${encodeURIComponent(relatorio_id)}&select=*&limit=1`, { headers });
        const rels = relResp.ok ? await relResp.json() : [];
        if (!rels.length) return res.status(404).json({ error: 'Relatório não encontrado.' });
        const rel = normalizarRelatorioRow(rels[0]);

        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(rel.empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        const empresa = emps[0] || { nome: 'Empresa Registada' };

        const marcaNome = empresa.nome_comercial || empresa.nome;
        const aliases = [...(empresa.marca_aliases || []), ...(empresa.apelidos_marca || [])];
        const allMarcas = [marcaNome, ...aliases].filter(Boolean).map(m => m.toLowerCase());

        const sinaisResp = await fetch(`${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&limit=300`, { headers });
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const ocorrencias = allSinais.filter(s => {
          if (s.empresa_id === rel.empresa_id) return true;
          const m = (s.marca_mencionada || '').toLowerCase();
          return allMarcas.some(al => m.includes(al));
        });

        const usoResp = await fetch(`${url}/rest/v1/uso_selo?empresa_id=eq.${encodeURIComponent(rel.empresa_id)}&select=*`, { headers });
        const usos = usoResp.ok ? await usoResp.json() : [];
        const metricas = {
          visitas_pagina: usos.reduce((a, b) => a + (b.visitas_pagina || 0), 0),
          verificacoes_widget: usos.reduce((a, b) => a + (b.verificacoes_widget || 0), 0)
        };

        const dadosRelatorio = estruturarRelatorioMensal({
          empresa,
          periodo: rel.periodo,
          ocorrencias,
          metricasSelo: metricas,
          versao: rel.versao || '1.0',
          geradoPor: rel.gerado_por || 'admin'
        });
        // Preserva o hash original registado na emissão
        if (rel.hash_ficheiro) {
          dadosRelatorio.hash_sha256 = rel.hash_ficheiro;
        }

        const html = renderRelatorioHtml(dadosRelatorio);
        return res.status(200).json({
          success: true,
          relatorio: { ...rel, html },
          html
        });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao reconstruir HTML do relatório: ' + err.message });
      }
    }

    // 2.13 APROVAÇÃO MANUAL DE RELATÓRIO (Critério 6)
    if (action === 'aprovar_relatorio') {
      const { relatorio_id, aprovado_por = 'admin' } = req.body;
      if (!relatorio_id) return res.status(400).json({ error: 'relatorio_id é obrigatório.' });

      try {
        const patchResp = await fetch(`${url}/rest/v1/relatorios_gerados?id=eq.${encodeURIComponent(relatorio_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            aprovado_por,
            aprovado_em: new Date().toISOString()
          })
        });

        if (!patchResp.ok) throw new Error(await patchResp.text());
        const rows = await patchResp.json();
        const rel = normalizarRelatorioRow(rows[0]);

        if (rel?.empresa_id) {
          await registrarHistorico(url, headers, {
            empresa_id: rel.empresa_id,
            acao: 'aprovacao_relatorio',
            depois: { relatorio_id, periodo: rel.periodo, hash: rel.hash_ficheiro },
            por: aprovado_por,
            motivo: `Relatório mensal ${rel.periodo} aprovado formalmente`
          });
        }

        return res.status(200).json({ success: true, relatorio: rel });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao aprovar relatório.' });
      }
    }

    // 2.14 MARCAR RELATÓRIO COMO ENVIADO AO CLIENTE (Bloqueado se não estiver aprovado — Critério 6)
    if (action === 'marcar_relatorio_enviado') {
      const { relatorio_id, por = 'admin' } = req.body;
      if (!relatorio_id) return res.status(400).json({ error: 'relatorio_id é obrigatório.' });

      try {
        const relResp = await fetch(`${url}/rest/v1/relatorios_gerados?id=eq.${encodeURIComponent(relatorio_id)}&select=*&limit=1`, { headers });
        const rels = relResp.ok ? await relResp.json() : [];
        if (!rels.length) return res.status(404).json({ error: 'Relatório não encontrado.' });
        const relAtual = rels[0];

        if (!relAtual.aprovado_em || !relAtual.aprovado_por) {
          return res.status(400).json({
            error: 'Bloqueio Critério 6: Um relatório mensal NÃO pode ser marcado como enviado sem aprovação manual prévia.'
          });
        }

        const agoraIso = new Date().toISOString();
        const patchResp = await fetch(`${url}/rest/v1/relatorios_gerados?id=eq.${encodeURIComponent(relatorio_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            enviado_em: agoraIso
          })
        });

        if (!patchResp.ok) throw new Error(await patchResp.text());
        const rows = await patchResp.json();
        const rel = normalizarRelatorioRow(rows[0]);

        await registrarHistorico(url, headers, {
          empresa_id: relAtual.empresa_id,
          acao: 'envio_relatorio_mensal',
          depois: { relatorio_id, periodo: relAtual.periodo, enviado_em: agoraIso },
          por,
          motivo: `Relatório ${relAtual.periodo} enviado ao cliente após aprovação`
        });

        return res.status(200).json({ success: true, relatorio: rel });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao registar envio do relatório: ' + err.message });
      }
    }

    // 2.15 CONVERTER MARCA DO RADAR / SOLICITAÇÃO EM LEAD NO PIPELINE B2B (1-Click Onboarding)
    if (action === 'converter_marca_lead') {
      const {
        marca,
        dominio_oficial,
        email_oficial,
        telefone_oficial,
        representante_nome,
        plano = 'radar',
        notas,
        por = 'admin'
      } = req.body;

      if (!marca || !String(marca).trim()) {
        return res.status(400).json({ error: 'O nome da marca é obrigatório para criar a Lead.' });
      }

      try {
        const nomeLimpo = String(marca).trim();
        const precoDefault = plano === 'radar' ? 290.00 : 49.00;

        const empInsert = await fetchComFallback(`${url}/rest/v1/empresas`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
          nome: nomeLimpo,
          nome_comercial: nomeLimpo,
          dominio_oficial: dominio_oficial ? String(dominio_oficial).trim().toLowerCase() : null,
          email_oficial: email_oficial ? String(email_oficial).trim().toLowerCase() : null,
          email_contacto: email_oficial ? String(email_oficial).trim().toLowerCase() : null,
          telefone_oficial: telefone_oficial ? String(telefone_oficial).trim() : null,
          representante_nome: representante_nome ? String(representante_nome).trim() : null,
          apelidos_marca: [nomeLimpo],
          marca_aliases: [nomeLimpo],
          plano,
          preco_acordado: precoDefault,
          estado: 'lead',
          status: 'inativo',
          notas: notas || 'Convertido diretamente a partir do Threat Radar / Solicitações B2B'
        });

        if (!empInsert.ok) throw new Error(await empInsert.text());
        const rows = await empInsert.json();
        const novaEmpresa = rows[0];

        await inicializarQuatroPilares(url, headers, novaEmpresa.id);

        await registrarHistorico(url, headers, {
          empresa_id: novaEmpresa.id,
          acao: 'conversao_radar_lead',
          depois: { nome: nomeLimpo, plano, estado: 'lead' },
          por,
          motivo: 'Marca convertida em Lead no Pipeline B2B a partir do Threat Radar'
        });

        return res.status(200).json({ success: true, empresa: novaEmpresa });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao converter marca em lead: ' + err.message });
      }
    }

    // 2.16 GERAR PACOTE PERICIAL DE TAKEDOWN & NOTIFICAÇÃO DE ABUSO (SIBS / CERT.PT / DECO / Seguradoras)
    if (action === 'gerar_pacote_takedown') {
      const {
        marca = 'Marca Vigiada',
        indicador = '',
        tipo_ioc = 'DOMÍNIO / CANAL',
        tatica_nome = 'Usurpação de Marca',
        ocorrencias_total = 1,
        primeira_deteccao = null,
        ultima_deteccao = null,
        empresa_id = null
      } = req.body;

      try {
        const sinaisResp = await fetch(
          `${url}/rest/v1/analises?veredito=in.(golpe,suspeito)&order=criado_em.desc&limit=100`,
          { headers }
        );
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const marcaLower = String(marca).toLowerCase();
        const indLower = String(indicador).toLowerCase();

        const relacionados = allSinais.filter(s => {
          const m = (s.marca_mencionada || '').toLowerCase();
          const c = (s.canal_mencionado || '').toLowerCase();
          return (marcaLower && m.includes(marcaLower)) || (indLower && c.includes(indLower));
        });

        const exemplosLimpos = relacionados.slice(0, 3).map(s => {
          const txt = limparTextoVitima(
            s.texto_original ||
            s.alerta_link ||
            `Deteção no canal ${s.canal || 'WhatsApp/SMS'} (${s.tipo || 'fraude'}) com indicador ${s.canal_mencionado || indicador} — Score ${s.risco_score || s.confianca || 90}/100.`
          );
          return txt.length > 140 ? txt.slice(0, 137) + '...' : txt;
        });

        const pacote = gerarPacoteTakedown({
          marca,
          indicador: indicador || 'Indicador em análise',
          tipo_ioc,
          tatica_nome,
          ocorrencias_total: Math.max(ocorrencias_total, relacionados.length, 1),
          primeira_deteccao,
          ultima_deteccao,
          exemplos_limpos: exemplosLimpos
        });

        if (empresa_id) {
          await registrarHistorico(url, headers, {
            empresa_id,
            acao: 'geracao_pacote_takedown',
            depois: { indicador, tipo_ioc, hash: pacote.hash_sha256 },
            motivo: `Pacote técnico de Takedown/Abuso gerado para ${indicador}`
          });
        }

        return res.status(200).json({
          success: true,
          pacote
        });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao gerar pacote de takedown: ' + err.message });
      }
    }

    // 2.17 ALTERNAR FLAG DE ENTIDADE DE TESTE (is_teste)
    if (action === 'toggle_empresa_teste') {
      const { empresa_id, is_teste, por = 'admin' } = req.body;
      if (!empresa_id || is_teste === undefined) {
        return res.status(400).json({ error: 'empresa_id e is_teste são obrigatórios.' });
      }

      try {
        const flag = !!is_teste;
        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, { is_teste: flag });

        if (!updateResp.ok) throw new Error(await updateResp.text());

        await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ is_teste: flag })
        });

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: flag ? 'marcar_como_teste' : 'desmarcar_teste',
          depois: { is_teste: flag },
          por,
          motivo: flag ? 'Entidade marcada como ambiente de demonstração/teste' : 'Entidade promovida para registo real de produção'
        });

        return res.status(200).json({ success: true, is_teste: flag });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao alterar modo de teste: ' + err.message });
      }
    }

    // 2.18 MÓDULO GOLPES NOVOS (FASE 1): DECIDIR ITEM DA FILA DE REVISÃO HUMANA (Secção 3.1)
    if (action === 'decidir_fila_revisao') {
      const {
        fila_id: rawFilaId,
        item_id,
        analise_ref,
        decisao,
        revisor = 'admin',
        notas = '',
        resumo_item = null
      } = req.body;
      const fila_id = rawFilaId || item_id;

      if (!fila_id && !analise_ref) {
        return res.status(400).json({ error: 'fila_id ou analise_ref é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let itemBase = (fila_id && mem.fila_revisao.get(fila_id)) ||
          [...mem.fila_revisao.values()].find(i => i.id === fila_id || i.analise_ref === analise_ref);

        if (!itemBase) {
          itemBase = {
            id: fila_id,
            analise_ref: analise_ref || `ref_${Date.now()}`,
            motivo: 'suspeito',
            resumo: resumo_item || {},
            estado: 'novo',
            criado_em: new Date().toISOString()
          };
        }

        const atualizado = aplicarDecisaoHumanaFila({
          item: itemBase,
          decisao,
          revisor,
          notas
        });

        mem.fila_revisao.set(atualizado.id, atualizado);

        // Tenta persistir na tabela fila_revisao do Supabase (upsert ou patch)
        try {
          if (fila_id) {
            const patchRes = await fetch(`${url}/rest/v1/fila_revisao?id=eq.${encodeURIComponent(fila_id)}`, {
              method: 'PATCH',
              headers: { ...headers, Prefer: 'return=representation' },
              body: JSON.stringify({
                estado: 'resolvido',
                decisao: atualizado.decisao,
                revisor: atualizado.revisor,
                notas: atualizado.notas,
                resolvido_em: atualizado.resolvido_em
              })
            });
            const rows = patchRes.ok ? await patchRes.json() : [];
            if (!rows.length) {
              await fetch(`${url}/rest/v1/fila_revisao`, {
                method: 'POST',
                headers: { ...headers, Prefer: 'return=minimal' },
                body: JSON.stringify({
                  id: atualizado.id,
                  analise_ref: atualizado.analise_ref,
                  motivo: atualizado.motivo || 'suspeito',
                  cluster_id: atualizado.cluster_id || null,
                  resumo: atualizado.resumo,
                  estado: 'resolvido',
                  decisao: atualizado.decisao,
                  revisor: atualizado.revisor,
                  notas: atualizado.notas,
                  resolvido_em: atualizado.resolvido_em
                })
              });
            }
          }
        } catch (_dbErr) {}

        // Se a decisão foi 'esquema_novo' e o operador indicou um nome de esquema, cria rascunho na biblioteca de esquemas (Fase 2)
        let esquemaCriado = null;
        if (atualizado.decisao === 'esquema_novo' && req.body.nome_esquema && String(req.body.nome_esquema).trim().length >= 3) {
          const resItem = atualizado.resumo || {};
          esquemaCriado = criarOuAtualizarEsquema({
            nome: req.body.nome_esquema,
            descricao: atualizado.notas || `Esquema identificado a partir da fila de revisão (${resItem.tipo || 'sinais suspeitos'}).`,
            canais: resItem.canal ? [resItem.canal] : ['whatsapp'],
            marcas: (resItem.marca && resItem.marca !== 'Marca não identificada') ? [resItem.marca] : [],
            sinais: Array.isArray(resItem.sinais) ? resItem.sinais : [],
            estado: 'rascunho',
            origem: 'consulta',
            revisto_por: atualizado.revisor
          });
          mem.esquemas.set(esquemaCriado.id, esquemaCriado);
          try {
            await fetch(`${url}/rest/v1/esquemas`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify(esquemaCriado)
            });
          } catch (_eErr) {}
        }

        // Se a decisão foi 'marca_nova' e o operador indicou marca e domínio oficial, cria proposta 'pendente' no dicionário (Fase 3)
        let propostaDicionario = null;
        if (atualizado.decisao === 'marca_nova' && req.body.marca_sugerida && req.body.dominio_sugerido) {
          propostaDicionario = proporAlteracaoDicionario({
            marca: req.body.marca_sugerida,
            dominio_oficial: req.body.dominio_sugerido,
            acao: 'adicionar',
            origem: 'fila_revisao',
            motivo: atualizado.notas || `Proposta criada a partir da fila de revisão (${atualizado.analise_ref})`
          });
          mem.dicionario_alteracoes.set(propostaDicionario.id, propostaDicionario);
          try {
            await fetch(`${url}/rest/v1/dicionario_alteracoes`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify(propostaDicionario)
            });
          } catch (_dErr) {}
        }

        // Regista no histórico de auditoria
        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'decisao_fila_revisao',
          depois: {
            fila_id: atualizado.id,
            analise_ref: atualizado.analise_ref,
            decisao: atualizado.decisao,
            notas: atualizado.notas,
            esquema_rascunho_id: esquemaCriado?.id || null,
            proposta_dicionario_id: propostaDicionario?.id || null
          },
          por: atualizado.revisor,
          motivo: `Decisão na fila de revisão: ${atualizado.decisao} (${atualizado.notas || 'sem nota'})`
        });

        return res.status(200).json({
          success: true,
          item: atualizado,
          esquema: esquemaCriado,
          proposta_dicionario: propostaDicionario
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // 2.19 MÓDULO GOLPES NOVOS (FASE 1): ALTERAR ESTADO DE CLUSTER DE SEMELHANÇA (Secção 3.2)
    // Um cluster nasce como 'possivel_campanha' e SÓ passa a 'ativa', 'encerrada' ou 'descartada' por decisão humana.
    if (action === 'alterar_estado_cluster') {
      const {
        cluster_id,
        fingerprint,
        estado,
        revisor = 'admin',
        notas = ''
      } = req.body;

      if (!cluster_id && !fingerprint) {
        return res.status(400).json({ error: 'cluster_id ou fingerprint é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let clusterBase = (fingerprint && mem.clusters.get(fingerprint)) ||
          [...mem.clusters.values()].find(c => c.id === cluster_id || c.fingerprint === fingerprint);

        if (!clusterBase) {
          clusterBase = {
            id: cluster_id,
            fingerprint: fingerprint || `fp_${Date.now()}`,
            indicadores: {},
            primeira_vez: new Date().toISOString(),
            ultima_vez: new Date().toISOString(),
            contagem: 3,
            contagem_24h: 3,
            estado: 'possivel_campanha'
          };
        }

        const atualizado = aplicarDecisaoHumanaCluster({
          cluster: clusterBase,
          novoEstado: estado,
          revisor,
          notas
        });

        mem.clusters.set(atualizado.fingerprint, atualizado);

        // Persiste na tabela clusters do Supabase se disponível
        try {
          const queryParam = fingerprint
            ? `fingerprint=eq.${encodeURIComponent(fingerprint)}`
            : `id=eq.${encodeURIComponent(cluster_id)}`;
          const patchRes = await fetch(`${url}/rest/v1/clusters?${queryParam}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=representation' },
            body: JSON.stringify({
              estado: atualizado.estado,
              revisor: atualizado.revisor,
              revisto_em: atualizado.revisto_em,
              notas: atualizado.notas
            })
          });
          const rows = patchRes.ok ? await patchRes.json() : [];
          if (!rows.length) {
            await fetch(`${url}/rest/v1/clusters`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify({
                id: atualizado.id,
                fingerprint: atualizado.fingerprint,
                indicadores: atualizado.indicadores || {},
                primeira_vez: atualizado.primeira_vez,
                ultima_vez: atualizado.ultima_vez,
                contagem: atualizado.contagem || 3,
                contagem_24h: atualizado.contagem_24h || 3,
                velocidade_por_hora: atualizado.velocidade_por_hora || 1,
                estado: atualizado.estado,
                revisor: atualizado.revisor,
                revisto_em: atualizado.revisto_em,
                notas: atualizado.notas
              })
            });
          }
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'decisao_cluster_campanha',
          depois: {
            cluster_id: atualizado.id,
            fingerprint: atualizado.fingerprint,
            estado: atualizado.estado,
            notas: atualizado.notas
          },
          por: atualizado.revisor,
          motivo: `Estado do agrupamento alterado para ${atualizado.estado} (${atualizado.notas || 'decisão humana'})`
        });

        return res.status(200).json({
          success: true,
          cluster: atualizado
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // 2.20 MÓDULO GOLPES NOVOS (FASE 1): INGESTAR EVENTO ANONIMIZADO PARA FILA & AGRUPAMENTO
    if (action === 'ingestar_item_fila_revisao') {
      const { evento } = req.body;
      if (!evento || typeof evento !== 'object') {
        return res.status(400).json({ error: 'Objeto evento é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        const clustersAtuais = [...mem.clusters.values()];
        const novosClusters = agruparEventosEmClusters([evento], clustersAtuais);
        for (const c of novosClusters) {
          mem.clusters.set(c.fingerprint, c);
        }

        const item = criarItemFilaRevisao(evento, novosClusters[0] || null);
        if (item) {
          mem.fila_revisao.set(item.id, item);
        }

        return res.status(200).json({
          success: true,
          item,
          clusters: novosClusters
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.21 MÓDULO GOLPES NOVOS (FASE 2): GERIR FONTE DE ALERTA OFICIAL (Secção 3.3)
    // =========================================================================
    if (action === 'gerir_fonte_alerta') {
      const {
        id,
        nome,
        url: fonteUrl,
        tipo = 'autoridade',
        estado = 'ativa',
        notas = ''
      } = req.body;

      if (!nome || !fonteUrl) {
        return res.status(400).json({ error: 'Nome e URL da fonte oficial são obrigatórios.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        const existente = (id && mem.fontes_alerta.get(id)) ||
          [...mem.fontes_alerta.values(), ...FONTES_ALERTA_INICIAIS].find(f => f.id === id || f.url === fonteUrl) || {};

        const fonteObj = {
          id: existente.id || id || (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : `fonte_${Date.now()}`),
          nome: sanitizarCampoAnonimizado(nome),
          url: String(fonteUrl).trim(),
          tipo: ['autoridade', 'marca', 'imprensa'].includes(tipo) ? tipo : 'autoridade',
          ultimo_check: existente.ultimo_check || null,
          ultimo_hash: existente.ultimo_hash || null,
          estado: ['ativa', 'pausada', 'erro'].includes(estado) ? estado : 'ativa',
          ultimo_erro: estado === 'ativa' ? null : (existente.ultimo_erro || null),
          notas: sanitizarCampoAnonimizado(notas),
          criado_em: existente.criado_em || new Date().toISOString()
        };

        mem.fontes_alerta.set(fonteObj.id, fonteObj);

        try {
          const patchRes = await fetch(`${url}/rest/v1/fontes_alerta?id=eq.${encodeURIComponent(fonteObj.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=representation' },
            body: JSON.stringify({
              nome: fonteObj.nome,
              url: fonteObj.url,
              tipo: fonteObj.tipo,
              estado: fonteObj.estado,
              ultimo_erro: fonteObj.ultimo_erro,
              notas: fonteObj.notas
            })
          });
          const rows = patchRes.ok ? await patchRes.json() : [];
          if (!rows.length) {
            await fetch(`${url}/rest/v1/fontes_alerta`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify(fonteObj)
            });
          }
        } catch (_dbErr) {}

        return res.status(200).json({ success: true, fonte: fonteObj });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.22 MÓDULO GOLPES NOVOS (FASE 2): VERIFICAR FONTES DE ALERTA OFICIAL (Secção 3.3)
    // Respeita obrigatoriamente robots.txt, guarda só título, ligação e data, e NUNCA silencia erros.
    // =========================================================================
    if (action === 'verificar_fontes_alerta') {
      const { fonte_id } = req.body || {};

      try {
        const mem = getMemoriaGolpesNovos();
        // Garante que as fontes iniciais estão carregadas
        if (mem.fontes_alerta.size === 0) {
          for (const f of FONTES_ALERTA_INICIAIS) {
            mem.fontes_alerta.set(f.id, { ...f });
          }
        }

        const todasFontes = [...mem.fontes_alerta.values()];
        const fontesAlvo = fonte_id
          ? todasFontes.filter(f => f.id === fonte_id)
          : todasFontes.filter(f => f.estado === 'ativa');

        const resultados = [];
        const novosAlertasTotais = [];

        for (const fonte of fontesAlvo) {
          const resCheck = await verificarFonteAlertaOficial(fonte);
          const fAtu = resCheck.fonteAtualizada;
          mem.fontes_alerta.set(fAtu.id, fAtu);

          // Persiste estado da fonte no Supabase (incluindo ultimo_erro se falhou ou foi bloqueado por robots.txt)
          try {
            const patchRes = await fetch(`${url}/rest/v1/fontes_alerta?id=eq.${encodeURIComponent(fAtu.id)}`, {
              method: 'PATCH',
              headers: { ...headers, Prefer: 'return=representation' },
              body: JSON.stringify({
                ultimo_check: fAtu.ultimo_check,
                ultimo_hash: fAtu.ultimo_hash,
                estado: fAtu.estado,
                ultimo_erro: fAtu.ultimo_erro,
                notas: fAtu.notas
              })
            });
            const rows = patchRes.ok ? await patchRes.json() : [];
            if (!rows.length) {
              await fetch(`${url}/rest/v1/fontes_alerta`, {
                method: 'POST',
                headers: { ...headers, Prefer: 'return=minimal' },
                body: JSON.stringify(fAtu)
              });
            }
          } catch (_dbErr) {}

          // Guarda apenas título, ligação e data dos novos alertas detetados
          for (const al of (resCheck.novosAlertas || [])) {
            // Evita duplicar o mesmo URL de alerta
            const jaExiste = [...mem.alertas_oficiais.values()].some(x => x.url === al.url);
            if (!jaExiste) {
              mem.alertas_oficiais.set(al.id, al);
              novosAlertasTotais.push(al);
              try {
                await fetch(`${url}/rest/v1/alertas_oficiais`, {
                  method: 'POST',
                  headers: { ...headers, Prefer: 'return=minimal' },
                  body: JSON.stringify({
                    id: al.id,
                    fonte_id: al.fonte_id,
                    titulo: al.titulo,
                    url: al.url,
                    data_publicacao: al.data_publicacao,
                    detetado_em: al.detetado_em,
                    estado: 'novo'
                  })
                });
              } catch (_dbErr) {}
            }
          }

          resultados.push({
            fonte_id: fAtu.id,
            nome: fAtu.nome,
            ok: resCheck.ok,
            bloqueado_robots: resCheck.bloqueado_robots,
            erro: resCheck.erro || null,
            novos_alertas: (resCheck.novosAlertas || []).length
          });
        }

        return res.status(200).json({
          success: true,
          resultados,
          novos_alertas: novosAlertasTotais
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.23 MÓDULO GOLPES NOVOS (FASE 2): REVER ALERTA OFICIAL E/OU CRIAR ESQUEMA (Secções 3.3 e 3.4)
    // =========================================================================
    if (action === 'rever_alerta_oficial') {
      const {
        alerta_id,
        estado = 'processado',
        revisor = 'Operador Admin',
        notas = '',
        criar_esquema = false,
        nome_esquema = '',
        descricao_esquema = '',
        canais_esquema = '',
        marcas_esquema = '',
        sinais_esquema = ''
      } = req.body || {};

      if (!alerta_id) {
        return res.status(400).json({ error: 'alerta_id é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let alertaBase = mem.alertas_oficiais.get(alerta_id);
        if (!alertaBase) {
          alertaBase = {
            id: alerta_id,
            titulo: req.body.titulo || 'Alerta Oficial',
            url: req.body.url || '',
            detetado_em: new Date().toISOString(),
            estado: 'novo'
          };
        }

        let esquemaCriado = null;
        if (criar_esquema && nome_esquema && String(nome_esquema).trim().length >= 3) {
          esquemaCriado = criarOuAtualizarEsquema({
            nome: nome_esquema,
            descricao: descricao_esquema || notas || `Esquema registado a partir de alerta oficial (${alertaBase.titulo}).`,
            canais: canais_esquema,
            marcas: marcas_esquema,
            sinais: sinais_esquema,
            estado: 'rascunho',
            origem: 'alerta',
            revisto_por: revisor
          });
          mem.esquemas.set(esquemaCriado.id, esquemaCriado);
          try {
            await fetch(`${url}/rest/v1/esquemas`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify(esquemaCriado)
            });
          } catch (_dbErr) {}
        }

        const alertaAtualizado = reverAlertaOficial(alertaBase, {
          estado,
          revisor,
          notas,
          esquema_id: esquemaCriado ? esquemaCriado.id : (req.body.esquema_id || null)
        });

        mem.alertas_oficiais.set(alertaAtualizado.id, alertaAtualizado);

        try {
          await fetch(`${url}/rest/v1/alertas_oficiais?id=eq.${encodeURIComponent(alertaAtualizado.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify({
              estado: alertaAtualizado.estado,
              esquema_id: alertaAtualizado.esquema_id,
              notas: alertaAtualizado.notas,
              revisor: alertaAtualizado.revisor,
              revisto_em: alertaAtualizado.revisto_em
            })
          });
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'revisao_alerta_oficial',
          depois: {
            alerta_id: alertaAtualizado.id,
            estado: alertaAtualizado.estado,
            esquema_id: alertaAtualizado.esquema_id,
            notas: alertaAtualizado.notas
          },
          por: alertaAtualizado.revisor,
          motivo: `Alerta oficial revisto como ${alertaAtualizado.estado}`
        });

        return res.status(200).json({
          success: true,
          alerta: alertaAtualizado,
          esquema: esquemaCriado
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.24 MÓDULO GOLPES NOVOS (FASE 2): GUARDAR / ALTERAR ESTADO DE ESQUEMA (Secção 3.4)
    // =========================================================================
    if (action === 'guardar_esquema' || action === 'alterar_estado_esquema') {
      const {
        id,
        esquema_id,
        nome,
        descricao,
        canais,
        marcas,
        sinais,
        estado = 'rascunho',
        origem = 'manual',
        revisor = 'Operador Admin'
      } = req.body || {};

      const targetId = id || esquema_id;

      try {
        const mem = getMemoriaGolpesNovos();
        const existente = (targetId && mem.esquemas.get(targetId)) || {};

        const esquemaObj = criarOuAtualizarEsquema({
          id: targetId || existente.id,
          nome: nome !== undefined ? nome : existente.nome,
          descricao: descricao !== undefined ? descricao : existente.descricao,
          canais: canais !== undefined ? canais : existente.canais,
          marcas: marcas !== undefined ? marcas : existente.marcas,
          sinais: sinais !== undefined ? sinais : existente.sinais,
          estado: estado !== undefined ? estado : existente.estado,
          origem: origem || existente.origem || 'manual',
          revisto_por: revisor,
          criado_em: existente.criado_em
        });

        mem.esquemas.set(esquemaObj.id, esquemaObj);

        try {
          const patchRes = await fetch(`${url}/rest/v1/esquemas?id=eq.${encodeURIComponent(esquemaObj.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=representation' },
            body: JSON.stringify({
              nome: esquemaObj.nome,
              descricao: esquemaObj.descricao,
              canais: esquemaObj.canais,
              marcas: esquemaObj.marcas,
              sinais: esquemaObj.sinais,
              estado: esquemaObj.estado,
              origem: esquemaObj.origem,
              revisto_por: esquemaObj.revisto_por,
              revisto_em: esquemaObj.revisto_em
            })
          });
          const rows = patchRes.ok ? await patchRes.json() : [];
          if (!rows.length) {
            await fetch(`${url}/rest/v1/esquemas`, {
              method: 'POST',
              headers: { ...headers, Prefer: 'return=minimal' },
              body: JSON.stringify(esquemaObj)
            });
          }
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'gestao_esquema',
          depois: {
            esquema_id: esquemaObj.id,
            nome: esquemaObj.nome,
            estado: esquemaObj.estado,
            origem: esquemaObj.origem
          },
          por: esquemaObj.revisto_por || revisor,
          motivo: `Esquema "${esquemaObj.nome}" guardado com estado ${esquemaObj.estado}`
        });

        return res.status(200).json({
          success: true,
          esquema: esquemaObj
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.25 MÓDULO GOLPES NOVOS (FASE 3): PROPOR ALTERAÇÃO AO DICIONÁRIO (Secção 3.5)
    // =========================================================================
    if (action === 'propor_dicionario') {
      const {
        marca,
        dominio_oficial,
        acao = 'adicionar',
        origem = 'manual',
        motivo = ''
      } = req.body || {};

      try {
        const mem = getMemoriaGolpesNovos();
        const proposta = proporAlteracaoDicionario({
          marca,
          dominio_oficial,
          acao,
          origem,
          motivo
        });

        mem.dicionario_alteracoes.set(proposta.id, proposta);

        try {
          await fetch(`${url}/rest/v1/dicionario_alteracoes`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify(proposta)
          });
        } catch (_dbErr) {}

        // Proposta 'pendente' NÃO altera o dicionário ativo (Critério 4)
        const dicionarioAtivo = compilarDicionarioAprovado([...mem.dicionario_alteracoes.values()]);

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'proposta_dicionario',
          depois: {
            proposta_id: proposta.id,
            marca: proposta.marca,
            dominio_oficial: proposta.dominio_oficial,
            acao: proposta.acao,
            estado: proposta.estado
          },
          por: 'admin',
          motivo: `Proposta de dicionário (${proposta.acao}: ${proposta.marca} -> ${proposta.dominio_oficial}) registada como pendente`
        });

        return res.status(200).json({
          success: true,
          proposta,
          dicionario_ativo: dicionarioAtivo
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.26 MÓDULO GOLPES NOVOS (FASE 3): APROVAR OU REJEITAR PROPOSTA DO DICIONÁRIO (Secção 3.5)
    // =========================================================================
    if (action === 'decidir_dicionario') {
      const {
        id,
        proposta_id,
        estado,
        aprovado_por = 'Operador Admin',
        motivo
      } = req.body || {};

      const targetId = id || proposta_id;
      if (!targetId) {
        return res.status(400).json({ error: 'O id da proposta do dicionário é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let propostaBase = mem.dicionario_alteracoes.get(targetId);

        if (!propostaBase) {
          try {
            const getRes = await fetch(`${url}/rest/v1/dicionario_alteracoes?id=eq.${encodeURIComponent(targetId)}&select=*`, { headers });
            const rows = getRes.ok ? await getRes.json() : [];
            if (rows.length > 0) propostaBase = rows[0];
          } catch (_e) {}
        }

        if (!propostaBase) {
          propostaBase = {
            id: targetId,
            marca: req.body.marca || 'Marca',
            dominio_oficial: req.body.dominio_oficial || 'dominio.pt',
            acao: req.body.acao || 'adicionar',
            origem: req.body.origem || 'manual',
            estado: 'pendente',
            criado_em: new Date().toISOString()
          };
        }

        const decidida = decidirAlteracaoDicionario(propostaBase, {
          estado,
          aprovado_por,
          motivo
        });

        mem.dicionario_alteracoes.set(decidida.id, decidida);

        try {
          await fetch(`${url}/rest/v1/dicionario_alteracoes?id=eq.${encodeURIComponent(decidida.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify({
              estado: decidida.estado,
              aprovado_por: decidida.aprovado_por,
              aprovado_em: decidida.aprovado_em,
              motivo: decidida.motivo
            })
          });
        } catch (_dbErr) {}

        // Atualiza a cache ativa do scanner apenas com as propostas aprovadas
        let todasAlteracoes = [...mem.dicionario_alteracoes.values()];
        try {
          const dicResp = await fetch(`${url}/rest/v1/dicionario_alteracoes?select=*&order=criado_em.asc&limit=500`, { headers });
          if (dicResp.ok) {
            const dbRows = await dicResp.json();
            const mapComb = new Map();
            for (const r of [...dbRows, ...todasAlteracoes]) {
              if (r && r.id) mapComb.set(r.id, r);
            }
            todasAlteracoes = [...mapComb.values()];
          }
        } catch (_e) {}

        const dicionarioAtivo = compilarDicionarioAprovado(todasAlteracoes);

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: `dicionario_${decidida.estado}`,
          depois: {
            proposta_id: decidida.id,
            marca: decidida.marca,
            dominio_oficial: decidida.dominio_oficial,
            acao: decidida.acao,
            estado: decidida.estado,
            aprovado_por: decidida.aprovado_por,
            aprovado_em: decidida.aprovado_em
          },
          por: decidida.aprovado_por,
          motivo: decidida.motivo || `Alteração de dicionário ${decidida.estado} por ${decidida.aprovado_por}`
        });

        return res.status(200).json({
          success: true,
          proposta: decidida,
          dicionario_ativo: dicionarioAtivo
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.27 MÓDULO GOLPES NOVOS (FASE 3): INTERRUPTOR DE ATIVAÇÃO DO DICIONÁRIO APROVADO
    // =========================================================================
    if (action === 'alternar_interruptor_dicionario') {
      const { ativo, revisor = 'Operador Admin' } = req.body || {};
      const novoEstado = ativo !== undefined ? Boolean(ativo) : !isApprovedDictionaryEnabled();
      setApprovedDictionaryEnabled(novoEstado);

      await registrarHistorico(url, headers, {
        empresa_id: null,
        acao: 'interruptor_dicionario',
        depois: { dicionario_interruptor_ativo: isApprovedDictionaryEnabled() },
        por: revisor,
        motivo: `Interruptor do dicionário aprovado alterado para ${isApprovedDictionaryEnabled() ? 'ATIVO' : 'DESATIVADO (apenas lista inicial)'}`
      });

      return res.status(200).json({
        success: true,
        dicionario_interruptor_ativo: isApprovedDictionaryEnabled()
      });
    }

    // =========================================================================
    // 2.28 MÓDULO GOLPES NOVOS (FASE 4): CRIAR AMOSTRA DE TESTE (Secção 3.6)
    // =========================================================================
    if (action === 'criar_amostra_teste') {
      const {
        semana,
        resumo_ou_texto_anonimizado,
        origem = 'real',
        tipo_real = null,
        classificado_por = null,
        golpe_novo = false,
        uso = 'rotativo'
      } = req.body || {};

      try {
        const mem = getMemoriaGolpesNovos();
        const novaAmostra = criarAmostraTeste({
          semana,
          resumo_ou_texto_anonimizado,
          origem,
          tipo_real,
          classificado_por,
          golpe_novo,
          uso
        });

        mem.amostras_teste.set(novaAmostra.id, novaAmostra);

        try {
          await fetch(`${url}/rest/v1/amostras_teste`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify(novaAmostra)
          });
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'criar_amostra_teste',
          depois: {
            amostra_id: novaAmostra.id,
            semana: novaAmostra.semana,
            origem: novaAmostra.origem,
            tipo_real: novaAmostra.tipo_real,
            golpe_novo: novaAmostra.golpe_novo,
            uso: novaAmostra.uso
          },
          por: novaAmostra.classificado_por || 'admin',
          motivo: `Amostra de teste "${novaAmostra.id}" registada para o conjunto ${novaAmostra.uso}`
        });

        return res.status(200).json({
          success: true,
          amostra: novaAmostra
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.29 MÓDULO GOLPES NOVOS (FASE 4): CLASSIFICAR AMOSTRA POR HUMANO (Secção 3.6 - Critério 5)
    // =========================================================================
    if (action === 'classificar_amostra_teste') {
      const {
        id,
        amostra_id,
        tipo_real,
        classificado_por,
        golpe_novo
      } = req.body || {};

      const targetId = id || amostra_id;
      if (!targetId) {
        return res.status(400).json({ error: 'O id da amostra de teste é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let amostraBase = mem.amostras_teste.get(targetId);

        if (!amostraBase) {
          try {
            const getRes = await fetch(`${url}/rest/v1/amostras_teste?id=eq.${encodeURIComponent(targetId)}&select=*`, { headers });
            const rows = getRes.ok ? await getRes.json() : [];
            if (rows.length > 0) amostraBase = rows[0];
          } catch (_e) {}
        }

        if (!amostraBase) {
          return res.status(404).json({ error: `Amostra de teste "${targetId}" não encontrada.` });
        }

        const amostraClassificada = classificarAmostraTeste(amostraBase, {
          tipo_real,
          classificado_por,
          golpe_novo
        });

        mem.amostras_teste.set(amostraClassificada.id, amostraClassificada);

        try {
          await fetch(`${url}/rest/v1/amostras_teste?id=eq.${encodeURIComponent(amostraClassificada.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify({
              tipo_real: amostraClassificada.tipo_real,
              classificado_por: amostraClassificada.classificado_por,
              classificado_em: amostraClassificada.classificado_em,
              golpe_novo: amostraClassificada.golpe_novo
            })
          });
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'classificar_amostra_teste',
          depois: {
            amostra_id: amostraClassificada.id,
            tipo_real: amostraClassificada.tipo_real,
            golpe_novo: amostraClassificada.golpe_novo,
            classificado_por: amostraClassificada.classificado_por,
            classificado_em: amostraClassificada.classificado_em
          },
          por: amostraClassificada.classificado_por,
          motivo: `Amostra classificada humanamente como ${amostraClassificada.tipo_real} (golpe_novo: ${amostraClassificada.golpe_novo})`
        });

        return res.status(200).json({
          success: true,
          amostra: amostraClassificada
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.30 MÓDULO GOLPES NOVOS (FASE 4): PROMOVER AMOSTRA PARA REGRESSÃO (Secção 3.6)
    // =========================================================================
    if (action === 'promover_amostra_regressao') {
      const {
        id,
        amostra_id,
        revisor = 'Operador Admin'
      } = req.body || {};

      const targetId = id || amostra_id;
      if (!targetId) {
        return res.status(400).json({ error: 'O id da amostra de teste é obrigatório.' });
      }

      try {
        const mem = getMemoriaGolpesNovos();
        let amostraBase = mem.amostras_teste.get(targetId);

        if (!amostraBase) {
          try {
            const getRes = await fetch(`${url}/rest/v1/amostras_teste?id=eq.${encodeURIComponent(targetId)}&select=*`, { headers });
            const rows = getRes.ok ? await getRes.json() : [];
            if (rows.length > 0) amostraBase = rows[0];
          } catch (_e) {}
        }

        if (!amostraBase) {
          return res.status(404).json({ error: `Amostra de teste "${targetId}" não encontrada.` });
        }

        const amostraPromovida = promoverAmostraParaRegressao(amostraBase);
        mem.amostras_teste.set(amostraPromovida.id, amostraPromovida);

        try {
          await fetch(`${url}/rest/v1/amostras_teste?id=eq.${encodeURIComponent(amostraPromovida.id)}`, {
            method: 'PATCH',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify({ uso: 'regressao' })
          });
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'promover_amostra_regressao',
          depois: {
            amostra_id: amostraPromovida.id,
            uso: 'regressao'
          },
          por: revisor,
          motivo: `Amostra promovida para o conjunto de regressão permanente (sai do conjunto rotativo)`
        });

        return res.status(200).json({
          success: true,
          amostra: amostraPromovida
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    }

    // =========================================================================
    // 2.31 MÓDULO GOLPES NOVOS (FASE 4): EXECUTAR BENCHMARK ROTATIVO (Secção 3.6 & Critério 5)
    // =========================================================================
    if (action === 'executar_benchmark_rotativo') {
      const {
        commit = process.env.VERCEL_GIT_COMMIT_SHA || 'local-head',
        revisor = 'Operador Auditor'
      } = req.body || {};

      try {
        const mem = getMemoriaGolpesNovos();

        // 1. Reúne amostras da memória + Supabase + seed inicial
        let amostrasCombinadas = [...mem.amostras_teste.values()];
        try {
          const amResp = await fetch(`${url}/rest/v1/amostras_teste?select=*&order=criado_em.desc&limit=300`, { headers });
          if (amResp.ok) {
            const dbAmostras = await amResp.json();
            const mapComb = new Map();
            for (const a of [...dbAmostras, ...amostrasCombinadas]) {
              if (a && a.id) mapComb.set(a.id, a);
            }
            amostrasCombinadas = [...mapComb.values()];
          }
        } catch (_e) {}

        // Filtra conjunto ativo rotativo
        const amostrasRotativas = amostrasCombinadas.filter(a => a.uso === 'rotativo');

        // CRITÉRIO 5 OBRIGATÓRIO: Bloqueia estritamente a corrida se faltar classificação humana prévia
        validarConjuntoBenchmarkRotativo(amostrasRotativas);

        // Executa o benchmark com intervalos de Wilson (95%), relatório separado de golpes novos e rotulagem estrita
        const relatorio = await executarBenchmarkRotativo(amostrasRotativas, { commit });

        mem.corridas_benchmark.set(relatorio.id, relatorio);

        // Persiste resultado da corrida no Supabase
        try {
          await fetch(`${url}/rest/v1/corridas_benchmark`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'return=minimal' },
            body: JSON.stringify({
              id: relatorio.id,
              data_hora: relatorio.data_hora,
              commit: relatorio.commit,
              hash_dataset: relatorio.hash_dataset,
              modelo: relatorio.modelo,
              amostra_id: `lote_${relatorio.amostras_totais}_amostras`,
              veredito: `${relatorio.acertos}/${relatorio.amostras_totais} (${relatorio.taxa_acerto}%)`,
              pontuacao: parseFloat(relatorio.taxa_acerto) || 0,
              origem_veredito: 'Benchmark Rotativo Fase 4',
              fontes: relatorio.distribuicao_decisoes,
              erro: null
            })
          });
        } catch (_dbErr) {}

        await registrarHistorico(url, headers, {
          empresa_id: null,
          acao: 'execucao_benchmark_rotativo',
          depois: {
            corrida_id: relatorio.id,
            hash_dataset: relatorio.hash_dataset,
            taxa_acerto: relatorio.taxa_acerto,
            intervalo_wilson: relatorio.intervalo_wilson_95,
            golpes_novos_cobertura: relatorio.relatorio_golpes_novos?.taxa_cobertura
          },
          por: revisor,
          motivo: `Executado ${relatorio.rotulagem} com taxa de acerto de ${relatorio.taxa_acerto}% (IC 95% Wilson: ${relatorio.intervalo_wilson_95})`
        });

        return res.status(200).json({
          success: true,
          relatorio
        });
      } catch (err) {
        // Erro nunca silenciado (ex: violação do Critério 5 ou falha do dataset)
        return res.status(400).json({
          error: err.message,
          bloqueado_criterio_5: err.message.includes('humanamente classificada')
        });
      }
    }

    return res.status(400).json({ error: 'Ação não reconhecida.' });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}

