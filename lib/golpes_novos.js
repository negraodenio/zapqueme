// lib/golpes_novos.js
// Módulo de Acompanhamento de Golpes Novos (Fase 1: Fila de Revisão & Agrupamento de Semelhança)
// Regras estritas:
//   - NUNCA guardar o texto bruto das mensagens.
//   - Guardar apenas resumos anonimizados, hashes (fingerprints) e indicadores técnicos não-pessoais.
//   - Um agrupamento com >= 3 ocorrências em 24h entra como 'possivel_campanha' e NUNCA 'ativa' sem decisão humana.
//   - Linguagem estrita em PT-PT: "sinais" e "possível campanha", nunca "burla confirmada" ou "campanha confirmada".

import crypto from 'node:crypto';
import { limparTextoVitima } from './report_generator.js';
import { extrairHostname, extrairIOCsFinanceiros, normalizarTexto } from './radar.js';

// Constante configurável (Secção 3.2): >= 3 ocorrências em 24 h -> estado 'possivel_campanha'
export const LIMIAR_OCORRENCIAS_CAMPANHA_24H = 3;

// Prazos de retenção (Secção 4)
export const POLITICA_RETENCAO = {
  fila_revisao_dias: 90,
  clusters_meses: 12,
  amostras_meses: 12
};

export const MOTIVOS_FILA_VALIDOS = [
  'suspeito',
  'confianca_baixa',
  'ia_vs_regra',
  'feedback_erro',
  'possivel_campanha'
];

export const DECISOES_FILA_VALIDAS = [
  'esquema_novo',
  'marca_nova',
  'falso_alarme',
  'sem_acao'
];

export const ESTADOS_CLUSTER_VALIDOS = [
  'possivel_campanha',
  'ativa',
  'encerrada',
  'descartada'
];

/**
 * Limpa rigorosamente qualquer string para garantir que NENHUM telefone, email,
 * NIF, IBAN, cartão ou número longo pessoal fica armazenado (Critério de Aceitação 1).
 */
export function sanitizarCampoAnonimizado(texto) {
  if (!texto || typeof texto !== 'string') return '';
  let limpo = limparTextoVitima(texto);

  // Remove qualquer sequência numérica longa residual (>= 6 dígitos seguidos ou separados por espaços/pontos/traços)
  limpo = limpo.replace(/\b\d(?:[\s.-]*\d){5,}\b/g, '[NUMERO REMOVIDO]');

  // Remove eventuais menções residuais a códigos OTP / PIN de 6 dígitos
  limpo = limpo.replace(/\b\d{6,}\b/g, '[NUMERO REMOVIDO]');

  return limpo.trim();
}

/**
 * Extrai apenas indicadores técnicos não-pessoais (domínio, entidade MB de 5 dígitos, marca, tipo)
 * garantindo que telefones pessoais, IBANs de vítimas, NIFs e emails pessoais NUNCA são guardados.
 */
export function extrairIndicadoresAnonimizados(entrada = {}) {
  const canalBruto = String(entrada.canal_mencionado || entrada.canal_indicador || entrada.dominio_falso || entrada.dominio || '');
  const alertaBruto = String(entrada.alerta_link || '');
  const iocs = extrairIOCsFinanceiros('', canalBruto, alertaBruto, entrada.tipo || '');

  let dominio = null;
  if (entrada.dominio_falso || entrada.dominio) {
    const hostDireto = extrairHostname(String(entrada.dominio_falso || entrada.dominio));
    if (hostDireto && hostDireto.includes('.') && !hostDireto.includes('@')) {
      dominio = hostDireto;
    }
  }
  if (!dominio && iocs.dominios && iocs.dominios.length > 0) {
    dominio = iocs.dominios[0];
  } else if (!dominio && canalBruto && !canalBruto.includes('@') && canalBruto.includes('.')) {
    const host = extrairHostname(canalBruto);
    if (host && host.includes('.')) dominio = host;
  }

  // Entidade Multibanco (5 dígitos institucionais SIBS — não é dado pessoal)
  let entidade_mb = null;
  if (entrada.entidade_mb && /^\d{5}$/.test(String(entrada.entidade_mb).trim())) {
    entidade_mb = String(entrada.entidade_mb).trim();
  } else if (iocs.entidades_mb && iocs.entidades_mb.length > 0) {
    entidade_mb = iocs.entidades_mb[0];
  }

  // Remetente / marca alegada (sem números de telefone ou emails)
  const marca = sanitizarCampoAnonimizado(entrada.marca_mencionada || entrada.marca || '')
    .replace(/\[.*?REMOVIDO\]/g, '')
    .trim() || null;

  return {
    dominio: dominio || null,
    entidade_mb: entidade_mb || null,
    marca: marca || null,
    tatica: entrada.tatica
      ? sanitizarCampoAnonimizado(String(entrada.tatica))
      : (iocs.tatica_nome || sanitizarCampoAnonimizado(entrada.tipo || 'outro'))
  };
}

/**
 * Gera um hash de semelhança (fingerprint SHA-256) a partir da estrutura da mensagem
 * ou dos seus metadados, SEM NUNCA guardar nem devolver o texto da mensagem (Secção 3.2).
 */
export function gerarFingerprintSemelhanca(entrada = {}) {
  const textoBase = String(
    entrada.texto_normalizado ||
    entrada.texto ||
    entrada.texto_original ||
    ''
  );
  const indicadores = extrairIndicadoresAnonimizados(entrada);

  // Normalização estrutural: remove URLs, emails, IBANs, todos os números e espaços variáveis
  let esqueleto = textoBase
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/https?:\/\/[^\s]+/g, '[link]')
    .replace(/www\.[^\s]+/g, '[link]')
    .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g, '[email]')
    .replace(/\bpt50[\s0-9]{21,30}\b/g, '[iban]')
    .replace(/\d+/g, '[n]')
    .replace(/[^a-z\[\]\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Se a entrada já não trazia texto (ex: registo já anonimizado da tabela analises),
  // usa a combinação estrutural de tipo + marca + domínio + entidade MB + sinais
  if (!esqueleto || esqueleto.length < 6) {
    const sinaisNorm = Array.isArray(entrada.sinais)
      ? entrada.sinais.map(s => normalizarTexto(sanitizarCampoAnonimizado(String(s)))).sort().join('|')
      : '';
    esqueleto = [
      normalizarTexto(entrada.tipo || 'outro'),
      normalizarTexto(indicadores.marca || 'sem_marca'),
      normalizarTexto(indicadores.dominio || 'sem_dominio'),
      normalizarTexto(indicadores.entidade_mb || 'sem_entidade'),
      sinaisNorm.slice(0, 120)
    ].join('::');
  }

  const semente = [
    esqueleto,
    indicadores.dominio || '',
    indicadores.entidade_mb || '',
    normalizarTexto(indicadores.marca || '')
  ].join('||');

  const hashHex = crypto.createHash('sha256').update(semente).digest('hex');
  return {
    fingerprint: `fp_${hashHex.slice(0, 24)}`,
    indicadores
  };
}

/**
 * Gera uma referência opaca (hash SHA-256) para a análise sem guardar conteúdo bruto.
 */
export function gerarAnaliseRef(entrada = {}) {
  if (entrada.analise_ref && typeof entrada.analise_ref === 'string' && entrada.analise_ref.startsWith('ref_')) {
    return entrada.analise_ref;
  }
  const baseId = String(
    entrada.analise_id ||
    entrada.id ||
    `${entrada.criado_em || new Date().toISOString()}_${Math.random()}`
  );
  const hash = crypto.createHash('sha256').update(baseId).digest('hex').slice(0, 20);
  return `ref_${hash}`;
}

/**
 * Constrói o objeto `resumo` estritamente anonimizado para a `fila_revisao` (Secção 3.1 e 4).
 * NUNCA inclui campos de texto bruto (`texto`, `texto_original`, `mensagem`).
 */
export function construirResumoAnonimizado(entrada = {}) {
  const indicadores = extrairIndicadoresAnonimizados(entrada);

  const sinaisBrutos = Array.isArray(entrada.sinais) ? entrada.sinais : [];
  const sinaisLimpos = sinaisBrutos
    .map(s => sanitizarCampoAnonimizado(String(s)))
    .filter(Boolean)
    .slice(0, 5);

  // Se não houver lista de sinais mas houver alerta_link, limpa o alerta_link como sinal técnico
  if (sinaisLimpos.length === 0 && entrada.alerta_link) {
    const alertaLimpo = sanitizarCampoAnonimizado(String(entrada.alerta_link));
    if (alertaLimpo) sinaisLimpos.push(alertaLimpo);
  }

  // Canal apresentado no resumo: apenas domínio ou entidade MB ou tipo de canal, nunca telefone/IBAN/email pessoal
  let canalAnonimizado = indicadores.dominio
    ? indicadores.dominio
    : (indicadores.entidade_mb ? `Entidade MB ${indicadores.entidade_mb}` : sanitizarCampoAnonimizado(String(entrada.canal_mencionado || entrada.canal || 'Não especificado')));

  const veredito = ['golpe', 'suspeito', 'legitimo'].includes(entrada.veredito)
    ? entrada.veredito
    : 'suspeito';

  const pontuacao = entrada.risco_score !== undefined
    ? Number(entrada.risco_score)
    : (entrada.pontuacao !== undefined ? Number(entrada.pontuacao) : ( entrada.confianca !== undefined ? Number(entrada.confianca) : 50 ));

  const confianca = entrada.confianca !== undefined ? Number(entrada.confianca) : pontuacao;

  return {
    tipo: sanitizarCampoAnonimizado(String(entrada.tipo || 'outro')) || 'outro',
    marca: indicadores.marca || 'Não identificada',
    canal: canalAnonimizado || 'Não especificado',
    indicadores: {
      dominio: indicadores.dominio,
      entidade_mb: indicadores.entidade_mb,
      tatica: indicadores.tatica
    },
    sinais: sinaisLimpos,
    veredito,
    pontuacao: Number.isFinite(pontuacao) ? Math.round(pontuacao) : 50,
    confianca: Number.isFinite(confianca) ? Math.round(confianca) : 50,
    origem_veredito: sanitizarCampoAnonimizado(String(entrada.origem_veredito || 'IA')) || 'IA'
  };
}

/**
 * Avalia se uma análise deve entrar automaticamente na `fila_revisao` (Secção 3.1):
 * - veredito 'suspeito'
 * - confiança baixa (< 75)
 * - discordância entre IA e regras ('ia_vs_regra')
 * - resposta 'ERRO' do utilizador ('feedback_erro')
 * - membro de cluster com >= 3 ocorrências em 24h ('possivel_campanha')
 */
export function avaliarMotivosFilaRevisao(entrada = {}, cluster = null) {
  const motivos = [];

  if (entrada.feedback_erro === true || String(entrada.comando_utilizador || '').toLowerCase() === 'erro' || entrada.motivo === 'feedback_erro') {
    motivos.push('feedback_erro');
  }

  // Discordância entre IA e Regra
  const fontes = Array.isArray(entrada.fontes_contributos) ? entrada.fontes_contributos : [];
  const temDiscordanciaExplicita = entrada.divergencia_ia_regra === true ||
    (entrada.veredito_ia && entrada.veredito_regra && entrada.veredito_ia !== entrada.veredito_regra) ||
    (fontes.includes('IA') && fontes.includes('Regra') && entrada.veredito === 'suspeito') ||
    entrada.motivo === 'ia_vs_regra';

  if (temDiscordanciaExplicita) {
    motivos.push('ia_vs_regra');
  }

  // Membro de possível campanha (>= 3 ocorrências em 24h)
  if (
    (cluster && (cluster.contagem_24h >= LIMIAR_OCORRENCIAS_CAMPANHA_24H || cluster.estado === 'possivel_campanha' || cluster.estado === 'ativa')) ||
    Number(entrada.vezes_reportada || 0) >= LIMIAR_OCORRENCIAS_CAMPANHA_24H ||
    entrada.motivo === 'possivel_campanha'
  ) {
    motivos.push('possivel_campanha');
  }

  // Veredito 'suspeito'
  if (entrada.veredito === 'suspeito' || entrada.motivo === 'suspeito') {
    motivos.push('suspeito');
  }

  // Confiança baixa (< 75%)
  const conf = entrada.confianca !== undefined ? Number(entrada.confianca) : 85;
  if ((Number.isFinite(conf) && conf < 75) || entrada.motivo === 'confianca_baixa') {
    motivos.push('confianca_baixa');
  }

  return {
    deve_entrar: motivos.length > 0,
    motivo_principal: motivos[0] || null,
    todos_motivos: motivos
  };
}

/**
 * Processa um lote de eventos/ocorrências num mapa de Clusters (Secção 3.2).
 * Regra crítica (Critério de Aceitação 2):
 *   - >= 3 ocorrências em 24h gera/mantém estado 'possivel_campanha'.
 *   - NUNCA atribui estado 'ativa' automaticamente (só por decisão humana explícita).
 */
export function agruparEventosEmClusters(eventos = [], clustersExistentes = [], opcoes = {}) {
  const opts = typeof opcoes === 'number' ? { agoraMs: opcoes } : (opcoes || {});
  const limiar24h = opts.limiar24h || LIMIAR_OCORRENCIAS_CAMPANHA_24H;
  const agoraMs = opts.agoraMs || Date.now();
  const janela24hMs = 24 * 60 * 60 * 1000;

  const mapa = new Map();

  // Pré-carrega clusters já existentes (preservando decisões humanas: 'ativa', 'encerrada', 'descartada')
  for (const c of (clustersExistentes || [])) {
    if (!c || !c.fingerprint) continue;
    mapa.set(c.fingerprint, {
      id: c.id || crypto.randomUUID(),
      fingerprint: c.fingerprint,
      indicadores: c.indicadores || {},
      primeira_vez: c.primeira_vez || new Date(agoraMs).toISOString(),
      ultima_vez: c.ultima_vez || new Date(agoraMs).toISOString(),
      contagem: Number(c.contagem) || 0,
      contagem_24h: Number(c.contagem_24h) || 0,
      velocidade_por_hora: Number(c.velocidade_por_hora) || 0,
      estado: ESTADOS_CLUSTER_VALIDOS.includes(c.estado) ? c.estado : 'possivel_campanha',
      revisor: c.revisor || null,
      revisto_em: c.revisto_em || null,
      notas: c.notas ? sanitizarCampoAnonimizado(c.notas) : null,
      _timestamps: []
    });
  }

  // Agrupa os novos eventos pelo fingerprint estrutural
  const acumuladorNovos = new Map();
  for (const ev of (eventos || [])) {
    if (!ev) continue;
    const { fingerprint, indicadores } = gerarFingerprintSemelhanca(ev);
    const tsIso = ev.criado_em || ev.data || new Date(agoraMs).toISOString();
    const tsMs = new Date(tsIso).getTime() || agoraMs;
    const peso = Math.max(1, parseInt(ev.vezes_reportada, 10) || 1);

    if (!acumuladorNovos.has(fingerprint)) {
      acumuladorNovos.set(fingerprint, {
        fingerprint,
        indicadores,
        primeira_vez: tsIso,
        ultima_vez: tsIso,
        contagem: 0,
        contagem_24h: 0,
        _timestamps: []
      });
    }

    const grupo = acumuladorNovos.get(fingerprint);
    grupo.contagem += peso;
    if ((agoraMs - tsMs) <= janela24hMs && (agoraMs - tsMs) >= -60000) {
      grupo.contagem_24h += peso;
    }
    for (let i = 0; i < peso; i++) {
      grupo._timestamps.push(tsMs);
    }
    if (tsIso < grupo.primeira_vez) grupo.primeira_vez = tsIso;
    if (tsIso > grupo.ultima_vez) grupo.ultima_vez = tsIso;
    if (!grupo.indicadores.dominio && indicadores.dominio) grupo.indicadores.dominio = indicadores.dominio;
    if (!grupo.indicadores.entidade_mb && indicadores.entidade_mb) grupo.indicadores.entidade_mb = indicadores.entidade_mb;
    if (!grupo.indicadores.marca && indicadores.marca) grupo.indicadores.marca = indicadores.marca;
  }

  for (const [fp, grupo] of acumuladorNovos.entries()) {
    const existente = mapa.get(fp);
    const duracaoHoras = Math.max(
      1,
      (new Date(grupo.ultima_vez).getTime() - new Date(grupo.primeira_vez).getTime()) / (60 * 60 * 1000)
    );
    const velocidade = Number((grupo.contagem_24h / Math.min(24, duracaoHoras)).toFixed(2));

    if (existente) {
      existente.contagem = Math.max(existente.contagem, grupo.contagem);
      existente.contagem_24h = Math.max(existente.contagem_24h, grupo.contagem_24h);
      if (grupo.primeira_vez < existente.primeira_vez) existente.primeira_vez = grupo.primeira_vez;
      if (grupo.ultima_vez > existente.ultima_vez) existente.ultima_vez = grupo.ultima_vez;
      existente.velocidade_por_hora = velocidade;
      existente.indicadores = { ...grupo.indicadores, ...existente.indicadores };
      // NUNCA promove automaticamente para 'ativa': mantém o estado humano se já revisto, ou 'possivel_campanha'
      if (!existente.revisor) {
        existente.estado = 'possivel_campanha';
      }
    } else if (grupo.contagem_24h >= limiar24h || grupo.contagem >= limiar24h) {
      // Critério 2: >= 3 ocorrências em 24h cria cluster SEMPRE com estado 'possivel_campanha'
      mapa.set(fp, {
        id: crypto.randomUUID(),
        fingerprint: fp,
        indicadores: grupo.indicadores,
        primeira_vez: grupo.primeira_vez,
        ultima_vez: grupo.ultima_vez,
        contagem: grupo.contagem,
        contagem_24h: grupo.contagem_24h,
        velocidade_por_hora: velocidade,
        estado: 'possivel_campanha',
        revisor: null,
        revisto_em: null,
        notas: null
      });
    }
  }

  const resultado = [...mapa.values()].map(c => {
    const { _timestamps, ...limpo } = c;
    return limpo;
  });

  return resultado.sort((a, b) => b.contagem_24h - a.contagem_24h || b.contagem - a.contagem);
}

/**
 * Constrói um item de `fila_revisao` validado e 100% livre de texto bruto.
 */
export function criarItemFilaRevisao(entrada = {}, clusterAssociado = null) {
  const avaliacao = avaliarMotivosFilaRevisao(entrada, clusterAssociado);
  if (!avaliacao.deve_entrar) return null;

  const resumo = construirResumoAnonimizado(entrada);
  const analise_ref = gerarAnaliseRef(entrada);
  const agora = new Date();
  const expira = new Date(agora.getTime() + POLITICA_RETENCAO.fila_revisao_dias * 24 * 60 * 60 * 1000);

  return {
    id: entrada.fila_id || crypto.randomUUID(),
    analise_ref,
    motivo: avaliacao.motivo_principal,
    cluster_id: clusterAssociado ? clusterAssociado.id : (entrada.cluster_id || null),
    resumo,
    estado: 'novo',
    decisao: null,
    notas: null,
    revisor: null,
    resolvido_em: null,
    expira_em: expira.toISOString(),
    criado_em: entrada.criado_em || agora.toISOString()
  };
}

/**
 * Aplica uma decisão humana a um item da `fila_revisao` (Secção 3.1).
 * Exige `decisao` válida e `revisor` identificado.
 */
export function aplicarDecisaoHumanaFila(arg1 = {}, arg2 = null) {
  const params = arg2 ? { item: arg1, ...arg2 } : arg1;
  const { item, decisao, revisor, notas = '' } = params;

  if (!item || typeof item !== 'object') {
    throw new Error('Item da fila de revisão inválido.');
  }
  if (!DECISOES_FILA_VALIDAS.includes(decisao)) {
    throw new Error(`Decisão inválida. Valores permitidos: ${DECISOES_FILA_VALIDAS.join(', ')}`);
  }
  if (!revisor || typeof revisor !== 'string' || !revisor.trim()) {
    throw new Error('O identificador do revisor humano é obrigatório.');
  }

  return {
    ...item,
    estado: 'resolvido',
    decisao,
    revisor: revisor.trim(),
    notas: sanitizarCampoAnonimizado(notas),
    resolvido_em: new Date().toISOString()
  };
}

/**
 * Aplica uma decisão humana ao estado de um Cluster (Secção 3.2).
 * Só por esta via um cluster pode passar de 'possivel_campanha' a 'ativa', 'encerrada' ou 'descartada'.
 */
export function aplicarDecisaoHumanaCluster(arg1 = {}, arg2 = null) {
  const params = arg2 ? { cluster: arg1, ...arg2 } : arg1;
  const { cluster, novoEstado, estado, revisor, notas = '' } = params;
  const estadoAlvo = novoEstado || estado;

  if (!cluster || typeof cluster !== 'object') {
    throw new Error('Cluster inválido.');
  }
  if (!ESTADOS_CLUSTER_VALIDOS.includes(estadoAlvo)) {
    throw new Error(`Estado de cluster inválido. Valores permitidos: ${ESTADOS_CLUSTER_VALIDOS.join(', ')}`);
  }
  if (!revisor || typeof revisor !== 'string' || !revisor.trim()) {
    throw new Error('A transição de estado de um cluster exige identificação do revisor humano.');
  }

  return {
    ...cluster,
    estado: estadoAlvo,
    revisor: revisor.trim(),
    notas: sanitizarCampoAnonimizado(notas),
    revisto_em: new Date().toISOString()
  };
}

// Cache em memória resiliente (fallback caso as tabelas do Supabase ainda não tenham sido migradas)
const memoriaEstado = {
  clusters: new Map(),
  fila_revisao: new Map()
};

export function getMemoriaGolpesNovos() {
  return memoriaEstado;
}

/**
 * Regista automaticamente uma resposta "ERRO" de um utilizador do WhatsApp ou Web
 * na `fila_revisao` (sem guardar texto bruto, apenas resumo anonimizado e referência hash).
 */
export async function registarFeedbackErroUtilizador(sessaoOuContrato = {}) {
  const contrato = sessaoOuContrato.contract || sessaoOuContrato || {};
  const entrada = {
    analise_id: sessaoOuContrato.analise_id || contrato.analise_id || crypto.randomUUID(),
    feedback_erro: true,
    comando_utilizador: 'erro',
    veredito: contrato.veredito || (contrato.level === 'high' ? 'golpe' : (contrato.level === 'medium' ? 'suspeito' : 'legitimo')),
    tipo: contrato.category || contrato.tipo || 'outro',
    marca_mencionada: contrato.brand || contrato.marca_mencionada || null,
    canal_mencionado: contrato.domain || contrato.canal_mencionado || null,
    sinais: Array.isArray(contrato.signals) ? contrato.signals : (Array.isArray(contrato.sinais) ? contrato.sinais : []),
    confianca: contrato.confidence || contrato.confianca || 60,
    risco_score: contrato.score || contrato.risco_score || 60,
    origem_veredito: contrato.source || contrato.origem_veredito || 'IA',
    criado_em: new Date().toISOString()
  };

  const itemFila = criarItemFilaRevisao(entrada, null);
  if (!itemFila) return null;

  memoriaEstado.fila_revisao.set(itemFila.id, itemFila);

  const sUrl = process.env.SUPABASE_URL;
  const sKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (sUrl && sKey) {
    try {
      await fetch(`${sUrl}/rest/v1/fila_revisao`, {
        method: 'POST',
        headers: {
          apikey: sKey,
          Authorization: `Bearer ${sKey}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal'
        },
        body: JSON.stringify({
          id: itemFila.id,
          analise_ref: itemFila.analise_ref,
          motivo: 'feedback_erro',
          cluster_id: null,
          resumo: itemFila.resumo,
          estado: 'novo',
          expira_em: itemFila.expira_em
        })
      });
    } catch (_err) {
      // Fail-open para nunca afetar o bot do WhatsApp
    }
  }

  return itemFila;
}

/**
 * Compila e sincroniza a Fila de Revisão e os Clusters a partir dos registos da base de dados
 * e das análises recentes (sem texto bruto).
 */
export function compilarEstadoFase1({
  clustersDb = [],
  filaDb = [],
  analisesRecentes = []
} = {}) {
  // 1. Combina clusters do banco + memória + agrupamento dinâmico das análises recentes
  const clustersBase = [...(clustersDb || []), ...memoriaEstado.clusters.values()];
  const clustersUnicosMap = new Map();
  for (const c of clustersBase) {
    if (c && c.fingerprint) clustersUnicosMap.set(c.fingerprint, c);
  }

  const clusters = agruparEventosEmClusters(analisesRecentes, [...clustersUnicosMap.values()]);
  for (const c of clusters) {
    memoriaEstado.clusters.set(c.fingerprint, c);
  }

  const clusterPorFp = new Map(clusters.map(c => [c.fingerprint, c]));

  // 2. Combina fila de revisão do banco + memória + deteção automática sobre análises recentes
  const filaMap = new Map();
  for (const f of [...memoriaEstado.fila_revisao.values(), ...(filaDb || [])]) {
    if (!f) continue;
    const key = f.analise_ref || f.id;
    // Garante que o resumo está sempre limpo
    const resumoSeguro = f.resumo && typeof f.resumo === 'object'
      ? construirResumoAnonimizado({ ...f.resumo, veredito: f.resumo.veredito, sinais: f.resumo.sinais, marca: f.resumo.marca, canal: f.resumo.canal })
      : construirResumoAnonimizado({});
    filaMap.set(key, {
      ...f,
      resumo: resumoSeguro
    });
  }

  for (const an of (analisesRecentes || [])) {
    if (!an) continue;
    const { fingerprint } = gerarFingerprintSemelhanca(an);
    const clusterAssoc = clusterPorFp.get(fingerprint) || null;
    const ref = gerarAnaliseRef(an);
    if (filaMap.has(ref)) continue;

    const novoItem = criarItemFilaRevisao(an, clusterAssoc);
    if (novoItem) {
      filaMap.set(ref, novoItem);
      memoriaEstado.fila_revisao.set(novoItem.id, novoItem);
    }
  }

  const fila_revisao = [...filaMap.values()].sort((a, b) => {
    // Novos primeiro, depois por data mais recente
    if (a.estado !== b.estado) {
      if (a.estado === 'novo') return -1;
      if (b.estado === 'novo') return 1;
    }
    return new Date(b.criado_em || 0).getTime() - new Date(a.criado_em || 0).getTime();
  });

  const resumo_modulo = {
    fila_pendentes: fila_revisao.filter(f => f.estado !== 'resolvido').length,
    fila_resolvidos: fila_revisao.filter(f => f.estado === 'resolvido').length,
    possiveis_campanhas: clusters.filter(c => c.estado === 'possivel_campanha').length,
    campanhas_ativas: clusters.filter(c => c.estado === 'ativa').length,
    retencao: POLITICA_RETENCAO
  };

  return {
    clusters,
    fila_revisao,
    resumo_modulo
  };
}

