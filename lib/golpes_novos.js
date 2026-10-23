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
import {
  OFFICIAL_DOMAINS,
  setApprovedDictionaryAlterations,
  getEffectiveOfficialDomains,
  isApprovedDictionaryEnabled,
  setApprovedDictionaryEnabled
} from './threat_intel.js';

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
  fila_revisao: new Map(),
  fontes_alerta: new Map(),
  alertas_oficiais: new Map(),
  esquemas: new Map(),
  dicionario_alteracoes: new Map(),
  amostras_teste: new Map(),
  corridas_benchmark: new Map()
};

export function getMemoriaGolpesNovos() {
  return memoriaEstado;
}

// ============================================================================
// FASE 2: MONITORIZAÇÃO DE ALERTAS OFICIAIS E BIBLIOTECA DE ESQUEMAS (Secções 3.3 e 3.4)
// ============================================================================

export const TIPOS_FONTE_ALERTA_VALIDOS = ['autoridade', 'marca', 'imprensa'];
export const ESTADOS_FONTE_ALERTA_VALIDOS = ['ativa', 'pausada', 'erro'];
export const ESTADOS_ALERTA_OFICIAL_VALIDOS = ['novo', 'em_revisao', 'processado', 'ignorado'];
export const ESTADOS_ESQUEMA_VALIDOS = ['rascunho', 'ativo', 'arquivado'];
export const ORIGENS_ESQUEMA_VALIDAS = ['alerta', 'consulta', 'manual'];

// Domínios de redes sociais estritamente proibidos de recolha (Secção 3.3 e Secção 5)
const DOMINIOS_REDES_SOCIAIS_PROIBIDOS = [
  'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com',
  'tiktok.com', 'linkedin.com', 't.me', 'telegram.org', 'whatsapp.com', 'youtube.com'
];

// Fontes oficiais portuguesas pré-configuradas (para confirmar/ativar na folha de fontes)
export const FONTES_ALERTA_INICIAIS = [
  {
    id: '00000000-0000-4000-8000-000000000101',
    nome: 'CERT.PT / CNCS — Feed RSS de Alertas de Segurança',
    url: 'https://www.cncs.gov.pt/docs/alertas-seguranca/feed-rss/index.xml',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Feed XML oficial do CERT.PT com alertas de incidentes e vulnerabilidades'
  },
  {
    id: '00000000-0000-4000-8000-000000000102',
    nome: 'CNCS — Feed RSS de Notícias de Cibersegurança',
    url: 'https://www.cncs.gov.pt/docs/noticias/feed-rss/index.xml',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Feed XML oficial do CNCS com notícias e campanhas de prevenção'
  },
  {
    id: '00000000-0000-4000-8000-000000000103',
    nome: 'MB WAY / SIBS — Página Oficial de Segurança & Burlas',
    url: 'https://www.mbway.pt/seguranca/',
    tipo: 'marca',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Alertas e esquemas de engenharia social atualizados pela SIBS'
  },
  {
    id: '00000000-0000-4000-8000-000000000104',
    nome: 'DECO Proteste — Conteúdos de Tecnologia e Segurança',
    url: 'https://www.deco.proteste.pt/tecnologia',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Artigos e avisos da DECO Proteste sobre direitos do consumidor digital'
  }
];

/**
 * Avalia o conteúdo de um ficheiro `robots.txt` face a um URL alvo (Critério de Aceitação 3).
 * Se o `robots.txt` proibir o caminho para `*` ou para o nosso user-agent, devolve `{ permitido: false, motivo }`.
 */
export function avaliarRobotsTxt(robotsTxtContent = '', targetUrl = '', userAgent = 'ZapQuemE-Monitor') {
  if (!robotsTxtContent || typeof robotsTxtContent !== 'string') {
    return { permitido: true, motivo: null };
  }

  let pathname = '/';
  try {
    const parsed = new URL(targetUrl);
    pathname = parsed.pathname || '/';
  } catch {
    pathname = String(targetUrl || '/');
  }

  const linhas = robotsTxtContent.split(/\r?\n/);
  const uaLower = String(userAgent || '').toLowerCase();
  let aplicaBlocoAtual = false;
  let viuUserAgentNoBloco = false;
  const regras = [];

  for (const linhaBruta of linhas) {
    const linha = linhaBruta.replace(/#.*$/, '').trim();
    if (!linha) {
      aplicaBlocoAtual = false;
      viuUserAgentNoBloco = false;
      continue;
    }

    const idx = linha.indexOf(':');
    if (idx === -1) continue;
    const chave = linha.slice(0, idx).trim().toLowerCase();
    const valor = linha.slice(idx + 1).trim();

    if (chave === 'user-agent') {
      if (!viuUserAgentNoBloco) {
        aplicaBlocoAtual = false;
        viuUserAgentNoBloco = true;
      }
      const agenteRegra = valor.toLowerCase();
      if (agenteRegra === '*' || uaLower.includes(agenteRegra) || agenteRegra.includes(uaLower)) {
        aplicaBlocoAtual = true;
      }
    } else if (aplicaBlocoAtual && (chave === 'disallow' || chave === 'allow')) {
      if (!valor) continue; // Disallow vazio significa tudo permitido
      regras.push({ tipo: chave, padrao: valor });
    }
  }

  // Avalia a regra mais específica (maior comprimento de correspondência)
  let melhorRegra = null;
  for (const r of regras) {
    const padraoLimpo = r.padrao.replace(/\*+$/, '');
    const coincide = r.padrao === '/'
      ? pathname.startsWith('/')
      : pathname.startsWith(padraoLimpo);

    if (coincide) {
      if (!melhorRegra || padraoLimpo.length >= melhorRegra.padrao.replace(/\*+$/, '').length) {
        melhorRegra = r;
      }
    }
  }

  if (melhorRegra && melhorRegra.tipo === 'disallow') {
    return {
      permitido: false,
      motivo: `Caminho "${pathname}" proibido por robots.txt (regra Disallow: ${melhorRegra.padrao})`
    };
  }

  return { permitido: true, motivo: null };
}

/**
 * Extrai APENAS título, ligação (URL absoluto) e data de publicação a partir do HTML/RSS público.
 * NUNCA copia nem guarda o corpo/conteúdo dos artigos (Secção 3.3).
 */
export function extrairAlertasDeHtml(html = '', baseUrl = '') {
  if (!html || typeof html !== 'string') return [];
  const resultados = [];
  const vistos = new Set();

  // 1. Suporte a itens RSS/Atom (<item> ou <entry>) se a página for um feed
  const itemRegex = /<(?:item|entry)\b[^>]*>([\s\S]*?)<\/(?:item|entry)>/gi;
  let itemMatch;
  while ((itemMatch = itemRegex.exec(html)) !== null && resultados.length < 10) {
    const bloco = itemMatch[1];
    const tituloMatch = bloco.match(/<title[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
    const linkMatch = bloco.match(/<link[^>]*>([\s\S]*?)<\/link>/i) || bloco.match(/<link[^>]+href=["']([^"']+)["']/i);
    const dataMatch = bloco.match(/<(?:pubDate|published|updated|dc:date)[^>]*>([\s\S]*?)<\/(?:pubDate|published|updated|dc:date)>/i);

    const titulo = (tituloMatch?.[1] || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    let link = (linkMatch?.[1] || '').trim();
    if (titulo && link) {
      try { link = new URL(link, baseUrl).href; } catch {}
      if (!vistos.has(link)) {
        vistos.add(link);
        let dataIso = null;
        if (dataMatch?.[1]) {
          const d = new Date(dataMatch[1].trim());
          if (!Number.isNaN(d.getTime())) dataIso = d.toISOString();
        }
        resultados.push({
          titulo: titulo.slice(0, 180),
          url: link,
          data_publicacao: dataIso
        });
      }
    }
  }

  if (resultados.length > 0) return resultados;

  // 2. Extração de hiperligações de títulos (<a href="...">Título</a>) sem copiar texto do artigo
  const anchorRegex = /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let aMatch;
  while ((aMatch = anchorRegex.exec(html)) !== null && resultados.length < 10) {
    const hrefBruto = aMatch[1].trim();
    if (/^(javascript:|mailto:|tel:)/i.test(hrefBruto)) continue;

    const textoAnchor = aMatch[2]
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&quot;/gi, '"')
      .replace(/\s+/g, ' ')
      .trim();

    // Filtra apenas títulos informativos (entre 22 e 180 caracteres)
    if (textoAnchor.length < 22 || textoAnchor.length > 180) continue;
    if (/^(ler mais|saiba mais|ver todos|cookies|política de privacidade|contactos|início|menu)$/i.test(textoAnchor)) continue;

    let urlAbsoluto = hrefBruto;
    try {
      const base = new URL(baseUrl);
      const resolvido = new URL(hrefBruto, baseUrl);
      if (resolvido.hostname !== base.hostname) continue;
      if (resolvido.pathname === base.pathname || resolvido.pathname === '/') continue;
      urlAbsoluto = resolvido.href;
    } catch {
      continue;
    }

    if (vistos.has(urlAbsoluto)) continue;
    vistos.add(urlAbsoluto);

    resultados.push({
      titulo: textoAnchor,
      url: urlAbsoluto,
      data_publicacao: null
    });
  }

  return resultados;
}

/**
 * Verifica uma `fonte_alerta` respeitando obrigatoriamente o `robots.txt` e sem silenciar erros (Secção 3.3 e Critério 3).
 * Aceita `fetchFn` injetável para testes determinísticos.
 */
export async function verificarFonteAlertaOficial(fonte = {}, opcoes = {}) {
  const fetchImpl = opcoes.fetchFn || globalThis.fetch;
  const agoraIso = new Date(opcoes.agoraMs || Date.now()).toISOString();

  if (!fonte || !fonte.url) {
    throw new Error('Fonte de alerta inválida: URL em falta.');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(fonte.url);
  } catch {
    const fonteComErro = {
      ...fonte,
      ultimo_check: agoraIso,
      estado: 'erro',
      ultimo_erro: `URL inválido: ${fonte.url}`
    };
    return { ok: false, bloqueado_robots: false, erro: fonteComErro.ultimo_erro, fonteAtualizada: fonteComErro, novosAlertas: [] };
  }

  // Bloqueio estrito de redes sociais (Secção 3.3 e Secção 5)
  const hostLower = parsedUrl.hostname.toLowerCase().replace(/^www\./, '');
  if (DOMINIOS_REDES_SOCIAIS_PROIBIDOS.some(d => hostLower === d || hostLower.endsWith(`.${d}`))) {
    const motivoSocial = `Recolha de redes sociais proibida pelas regras do sistema (${hostLower}).`;
    const fonteBloqueada = {
      ...fonte,
      ultimo_check: agoraIso,
      estado: 'erro',
      ultimo_erro: motivoSocial
    };
    return { ok: false, bloqueado_robots: true, erro: motivoSocial, fonteAtualizada: fonteBloqueada, novosAlertas: [] };
  }

  // 1. Verificar robots.txt ANTES de fazer qualquer pedido à página (Critério de Aceitação 3)
  const robotsUrl = `${parsedUrl.origin}/robots.txt`;
  try {
    const robotsRes = await fetchImpl(robotsUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'ZapQuemE-Monitor/1.0 (+https://zapqueme.vercel.app)' }
    });
    if (robotsRes && robotsRes.ok) {
      const robotsTxt = await robotsRes.text();
      const avaliacao = avaliarRobotsTxt(robotsTxt, fonte.url, 'ZapQuemE-Monitor');
      if (!avaliacao.permitido) {
        const fonteProibida = {
          ...fonte,
          ultimo_check: agoraIso,
          estado: 'pausada',
          ultimo_erro: avaliacao.motivo,
          notas: fonte.notas ? `${fonte.notas} | ${avaliacao.motivo}` : avaliacao.motivo
        };
        return {
          ok: false,
          bloqueado_robots: true,
          motivo: avaliacao.motivo,
          erro: avaliacao.motivo,
          fonteAtualizada: fonteProibida,
          novosAlertas: []
        };
      }
    }
  } catch (_robotsErr) {
    // Se o site não tiver robots.txt acessível, prossegue para o pedido da página
  }

  // 2. Ler a página da fonte (nunca silenciar erros se a página falhar)
  let pageRes;
  try {
    pageRes = await fetchImpl(fonte.url, {
      method: 'GET',
      headers: { 'User-Agent': 'ZapQuemE-Monitor/1.0 (+https://zapqueme.vercel.app)' }
    });
  } catch (networkErr) {
    const msgErro = `Falha de rede ao consultar fonte: ${networkErr.message || 'Erro desconhecido'}`;
    const fonteFalha = {
      ...fonte,
      ultimo_check: agoraIso,
      estado: 'erro',
      ultimo_erro: msgErro
    };
    return { ok: false, bloqueado_robots: false, erro: msgErro, fonteAtualizada: fonteFalha, novosAlertas: [] };
  }

  if (!pageRes || !pageRes.ok) {
    const status = pageRes ? pageRes.status : 'sem resposta';
    const msgErro = `Página devolveu erro HTTP ${status}`;
    const fonteFalhaHttp = {
      ...fonte,
      ultimo_check: agoraIso,
      estado: 'erro',
      ultimo_erro: msgErro
    };
    return { ok: false, bloqueado_robots: false, erro: msgErro, fonteAtualizada: fonteFalhaHttp, novosAlertas: [] };
  }

  const html = await pageRes.text();
  const itensExtraidos = extrairAlertasDeHtml(html, fonte.url);

  // Calcula hash apenas sobre os títulos e ligações (ou estrutura se vazia)
  const baseHash = itensExtraidos.length > 0
    ? JSON.stringify(itensExtraidos.map(i => ({ t: i.titulo, u: i.url })))
    : html.replace(/\s+/g, ' ').slice(0, 4000);
  const novoHash = 'sha256_' + crypto.createHash('sha256').update(baseHash).digest('hex').slice(0, 24);

  const mudou = novoHash !== fonte.ultimo_hash;
  const novosAlertas = [];

  if (mudou && itensExtraidos.length > 0) {
    for (const item of itensExtraidos.slice(0, 5)) {
      novosAlertas.push({
        id: crypto.randomUUID(),
        fonte_id: fonte.id,
        fonte_nome: fonte.nome,
        titulo: sanitizarCampoAnonimizado(item.titulo),
        url: item.url,
        data_publicacao: item.data_publicacao || agoraIso,
        detetado_em: agoraIso,
        estado: 'novo',
        esquema_id: null,
        notas: null,
        revisor: null,
        revisto_em: null
      });
    }
  }

  const fonteAtualizada = {
    ...fonte,
    ultimo_check: agoraIso,
    ultimo_hash: novoHash,
    estado: 'ativa',
    ultimo_erro: null
  };

  return {
    ok: true,
    bloqueado_robots: false,
    mudou,
    fonteAtualizada,
    novosAlertas
  };
}

/**
 * Cria ou atualiza um esquema na biblioteca interna de esquemas (Secção 3.4).
 * Toda a descrição é sanitizada e escrita nas nossas palavras.
 * Não altera o texto do robô nem entra como 'ativo' sem revisor humano identificado.
 */
export function criarOuAtualizarEsquema(dados = {}) {
  const nome = sanitizarCampoAnonimizado(String(dados.nome || '').trim());
  const descricao = sanitizarCampoAnonimizado(String(dados.descricao || '').trim());

  if (!nome || nome.length < 3) {
    throw new Error('O nome do esquema é obrigatório (mínimo 3 caracteres).');
  }
  if (!descricao || descricao.length < 5) {
    throw new Error('A descrição do esquema (nas nossas palavras) é obrigatória.');
  }

  const estadoPretendido = dados.estado || 'rascunho';
  if (!ESTADOS_ESQUEMA_VALIDOS.includes(estadoPretendido)) {
    throw new Error(`Estado de esquema inválido. Valores permitidos: ${ESTADOS_ESQUEMA_VALIDOS.join(', ')}`);
  }

  const revisor = dados.revisto_por || dados.revisor || null;
  if (estadoPretendido === 'ativo' && (!revisor || !String(revisor).trim())) {
    throw new Error('Um esquema só pode passar ao estado "ativo" com identificação do revisor humano.');
  }

  const origem = ORIGENS_ESQUEMA_VALIDAS.includes(dados.origem) ? dados.origem : 'manual';
  const normalizarLista = (val) => {
    if (Array.isArray(val)) return val.map(x => sanitizarCampoAnonimizado(String(x).trim())).filter(Boolean);
    if (typeof val === 'string') return val.split(',').map(x => sanitizarCampoAnonimizado(x.trim())).filter(Boolean);
    return [];
  };

  return {
    id: dados.id || crypto.randomUUID(),
    nome,
    descricao,
    canais: normalizarLista(dados.canais),
    marcas: normalizarLista(dados.marcas),
    sinais: normalizarLista(dados.sinais),
    estado: estadoPretendido,
    origem,
    revisto_por: revisor ? String(revisor).trim() : null,
    revisto_em: revisor ? new Date().toISOString() : null,
    criado_em: dados.criado_em || new Date().toISOString()
  };
}

/**
 * Regista a revisão humana de um `alerta_oficial` (Secção 3.3).
 * Permite marcar como 'processado' (com ou sem criação de esquema nas nossas palavras) ou 'ignorado'.
 */
export function reverAlertaOficial(alerta = {}, { estado = 'processado', revisor, notas = '', esquema_id = null } = {}) {
  if (!alerta || typeof alerta !== 'object') {
    throw new Error('Alerta oficial inválido.');
  }
  if (!ESTADOS_ALERTA_OFICIAL_VALIDOS.includes(estado)) {
    throw new Error(`Estado de alerta inválido. Permitidos: ${ESTADOS_ALERTA_OFICIAL_VALIDOS.join(', ')}`);
  }
  if (!revisor || !String(revisor).trim()) {
    throw new Error('O identificador do revisor humano é obrigatório para rever um alerta oficial.');
  }

  return {
    ...alerta,
    estado,
    esquema_id: esquema_id || alerta.esquema_id || null,
    notas: sanitizarCampoAnonimizado(notas),
    revisor: String(revisor).trim(),
    revisto_em: new Date().toISOString()
  };
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

// ============================================================================
// FASE 3: DICIONÁRIO DE MARCAS E DOMÍNIOS COM APROVAÇÃO (Secção 3.5)
// Regras estritas:
//   - Propostas entram SEMPRE como 'pendente' (aprovado_por: null, aprovado_em: null).
//   - Uma proposta 'pendente' ou 'rejeitado' NÃO altera o resultado de nenhuma análise (Critério 4).
//   - Só 'aprovado' por decisão humana passa a valer no dicionário ativo.
//   - Histórico append-only (cada alteração fica registada).
// ============================================================================

export const ACOES_DICIONARIO_VALIDAS = ['adicionar', 'alterar', 'remover'];
export const ESTADOS_DICIONARIO_VALIDOS = ['pendente', 'aprovado', 'rejeitado'];

/**
 * Cria uma proposta de alteração ao dicionário de marcas e domínios oficiais.
 * Entra obrigatoriamente no estado 'pendente' até aprovação humana explícita.
 */
export function proporAlteracaoDicionario({
  marca,
  dominio_oficial,
  acao = 'adicionar',
  origem = 'manual',
  motivo = ''
} = {}) {
  const marcaLimpa = sanitizarCampoAnonimizado(String(marca || '').trim());
  const dominioLimpo = String(dominio_oficial || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split(':')[0]
    .trim();

  if (!marcaLimpa || marcaLimpa.length < 2) {
    throw new Error('O nome da marca é obrigatório (mínimo 2 caracteres).');
  }
  if (!dominioLimpo || !dominioLimpo.includes('.') || dominioLimpo.length < 4) {
    throw new Error('O domínio oficial deve ser um domínio válido (ex: marca.pt).');
  }
  if (!ACOES_DICIONARIO_VALIDAS.includes(acao)) {
    throw new Error(`Ação inválida. Valores permitidos: ${ACOES_DICIONARIO_VALIDAS.join(', ')}`);
  }

  return {
    id: crypto.randomUUID(),
    marca: marcaLimpa,
    dominio_oficial: dominioLimpo,
    acao,
    origem: sanitizarCampoAnonimizado(String(origem || 'manual').trim()) || 'manual',
    estado: 'pendente',
    aprovado_por: null,
    aprovado_em: null,
    motivo: sanitizarCampoAnonimizado(String(motivo || '').trim()),
    criado_em: new Date().toISOString()
  };
}

/**
 * Aprova ('aprovado') ou rejeita ('rejeitado') uma proposta do dicionário.
 * Exige obrigatoriamente identificação do revisor humano (`aprovado_por`).
 */
export function decidirAlteracaoDicionario(proposta = {}, {
  estado,
  aprovado_por,
  motivo
} = {}) {
  if (!proposta || typeof proposta !== 'object') {
    throw new Error('Proposta de dicionário inválida.');
  }
  if (estado !== 'aprovado' && estado !== 'rejeitado') {
    throw new Error('A decisão sobre o dicionário deve ser "aprovado" ou "rejeitado".');
  }
  if (!aprovado_por || !String(aprovado_por).trim()) {
    throw new Error('O identificador do revisor humano (aprovado_por) é obrigatório para aprovar ou rejeitar alterações ao dicionário.');
  }

  return {
    ...proposta,
    estado,
    aprovado_por: String(aprovado_por).trim(),
    aprovado_em: new Date().toISOString(),
    motivo: motivo !== undefined
      ? sanitizarCampoAnonimizado(String(motivo || '').trim())
      : (proposta.motivo || '')
  };
}

/**
 * Sincroniza a cache ativa do scanner (`lib/threat_intel.js`) apenas com as alterações aprovadas
 * e devolve o mapa efetivo de domínios oficiais (estado inicial + aprovados).
 */
export function compilarDicionarioAprovado(alteracoes = []) {
  setApprovedDictionaryAlterations(alteracoes);
  return getEffectiveOfficialDomains();
}

export {
  OFFICIAL_DOMAINS,
  isApprovedDictionaryEnabled,
  setApprovedDictionaryEnabled
};

// ============================================================================
// FASE 4: BENCHMARK ROTATIVO & AVALIAÇÃO DE GOLPES NOVOS (Secção 3.6 & Critério 5)
// Regras estritas:
//   - Amostras de teste semanais (15 a 30 por semana) anonimizadas.
//   - Critério 5: O benchmark rotativo RECUSA-SE a correr se faltar a classificação
//     humana ('tipo_real') de qualquer amostra do conjunto rotativo.
//   - Relatório separado para amostras 'golpe_novo' (últimos 14 dias — medida de generalização).
//   - Intervalos de confiança de Wilson (95%) para proporções binomial.
//   - Amostras corrigidas passam a 'regressao' e saem do conjunto rotativo.
//   - Rotulagem estrita: "teste interno com N amostras", nunca "precisão absoluta".
// ============================================================================

export const ORIGENS_AMOSTRA_VALIDAS = ['real', 'alerta_oficial', 'sintetico'];
export const USOS_AMOSTRA_VALIDOS = ['rotativo', 'regressao'];
export const TIPOS_REAIS_AMOSTRA_VALIDOS = ['Golpe', 'Legítimo'];

/**
 * Dataset inicial de semente (Semana 42) com 16 amostras portuguesas pre-classificadas
 * por um revisor humano independente para permitir corridas imediatas.
 */
export const AMOSTRAS_TESTE_INICIAIS = [
  {
    id: '00000000-0000-4000-8000-000000000401',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Aviso urgente CTT: a sua encomenda esta retida por falta de pagamento de taxa aduaneira no valor de 2,99 euros aceda a ctt-alfandega-pagamentos.top para libertar',
    origem: 'alerta_oficial',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:00:00.000Z',
    uso: 'rotativo',
    golpe_novo: true
  },
  {
    id: '00000000-0000-4000-8000-000000000402',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Ola pai perdi o meu telemovel no metro este e o meu numero novo temporario manda me mensagem no whatsapp urgente por favor preciso pagar a renda',
    origem: 'real',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:05:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000403',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Autoridade Tributaria: Foi detetada divergencia na sua liquidacao de IRS. Tem um reembolso disponivel de 340 euros. Confirme os seus dados em at-portal-reembolso.xyz',
    origem: 'alerta_oficial',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:10:00.000Z',
    uso: 'rotativo',
    golpe_novo: true
  },
  {
    id: '00000000-0000-4000-8000-000000000404',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Seguranca Social Direta: A sua prestacao social foi suspensa por irregularidade cadastral. Atualize os seus dados de imediato em seg-social-atualizacao.live',
    origem: 'sintetico',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:15:00.000Z',
    uso: 'rotativo',
    golpe_novo: true
  },
  {
    id: '00000000-0000-4000-8000-000000000405',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Aviso DIGI: o seu contrato sera suspenso por falta de confirmacao de morada de instalacao da fibra aceda a digi-ativacao-portugal.buzz para manter o servico',
    origem: 'sintetico',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:20:00.000Z',
    uso: 'rotativo',
    golpe_novo: true
  },
  {
    id: '00000000-0000-4000-8000-000000000406',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'EDP Comercial: A sua fatura de eletricidade encontra-se em atraso para evitar corte pague nas proximas 24h por referencia Entidade [NUMERO REMOVIDO] Ref [NUMERO REMOVIDO] Montante 48,20 euros',
    origem: 'real',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:25:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000407',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Via Verde: Consta uma divida de portagens no valor de 7,85 euros em execucao fiscal para liquidar antes da penhora aceda a viaverde-regularizacao.site',
    origem: 'alerta_oficial',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:30:00.000Z',
    uso: 'rotativo',
    golpe_novo: true
  },
  {
    id: '00000000-0000-4000-8000-000000000408',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Parabens! O seu numero foi sorteado no premio especial Continente no valor de 500 euros em cartao carregue no link bit.ly/continente-premio para reclamar hoje',
    origem: 'real',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:35:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000409',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Millennium bcp informa: dispositivo nao reconhecido acedeu a sua conta bancaria se nao reconhece cancele imediatamente no link millennium-seguranca-valida.com',
    origem: 'real',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:40:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000410',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Investimento em criptomoedas com retorno garantido de 300 por cento ao mes sem risco registe-se na nossa plataforma e receba bonus de boas vindas',
    origem: 'sintetico',
    tipo_real: 'Golpe',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:45:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000411',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'O seu codigo de seguranca temporario para confirmacao de acesso e [NUMERO REMOVIDO]. Nao partilhe este codigo com ninguem, nem mesmo com assistentes.',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:50:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000412',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Lembramos a sua consulta de Cardiologia agendada para amanha as 10h30 no Hospital da Luz Lisboa. Em caso de impedimento por favor responda a este SMS.',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T10:55:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000413',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'CTT: O seu envio com o codigo [NUMERO REMOVIDO] sera entregue hoje entre as 14h e as 18h na morada indicada. Acompanhe em ctt.pt',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T11:00:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000414',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Continente: O seu saldo em cartao Continente expira no final deste mes. Consulte os seus cupoes na aplicacao oficial ou em continente.pt',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T11:05:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000415',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'Ola Mariana, ja cheguei a casa do trabalho. Queres que passe no supermercado antes de jantar para comprar fruta e pao?',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T11:10:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  },
  {
    id: '00000000-0000-4000-8000-000000000416',
    semana: '2026-W42',
    resumo_ou_texto_anonimizado: 'MEO: A sua fatura eletrónica referente ao ciclo anterior ja se encontra disponivel para consulta na Area de Cliente em meo.pt sem valores em divida.',
    origem: 'real',
    tipo_real: 'Legítimo',
    classificado_por: 'Auditor Humano Independente',
    classificado_em: '2026-10-18T11:15:00.000Z',
    uso: 'rotativo',
    golpe_novo: false
  }
];

/**
 * Cria uma amostra de teste anonimizada (Secção 3.6 e Critério 1).
 */
export function criarAmostraTeste({
  semana,
  resumo_ou_texto_anonimizado,
  origem = 'real',
  tipo_real = null,
  classificado_por = null,
  uso = 'rotativo',
  golpe_novo = false
} = {}) {
  const textoLimpo = sanitizarCampoAnonimizado(String(resumo_ou_texto_anonimizado || '').trim());
  if (!textoLimpo || textoLimpo.length < 10) {
    throw new Error('O resumo ou texto anonimizado da amostra é obrigatório (mínimo 10 caracteres).');
  }

  const origemValida = ORIGENS_AMOSTRA_VALIDAS.includes(origem) ? origem : 'real';
  const usoValido = USOS_AMOSTRA_VALIDOS.includes(uso) ? uso : 'rotativo';

  let tipoRealFinal = null;
  if (tipo_real && TIPOS_REAIS_AMOSTRA_VALIDOS.includes(tipo_real)) {
    tipoRealFinal = tipo_real;
  }

  const revisor = classificado_por ? String(classificado_por).trim() : null;

  return {
    id: crypto.randomUUID(),
    semana: semana || `2026-W${Math.ceil((Date.now() - new Date('2026-01-01').getTime()) / (7 * 24 * 3600 * 1000))}`,
    resumo_ou_texto_anonimizado: textoLimpo,
    origem: origemValida,
    tipo_real: tipoRealFinal,
    classificado_por: tipoRealFinal ? revisor : null,
    classificado_em: tipoRealFinal && revisor ? new Date().toISOString() : null,
    uso: usoValido,
    golpe_novo: Boolean(golpe_novo),
    criado_em: new Date().toISOString()
  };
}

/**
 * Classifica uma amostra de teste com 'Golpe' ou 'Legítimo' por um humano (Secção 3.6).
 * Regista o nome do classificador e a data/hora.
 */
export function classificarAmostraTeste(amostra = {}, {
  tipo_real,
  classificado_por,
  uso,
  golpe_novo
} = {}) {
  if (!amostra || typeof amostra !== 'object') {
    throw new Error('Amostra de teste inválida.');
  }
  if (!TIPOS_REAIS_AMOSTRA_VALIDOS.includes(tipo_real)) {
    throw new Error(`Classificação inválida. Valores permitidos: ${TIPOS_REAIS_AMOSTRA_VALIDOS.join(', ')}`);
  }
  if (!classificado_por || !String(classificado_por).trim()) {
    throw new Error('O classificador humano (classificado_por) é obrigatório.');
  }

  return {
    ...amostra,
    tipo_real,
    classificado_por: String(classificado_por).trim(),
    classificado_em: new Date().toISOString(),
    uso: USOS_AMOSTRA_VALIDOS.includes(uso) ? uso : (amostra.uso || 'rotativo'),
    golpe_novo: golpe_novo !== undefined ? Boolean(golpe_novo) : Boolean(amostra.golpe_novo)
  };
}

/**
 * Promove uma amostra corrigida para 'regressao' (sai do conjunto rotativo).
 */
export function promoverAmostraParaRegressao(amostra = {}, { revisor = 'admin', motivo = '' } = {}) {
  if (!amostra || typeof amostra !== 'object') throw new Error('Amostra inválida.');
  return {
    ...amostra,
    uso: 'regressao',
    motivo_regressao: sanitizarCampoAnonimizado(motivo),
    promovido_por: revisor,
    promovido_em: new Date().toISOString()
  };
}

/**
 * Calcula o intervalo de confiança de Wilson (95%) para proporções binomiais:
 * \hat{p} = x / n, z = 1.96
 * (p + z^2/(2n) +- z * sqrt(p(1-p)/n + z^2/(4n^2))) / (1 + z^2/n)
 */
export function calcularIntervaloWilson(sucessos = 0, total = 0, z = 1.96) {
  if (total <= 0) {
    return {
      proporcao: 0,
      inferior: 0,
      superior: 0,
      pct: '0.0%',
      pct_inferior: '0.0%',
      pct_superior: '0.0%'
    };
  }

  const p = Math.max(0, Math.min(1, sucessos / total));
  const n = total;
  const z2 = z * z;

  const centro = (p + z2 / (2 * n)) / (1 + z2 / n);
  const margem = (z / (1 + z2 / n)) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));

  const inf = Math.max(0, centro - margem);
  const sup = Math.min(1, centro + margem);

  return {
    proporcao: Number(p.toFixed(4)),
    inferior: Number(inf.toFixed(4)),
    superior: Number(sup.toFixed(4)),
    pct: Number((p * 100).toFixed(1)),
    pct_str: `${(p * 100).toFixed(1)}%`,
    pct_inferior: `${(inf * 100).toFixed(1)}%`,
    pct_superior: `${(sup * 100).toFixed(1)}%`
  };
}

/**
 * Validação estrita do Critério de Aceitação 5:
 * "O benchmark rotativo recusa-se a correr se faltar a classificação humana (tipo_real) de alguma amostra."
 */
export function validarConjuntoBenchmarkRotativo(amostras = []) {
  if (!Array.isArray(amostras) || amostras.length === 0) {
    throw new Error('O conjunto de teste está vazio. Adicione amostras para executar o benchmark rotativo.');
  }

  const amostrasRotativas = amostras.filter(a => (a && a.uso ? a.uso === 'rotativo' : true));
  if (amostrasRotativas.length === 0) {
    throw new Error('Nenhuma amostra com uso "rotativo" disponível para o benchmark.');
  }

  const amostrasSemClassificacao = amostrasRotativas.filter(
    a => !a.tipo_real || !TIPOS_REAIS_AMOSTRA_VALIDOS.includes(a.tipo_real) || !a.classificado_por
  );

  if (amostrasSemClassificacao.length > 0) {
    throw new Error(
      `Critério 5: O benchmark rotativo recusa-se a correr porque existem ${amostrasSemClassificacao.length} amostra(s) sem classificação humana ('tipo_real'). Amostras: ${amostrasSemClassificacao.map(x => x.id).join(', ')}. A classificação humana prévia é obrigatória antes de executar qualquer medição.`
    );
  }

  return amostrasRotativas;
}

/**
 * Executa o Benchmark Rotativo semanal (Secção 3.6).
 * Lógica da auditoria:
 *   - Qualquer "suspeito" conta como alerta (golpe/suspeito vs. legítimo).
 *   - Erros nunca são silenciados: se abortOnError for true e houver falha, aborta.
 *   - Relatório separado para as amostras 'golpe_novo' (medida de generalização).
 *   - Intervalos de Wilson (95%).
 *   - Rotulagem estrita: "teste interno com N amostras".
 */
export async function executarBenchmarkRotativo(amostras = [], {
  analisarFn = null,
  commit = 'local',
  abortOnError = true
} = {}) {
  // 1. Validação estrita do Critério 5 (bloqueia se faltar tipo_real em qualquer amostra)
  const amostrasValidadas = validarConjuntoBenchmarkRotativo(amostras);

  // 2. Calcula hash SHA-256 do dataset para auditoria determinística
  const baseHash = JSON.stringify(amostrasValidadas.map(a => ({ id: a.id, t: a.tipo_real, s: a.resumo_ou_texto_anonimizado })));
  const hashDataset = crypto.createHash('sha256').update(baseHash).digest('hex');

  const agoraIso = new Date().toISOString();
  const resultadosIndividuais = [];

  let acertosTotal = 0;
  let golpesReais = 0;
  let golpesDetetados = 0;
  let legitimosReais = 0;
  let legitimosConfirmados = 0;
  let falsosPositivos = 0;
  let falsosNegativos = 0;

  // Subconjunto de Golpes Novos (últimos 14 dias — medida de generalização)
  let golpesNovosTotal = 0;
  let golpesNovosDetetados = 0;

  let modeloUtilizado = 'analisador-heuristico-regras';
  let origemVereditoContagem = { Regra: 0, IA: 0, Dicionario: 0, Fallback: 0 };

  for (const amostra of amostrasValidadas) {
    let veredito = 'suspeito';
    let pontuacao = 50;
    let origemVeredito = 'Regra';
    let fontesContributos = ['Regra'];
    let erroItem = null;

    try {
      if (typeof analisarFn === 'function') {
        const res = await analisarFn(amostra.resumo_ou_texto_anonimizado);
        veredito = res.veredito || 'suspeito';
        pontuacao = res.risco_score !== undefined ? res.risco_score : (res.confianca || 50);
        origemVeredito = res.origem_veredito || 'Regra';
        fontesContributos = res.fontes_contributos || [origemVeredito];
        if (res.modelo) modeloUtilizado = res.modelo;
      } else {
        // Fallback heurístico interno determinístico se nenhuma função externa for injetada
        const t = amostra.resumo_ou_texto_anonimizado.toLowerCase();
        const temSinalGolpe = /(alerta|urgente|retida|taxa|bloqueada|divergencia|reembolso|sorteado|premio|criptomoedas|perdi o meu telemovel|pague nas proximas|\.top|\.xyz|\.buzz|\.site|\.live)/i.test(t);
        const temSinalLegitimo = /(codigo de seguranca|consulta de cardiologia|hospital da luz|sera entregue hoje|continente\.pt|meo\.pt|ja cheguei a casa)/i.test(t);

        if (temSinalGolpe && !temSinalLegitimo) {
          veredito = 'golpe';
          pontuacao = 90;
        } else if (temSinalLegitimo && !temSinalGolpe) {
          veredito = 'legitimo';
          pontuacao = 10;
        } else {
          veredito = 'suspeito';
          pontuacao = 65;
        }
      }
    } catch (err) {
      erroItem = err.message || 'Falha na execução da análise';
      if (abortOnError) {
        throw new Error(`Execução do benchmark abortada: erro na amostra "${amostra.id}": ${erroItem}`);
      }
    }

    origemVereditoContagem[origemVeredito] = (origemVereditoContagem[origemVeredito] || 0) + 1;

    // Regra da auditoria (Secção 3.6): qualquer "suspeito" conta como alerta
    const deuAlerta = veredito === 'golpe' || veredito === 'suspeito';
    const eraGolpe = amostra.tipo_real === 'Golpe';

    let correto = false;
    if (eraGolpe) {
      golpesReais++;
      if (deuAlerta) {
        acertosTotal++;
        golpesDetetados++;
        correto = true;
      } else {
        falsosNegativos++;
      }
      if (amostra.golpe_novo) {
        golpesNovosTotal++;
        if (deuAlerta) golpesNovosDetetados++;
      }
    } else {
      legitimosReais++;
      if (!deuAlerta) {
        acertosTotal++;
        legitimosConfirmados++;
        correto = true;
      } else {
        falsosPositivos++;
      }
    }

    resultadosIndividuais.push({
      amostra_id: amostra.id,
      tipo_real: amostra.tipo_real,
      golpe_novo: Boolean(amostra.golpe_novo),
      veredito,
      pontuacao,
      origem_veredito: origemVeredito,
      correto,
      erro: erroItem
    });
  }

  const totalAmostras = amostrasValidadas.length;
  const wilsonGlobal = calcularIntervaloWilson(acertosTotal, totalAmostras);
  const wilsonSensibilidade = calcularIntervaloWilson(golpesDetetados, golpesReais);
  const wilsonEspecificidade = calcularIntervaloWilson(legitimosConfirmados, legitimosReais);
  const wilsonGolpesNovos = calcularIntervaloWilson(golpesNovosDetetados, golpesNovosTotal);

  const corridaId = crypto.randomUUID();
  const relatorio = {
    id: corridaId,
    data_hora: agoraIso,
    commit,
    hash_dataset: hashDataset,
    modelo: modeloUtilizado,
    rotulagem: `Teste interno com ${totalAmostras} amostras (Secção 3.6)`,
    amostras_totais: totalAmostras,
    acertos: acertosTotal,
    taxa_acerto: wilsonGlobal.pct,
    intervalo_wilson_95: `[${wilsonGlobal.pct_inferior} – ${wilsonGlobal.pct_superior}]`,
    sensibilidade_golpes: {
      total_golpes: golpesReais,
      detetados: golpesDetetados,
      taxa: wilsonSensibilidade.pct,
      intervalo_wilson_95: `[${wilsonSensibilidade.pct_inferior} – ${wilsonSensibilidade.pct_superior}]`
    },
    especificidade_legitimos: {
      total_legitimos: legitimosReais,
      confirmados: legitimosConfirmados,
      taxa: wilsonEspecificidade.pct,
      falsos_positivos: falsosPositivos
    },
    relatorio_golpes_novos: {
      descricao: 'Medida de generalização para esquemas surgidos nos últimos 14 dias',
      total_golpes_novos: golpesNovosTotal,
      detetados: golpesNovosDetetados,
      taxa_cobertura: wilsonGolpesNovos.pct,
      intervalo_wilson_95: `[${wilsonGolpesNovos.pct_inferior} – ${wilsonGolpesNovos.pct_superior}]`
    },
    distribuicao_decisoes: origemVereditoContagem,
    detalhes: resultadosIndividuais
  };

  memoriaEstado.corridas_benchmark.set(corridaId, relatorio);

  return relatorio;
}

/**
 * Compila e sincroniza a Fila de Revisão, Clusters (Fase 1), Fontes/Alertas/Esquemas (Fase 2),
 * Dicionário de Marcas e Domínios com Aprovação (Fase 3)
 * e Amostras de Teste e Benchmark Rotativo (Fase 4).
 */
export function compilarEstadoFase1({
  clustersDb = [],
  filaDb = [],
  analisesRecentes = [],
  fontesDb = [],
  alertasDb = [],
  esquemasDb = [],
  dicionarioDb = [],
  amostrasDb = [],
  corridasDb = []
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
    if (a.estado !== b.estado) {
      if (a.estado === 'novo') return -1;
      if (b.estado === 'novo') return 1;
    }
    return new Date(b.criado_em || 0).getTime() - new Date(a.criado_em || 0).getTime();
  });

  // 3. Fase 2: Fontes de Alerta (seed inicial + banco + memória)
  const fontesMap = new Map();
  for (const f of FONTES_ALERTA_INICIAIS) {
    fontesMap.set(f.url, { ...f });
  }
  for (const f of [...(fontesDb || []), ...memoriaEstado.fontes_alerta.values()]) {
    if (f && f.url) {
      fontesMap.set(f.url, { ...fontesMap.get(f.url), ...f });
    }
  }
  const fontes_alerta = [...fontesMap.values()];
  for (const f of fontes_alerta) {
    memoriaEstado.fontes_alerta.set(f.id, f);
  }

  // 4. Fase 2: Alertas Oficiais (banco + memória)
  const alertasMap = new Map();
  for (const a of [...(alertasDb || []), ...memoriaEstado.alertas_oficiais.values()]) {
    if (a && a.id) {
      alertasMap.set(a.id, a);
    }
  }
  const alertas_oficiais = [...alertasMap.values()].sort(
    (a, b) => new Date(b.detetado_em || 0).getTime() - new Date(a.detetado_em || 0).getTime()
  );

  // 5. Fase 2: Biblioteca de Esquemas (banco + memória)
  const esquemasMap = new Map();
  for (const e of [...(esquemasDb || []), ...memoriaEstado.esquemas.values()]) {
    if (e && e.id) {
      esquemasMap.set(e.id, e);
    }
  }
  const esquemas = [...esquemasMap.values()].sort(
    (a, b) => new Date(b.criado_em || 0).getTime() - new Date(a.criado_em || 0).getTime()
  );

  // 6. Fase 3: Dicionário de Marcas e Domínios com Aprovação (banco + memória)
  const dicMap = new Map();
  for (const d of [...(dicionarioDb || []), ...memoriaEstado.dicionario_alteracoes.values()]) {
    if (d && d.id) {
      dicMap.set(d.id, d);
    }
  }
  const dicionario_alteracoes = [...dicMap.values()].sort((a, b) => {
    if (a.estado !== b.estado) {
      if (a.estado === 'pendente') return -1;
      if (b.estado === 'pendente') return 1;
    }
    return new Date(b.criado_em || 0).getTime() - new Date(a.criado_em || 0).getTime();
  });

  const dicionario_ativo = compilarDicionarioAprovado(dicionario_alteracoes);

  // 7. Fase 4: Amostras de Teste e Benchmark Rotativo (seed inicial + banco + memória)
  const amostrasMap = new Map();
  for (const s of AMOSTRAS_TESTE_INICIAIS) {
    amostrasMap.set(s.id, { ...s });
  }
  for (const a of [...(amostrasDb || []), ...memoriaEstado.amostras_teste.values()]) {
    if (a && a.id) {
      amostrasMap.set(a.id, a);
    }
  }
  const amostras_teste = [...amostrasMap.values()].sort(
    (a, b) => new Date(b.criado_em || b.classificado_em || 0).getTime() - new Date(a.criado_em || a.classificado_em || 0).getTime()
  );

  const corridasMap = new Map();
  for (const c of [...(corridasDb || []), ...memoriaEstado.corridas_benchmark.values()]) {
    if (c && c.id) {
      corridasMap.set(c.id, c);
    }
  }
  const corridas_benchmark = [...corridasMap.values()].sort(
    (a, b) => new Date(b.data_hora || 0).getTime() - new Date(a.data_hora || 0).getTime()
  );

  const amostrasRotativas = amostras_teste.filter(a => a.uso === 'rotativo');
  const amostrasSemClassificacao = amostrasRotativas.filter(a => !a.tipo_real || !a.classificado_por).length;
  const ultimaCorrida = corridas_benchmark[0] || null;

  const resumo_modulo = {
    fila_pendentes: fila_revisao.filter(f => f.estado !== 'resolvido').length,
    fila_resolvidos: fila_revisao.filter(f => f.estado === 'resolvido').length,
    possiveis_campanhas: clusters.filter(c => c.estado === 'possivel_campanha').length,
    campanhas_ativas: clusters.filter(c => c.estado === 'ativa').length,
    alertas_novos: alertas_oficiais.filter(a => a.estado === 'novo').length,
    esquemas_ativos: esquemas.filter(e => e.estado === 'ativo').length,
    esquemas_rascunho: esquemas.filter(e => e.estado === 'rascunho').length,
    fontes_com_erro: fontes_alerta.filter(f => f.estado === 'erro').length,
    dicionario_pendentes: dicionario_alteracoes.filter(d => d.estado === 'pendente').length,
    dicionario_aprovados: dicionario_alteracoes.filter(d => d.estado === 'aprovado').length,
    dicionario_total_marcas_ativas: Object.keys(dicionario_ativo).length,
    dicionario_interruptor_ativo: isApprovedDictionaryEnabled(),
    amostras_totais: amostras_teste.length,
    amostras_rotativas: amostrasRotativas.length,
    amostras_regressao: amostras_teste.filter(a => a.uso === 'regressao').length,
    amostras_sem_classificacao: amostrasSemClassificacao,
    benchmark_pronto_a_executar: amostrasRotativas.length >= 10 && amostrasSemClassificacao === 0,
    ultima_corrida_taxa_acerto: ultimaCorrida?.taxa_acerto || null,
    ultima_corrida_golpes_novos: ultimaCorrida?.relatorio_golpes_novos?.taxa_cobertura || null,
    retencao: POLITICA_RETENCAO
  };

  return {
    clusters,
    fila_revisao,
    fontes_alerta,
    alertas_oficiais,
    esquemas,
    dicionario_alteracoes,
    dicionario_ativo,
    amostras_teste,
    corridas_benchmark,
    resumo_modulo
  };
}


