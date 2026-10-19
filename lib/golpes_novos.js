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
  dicionario_alteracoes: new Map()
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
    nome: 'CERT.PT / CNCS — Avisos e Alertas de Cibersegurança',
    url: 'https://www.cncs.gov.pt/pt/noticias/',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Centro Nacional de Cibersegurança (confirmar página de notícias/alertas)'
  },
  {
    id: '00000000-0000-4000-8000-000000000102',
    nome: 'Banco de Portugal — Alertas de Fraude e Segurança',
    url: 'https://clientebancario.bportugal.pt/pt-pt/noticias',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Portal do Cliente Bancário — Banco de Portugal (confirmar página)'
  },
  {
    id: '00000000-0000-4000-8000-000000000103',
    nome: 'Polícia Judiciária — Comunicados e Alertas de Burlas',
    url: 'https://www.policiajudiciaria.pt/notas-de-imprensa/',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Notas de imprensa oficiais da PJ sobre esquemas de burla'
  },
  {
    id: '00000000-0000-4000-8000-000000000104',
    nome: 'DECO Proteste — Alertas de Burlas ao Consumidor',
    url: 'https://www.deco.proteste.pt/tecnologia/redes-sociais/noticias',
    tipo: 'autoridade',
    ultimo_check: null,
    ultimo_hash: null,
    estado: 'ativa',
    ultimo_erro: null,
    notas: 'Alertas públicos de defesa do consumidor (confirmar secção)'
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

/**
 * Compila e sincroniza a Fila de Revisão, Clusters (Fase 1), Fontes/Alertas/Esquemas (Fase 2)
 * e Dicionário de Marcas e Domínios com Aprovação (Fase 3).
 */
export function compilarEstadoFase1({
  clustersDb = [],
  filaDb = [],
  analisesRecentes = [],
  fontesDb = [],
  alertasDb = [],
  esquemasDb = [],
  dicionarioDb = []
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

  // Atualiza a cache ativa do scanner apenas com as propostas aprovadas
  const dicionario_ativo = compilarDicionarioAprovado(dicionario_alteracoes);

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
    resumo_modulo
  };
}


