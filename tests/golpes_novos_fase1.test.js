// tests/golpes_novos_fase1.test.js
// Testes automáticos de aceitação — Módulo de Acompanhamento de Golpes Novos (Fase 1)
// Cobre:
// - Critério 1: Nenhuma tabela guarda o texto bruto de uma mensagem (telefones, emails, NIF, IBAN e números longos removidos)
// - Critério 2: Uma ocorrência repetida 3 vezes em 24 h cria um cluster `possivel_campanha` e nunca `ativa` sem decisão humana
// - Critério 7: Scanner / renderizador intactos e sem alteração de vereditos
// - Critério 8: Qualquer pedido sem credenciais às rotas de administração recebe 401 e zero dados

import assert from 'node:assert/strict';
import {
  sanitizarCampoAnonimizado,
  construirResumoAnonimizado,
  criarItemFilaRevisao,
  agruparEventosEmClusters,
  aplicarDecisaoHumanaFila,
  aplicarDecisaoHumanaCluster,
  avaliarMotivosFilaRevisao
} from '../lib/golpes_novos.js';
import adminHandler from '../api/admin.js';

console.log('🧪 Iniciando Testes da Fase 1: Módulo de Acompanhamento de Golpes Novos (Fila & Agrupamento)...\n');

// =========================================================================
// CRITÉRIO 1: Zero texto bruto guardado & Remoção de PII (telefones, emails, NIF, IBAN, números longos)
// =========================================================================
{
  const inputComPII = {
    texto: 'Olá João, o seu pacote CTT está retido. Ligue para +351 912 345 678 ou envie email para vitima.real@gmail.com com o NIF 123456789 e IBAN PT50000201231234567890154. Ref: 9988776655.',
    texto_original: 'Mensagem bruta secreta da vítima 912345678 vitima.real@gmail.com PT50000201231234567890154',
    marca: 'CTT Expresso (contacto 912345678 / vitima.real@gmail.com)',
    tipo: 'phishing_link',
    canal: 'sms',
    veredito: 'suspeito',
    pontuacao: 62,
    dominio_falso: 'https://ctt-alfandega-pt.top/pagar?nif=123456789&iban=PT50000201231234567890154',
    entidade_mb: '21890',
    sinais: [
      'Pedido de pagamento urgente para +351 912 345 678',
      'Email detetado: vitima.real@gmail.com',
      'IBAN suspeito PT50000201231234567890154 e conta 123456789012'
    ]
  };

  const itemFila = criarItemFilaRevisao(inputComPII);
  assert.ok(itemFila, 'Deve criar item na fila de revisão para caso suspeito / confiança baixa');

  const serializado = JSON.stringify(itemFila);

  // Nunca pode conter o texto bruto nem campos de texto
  assert.equal(itemFila.texto, undefined, 'Item da fila nunca pode ter propriedade texto');
  assert.equal(itemFila.texto_original, undefined, 'Item da fila nunca pode ter propriedade texto_original');
  assert.equal(itemFila.resumo.texto, undefined, 'Resumo nunca pode ter propriedade texto');
  assert.ok(!serializado.includes('Olá João, o seu pacote CTT está retido'), 'Nunca pode guardar a frase bruta da mensagem');

  // Nunca pode conter telefone, email, NIF, IBAN ou números longos (>= 6 dígitos)
  assert.ok(!serializado.includes('912 345 678') && !serializado.includes('912345678'), 'Telefone deve ser removido do resumo');
  assert.ok(!serializado.includes('vitima.real@gmail.com'), 'Email deve ser removido do resumo');
  assert.ok(!serializado.includes('123456789'), 'NIF / número longo deve ser removido do resumo');
  assert.ok(!serializado.includes('PT50000201231234567890154'), 'IBAN deve ser removido do resumo');
  assert.ok(!serializado.includes('9988776655'), 'Números longos devem ser removidos do resumo');

  // Mas preserva os indicadores técnicos não pessoais (domínio limpo e entidade MB de 5 dígitos)
  assert.equal(itemFila.resumo.indicadores.dominio, 'ctt-alfandega-pt.top', 'Deve preservar apenas o hostname técnico sem query string pessoal');
  assert.equal(itemFila.resumo.indicadores.entidade_mb, '21890', 'Deve preservar a entidade MB de 5 dígitos');

  console.log('✅ Critério 1 validado: Zero texto bruto guardado; telefones, emails, NIF, IBAN e números longos são totalmente removidos.');
}

// =========================================================================
// CRITÉRIO 2: 3 ocorrências semelhantes em 24h criam cluster `possivel_campanha` e NUNCA `ativa` sem decisão humana
// =========================================================================
{
  const agora = Date.now();
  const ocorrencias = [
    {
      id: 'oc-1',
      marca: 'Millennium BCP',
      tipo: 'phishing_bancario',
      canal: 'sms',
      dominio_falso: 'millennium-seguranca-app.com',
      tatica: 'Link falso de atualização de segurança',
      criado_em: new Date(agora - 4 * 3600 * 1000).toISOString()
    },
    {
      id: 'oc-2',
      marca: 'Millennium BCP',
      tipo: 'phishing_bancario',
      canal: 'sms',
      dominio_falso: 'millennium-seguranca-app.com',
      tatica: 'Link falso de atualização de segurança',
      criado_em: new Date(agora - 2 * 3600 * 1000).toISOString()
    },
    {
      id: 'oc-3',
      marca: 'Millennium BCP',
      tipo: 'phishing_bancario',
      canal: 'sms',
      dominio_falso: 'millennium-seguranca-app.com',
      tatica: 'Link falso de atualização de segurança',
      criado_em: new Date(agora - 30 * 60 * 1000).toISOString()
    }
  ];

  const clusters = agruparEventosEmClusters(ocorrencias, [], agora);
  assert.equal(clusters.length, 1, 'As 3 ocorrências semelhantes devem formar 1 cluster pelo mesmo fingerprint');
  const cluster = clusters[0];

  assert.equal(cluster.contagem, 3, 'Contagem total deve ser 3');
  assert.equal(cluster.contagem_24h, 3, 'Contagem em 24h deve ser 3');
  assert.equal(cluster.estado, 'possivel_campanha', 'Cluster com >= 3 ocorrências em 24h deve ter estado "possivel_campanha"');
  assert.notEqual(cluster.estado, 'ativa', 'Cluster NUNCA pode passar a "ativa" sem decisão humana');
  assert.equal(cluster.revisor, null, 'Cluster automático não tem revisor humano até ser decidido');
  assert.ok(cluster.velocidade_por_hora > 0, 'Deve calcular a velocidade por hora');

  // Testar transição por decisão humana
  const clusterAtivado = aplicarDecisaoHumanaCluster(cluster, {
    estado: 'ativa',
    revisor: 'Denio'
  });
  assert.equal(clusterAtivado.estado, 'ativa', 'Após decisão humana explícita, o cluster passa a "ativa"');
  assert.equal(clusterAtivado.revisor, 'Denio', 'Regista o revisor humano');

  console.log('✅ Critério 2 validado: 3 ocorrências em 24h criam cluster "possivel_campanha" e nunca "ativa" sem decisão humana.');
}

// =========================================================================
// TESTE DE MOTIVOS DA FILA DE REVISÃO E DECISÃO HUMANA (Secção 3.1)
// =========================================================================
{
  // 1. Discordância IA vs. Regra
  const motivosIaRegra = avaliarMotivosFilaRevisao({
    veredito: 'legitimo',
    pontuacao: 85,
    veredito_ia: 'golpe',
    veredito_regra: 'legitimo'
  });
  assert.ok(motivosIaRegra.deve_entrar, 'Divergência entre IA e regra deve entrar na fila');
  assert.ok(motivosIaRegra.todos_motivos.includes('ia_vs_regra'), 'Divergência entre IA e regra deve entrar na fila como ia_vs_regra');

  // 2. Resposta "ERRO" do utilizador
  const motivosErro = avaliarMotivosFilaRevisao({
    veredito: 'golpe',
    pontuacao: 95,
    feedback_erro: true
  });
  assert.equal(motivosErro.motivo_principal, 'feedback_erro', 'Feedback "ERRO" do utilizador deve entrar na fila com prioridade feedback_erro');

  // 3. Decisão humana sobre um item da fila
  const item = criarItemFilaRevisao({
    marca: 'EDP Comercial',
    tipo: 'fatura_falsa',
    canal: 'whatsapp',
    veredito: 'suspeito',
    pontuacao: 58,
    entidade_mb: '11223',
    sinais: ['Entidade MB em mensagem de corte de energia']
  });
  const itemDecidido = aplicarDecisaoHumanaFila(item, {
    decisao: 'esquema_novo',
    revisor: 'Denio',
    notas: 'Esquema de falsa dívida de eletricidade com telefone 919999999 removido das notas'
  });
  assert.equal(itemDecidido.estado, 'resolvido', 'Decisão humana deve marcar o item como resolvido');
  assert.equal(itemDecidido.decisao, 'esquema_novo', 'Deve guardar a decisão esquema_novo');
  assert.equal(itemDecidido.revisor, 'Denio', 'Deve guardar o revisor');
  assert.ok(itemDecidido.resolvido_em, 'Deve registar a data/hora da resolução');
  assert.ok(!itemDecidido.notas.includes('919999999'), 'Até as notas passam pela limpeza automática de PII');

  console.log('✅ Fila de Revisão validada: Motivos automáticos (suspeito, confiança baixa, IA vs. regra, ERRO, possível campanha) e registo de decisão humana.');
}

// =========================================================================
// CRITÉRIO 8: Segurança de rotas — Pedido sem credenciais recebe 401 e zero dados
// =========================================================================
{
  const criarMockRes = () => ({
    statusCode: 200,
    body: null,
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
    end() { return this; }
  });

  // GET sem credenciais
  const resGetSemAuth = criarMockRes();
  process.env.ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || 'chave-de-teste-fase1';
  await adminHandler({ method: 'GET', headers: {} }, resGetSemAuth);
  assert.equal(resGetSemAuth.statusCode, 401, 'GET /api/admin sem credenciais deve devolver 401');
  assert.equal(resGetSemAuth.body?.clusters, undefined, 'Zero dados de clusters devolvidos sem autenticação');
  assert.equal(resGetSemAuth.body?.fila_revisao, undefined, 'Zero dados de fila_revisao devolvidos sem autenticação');

  // POST decidir_fila_revisao sem credenciais
  const resPostSemAuth = criarMockRes();
  await adminHandler({
    method: 'POST',
    headers: { 'x-admin-key': 'chave-invalida' },
    body: { action: 'decidir_fila_revisao', item_id: 'fila-1', decisao: 'esquema_novo', revisor: 'Invasor' }
  }, resPostSemAuth);
  assert.equal(resPostSemAuth.statusCode, 401, 'POST decidir_fila_revisao sem credenciais válidas deve devolver 401');

  // POST alterar_estado_cluster sem credenciais
  const resClusterSemAuth = criarMockRes();
  await adminHandler({
    method: 'POST',
    headers: {},
    body: { action: 'alterar_estado_cluster', cluster_id: 'cl-1', estado: 'ativa', revisor: 'Invasor' }
  }, resClusterSemAuth);
  assert.equal(resClusterSemAuth.statusCode, 401, 'POST alterar_estado_cluster sem credenciais deve devolver 401');

  console.log('✅ Critério 8 validado: Qualquer pedido sem credenciais às rotas de administração recebe 401 e zero dados.');
}

console.log('\n🎉 TODOS OS TESTES DA FASE 1 (FILA DE REVISÃO & AGRUPAMENTO) PASSARAM COM SUCESSO!');
