// tests/golpes_novos_fase3.test.js
// Testes de Aceitação da Fase 3: Dicionário de Marcas e Domínios com Aprovação
// Regras Estritas:
//   - Propostas entram como 'pendente' (aprovado_por: null, aprovado_em: null).
//   - Critério 4: Propostas 'pendente' ou 'rejeitado' NUNCA alteram o resultado de nenhuma análise.
//   - Apenas alterações com estado === 'aprovado' e aprovado_por válido entram em vigor.
//   - O scanner lê do dicionário aprovado com cache e interruptor de ativação (Critério 7).
//   - Com os dados iniciais, o dicionário aprovado é 100% idêntico a OFFICIAL_DOMAINS (zero desvios).

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  proporAlteracaoDicionario,
  decidirAlteracaoDicionario,
  compilarDicionarioAprovado,
  compilarEstadoFase1,
  OFFICIAL_DOMAINS,
  isApprovedDictionaryEnabled,
  setApprovedDictionaryEnabled
} from '../lib/golpes_novos.js';
import {
  isOfficialDomain,
  checkBrandImpersonation,
  getEffectiveOfficialDomains,
  setApprovedDictionaryAlterations
} from '../lib/threat_intel.js';

test('Fase 3: Criar proposta de marca e domínio entra obrigatoriamente como "pendente"', () => {
  const proposta = proporAlteracaoDicionario({
    marca: 'DIGI Portugal',
    dominio_oficial: 'https://www.digi.pt/tarifarios',
    acao: 'adicionar',
    origem: 'fila_revisao',
    motivo: 'Nova operadora lançada em Portugal'
  });

  assert.ok(proposta.id);
  assert.equal(proposta.marca, 'DIGI Portugal');
  assert.equal(proposta.dominio_oficial, 'digi.pt'); // Normalizado sem https://www.
  assert.equal(proposta.acao, 'adicionar');
  assert.equal(proposta.estado, 'pendente');
  assert.equal(proposta.aprovado_por, null);
  assert.equal(proposta.aprovado_em, null);
  assert.ok(proposta.criado_em);
});

test('Fase 3 (Critério 4): Proposta no estado "pendente" NÃO altera o dicionário ativo nem o scanner', () => {
  // Limpa cache para estado base
  setApprovedDictionaryAlterations([]);
  setApprovedDictionaryEnabled(true);

  const propostaPendente = proporAlteracaoDicionario({
    marca: 'Banco Inexistente XPTO',
    dominio_oficial: 'bancoxpto.pt',
    acao: 'adicionar',
    origem: 'manual'
  });

  // Compila com a proposta pendente
  const dicionario = compilarDicionarioAprovado([propostaPendente]);

  // Critério 4: Não deve constar do dicionário nem ser reconhecido como oficial
  assert.equal(dicionario.banco_inexistente_xpto, undefined);
  assert.equal(isOfficialDomain('bancoxpto.pt'), false);

  // E uma mensagem a imitar a marca não aciona verificação oficial de banco inexiste
  const resImpersonation = checkBrandImpersonation('https://bancoxpto-alerta.com', 'Aviso Banco Inexistente XPTO');
  assert.equal(resImpersonation, null);
});

test('Fase 3 (Critério 4): Proposta "rejeitada" NÃO entra em vigor', () => {
  const proposta = proporAlteracaoDicionario({
    marca: 'Marca Rejeitada',
    dominio_oficial: 'marcarejeitada.pt',
    acao: 'adicionar'
  });

  const rejeitada = decidirAlteracaoDicionario(proposta, {
    estado: 'rejeitado',
    aprovado_por: 'Operador Admin',
    motivo: 'Domínio não corresponde ao registo oficial do INPI'
  });

  assert.equal(rejeitada.estado, 'rejeitado');
  assert.equal(rejeitada.aprovado_por, 'Operador Admin');
  assert.ok(rejeitada.aprovado_em);

  const dicionario = compilarDicionarioAprovado([rejeitada]);
  assert.equal(dicionario.marca_rejeitada, undefined);
  assert.equal(isOfficialDomain('marcarejeitada.pt'), false);
});

test('Fase 3: Decisão de aprovação exige identificador do revisor humano', () => {
  const proposta = proporAlteracaoDicionario({
    marca: 'Nova Marca Teste',
    dominio_oficial: 'novamarca.pt'
  });

  assert.throws(() => {
    decidirAlteracaoDicionario(proposta, { estado: 'aprovado', aprovado_por: '' });
  }, /aprovado_por/i);
});

test('Fase 3: Alteração aprovada entra em vigor no scanner (`isOfficialDomain` e `checkBrandImpersonation`)', () => {
  const proposta = proporAlteracaoDicionario({
    marca: 'DIGI Portugal',
    dominio_oficial: 'digi.pt',
    acao: 'adicionar',
    origem: 'fila_revisao',
    motivo: 'Aprovado pelo operador após confirmação de licença Anacom'
  });

  const aprovada = decidirAlteracaoDicionario(proposta, {
    estado: 'aprovado',
    aprovado_por: 'Operador Senior',
    motivo: 'Confirmado no Whois e na Anacom'
  });

  compilarDicionarioAprovado([aprovada]);

  // 1. Domínio oficial agora é reconhecido pelo scanner
  assert.equal(isOfficialDomain('digi.pt'), true);
  assert.equal(isOfficialDomain('subdominio.digi.pt'), true);

  // 2. Link malicioso a imitar a nova marca oficial é detetado com usurpação de marca!
  const resImpersonation = checkBrandImpersonation(
    'https://digi-fatura-urgente.top/pagar',
    'Mensagem da Digi Portugal: a sua fatura está pendente'
  );

  assert.ok(resImpersonation);
  assert.equal(resImpersonation.impersonated, true);
  assert.ok(resImpersonation.evidence.includes('DIGI_PORTUGAL'));
  assert.ok(resImpersonation.evidence.includes('digi.pt'));
});

test('Fase 3: Interruptor de ativação permite desativar a leitura do dicionário e repor a base', () => {
  // Com o interruptor desativado, o scanner volta estritamente à base inicial OFFICIAL_DOMAINS
  setApprovedDictionaryEnabled(false);
  assert.equal(isApprovedDictionaryEnabled(), false);

  assert.equal(isOfficialDomain('digi.pt'), false);
  const dominiosBase = getEffectiveOfficialDomains();
  assert.equal(dominiosBase.digi_portugal, undefined);

  // Reativa o interruptor
  setApprovedDictionaryEnabled(true);
  assert.equal(isApprovedDictionaryEnabled(), true);
  assert.equal(isOfficialDomain('digi.pt'), true);
});

test('Fase 3: Histórico e compilação do estado em compilarEstadoFase1', () => {
  const p1 = proporAlteracaoDicionario({ marca: 'Marca A', dominio_oficial: 'marca-a.pt' });
  const p2 = proporAlteracaoDicionario({ marca: 'Marca B', dominio_oficial: 'marca-b.pt' });
  const a2 = decidirAlteracaoDicionario(p2, { estado: 'aprovado', aprovado_por: 'Admin' });

  const estado = compilarEstadoFase1({
    dicionarioDb: [p1, a2]
  });

  assert.ok(Array.isArray(estado.dicionario_alteracoes));
  assert.equal(estado.dicionario_alteracoes.length >= 2, true);
  assert.ok(estado.dicionario_ativo);
  assert.equal(estado.resumo_modulo.dicionario_pendentes >= 1, true);
  assert.equal(estado.resumo_modulo.dicionario_aprovados >= 1, true);
  assert.equal(typeof estado.resumo_modulo.dicionario_total_marcas_ativas, 'number');
  assert.equal(estado.resumo_modulo.dicionario_interruptor_ativo, true);
});

test('Fase 3 (Critério 7): Estado inicial sem alterações aprovadas é idêntico a OFFICIAL_DOMAINS', () => {
  setApprovedDictionaryAlterations([]);
  const effective = getEffectiveOfficialDomains();

  for (const [key, list] of Object.entries(OFFICIAL_DOMAINS)) {
    assert.deepEqual(effective[key], list, `Chave ${key} deve ser idêntica ao baseline inicial`);
  }
});
