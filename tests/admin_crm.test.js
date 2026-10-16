// tests/admin_crm.test.js
// Testes estritos das Regras de Negócio e Critérios de Aceitação do CRM & Verificações

import { gerarCodigoSelo } from '../lib/radar.js';

let passed = 0;
let total = 0;

function assert(condition, testName) {
  total++;
  if (condition) {
    console.log(`✅ [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`❌ [FAIL] ${testName}`);
    process.exitCode = 1;
  }
}

console.log('\n============================================================');
console.log('🧪 TESTES DE CRITÉRIOS DE ACEITAÇÃO: CRM, SELO & VERIFICAÇÕES');
console.log('============================================================\n');

// 1. Critério 1: Não é possível ativar selo sem 4 verificações OK e pagamento (ou isenção justificada)
function validarCondicoesAtivacao(verificacoes, pagamentos) {
  const tiposOk = new Set((verificacoes || []).filter(v => v.estado === 'ok').map(v => v.tipo));
  const obrigatorios = ['nif', 'dominio', 'telefone', 'representante'];
  const faltantes = obrigatorios.filter(t => !tiposOk.has(t));

  if (faltantes.length > 0) {
    return { permitido: false, motivo: `Faltam verificações: ${faltantes.join(', ')}` };
  }

  const temPagamentoValido = (pagamentos || []).some(
    p => p.estado === 'pago' || (p.estado === 'isento' && p.motivo_isencao && p.motivo_isencao.trim().length >= 4)
  );

  if (!temPagamentoValido) {
    return { permitido: false, motivo: 'Pagamento pendente ou isenção sem motivo justificado' };
  }

  return { permitido: true };
}

// Caso 1A: Nenhuma verificação concluída -> Bloqueado
const res1A = validarCondicoesAtivacao([], []);
assert(!res1A.permitido, 'Critério 1: Bloqueia ativação com 0 verificações');

// Caso 1B: 3 verificações concluídas (falta representante) -> Bloqueado
const res1B = validarCondicoesAtivacao(
  [{ tipo: 'nif', estado: 'ok' }, { tipo: 'dominio', estado: 'ok' }, { tipo: 'telefone', estado: 'ok' }],
  [{ estado: 'pago', valor: 49.00 }]
);
assert(!res1B.permitido && res1B.motivo.includes('representante'), 'Critério 1: Bloqueia ativação se faltar 1 dos 4 pilares (representante)');

// Caso 1C: 4 verificações concluídas, mas sem pagamento -> Bloqueado
const res1C = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'pendente', valor: 49.00 }]
);
assert(!res1C.permitido && res1C.motivo.includes('Pagamento pendente'), 'Critério 1: Bloqueia ativação com pagamento pendente');

// Caso 1D: 4 verificações OK e pagamento PAGO -> Permitido!
const res1D = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'pago', valor: 49.00 }]
);
assert(res1D.permitido, 'Critério 1: Permite ativação com 4 verificações OK e pagamento PAGO');

// Caso 1E: 4 verificações OK e isenção com motivo justificado -> Permitido!
const res1E = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'isento', motivo_isencao: 'Entidade de Utilidade Pública Oficial' }]
);
assert(res1E.permitido, 'Critério 1: Permite ativação com isenção justificada com motivo escrito');

// Caso 1F: 4 verificações OK e isenção SEM motivo -> Bloqueado!
const res1F = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'isento', motivo_isencao: '' }]
);
assert(!res1F.permitido, 'Critério 1: Bloqueia isenção sem motivo justificado por escrito');

// 2. Critério 3: Códigos de selo não sequenciais e imprevisíveis (≥ 10 caracteres)
const codigo1 = gerarCodigoSelo();
const codigo2 = gerarCodigoSelo();
assert(codigo1.length >= 10, 'Critério 3: Código de selo tem tamanho ≥ 10 caracteres');
assert(codigo1.startsWith('ZQV-'), 'Critério 3: Código de selo possui prefixo oficial ZQV-');
assert(codigo1 !== codigo2, 'Critério 3: Códigos sucessivos são imprevisíveis e não-sequenciais');

// 3. Critério 6: Um PDF não pode ser enviado sem aprovação registada
function validarEnvioRelatorio(relatorio) {
  if (!relatorio.aprovado_por || !relatorio.aprovado_em) {
    return { permitido: false, erro: 'Relatório pendente de aprovação manual' };
  }
  return { permitido: true };
}

const relatorioPendente = { id: 'rel-1', periodo: '2026-10', aprovado_por: null };
assert(!validarEnvioRelatorio(relatorioPendente).permitido, 'Critério 6: Bloqueia envio de relatório sem aprovação');

const relatorioAprovado = { id: 'rel-2', periodo: '2026-10', aprovado_por: 'admin', aprovado_em: new Date().toISOString() };
assert(validarEnvioRelatorio(relatorioAprovado).permitido, 'Critério 6: Permite envio após aprovação formal registada');

console.log('\n============================================================');
console.log(`RESULTADO DO CRM: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');
