// tests/report_generator.test.js
// Validação pericial do gerador de relatórios mensais e anonimização de vítimas

import {
  limparTextoVitima,
  estruturarRelatorioMensal,
  renderRelatorioHtml,
  calcularHashRelatorio
} from '../lib/report_generator.js';

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
console.log('🧪 TESTES DO GERADOR DE RELATÓRIO MENSAL & ANONIMIZAÇÃO');
console.log('============================================================\n');

// 1. Teste de Sanitização de Dados de Vítimas (Critério 4)
const textoSujo = 'Olá Maria, o seu NIF 123456789 tem dívida. Contacte o telemóvel 912345678 ou +351 934567890. ' +
  'Pague por IBAN PT50003506500001234567890 ou envie comprovativo para maria.silva@gmail.com. Cartão 4532 1122 3344 5566.';

const textoLimpo = limparTextoVitima(textoSujo);

assert(!textoLimpo.includes('123456789'), 'Critério 4: NIF da vítima removido com sucesso');
assert(!textoLimpo.includes('912345678'), 'Critério 4: Telemóvel nacional removido com sucesso');
assert(!textoLimpo.includes('934567890'), 'Critério 4: Telemóvel internacional removido com sucesso');
assert(!textoLimpo.includes('PT50003506500001234567890'), 'Critério 4: IBAN removido com sucesso');
assert(!textoLimpo.includes('maria.silva@gmail.com'), 'Critério 4: Email de vítima removido com sucesso');
assert(!textoLimpo.includes('4532 1122 3344 5566'), 'Critério 4: Cartão bancário removido com sucesso');
assert(textoLimpo.includes('[NIF REMOVIDO]'), 'Critério 4: Marcação explícita de [NIF REMOVIDO]');
assert(textoLimpo.includes('[TELEFONE REMOVIDO]'), 'Critério 4: Marcação explícita de [TELEFONE REMOVIDO]');
assert(textoLimpo.includes('[IBAN REMOVIDO]'), 'Critério 4: Marcação explícita de [IBAN REMOVIDO]');

// 2. Teste do Relatório SEM Dados no Período (Critério 5)
const empresaMock = {
  nome: 'Empresa Teste Lda',
  nome_comercial: 'Empresa Teste',
  nif: '501234567',
  codigo_selo: 'ZQV-TEST999',
  plano: 'radar'
};

const dadosSemSinais = estruturarRelatorioMensal({
  empresa: empresaMock,
  periodo: '2026-10',
  ocorrencias: []
});

const htmlSemSinais = renderRelatorioHtml(dadosSemSinais);

assert(htmlSemSinais.includes('Sem sinais detetados neste período'), 'Critério 5: Exibe exatamente "Sem sinais detetados neste período"');
assert(dadosSemSinais.resumo.total_sinais === 0, 'Resumo contabiliza 0 sinais');

// 3. Teste do Relatório COM Dados Sujos (Garante que HTML final nunca vaza dados)
const ocorrenciasSujas = [
  {
    criado_em: '2026-10-12T10:00:00Z',
    canal: 'SMS',
    tipo: 'Smishing Via Verde',
    alerta_link: 'https://viaverde-falsa.top',
    canal_mencionado: '+351919999999',
    texto_original: 'Via Verde: pague 12,45€ para o IBAN PT5000001234567890 ou ligue 918765432 cliente João Silva.',
    risco_score: 90,
    veredito: 'golpe'
  }
];

const dadosComSinais = estruturarRelatorioMensal({
  empresa: empresaMock,
  periodo: '2026-10',
  ocorrencias: ocorrenciasSujas
});

const htmlComSinais = renderRelatorioHtml(dadosComSinais);

assert(!htmlComSinais.includes('PT5000001234567890'), 'HTML do relatório limpa IBAN antes de renderizar');
assert(!htmlComSinais.includes('918765432'), 'HTML do relatório limpa telefone de vítima');
assert(htmlComSinais.includes('viaverde-falsa.top'), 'HTML do relatório mantém domínio do impostor para bloqueio');
assert(htmlComSinais.includes('Hash SHA-256'), 'HTML do relatório inclui rodapé forense com Hash SHA-256');
assert(dadosComSinais.hash_sha256.length === 64, 'Hash SHA-256 gerado possui 64 caracteres hexadecimais');

// 4. Teste de Reproducibilidade de Hash
const hash1 = calcularHashRelatorio(dadosComSinais);
const hash2 = calcularHashRelatorio(dadosComSinais);
assert(hash1 === hash2, 'Hash SHA-256 é estritamente determinístico e reprodutível');

console.log('\n============================================================');
console.log(`RESULTADO DO RELATÓRIO: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');
