// tests/renderer.test.js
// Validação estrita dos Critérios de Aceitação do Novo Formato WhatsApp
// Critérios: ≤ 600 chars, ≤ 12 linhas, termos proibidos, snapshots T1/T2/T3, comandos AJUDA/DETALHES/ÚTIL/ERRO

import {
  buildDataContract,
  renderWhatsAppResponse,
  renderHelpResponse,
  renderDetailsResponse,
  renderFeedbackResponse,
  renderNoSessionResponse,
  PROHIBITED_TERMS
} from '../lib/renderer.js';

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
console.log('🧪 TESTES DO NOVO FORMATO WHATSAPP (RENDERER & COMANDOS)');
console.log('============================================================\n');

// 1. Teste de Snapshots dos 3 Casos Obrigatórios (Seção 6)

// Caso 1: [Entrega retida. Pague a taxa em exemplo-ctt.top] com marca CTT identificada => T1
const parsedCaso1 = {
  veredito: 'golpe',
  risco_score: 95,
  marca: 'CTT',
  dominio: 'exemplo-ctt.top',
  dominio_oficial: 'ctt.pt',
  sinais: ['Domínio não oficial a imitar os CTT', 'Taxa urgente']
};
const contractCaso1 = buildDataContract(parsedCaso1, 'Entrega retida. Pague a taxa em https://exemplo-ctt.top');
const msgCaso1 = renderWhatsAppResponse(contractCaso1);

assert(contractCaso1.template === 'link_brand', 'Caso 1 gera template link_brand (T1)');
assert(msgCaso1.includes('🔴 *Provável golpe: não clique nem pague.*'), 'Caso 1 tem título T1');
assert(msgCaso1.includes('o link (exemplo-ctt.top) não é o site oficial de CTT (ctt.pt)'), 'Caso 1 inclui explicação com domínio oficial');
assert(msgCaso1.includes('Se espera algo de CTT, confirme no site ou na app oficial.'), 'Caso 1 inclui ação contextualizada CTT');

// Caso 2: "Ola mae perdi o telemovel e estou temporariamente neste numero..." => T2
const parsedCaso2 = {
  veredito: 'suspeito',
  risco_score: 70,
  sinais: ['Contacto atípico alegando perda de telemóvel']
};
const contractCaso2 = buildDataContract(parsedCaso2, 'Ola mae perdi o telemovel e estou temporariamente neste numero...');
const msgCaso2 = renderWhatsAppResponse(contractCaso2);

assert(contractCaso2.template === 'familiar', 'Caso 2 gera template familiar (T2)');
assert(msgCaso2.includes('🟠 *Suspeito: parece o golpe do "Olá mãe/pai".*'), 'Caso 2 tem título T2 suspeito');
assert(msgCaso2.includes('Ligue para o número habitual do seu familiar'), 'Caso 2 tem recomendação de ligar para número habitual');

// Caso 2b: "Olá mãe... podes mandar 280 euros por mbway?" => T2 sobe para 🔴
const parsedCaso2b = {
  veredito: 'golpe',
  risco_score: 95,
  sinais: ['Pedido de dinheiro via MB WAY']
};
const contractCaso2b = buildDataContract(parsedCaso2b, 'Ola mae perdi o telemovel, podes mandar 280 euros por mbway para pagar uma conta?');
const msgCaso2b = renderWhatsAppResponse(contractCaso2b);
assert(msgCaso2b.includes('🔴 *Provável golpe: não envie dinheiro.*'), 'Caso 2 com pedido de dinheiro sobe para 🔴 Provável golpe');

// Caso 3: [Fatura] Entidade [00000] Ref [000000000] Valor [00,00] EUR => T3
const parsedCaso3 = {
  veredito: 'suspeito',
  risco_score: 50,
  marca: 'EDP Comercial',
  sinais: ['Dados de pagamento por referência']
};
const contractCaso3 = buildDataContract(parsedCaso3, 'Fatura EDP Comercial: Entidade 21249 Ref 123456789 Valor 45,00 EUR');
const msgCaso3 = renderWhatsAppResponse(contractCaso3);

assert(contractCaso3.template === 'reference', 'Caso 3 gera template reference (T3)');
assert(msgCaso3.includes('🟠 *Atenção: confirme antes de pagar.*'), 'Caso 3 tem título neutro de Atenção');
assert(!msgCaso3.toLowerCase().includes('golpe'), 'Caso 3 nunca menciona golpe');
assert(msgCaso3.includes('não conseguimos confirmar a origem do pedido'), 'Caso 3 explica neutralidade');

// Caso 4: Sem sinais de risco => T4
const parsedCaso4 = {
  veredito: 'sem sinais de risco',
  risco_score: 10,
  sinais: []
};
const contractCaso4 = buildDataContract(parsedCaso4, 'Olá pai, já cheguei a casa.');
const msgCaso4 = renderWhatsAppResponse(contractCaso4);
assert(msgCaso4.includes('🟢 *Sem sinais de risco encontrados.*'), 'Caso 4 gera T4 sem sinais de risco');
assert(msgCaso4.includes('Isto não garante que a mensagem seja segura.'), 'Caso 4 avisa sobre ausência de garantia');

// Caso 5: Erro / Timeout => T5
const parsedCaso5 = { isError: true };
const contractCaso5 = buildDataContract(parsedCaso5, '');
const msgCaso5 = renderWhatsAppResponse(contractCaso5);
assert(msgCaso5.includes('⚪ *Não foi possível analisar esta mensagem agora.*'), 'Caso 5 gera T5 em caso de erro');

// 2. Teste Estrito de Caracteres (≤ 600) e Linhas (≤ 12)
const todasMensagens = [
  { nome: 'T1 (Marca CTT)', msg: msgCaso1 },
  { nome: 'T2 (Olá mãe contato)', msg: msgCaso2 },
  { nome: 'T2 (Olá mãe dinheiro)', msg: msgCaso2b },
  { nome: 'T3 (Multibanco neutro)', msg: msgCaso3 },
  { nome: 'T4 (Sem risco)', msg: msgCaso4 },
  { nome: 'T5 (Erro)', msg: msgCaso5 }
];

for (const item of todasMensagens) {
  const charCount = item.msg.length;
  // Conta linhas não-vazias e linhas totais
  const totalLinhas = item.msg.split('\n').length;
  const linhasNaoVazias = item.msg.split('\n').filter(l => l.trim().length > 0).length;

  assert(charCount <= 600, `${item.nome}: tamanho (${charCount} chars) ≤ 600 caracteres`);
  assert(linhasNaoVazias <= 12, `${item.nome}: linhas de conteúdo (${linhasNaoVazias}) ≤ 12 linhas`);
  assert(totalLinhas <= 15, `${item.nome}: total com espaçamento (${totalLinhas}) cabe no ecrã sem colapsar`);
}

// 3. Teste de Termos Proibidos
for (const item of todasMensagens) {
  const lower = item.msg.toLowerCase();
  for (const termo of PROHIBITED_TERMS) {
    // Termos específicos que não devem aparecer como alegações
    const regex = new RegExp(`\\b${termo}\\b`, 'i');
    const hasForbidden = regex.test(lower);
    assert(!hasForbidden, `${item.nome}: NÃO contém o termo proibido "${termo}"`);
  }
}

// 4. Teste de Comandos (AJUDA, DETALHES, ÚTIL, ERRO)
const msgAjuda = renderHelpResponse();
assert(msgAjuda.includes('Já clicou ou pagou? Faça isto agora:'), 'Comando AJUDA exibe protocolo emergencial');
assert(msgAjuda.includes('queixaselectronicas.mai.gov.pt'), 'Comando AJUDA inclui canal oficial do MAI');
assert(msgAjuda.includes('116 006'), 'Comando AJUDA inclui apoio à vítima APAV');

const msgDetalhes = renderDetailsResponse(contractCaso1);
assert(msgDetalhes.includes('*Detalhes da análise:*'), 'Comando DETALHES exibe cabeçalho');
assert(msgDetalhes.includes('Esta análise é automática e pode errar.'), 'Comando DETALHES inclui aviso de falibilidade');
assert(!msgDetalhes.includes('95/100'), 'Comando DETALHES não expõe pontuação numérica ao utilizador');

assert(renderFeedbackResponse('util') === 'Obrigado!', 'Comando ÚTIL responde "Obrigado!"');
assert(renderFeedbackResponse('erro') === 'Obrigado. Vamos rever esta análise.', 'Comando ERRO responde adequadamente');
assert(renderNoSessionResponse().includes('últimas 24 horas'), 'Mensagem sem sessão expira adequadamente');

console.log('\n============================================================');
console.log(`RESULTADO DO RENDERER: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');
