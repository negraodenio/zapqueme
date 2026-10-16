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

// 2. Testes de Diversidade dos Mais de 50 Tipos de Golpe (Arquitetura Universal)

// Caso 6: Criptomoedas / Lucro Garantido
const parsedCaso6 = {
  veredito: 'golpe',
  risco_score: 92,
  sinais: ['Promessa irreal de retorno financeiro diário']
};
const contractCaso6 = buildDataContract(parsedCaso6, 'Ganhe 500 euros por dia com retornos garantidos no nosso canal VIP de criptomoedas');
const msgCaso6 = renderWhatsAppResponse(contractCaso6);
assert(contractCaso6.template === 'crypto_investment', 'Caso 6 identifica crypto_investment');
assert(msgCaso6.includes('🔴 *Provável golpe: não envie dinheiro.*'), 'Caso 6 tem título de alerta de envio');
assert(msgCaso6.includes('Não transfira dinheiro nem compre criptoativos'), 'Caso 6 alerta sobre criptoativos');

// Caso 7: Falso Emprego / Tarefas online (Amazon / TikTok)
const parsedCaso7 = {
  veredito: 'golpe',
  risco_score: 88,
  sinais: ['Oferta de emprego com pagamento por tarefas e pagamento de taxas']
};
const contractCaso7 = buildDataContract(parsedCaso7, 'Recrutamento Amazon: ganhe 150€ a 300€ por dia a avaliar produtos e vídeos. Envie mensagem.');
const msgCaso7 = renderWhatsAppResponse(contractCaso7);
assert(contractCaso7.template === 'job_offer', 'Caso 7 identifica job_offer');
assert(msgCaso7.includes('🔴 *Provável golpe: não faça pagamentos.*'), 'Caso 7 tem título de emprego falso');
assert(msgCaso7.includes('Nenhuma empresa séria cobra dinheiro para trabalhar'), 'Caso 7 orienta sobre recrutamento');

// Caso 8: Burla MB WAY no Multibanco (vendedor OLX / Vinted)
const parsedCaso8 = {
  veredito: 'golpe',
  risco_score: 95,
  sinais: ['Tentativa de manipular a vítima para ir ao multibanco associar número']
};
const contractCaso8 = buildDataContract(parsedCaso8, 'Quero comprar o artigo no OLX. Vá a uma caixa Multibanco, selecione outras operações e coloque o meu número.');
const msgCaso8 = renderWhatsAppResponse(contractCaso8);
assert(contractCaso8.template === 'mbway_seller', 'Caso 8 identifica mbway_seller');
assert(msgCaso8.includes('🔴 *Provável golpe: não vá ao Multibanco.*'), 'Caso 8 alerta especificamente contra ida ao ATM');
assert(msgCaso8.includes('Para receber por MB WAY só precisa de dar o seu número'), 'Caso 8 esclarece mecanismo do MB WAY');

// Caso 9: Falso Apoio Bancário por Telefone / Spoofing
const parsedCaso9 = {
  veredito: 'golpe',
  risco_score: 90,
  sinais: ['Alerta de segurança forjado para induzir chamada telefónica']
};
const contractCaso9 = buildDataContract(parsedCaso9, 'Alerta de segurança: cartão bloqueado por suspeita de fraude. Ligue já para 912345678.');
const msgCaso9 = renderWhatsAppResponse(contractCaso9);
assert(contractCaso9.template === 'fake_bank_support', 'Caso 9 identifica fake_bank_support');
assert(msgCaso9.includes('🔴 *Provável golpe: não ligue para este número.*'), 'Caso 9 alerta contra ligar para o número');
assert(msgCaso9.includes('número no verso do cartão'), 'Caso 9 recomenda ligar para o verso do cartão');

// Caso 10: Falsa Notificação Policial / Judicial
const parsedCaso10 = {
  veredito: 'golpe',
  risco_score: 95,
  sinais: ['Ameaça de prisão da Polícia Judiciária para cobrança de multa']
};
const contractCaso10 = buildDataContract(parsedCaso10, 'Polícia Judiciária e Europol: mandado de detenção iminente por infração na internet. Pague a caução de 500€.');
const msgCaso10 = renderWhatsAppResponse(contractCaso10);
assert(contractCaso10.template === 'fake_police_legal', 'Caso 10 identifica fake_police_legal');
assert(msgCaso10.includes('🔴 *Provável golpe: não responda nem pague.*'), 'Caso 10 tem título de notificação judicial');

// Caso 11: Golpe Dinâmico Universal (ex: burla de chantagem ou categoria atípica sem template fixo)
const parsedCaso11 = {
  veredito: 'golpe',
  risco_score: 85,
  explicacao_simples: 'A mensagem exige resgate sob ameaça de divulgação de alegadas gravações privadas.',
  sinais: ['Extorsão digital sem prova técnica']
};
const contractCaso11 = buildDataContract(parsedCaso11, 'Temos controlo do seu computador e gravámos vídeos seus. Pague 300€ ou enviamos aos seus contactos.');
const msgCaso11 = renderWhatsAppResponse(contractCaso11);
assert(contractCaso11.template === 'general_scam', 'Caso 11 cai no motor universal general_scam');
assert(msgCaso11.includes('🔴 *Provável golpe: não pague nem aceda.*'), 'Caso 11 gera título universal de alerta');
assert(msgCaso11.includes('a mensagem exige resgate sob ameaça'), 'Caso 11 sintetiza explicação higienizada');
assert(msgCaso11.includes('1. Não clique em links, não forneça códigos nem transfira dinheiro.'), 'Caso 11 aplica 3 passos universais');

// 3. Teste Estrito de Caracteres (≤ 600) e Linhas (≤ 12) para TODAS as categorias
const todasMensagens = [
  { nome: 'T1 (Marca CTT)', msg: msgCaso1 },
  { nome: 'T2 (Olá mãe contato)', msg: msgCaso2 },
  { nome: 'T2 (Olá mãe dinheiro)', msg: msgCaso2b },
  { nome: 'T3 (Multibanco neutro)', msg: msgCaso3 },
  { nome: 'T4 (Sem risco)', msg: msgCaso4 },
  { nome: 'T5 (Erro)', msg: msgCaso5 },
  { nome: 'Cripto / Investimento', msg: msgCaso6 },
  { nome: 'Falso Emprego / Tarefas', msg: msgCaso7 },
  { nome: 'MB WAY Vendedor OLX', msg: msgCaso8 },
  { nome: 'Falso Apoio Bancário', msg: msgCaso9 },
  { nome: 'Falsa Notificação PJ', msg: msgCaso10 },
  { nome: 'Golpe Dinâmico Universal', msg: msgCaso11 }
];

for (const item of todasMensagens) {
  const charCount = item.msg.length;
  // Conta linhas não-vazias e linhas totais
  const totalLinhas = item.msg.split('\n').length;
  const linhasNaoVazias = item.msg.split('\n').filter(l => l.trim().length > 0).length;

  assert(charCount <= 600, `${item.nome}: tamanho (${charCount} chars) ≤ 600 caracteres`);
  assert(linhasNaoVazias <= 12, `${item.nome}: linhas de conteúdo (${linhasNaoVazias}) ≤ 12 linhas`);
  assert(totalLinhas <= 16, `${item.nome}: total com espaçamento (${totalLinhas}) cabe no ecrã sem colapsar`);
}

// 4. Teste de Termos Proibidos
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
