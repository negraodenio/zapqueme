// tests/motor_regressao.test.js
// Regressão do motor de deteção: falsos positivos por substring, link oficial + burla,
// extração de links, encurtadores/SSRF e fallback heurístico. Sem rede.
import assert from 'node:assert/strict';
import {
  checkBrandImpersonation,
  extractUrls,
  isShortenerHost,
  isPrivateIpOrHost,
  unshortenUrl
} from '../lib/threat_intel.js';
import { heuristicAnalyze } from '../lib/scanner.js';

let ok = 0;
const t = (nome, fn) => { fn(); ok++; console.log('✅', nome); };

// --- Falsos positivos do dicionário de marcas (palavras comuns não são marcas)
const legitimas = [
  ['Faz 10 anos que somos clientes. https://padariasantos.pt/aniversario', 'anos'],
  ['Nós enviámos o recibo em https://clinicamendes.pt/recibo/889', 'nós'],
  ['Posteriormente enviaremos o recibo: https://empresa-exemplo.pt/recibo', 'poste'],
  ['Our groups meet Monday https://meetup-lisboa.pt', 'groups'],
  ['Cadeira azul reservada: https://moveis-azul.pt', 'azul'],
  ['Thanks for your purchase https://loja.pt', 'purchase'],
  ['O advogado enviou os honorários https://escritoriosilva.pt/fatura', 'advogado'],
  ['Pagamento da portagem recebido https://empresa.pt/x', 'portagem'],
  ['Ups, enganei-me no link https://minhaloja.pt', 'ups interjeição']
];
for (const [txt, why] of legitimas) {
  t(`sem falso positivo: "${why}"`, () => {
    const r = checkBrandImpersonation(txt.match(/https?:\/\/\S+/)[0], txt);
    assert.ok(!r?.impersonated, `"${why}" não devia acionar marca (obtido ${r?.brand})`);
  });
}
t('hostname gnosis.com / azulejos.pt não acionam NOS / Continente', () => {
  assert.ok(!checkBrandImpersonation('https://gnosis.com/x', 'ola')?.impersonated);
  assert.ok(!checkBrandImpersonation('https://azulejos.pt/x', 'ola')?.impersonated);
});

// --- Continua a apanhar burlas reais
t('apanha ctt-entrega.top mesmo sem texto', () => {
  assert.equal(checkBrandImpersonation('https://ctt-entrega.top/x', 'ola')?.brand, 'CTT');
});
t('apanha cttpagamento colado', () => {
  assert.equal(checkBrandImpersonation('https://cttpagamento.xyz/x', '')?.brand, 'CTT');
});
t('apanha millennium colado no domínio', () => {
  assert.equal(checkBrandImpersonation('https://millennium-bcp-seguro.top', '')?.brand, 'MILLENNIUM');
});
t('apanha NOS pelo token do domínio (nos-fatura.top) e pela expressão "fatura NOS"', () => {
  assert.equal(checkBrandImpersonation('https://nos-fatura.top/x', '')?.brand, 'NOS');
  assert.equal(checkBrandImpersonation('https://faturas-seguras.pt/x', 'A sua fatura NOS está em atraso')?.brand, 'NOS');
});
t('subdomínio falso de domínio oficial é apanhado (ctt.pt.verificacao.com)', () => {
  assert.equal(checkBrandImpersonation('https://ctt.pt.verificacao-fatura.com/pagar', 'CTT encomenda')?.brand, 'CTT');
});
t('domínio oficial não é marcado', () => {
  assert.equal(checkBrandImpersonation('https://www.ctt.pt/rastreio', 'CTT encomenda'), null);
});

// --- Extração de links
const casos = {
  'ctt-entrega.click/abc': 'https://ctt-entrega.click/abc',
  'paga em segura-pagamento.vip agora': 'https://segura-pagamento.vip',
  'vai a minhaconta.icu/login': 'https://minhaconta.icu/login',
  'abre bit.ly/3xyz': 'https://bit.ly/3xyz',
  'abre shorturl.at/abc': 'https://shorturl.at/abc',
  'ver t.ly/xyz': 'https://t.ly/xyz',
  'aviso: mbway-seguro.cc': 'https://mbway-seguro.cc'
};
for (const [entrada, esperado] of Object.entries(casos)) {
  t(`extrai link de "${entrada}"`, () => assert.ok(extractUrls(entrada).includes(esperado), JSON.stringify(extractUrls(entrada))));
}
t('email não é link', () => assert.deepEqual(extractUrls('fale com joao@gmail.com'), []));

// --- Encurtadores e SSRF
t('encurtador por hostname exato (não substring)', () => {
  assert.ok(isShortenerHost('bit.ly'));
  assert.ok(isShortenerHost('www.bit.ly'));
  assert.ok(!isShortenerHost('sunset.com'));
  assert.ok(!isShortenerHost('market.com'));
  assert.ok(!isShortenerHost('evil.t.co.attacker.pt'));
});
t('hosts privados / internos bloqueados', () => {
  for (const h of ['localhost', '127.0.0.1', '10.0.0.5', '169.254.169.254', '2130706433', '0x7f000001', '[::ffff:127.0.0.1]', '::1', 'fc00::1', '100.64.0.1', 'srv.internal']) {
    assert.ok(isPrivateIpOrHost(h), h);
  }
  assert.ok(!isPrivateIpOrHost('ctt.pt'));
});
{ // unshortenUrl não faz pedidos a hosts que não são encurtadores
  const nome = 'unshortenUrl não faz pedidos a hosts que não são encurtadores';
  const antes = globalThis.fetch;
  let chamadas = 0;
  globalThis.fetch = async () => { chamadas++; throw new Error('não devia chamar'); };
  try {
    assert.equal(await unshortenUrl('https://sunset.com/x'), 'https://sunset.com/x');
    assert.equal(chamadas, 0);
  } finally { globalThis.fetch = antes; }
  ok++; console.log('✅', nome);
}

// --- Fallback heurístico
t('heurística: clínica + MB WAY NÃO é legítima', () => {
  const r = heuristicAnalyze('Lembrete: a sua consulta é amanhã. Para confirmar pague 40 euros por MB WAY para 912345678');
  assert.notEqual(r.veredito, 'legitimo');
});
t('heurística: mensagem de família não é golpe', () => {
  assert.notEqual(heuristicAnalyze('Mãe, o pai está no hospital, é urgente, liga-me').veredito, 'golpe');
});
t('heurística: aviso de dispositivo da Netflix não é golpe', () => {
  assert.notEqual(heuristicAnalyze('Novo dispositivo adicionado à sua conta Netflix. Se foi você, ignore.').veredito, 'golpe');
});
t('heurística: falso filho com número novo continua golpe', () => {
  assert.equal(heuristicAnalyze('Oi mãe, troquei de número, o meu telemóvel quebrou. Preciso de um pix urgente').veredito, 'golpe');
});
t('heurística: cartão bloqueado + ligue continua golpe', () => {
  assert.equal(heuristicAnalyze('Vimos que o seu cartão foi bloqueado. Ligue 910000000').veredito, 'golpe');
});
t('heurística: link oficial + MB WAY não é legítimo', () => {
  const r = heuristicAnalyze('CTT: encomenda retida. Veja https://www.ctt.pt/rastreio e pague a taxa por MB WAY para 912345670');
  assert.notEqual(r.veredito, 'legitimo');
});
t('heurística: link oficial sem pedido continua legítimo', () => {
  assert.equal(heuristicAnalyze('CTT: a sua encomenda foi entregue. Detalhes em https://www.ctt.pt/rastreio').veredito, 'legitimo');
});

// aguarda promessas dos testes assíncronos
await new Promise(r => setTimeout(r, 50));
console.log(`\nRESULTADO: ${ok} verificações do motor passaram.`);
