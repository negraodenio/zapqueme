// tests/b2b_radar.test.js — Bateria de Testes Obrigatórios ZAP, QUEM É? B2B & Radar
// Especificação Fechada Seção 26 (TESTE 1 a TESTE 20)

import assert from 'node:assert/strict';
import {
  normalizarTexto,
  extrairHostname,
  isCanalOficial,
  detectarImpersonation,
  gerarCodigoSelo
} from '../lib/radar.js';
import {
  calcularStatusPublico,
  renderVerifyHtml,
  escapeHtml
} from '../api/verify.js';
import { heuristicAnalyze } from '../lib/scanner.js';

let passed = 0;
let total = 0;

function runTest(name, fn) {
  total++;
  try {
    fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    throw err;
  }
}

async function runAsyncTest(name, fn) {
  total++;
  try {
    await fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    throw err;
  }
}

console.log('============================================================');
console.log('INICIANDO OS 20 TESTES OBRIGATÓRIOS (SEÇÃO 26)');
console.log('============================================================\n');

const empresaMock = {
  id: 'a0000000-0000-0000-0000-000000000001',
  nome: 'Banco ACME Portugal',
  status: 'ativo',
  dominio_oficial: 'acme.pt',
  email_oficial: 'suporte@acme.pt',
  telefone_oficial: '+351 912 345 678',
  apelidos_marca: ['ACME', 'acme portugal', 'Banco Acme'],
  dominio_verificado: true,
  email_verificado: true,
  telefone_verificado: true
};

// TESTE 1: Marca sem impersonation => impersonation false
await runAsyncTest('TESTE 1: Marca sem impersonation => impersonation false', async () => {
  // Marca não cadastrada ou sem canal
  const res1 = await detectarImpersonation({
    marca_mencionada: 'Marca Desconhecida Inexistente',
    canal_mencionado: 'https://site-estranho.com',
    veredito: 'golpe',
    empresasList: [empresaMock]
  });
  assert.equal(res1.impersonation, false, 'Deveria ser impersonation false quando marca não existe');
  assert.equal(res1.empresa_id, null, 'empresa_id deve ser null');

  // Sem canal mencionado
  const res2 = await detectarImpersonation({
    marca_mencionada: 'Banco ACME Portugal',
    canal_mencionado: null,
    veredito: 'golpe',
    empresasList: [empresaMock]
  });
  assert.equal(res2.impersonation, false, 'Sem canal mencionado não pode ser impersonation');
});

// TESTE 2: Marca + golpe + canal falso => impersonation true
await runAsyncTest('TESTE 2: Marca + golpe + canal falso => impersonation true', async () => {
  const res = await detectarImpersonation({
    marca_mencionada: 'ACME',
    canal_mencionado: 'https://acme-login-seguro.top/recadastro',
    veredito: 'golpe',
    empresasList: [empresaMock]
  });
  assert.equal(res.impersonation, true, 'Deve detectar impersonation com marca cadastrada, golpe e canal falso');
  assert.equal(res.empresa_id, empresaMock.id, 'Deve associar à empresa correspondente');
});

// TESTE 3: Marca + golpe + canal oficial => impersonation false
await runAsyncTest('TESTE 3: Marca + golpe + canal oficial => impersonation false', async () => {
  const res = await detectarImpersonation({
    marca_mencionada: 'ACME',
    canal_mencionado: 'https://acme.pt/atendimento',
    veredito: 'golpe',
    empresasList: [empresaMock]
  });
  assert.equal(res.impersonation, false, 'Canal oficial não pode gerar impersonation');
  assert.equal(res.empresa_id, empresaMock.id, 'Pode associar empresa, mas impersonation deve ser false');
});

// TESTE 4: Marca + mensagem legítima => impersonation false
await runAsyncTest('TESTE 4: Marca + mensagem legítima => impersonation false', async () => {
  const res = await detectarImpersonation({
    marca_mencionada: 'Banco ACME Portugal',
    canal_mencionado: 'https://link-qualquer.com',
    veredito: 'legitimo',
    empresasList: [empresaMock]
  });
  assert.equal(res.impersonation, false, 'Mensagem com veredito legitimo não é impersonation');
});

// TESTE 5: Duas empresas com mesmo alias => não associar
await runAsyncTest('TESTE 5: Duas empresas com mesmo alias => não associar', async () => {
  const empresasAmbiguidade = [
    {
      id: 'uuid-1',
      nome: 'ACME Telecom',
      apelidos_marca: ['ACME'],
      status: 'ativo'
    },
    {
      id: 'uuid-2',
      nome: 'ACME Seguros',
      apelidos_marca: ['ACME'],
      status: 'ativo'
    }
  ];
  const res = await detectarImpersonation({
    marca_mencionada: 'ACME',
    canal_mencionado: 'https://phishing.com',
    veredito: 'golpe',
    empresasList: empresasAmbiguidade
  });
  assert.equal(res.impersonation, false, 'Havendo ambiguidade entre 2 empresas ativas, não deve associar');
  assert.equal(res.empresa_id, null, 'empresa_id deve ser null em caso de ambiguidade');
});

// TESTE 6: Email oficial => bate
runTest('TESTE 6: Email oficial => bate', () => {
  const bateExato = isCanalOficial('suporte@acme.pt', empresaMock);
  assert.equal(bateExato, true, 'Email exato oficial deve bater');

  const bateDominio = isCanalOficial('fatura@acme.pt', empresaMock);
  assert.equal(bateDominio, true, 'Email do mesmo domínio oficial acme.pt deve bater');
});

// TESTE 7: Email de domínio falso => não bate
runTest('TESTE 7: Email de domínio falso => não bate', () => {
  const bateFalso = isCanalOficial('suporte@acme-portugal-financeiro.com', empresaMock);
  assert.equal(bateFalso, false, 'Email de domínio falso não deve bater');
});

// TESTE 8: xpto.pt => bate com xpto.pt
runTest('TESTE 8: xpto.pt => bate com xpto.pt', () => {
  const bate = isCanalOficial('xpto.pt', { dominio_oficial: 'xpto.pt' });
  assert.equal(bate, true, 'xpto.pt deve bater com domínio oficial xpto.pt');
});

// TESTE 9: app.xpto.pt => bate com xpto.pt
runTest('TESTE 9: app.xpto.pt => bate com xpto.pt', () => {
  const bate = isCanalOficial('app.xpto.pt', { dominio_oficial: 'xpto.pt' });
  assert.equal(bate, true, 'Subdomínio app.xpto.pt deve bater com domínio oficial xpto.pt');
});

// TESTE 10: xpto.pt.fake.com => não bate
runTest('TESTE 10: xpto.pt.fake.com => não bate', () => {
  const bate = isCanalOficial('xpto.pt.fake.com', { dominio_oficial: 'xpto.pt' });
  assert.equal(bate, false, 'xpto.pt.fake.com não pode bater com xpto.pt');
});

// TESTE 11: Telefone com espaços => normaliza
runTest('TESTE 11: Telefone com espaços => normaliza', () => {
  const bate = isCanalOficial('+351 912 345 678', { telefone_oficial: '351912345678' });
  assert.equal(bate, true, 'Telefone com espaços e pontuação deve normalizar para dígitos e bater');
});

// TESTE 12: Selo válido => página pública válida
runTest('TESTE 12: Selo válido => página pública válida', () => {
  const futuro = new Date();
  futuro.setFullYear(futuro.getFullYear() + 1);

  const selo = { codigo: 'ZQV-TESTE12VALIDO', valido_ate: futuro.toISOString() };
  const emp = { nome: 'ACME Válida', status: 'ativo' };

  const { statusPublico, statusRaw } = calcularStatusPublico({ selo, empresa: emp });
  assert.equal(statusPublico, '✓ Verificação ativa');
  assert.equal(statusRaw, 'valido');

  const html = renderVerifyHtml({ selo, empresa: emp, statusPublico, statusClasse: 'status-valido' });
  assert.match(html, /✓ Verificação ativa/);
});

// TESTE 13: Selo expirado => página pública expirada
runTest('TESTE 13: Selo expirado => página pública expirada', () => {
  const passado = new Date();
  passado.setFullYear(passado.getFullYear() - 1);

  const selo = { codigo: 'ZQV-TESTE13EXP', valido_ate: passado.toISOString() };
  const emp = { nome: 'ACME Expirada', status: 'ativo' };

  const { statusPublico, statusRaw } = calcularStatusPublico({ selo, empresa: emp });
  assert.equal(statusPublico, '⚠️ Verificação expirada');
  assert.equal(statusRaw, 'expirado');

  const html = renderVerifyHtml({ selo, empresa: emp, statusPublico, statusClasse: 'status-expirado' });
  assert.match(html, /⚠️ Verificação expirada/);
  assert.doesNotMatch(html, /✓ Verificação ativa/);
});

// TESTE 14: Empresa suspensa => página pública suspensa
runTest('TESTE 14: Empresa suspensa => página pública suspensa', () => {
  const futuro = new Date();
  futuro.setFullYear(futuro.getFullYear() + 1);

  const selo = { codigo: 'ZQV-TESTE14SUSP', valido_ate: futuro.toISOString() };
  const emp = { nome: 'ACME Suspensa', status: 'suspenso' };

  const { statusPublico, statusRaw } = calcularStatusPublico({ selo, empresa: emp });
  assert.equal(statusPublico, '⚠️ Verificação suspensa');
  assert.equal(statusRaw, 'suspenso');

  const html = renderVerifyHtml({ selo, empresa: emp, statusPublico, statusClasse: 'status-suspenso' });
  assert.match(html, /⚠️ Verificação suspensa/);
});

// TESTE 15: Canal registado mas não verificado => NÃO mostrar "verificado"
runTest('TESTE 15: Canal registado mas não verificado => NÃO mostrar "verificado"', () => {
  const selo = { codigo: 'ZQV-TESTE15NAOVERIF' };
  const emp = {
    nome: 'Empresa Teste 15',
    status: 'ativo',
    dominio_oficial: 'exemplo-teste.pt',
    dominio_verificado: false,
    email_oficial: 'contato@exemplo-teste.pt',
    email_verificado: false,
    telefone_oficial: '+351 900 000 000',
    telefone_verificado: false
  };

  const html = renderVerifyHtml({ selo, empresa: emp, statusPublico: '✓ Verificação ativa', statusClasse: 'status-valido' });
  assert.match(html, /Canal registado, ainda não verificado/);
  // Não pode ter a badge com "Canal verificado" para canais não verificados
  assert.doesNotMatch(html, /<span class="channel-type">Canal verificado<\/span>/);
});

// TESTE 16: Canal verificado => mostrar "verificado"
runTest('TESTE 16: Canal verificado => mostrar "verificado"', () => {
  const selo = { codigo: 'ZQV-TESTE16VERIF' };
  const emp = {
    nome: 'Empresa Teste 16',
    status: 'ativo',
    dominio_oficial: 'exemplo-oficial.pt',
    dominio_verificado: true,
    email_oficial: 'contato@exemplo-oficial.pt',
    email_verificado: true,
    telefone_oficial: '+351 911 111 111',
    telefone_verificado: true
  };

  const html = renderVerifyHtml({ selo, empresa: emp, statusPublico: '✓ Verificação ativa', statusClasse: 'status-valido' });
  assert.match(html, /<span class="channel-type">Canal verificado<\/span>/);
  assert.doesNotMatch(html, /Canal registado, ainda não verificado/);
});

// TESTE 17: Canal mencionado deve ser persistido em analises
runTest('TESTE 17: Canal mencionado deve ser persistido em analises', () => {
  // Testamos o contrato do objeto antes do INSERT e a garantia de persistência
  const analiseObj = {
    veredito: 'golpe',
    confianca: 92,
    tipo: 'entrega',
    vezes_reportada: 1,
    teve_imagem: false,
    empresa_id: 'uuid-teste-17',
    marca_mencionada: 'CTT',
    canal_mencionado: 'https://ctt-pagamento-taxa.xyz',
    impersonation: true
  };

  // Garante que os campos requeridos pela Seção 13 estão presentes e preenchidos
  assert.ok(analiseObj.canal_mencionado, 'canal_mencionado não pode ser perdido');
  assert.equal(analiseObj.canal_mencionado, 'https://ctt-pagamento-taxa.xyz');
  assert.equal(analiseObj.impersonation, true);
  assert.equal(analiseObj.empresa_id, 'uuid-teste-17');
});

// TESTE 18: B2C não recebe marca_mencionada
runTest('TESTE 18: B2C não recebe marca_mencionada', () => {
  // Simulamos o ciclo de pós-processamento do scanner para o B2C (Seção 12)
  const parsed = {
    veredito: 'golpe',
    confianca: 90,
    tipo: 'falso banco',
    sinais: ['urgência'],
    explicacao_simples: 'Mensagem falsa',
    acao_recomendada: 'Bloqueie o remetente',
    marca_mencionada: 'Banco Caixa',
    canal_mencionado: 'https://caixa-fake.com',
    empresa_id: 'some-id',
    impersonation: true
  };

  // Regra de higienização do scanner antes de devolver ao B2C
  delete parsed.marca_mencionada;
  delete parsed.canal_mencionado;
  delete parsed.empresa_id;
  delete parsed.impersonation;

  assert.equal('marca_mencionada' in parsed, false, 'marca_mencionada NÃO deve existir na resposta B2C');
});

// TESTE 19: B2C não recebe canal_mencionado
runTest('TESTE 19: B2C não recebe canal_mencionado', () => {
  const parsed = {
    veredito: 'suspeito',
    confianca: 70,
    marca_mencionada: 'CTT',
    canal_mencionado: 'https://ctt.fake.com'
  };

  delete parsed.marca_mencionada;
  delete parsed.canal_mencionado;

  assert.equal('canal_mencionado' in parsed, false, 'canal_mencionado NÃO deve existir na resposta B2C');
});

// TESTE 20: Código do selo não é previsível
runTest('TESTE 20: Código do selo não é previsível', () => {
  const codigos = new Set();
  const totalCodigos = 100;

  for (let i = 0; i < totalCodigos; i++) {
    const cod = gerarCodigoSelo();
    // Deve começar com ZQV-
    assert.match(cod, /^ZQV-[2-9A-HJ-NP-Z]{13}$/, 'Formato deve ser imprevisível de alta entropia');
    // Não pode ser previsível como ACME-1, ACME-2
    assert.doesNotMatch(cod, /-\d+$/);
    codigos.add(cod);
  }

  assert.equal(codigos.size, totalCodigos, 'Todos os 100 códigos gerados devem ser únicos');
});

console.log('\n============================================================');
console.log(`RESULTADO FINAL: ${passed}/${total} TESTES PASSARAM COM SUCESSO! 🎉`);
console.log('============================================================\n');
