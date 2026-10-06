// tests/preproduction_fixes.test.js
// Testes automatizados das correções de pré-produção B2B (Phase 1 a 6)
import assert from 'node:assert/strict';
import { calcularStatusPublico } from '../api/verify.js';
import { generateHorizontalBadge } from '../api/badge.js';
import adminHandler from '../api/admin.js';
import empresaHandler from '../api/empresa.js';
import analyzeHandler from '../api/analyze.js';

let totalTests = 0;
let passedTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`✅ [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    process.exitCode = 1;
  }
}

async function runAsyncTest(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`✅ [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    process.exitCode = 1;
  }
}

console.log('============================================================');
console.log('TESTES DAS CORREÇÕES DE PRÉ-PRODUÇÃO (PHASES 1 - 6)');
console.log('============================================================\n');

// 1. calcularStatusPublico com selo desativado (soft-deleted)
runTest('TESTE FIX-01: Selo com ativo=false retorna status "inativo"', () => {
  const selo = { codigo: 'ZQV-TESTEINATIVO', ativo: false, valido_ate: new Date(Date.now() + 86400000).toISOString() };
  const emp = { nome: 'Empresa Teste', status: 'ativo' };

  const { statusPublico, statusRaw, statusClasse } = calcularStatusPublico({ selo, empresa: emp });
  assert.equal(statusRaw, 'inativo', 'Selo inativo deve ter statusRaw = inativo');
  assert.equal(statusPublico, '⚠️ Verificação inativa');
  assert.equal(statusClasse, 'status-inativo');
});

// 2. Admin Security: rejeita chamada sem chave
await runAsyncTest('TESTE FIX-02: Admin rejeita requisições sem x-admin-key (401)', async () => {
  process.env.ADMIN_SECRET_KEY = 'zaptestsecret123';
  const req = {
    method: 'GET',
    headers: {},
    query: {}
  };
  let statusCode = 0;
  let responseData = null;
  const res = {
    status(c) { statusCode = c; return this; },
    json(d) { responseData = d; return this; }
  };

  await adminHandler(req, res);
  assert.equal(statusCode, 401, 'Deve retornar 401 Unauthorized');
  assert.match(responseData.error, /Acesso não autorizado/);
});

// 3. Admin Security: rejeita chave passada via query param (?secret=)
await runAsyncTest('TESTE FIX-03: Admin rejeita secret passado via ?secret= query param (401)', async () => {
  process.env.ADMIN_SECRET_KEY = 'zaptestsecret123';
  const req = {
    method: 'GET',
    headers: {},
    query: { secret: 'zaptestsecret123' }
  };
  let statusCode = 0;
  let responseData = null;
  const res = {
    status(c) { statusCode = c; return this; },
    json(d) { responseData = d; return this; }
  };

  await adminHandler(req, res);
  assert.equal(statusCode, 401, 'Deve rejeitar secret via query parameter');
});

// 4. Admin Security: aceita chamada com header x-admin-key correto
await runAsyncTest('TESTE FIX-04: Admin aceita x-admin-key válido no header', async () => {
  process.env.ADMIN_SECRET_KEY = 'zaptestsecret123';
  const req = {
    method: 'GET',
    headers: { 'x-admin-key': 'zaptestsecret123' },
    query: {}
  };
  let statusCode = 0;
  let responseData = null;
  const res = {
    status(c) { statusCode = c; return this; },
    json(d) { responseData = d; return this; }
  };

  // Testa autenticação prévia
  await adminHandler(req, res);
  assert.notEqual(statusCode, 401, 'Não deve retornar 401 quando x-admin-key está correto');
});

// 5. api/empresa.js valida parâmetros obrigatórios
await runAsyncTest('TESTE FIX-05: api/empresa.js exige codigo, dominio ou slug', async () => {
  const req = {
    method: 'GET',
    query: {},
    headers: {}
  };
  let statusCode = 0;
  let responseData = null;
  const res = {
    setHeader() {},
    status(c) { statusCode = c; return this; },
    json(d) { responseData = d; return this; }
  };

  await empresaHandler(req, res);
  assert.equal(statusCode, 400, 'Deve retornar 400 para requisição sem parâmetros');
  assert.match(responseData.error, /Parâmetro codigo, dominio ou slug é obrigatório/);
});

// 6. api/analyze.js rate limiting
await runAsyncTest('TESTE FIX-06: api/analyze.js rejeita requisições não-POST com 405', async () => {
  const req = {
    method: 'GET',
    headers: {}
  };
  let statusCode = 0;
  let responseData = null;
  const res = {
    status(c) { statusCode = c; return this; },
    json(d) { responseData = d; return this; }
  };

  await analyzeHandler(req, res);
  assert.equal(statusCode, 405, 'Deve retornar 405 Method Not Allowed para GET');
});

// 7. Badge SVG reflete status inativo
runTest('TESTE FIX-07: Badge Horizontal reflete status inativo', () => {
  const svg = generateHorizontalBadge({
    codigo: 'ZQV-TESTEINATIVO',
    empresaNome: 'Empresa Desativada',
    status: 'inativo',
    statusTexto: 'Verificação inativa'
  });

  assert.match(svg, /VERIFICAÇÃO EXPIRADA|VERIFICAÇÃO SUSPENSA|#f59e0b/);
  assert.doesNotMatch(svg, /CANAIS CONFIRMADOS/);
});

console.log('\n============================================================');
console.log(`RESULTADO DOS FIXES: ${passedTests}/${totalTests} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
