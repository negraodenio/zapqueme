import assert from 'node:assert/strict';
import adminHandler from '../api/admin.js';
import { calcularStatusPublico } from '../api/verify.js';
import { generateHorizontalBadge, generatePrincipalBadge } from '../api/badge.js';

// Assegurar variáveis de ambiente mínimas para testes de rotas
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://mock.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'mock_service_key_for_testing';
process.env.ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';

function mockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(k, v) {
      this.headers[k.toLowerCase()] = v;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    },
    end() {
      return this;
    }
  };
  return res;
}

console.log('\n============================================================');
console.log('🧪 TESTES DE SEGURANÇA E DADOS DE TESTE (FASE 1)');
console.log('============================================================\n');

let passed = 0;
let total = 0;

function run(name, fn) {
  total++;
  try {
    fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}: ${err.message}`);
    process.exitCode = 1;
  }
}

async function runAsync(name, fn) {
  total++;
  try {
    await fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}: ${err.message}`);
    process.exitCode = 1;
  }
}

// -----------------------------------------------------------------------------
// 1. SEGURANÇA: BLOQUEIO SERVER-SIDE SEM AUTENTICAÇÃO
// -----------------------------------------------------------------------------
await runAsync('Critério 1: GET /api/admin sem credenciais devolve 401 e ZERO dados', async () => {
  const req = { method: 'GET', headers: {}, query: {} };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 401, 'Deve devolver status HTTP 401');
  assert.ok(res.body?.error, 'Deve conter mensagem de erro');
  assert.equal(res.body?.empresas, undefined, 'NÃO pode devolver lista de empresas');
  assert.equal(res.body?.leads, undefined, 'NÃO pode devolver leads comerciais');
  assert.equal(res.body?.selos, undefined, 'NÃO pode devolver selos');
  assert.equal(res.body?.kpis, undefined, 'NÃO pode devolver KPIs');
});

await runAsync('Critério 1: POST /api/admin sem credenciais devolve 401 e bloqueia execução', async () => {
  const req = { method: 'POST', headers: {}, body: { action: 'create_empresa', nome: 'Invasor' } };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 401, 'Deve devolver status HTTP 401');
  assert.equal(res.body?.success, undefined, 'Não pode processar a ação');
});

await runAsync('Critério 1: GET /api/admin com chave errada devolve 401', async () => {
  const req = { method: 'GET', headers: { 'x-admin-key': 'chave_falsa_123' }, query: {} };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 401, 'Chave errada deve ser rejeitada com 401');
});

await runAsync('Critério 1: GET /api/admin com header Authorization Bearer válido passa na autenticação', async () => {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';
  const req = { method: 'GET', headers: { authorization: `Bearer ${adminSecret}` }, query: {} };
  const res = mockRes();
  await adminHandler(req, res);

  // Se o Supabase estiver configurado ou com aviso, o status não é 401
  assert.notEqual(res.statusCode, 401, 'Bearer válido não deve ser rejeitado com 401');
});

// -----------------------------------------------------------------------------
// 2. DADOS DE TESTE: PÁGINA PÚBLICA /verify E BADGES
// -----------------------------------------------------------------------------
run('Critério 2: Entidade de teste (is_teste: true) mostra "🧪 Página de teste" e nunca "Ativo"', () => {
  const resTeste = calcularStatusPublico({
    selo: { ativo: true, is_teste: true, valido_ate: '2028-01-01' },
    empresa: { status: 'ativo', estado: 'ativo' }
  });

  assert.equal(resTeste.statusPublico, '🧪 Página de teste', 'Deve indicar claramente que é página de teste');
  assert.equal(resTeste.statusRaw, 'teste');
  assert.equal(resTeste.statusClasse, 'status-teste');
  assert.equal(resTeste.isTeste, true);
  assert.notEqual(resTeste.statusPublico, '✓ Verificação ativa', 'NUNCA pode mostrar Verificação ativa');
});

run('Critério 2: Empresa de teste associada a selo regular também força status de teste', () => {
  const resTeste = calcularStatusPublico({
    selo: { ativo: true, valido_ate: '2028-01-01' },
    empresa: { status: 'ativo', is_teste: true }
  });

  assert.equal(resTeste.statusPublico, '🧪 Página de teste');
  assert.equal(resTeste.isTeste, true);
});

run('Critério 2: Badge Horizontal de teste exibe "PÁGINA DE TESTE" e pílula "TESTE"', () => {
  const svg = generateHorizontalBadge({
    codigo: 'ZQV-TESTE-999',
    empresaNome: 'Banco XPTO',
    status: 'teste',
    statusTexto: 'Página de teste'
  });

  assert.ok(svg.includes('PÁGINA DE TESTE'), 'SVG deve conter PÁGINA DE TESTE');
  assert.ok(svg.includes('TESTE'), 'Pílula do selo deve conter TESTE');
  assert.ok(!svg.includes('CANAIS CONFIRMADOS'), 'NÃO pode exibir CANAIS CONFIRMADOS');
  assert.ok(!svg.includes('OFICIAL'), 'NÃO pode exibir OFICIAL');
});

run('Critério 2: Badge Principal de teste exibe "PÁGINA DE TESTE" em vez de "VERIFICAÇÃO ATIVA"', () => {
  const svg = generatePrincipalBadge({
    codigo: 'ZQV-TESTE-999',
    empresaNome: 'Banco XPTO',
    status: 'teste',
    statusTexto: 'Página de teste'
  });

  assert.ok(svg.includes('PÁGINA DE TESTE'), 'SVG principal deve conter PÁGINA DE TESTE');
  assert.ok(!svg.includes('VERIFICAÇÃO ATIVA'), 'NÃO pode exibir VERIFICAÇÃO ATIVA');
});

// -----------------------------------------------------------------------------
// 3. AÇÕES DESTRUTIVAS: SOFT-DELETE & MOTIVO OBRIGATÓRIO
// -----------------------------------------------------------------------------
run('Critério 4: Arquivamento de selo (arquivado_em) muda status público para inativo', () => {
  const resInativo = calcularStatusPublico({
    selo: { ativo: false, arquivado_em: new Date().toISOString() },
    empresa: { status: 'ativo' }
  });

  assert.equal(resInativo.statusPublico, '⚠️ Verificação inativa');
  assert.equal(resInativo.arquivado, true);
});

await runAsync('Critério 4: Arquivar selo (delete_selo) exige motivo por escrito', async () => {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';
  const req = {
    method: 'POST',
    headers: { 'x-admin-key': adminSecret },
    body: { action: 'delete_selo', selo_id: '123' } // sem motivo
  };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 400, 'Deve rejeitar com 400 sem motivo');
  assert.ok(res.body?.error?.includes('motivo'), 'Mensagem deve indicar que motivo é obrigatório');
});

await runAsync('Critério 4: Regenerar selo (regenerar_selo) exige motivo por escrito', async () => {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';
  const req = {
    method: 'POST',
    headers: { 'x-admin-key': adminSecret },
    body: { action: 'regenerar_selo', selo_id: '123' } // sem motivo
  };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 400, 'Deve rejeitar com 400 sem motivo');
  assert.ok(res.body?.error?.includes('motivo'), 'Mensagem deve indicar que motivo é obrigatório');
});

await runAsync('Critério 4: Suspender empresa (set_empresa_status) exige motivo por escrito', async () => {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';
  const req = {
    method: 'POST',
    headers: { 'x-admin-key': adminSecret },
    body: { action: 'set_empresa_status', id: '123', status: 'suspenso' } // sem motivo
  };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 400, 'Deve rejeitar com 400 sem motivo');
  assert.ok(res.body?.error?.includes('motivo'), 'Mensagem deve indicar que motivo é obrigatório');
});

await runAsync('Critério 4: Arquivar empresa (archive_empresa) exige motivo por escrito', async () => {
  const adminSecret = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';
  const req = {
    method: 'POST',
    headers: { 'x-admin-key': adminSecret },
    body: { action: 'archive_empresa', empresa_id: '123' } // sem motivo
  };
  const res = mockRes();
  await adminHandler(req, res);

  assert.equal(res.statusCode, 400, 'Deve rejeitar com 400 sem motivo');
  assert.ok(res.body?.error?.includes('motivo'), 'Mensagem deve indicar que motivo é obrigatório');
});

console.log('\n============================================================');
console.log(`RESULTADO DA SEGURANÇA & DADOS DE TESTE: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');
