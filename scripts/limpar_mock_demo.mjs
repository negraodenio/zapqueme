import dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !key) {
  console.error('SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY ausente em .env.local');
  process.exit(1);
}

const projectRef = new URL(url).hostname.split('.')[0];
const confirmPhrase = `DELETE MOCK DATA ${projectRef}`;
if (process.env.NODE_ENV === 'production' || process.env.ALLOW_MOCK_DEMO_CLEANUP !== 'true' || process.env.CONFIRM_SUPABASE_PROJECT_REF !== projectRef || process.env.CONFIRM_MOCK_DEMO_DELETE !== confirmPhrase) {
  console.error(`Limpeza cancelada. Use apenas no projeto de demonstração com ALLOW_MOCK_DEMO_CLEANUP=true, CONFIRM_SUPABASE_PROJECT_REF=${projectRef} e CONFIRM_MOCK_DEMO_DELETE="${confirmPhrase}". NODE_ENV=production é sempre recusado.`);
  process.exit(1);
}

const headers = {
  apikey: key,
  Authorization: `Bearer ${key}`
};

async function limpar() {
  console.log('--- Limpando Dados de Demonstração / Apresentação do Supabase ---');

  // 1. Deletar análises mock
  const resAn = await fetch(`${url}/rest/v1/analises?id=like.00000000-0000-4000-8000-40000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resAn.ok) throw new Error(`Falha ao remover análises de demonstração (HTTP ${resAn.status})`);
  console.log('1. Pedidos de remoção de análises enviados:', resAn.status);

  // 2. Deletar leads mock
  const resLe = await fetch(`${url}/rest/v1/leads?id=like.00000000-0000-4000-8000-30000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resLe.ok) throw new Error(`Falha ao remover leads de demonstração (HTTP ${resLe.status})`);
  console.log('2. Pedidos de remoção de leads enviados:', resLe.status);

  // 3. Deletar pagamentos mock
  const resPag = await fetch(`${url}/rest/v1/pagamentos?id=like.00000000-0000-4000-8000-20000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resPag.ok) throw new Error(`Falha ao remover pagamentos de demonstração (HTTP ${resPag.status})`);
  console.log('3. Pedidos de remoção de pagamentos enviados:', resPag.status);

  // 4. Deletar verificações das empresas mock
  const resVer = await fetch(`${url}/rest/v1/verificacoes?empresa_id=like.00000000-0000-4000-8000-00000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resVer.ok) throw new Error(`Falha ao remover verificações de demonstração (HTTP ${resVer.status})`);
  console.log('4. Pedidos de remoção de verificações enviados:', resVer.status);

  // 5. Deletar selos mock
  const resSel = await fetch(`${url}/rest/v1/selos?id=like.00000000-0000-4000-8000-10000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resSel.ok) throw new Error(`Falha ao remover selos de demonstração (HTTP ${resSel.status})`);
  console.log('5. Pedidos de remoção de selos enviados:', resSel.status);

  // 6. Deletar empresas mock
  const resEmp = await fetch(`${url}/rest/v1/empresas?id=like.00000000-0000-4000-8000-00000000000*`, {
    method: 'DELETE',
    headers
  });
  if (!resEmp.ok) throw new Error(`Falha ao remover empresas de demonstração (HTTP ${resEmp.status})`);
  console.log('6. Pedidos de remoção de empresas enviados:', resEmp.status);

  console.log('\nPedidos enviados. Confirme no Supabase que os registos de demonstração foram removidos; isto não restaura o estado anterior da base de dados.');
}

limpar().catch(err => {
  console.error('Falha ao limpar:', err);
  process.exit(1);
});
