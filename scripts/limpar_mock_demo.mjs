import dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !key) {
  console.error('SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY ausente em .env.local');
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
  console.log('1. Análises mock removidas:', resAn.status);

  // 2. Deletar leads mock
  const resLe = await fetch(`${url}/rest/v1/leads?id=like.00000000-0000-4000-8000-30000000000*`, {
    method: 'DELETE',
    headers
  });
  console.log('2. Leads mock removidos:', resLe.status);

  // 3. Deletar pagamentos mock
  const resPag = await fetch(`${url}/rest/v1/pagamentos?id=like.00000000-0000-4000-8000-20000000000*`, {
    method: 'DELETE',
    headers
  });
  console.log('3. Pagamentos mock removidos:', resPag.status);

  // 4. Deletar verificações das empresas mock
  const resVer = await fetch(`${url}/rest/v1/verificacoes?empresa_id=like.00000000-0000-4000-8000-00000000000*`, {
    method: 'DELETE',
    headers
  });
  console.log('4. Verificações mock removidas:', resVer.status);

  // 5. Deletar selos mock
  const resSel = await fetch(`${url}/rest/v1/selos?id=like.00000000-0000-4000-8000-10000000000*`, {
    method: 'DELETE',
    headers
  });
  console.log('5. Selos mock removidos:', resSel.status);

  // 6. Deletar empresas mock
  const resEmp = await fetch(`${url}/rest/v1/empresas?id=like.00000000-0000-4000-8000-00000000000*`, {
    method: 'DELETE',
    headers
  });
  console.log('6. Empresas mock removidas:', resEmp.status);

  console.log('\n🧹 BANCO DE DADOS RESTAURADO AO ESTADO ORIGINAL!');
}

limpar().catch(err => {
  console.error('Falha ao limpar:', err);
  process.exit(1);
});
