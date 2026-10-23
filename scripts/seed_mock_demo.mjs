import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config({ path: '.env.local' });

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !key) {
  console.error('SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY ausente em .env.local');
  process.exit(1);
}

const headers = {
  'Content-Type': 'application/json',
  apikey: key,
  Authorization: `Bearer ${key}`,
  Prefer: 'return=representation'
};

const MOCK_TAG = '[MOCK_DEMO_2026]';

async function seed() {
  console.log('--- Iniciando Seed de Dados de Demonstração (Apresentação ZapQuemÉ) ---');

  // 1. EMPRESAS
  const empresasMock = [
    {
      id: '00000000-0000-4000-8000-000000000001',
      nome: 'Clínica Dentária Santa Madalena',
      nome_legal: 'Santa Madalena Cuidados Dentários Lda',
      nome_comercial: 'Clínica Santa Madalena',
      nif: '509812345',
      nif_verificado: true,
      dominio_oficial: 'clinicasantamadalena.pt',
      dominio_verificado: true,
      telefone_oficial: '+351 21 000 1122',
      telefone_verificado: true,
      email_oficial: 'contacto@clinicasantamadalena.pt',
      email_verificado: true,
      email_contacto: 'direcao@clinicasantamadalena.pt',
      representante_nome: 'Dr. António Ferreira',
      representante_cargo: 'Diretor Clínico',
      estado: 'ativo',
      plano: 'selo',
      preco_acordado: 49,
      codigo_selo: 'MADALENA-7821',
      status: 'ativo',
      is_teste: false,
      notas: `${MOCK_TAG} Empresa com selo ativo para apresentação.`
    },
    {
      id: '00000000-0000-4000-8000-000000000002',
      nome: 'Lusitana Mediação Imobiliária',
      nome_legal: 'Lusitana Imóveis Lda',
      nome_comercial: 'Lusitana Mediação Imobiliária',
      nif: '508123987',
      nif_verificado: true,
      dominio_oficial: 'lusitanaimoveis.pt',
      dominio_verificado: true,
      telefone_oficial: '+351 21 999 4455',
      telefone_verificado: true,
      email_oficial: 'info@lusitanaimoveis.pt',
      email_verificado: true,
      email_contacto: 'carlos.mendes@lusitanaimoveis.pt',
      representante_nome: 'Carlos Mendes',
      representante_cargo: 'Sócio-Gerente',
      estado: 'ativo',
      plano: 'selo',
      preco_acordado: 49,
      codigo_selo: 'LUSITANA-3942',
      status: 'ativo',
      is_teste: false,
      notas: `${MOCK_TAG} Empresa com selo ativo para apresentação.`
    },
    {
      id: '00000000-0000-4000-8000-000000000003',
      nome: 'Almeida & Associados - Advogados',
      nome_legal: 'Almeida & Associados Sociedade de Advogados SP RL',
      nome_comercial: 'Almeida & Associados',
      nif: '507456123',
      nif_verificado: true,
      dominio_oficial: 'almeidaadvogados.pt',
      dominio_verificado: true,
      telefone_oficial: '+351 22 555 8899',
      telefone_verificado: true,
      email_oficial: 'geral@almeidaadvogados.pt',
      email_verificado: true,
      email_contacto: 'sofia.barreto@almeidaadvogados.pt',
      representante_nome: 'Dra. Sofia Barreto',
      representante_cargo: 'Sócia Coordenadora',
      estado: 'ativo',
      plano: 'selo',
      preco_acordado: 49,
      codigo_selo: 'ALMEIDA-5510',
      status: 'ativo',
      is_teste: false,
      notas: `${MOCK_TAG} Sociedade de advogados com selo anti-impersonation ativo.`
    },
    {
      id: '00000000-0000-4000-8000-000000000004',
      nome: 'TechLog Ibérica - Logística & Express',
      nome_legal: 'TechLog Soluções de Transporte Ibérico SA',
      nome_comercial: 'TechLog Ibérica',
      nif: '510334889',
      nif_verificado: true,
      dominio_oficial: 'techlog-express.pt',
      dominio_verificado: true,
      telefone_oficial: '+351 21 333 7788',
      telefone_verificado: true,
      email_oficial: 'operacoes@techlog-express.pt',
      email_verificado: true,
      email_contacto: 'seguranca@techlog-express.pt',
      representante_nome: 'Manuel Matos',
      representante_cargo: 'CISO / Diretor de Operações',
      estado: 'ativo',
      plano: 'radar',
      preco_acordado: 290,
      codigo_selo: 'TECHLOG-9901',
      status: 'ativo',
      is_teste: false,
      notas: `${MOCK_TAG} Cliente acompanhamento Threat Radar ativo.`
    },
    {
      id: '00000000-0000-4000-8000-000000000005',
      nome: 'Farmácia Central de Cascais',
      nome_legal: 'Farmácia Central Cascais Unipessoal Lda',
      nome_comercial: 'Farmácia Central Cascais',
      nif: '502119933',
      nif_verificado: true,
      dominio_oficial: 'farmaciacentralcascais.pt',
      dominio_verificado: true,
      telefone_oficial: '+351 21 484 0000',
      telefone_verificado: false,
      email_oficial: 'geral@farmaciacentralcascais.pt',
      email_verificado: true,
      email_contacto: 'dra.mariana@farmaciacentralcascais.pt',
      representante_nome: 'Dra. Mariana Santos',
      representante_cargo: 'Farmacêutica Diretora Técnica',
      estado: 'em_verificacao',
      plano: 'selo',
      preco_acordado: 49,
      codigo_selo: null,
      status: 'inativo',
      is_teste: false,
      notas: `${MOCK_TAG} Em processo de validação do número de WhatsApp.`
    },
    {
      id: '00000000-0000-4000-8000-000000000006',
      nome: 'AutoMecânica Ribatejana',
      nome_legal: 'Auto Reparadora do Ribatejo Lda',
      nome_comercial: 'AutoMecânica Ribatejana',
      nif: '503221144',
      dominio_oficial: 'automecanicaribatejo.pt',
      telefone_oficial: '+351 243 000 111',
      email_oficial: 'oficina@automecanicaribatejo.pt',
      representante_nome: 'João Pedro Silva',
      representante_cargo: 'Proprietário',
      estado: 'lead',
      plano: 'selo',
      preco_acordado: 49,
      codigo_selo: null,
      status: 'inativo',
      is_teste: false,
      notas: `${MOCK_TAG} Proposta enviada após contacto comercial.`
    }
  ];

  console.log('1. Inserindo empresas mock...');
  for (const emp of empresasMock) {
    const res = await fetch(`${url}/rest/v1/empresas`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify(emp)
    });
    if (!res.ok) console.warn('Erro ao inserir empresa:', emp.nome, await res.text());
  }

  // 2. SELOS
  const selosMock = [
    {
      id: '00000000-0000-4000-8000-100000000001',
      empresa_id: '00000000-0000-4000-8000-000000000001',
      codigo: 'MADALENA-7821',
      tipo: 'selo',
      ativo: true,
      monitorizacao_impersonation: true,
      valido_ate: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      is_teste: false
    },
    {
      id: '00000000-0000-4000-8000-100000000002',
      empresa_id: '00000000-0000-4000-8000-000000000002',
      codigo: 'LUSITANA-3942',
      tipo: 'selo',
      ativo: true,
      monitorizacao_impersonation: true,
      valido_ate: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      is_teste: false
    },
    {
      id: '00000000-0000-4000-8000-100000000003',
      empresa_id: '00000000-0000-4000-8000-000000000003',
      codigo: 'ALMEIDA-5510',
      tipo: 'selo',
      ativo: true,
      monitorizacao_impersonation: true,
      valido_ate: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      is_teste: false
    },
    {
      id: '00000000-0000-4000-8000-100000000004',
      empresa_id: '00000000-0000-4000-8000-000000000004',
      codigo: 'TECHLOG-9901',
      tipo: 'radar',
      ativo: true,
      monitorizacao_impersonation: true,
      valido_ate: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      is_teste: false
    }
  ];

  console.log('2. Inserindo selos mock...');
  for (const selo of selosMock) {
    const res = await fetch(`${url}/rest/v1/selos`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify(selo)
    });
    if (!res.ok) console.warn('Erro ao inserir selo:', selo.codigo, await res.text());
  }

  // 3. VERIFICACOES (4 Pilares)
  console.log('3. Inserindo verificações dos 4 pilares...');
  const pilares = ['nif', 'dominio', 'telefone', 'representante'];
  let vIdx = 1;
  for (const emp of empresasMock.slice(0, 4)) {
    for (const p of pilares) {
      const vId = `00000000-0000-4000-8000-5000000000${String(vIdx++).padStart(2, '0')}`;
      await fetch(`${url}/rest/v1/verificacoes`, {
        method: 'POST',
        headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
        body: JSON.stringify({
          id: vId,
          empresa_id: emp.id,
          tipo: p,
          estado: 'ok',
          prova: `${MOCK_TAG} Validação documental e técnica concluída com sucesso.`,
          verificado_em: new Date().toISOString()
        })
      });
    }
  }

  // 4. PAGAMENTOS
  console.log('4. Inserindo pagamentos confirmados...');
  const agora = new Date();
  const mesQueVem = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  const pagamentosMock = [
    {
      id: '00000000-0000-4000-8000-200000000001',
      empresa_id: '00000000-0000-4000-8000-000000000001',
      valor: 49.00,
      data: agora.toISOString(),
      metodo: 'mbway',
      referencia: 'MBWAY-910293847',
      fatura_numero: 'FT 2026/0142',
      periodo_inicio: agora.toISOString().split('T')[0],
      periodo_fim: mesQueVem.toISOString().split('T')[0],
      estado: 'pago'
    },
    {
      id: '00000000-0000-4000-8000-200000000002',
      empresa_id: '00000000-0000-4000-8000-000000000002',
      valor: 49.00,
      data: agora.toISOString(),
      metodo: 'transferencia',
      referencia: 'SEPA-TRF-8823',
      fatura_numero: 'FT 2026/0143',
      periodo_inicio: agora.toISOString().split('T')[0],
      periodo_fim: mesQueVem.toISOString().split('T')[0],
      estado: 'pago'
    },
    {
      id: '00000000-0000-4000-8000-200000000003',
      empresa_id: '00000000-0000-4000-8000-000000000003',
      valor: 49.00,
      data: agora.toISOString(),
      metodo: 'multibanco',
      referencia: 'ENT 21245 SUB 123456789',
      fatura_numero: 'FT 2026/0144',
      periodo_inicio: agora.toISOString().split('T')[0],
      periodo_fim: mesQueVem.toISOString().split('T')[0],
      estado: 'pago'
    },
    {
      id: '00000000-0000-4000-8000-200000000004',
      empresa_id: '00000000-0000-4000-8000-000000000004',
      valor: 290.00,
      data: agora.toISOString(),
      metodo: 'transferencia',
      referencia: 'SEPA-TECHLOG-M01',
      fatura_numero: 'FT 2026/0145',
      periodo_inicio: agora.toISOString().split('T')[0],
      periodo_fim: mesQueVem.toISOString().split('T')[0],
      estado: 'pago'
    }
  ];

  for (const pag of pagamentosMock) {
    const res = await fetch(`${url}/rest/v1/pagamentos`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify(pag)
    });
    if (!res.ok) console.warn('Erro ao inserir pagamento:', await res.text());
  }

  // 5. LEADS COMERCIAIS
  console.log('5. Inserindo leads comerciais...');
  const leadsMock = [
    {
      id: '00000000-0000-4000-8000-300000000001',
      nome: 'Dra. Inês Vasconcelos',
      empresa: 'Gabinete Médico do Parque',
      email: 'ines.vasconcelos@grupomedicoparque.pt',
      whatsapp: '+351 912 345 678',
      website: 'https://grupomedicoparque.pt',
      plano_interesse: 'selo',
      status: 'novo',
      criado_em: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-300000000002',
      nome: 'Rui Figueiredo',
      empresa: 'Soluções Contábeis & Fiscais Lda',
      email: 'rui.figueiredo@solucoescontabeis.pt',
      whatsapp: '+351 960 112 233',
      website: 'https://solucoescontabeis.pt',
      plano_interesse: 'selo',
      status: 'em_contacto',
      criado_em: new Date(Date.now() - 24 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-300000000003',
      nome: 'Eng. Duarte Pacheco',
      empresa: 'VipCar Rent-a-Car',
      email: 'duarte@vipcarportugal.com',
      whatsapp: '+351 933 887 766',
      website: 'https://vipcarportugal.com',
      plano_interesse: 'radar',
      status: 'novo',
      criado_em: new Date(Date.now() - 48 * 3600 * 1000).toISOString()
    }
  ];

  for (const lead of leadsMock) {
    const res = await fetch(`${url}/rest/v1/leads`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify(lead)
    });
    if (!res.ok) console.warn('Erro ao inserir lead:', await res.text());
  }

  // 6. ANÁLISES & RADAR DE AMEAÇAS (Evidências de golpes em Portugal)
  console.log('6. Inserindo análises com marcas para enriquecer o Threat Radar e Ocorrências...');
  const analisesMock = [
    {
      id: '00000000-0000-4000-8000-400000000001',
      veredito: 'golpe',
      confianca: 98,
      tipo: 'sms_urgencia',
      vezes_reportada: 14,
      teve_imagem: false,
      marca_mencionada: 'CTT',
      canal_mencionado: 'SMS',
      impersonation: true,
      risco_score: 95,
      alerta_link: 'https://ctt-encomenda-alfandega-pagamento.com',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 1 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000002',
      veredito: 'golpe',
      confianca: 96,
      tipo: 'mbway_falso_comprador',
      vezes_reportada: 8,
      teve_imagem: false,
      marca_mencionada: 'MB WAY',
      canal_mencionado: 'WhatsApp',
      impersonation: true,
      risco_score: 92,
      alerta_link: 'https://ativar-mbway-olx-seguro.info',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 4 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000003',
      veredito: 'golpe',
      confianca: 95,
      tipo: 'corte_energia',
      vezes_reportada: 11,
      teve_imagem: false,
      marca_mencionada: 'EDP',
      canal_mencionado: 'SMS',
      impersonation: true,
      risco_score: 90,
      alerta_link: 'https://edp-comercial-pagamentos-urgentes.net',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 8 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000004',
      veredito: 'golpe',
      confianca: 99,
      tipo: 'phishing_bancario',
      vezes_reportada: 6,
      teve_imagem: false,
      marca_mencionada: 'Novo Banco',
      canal_mencionado: 'SMS',
      impersonation: true,
      risco_score: 98,
      alerta_link: 'https://novobanco-validar-dispositivo-acesso.org',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 12 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000005',
      veredito: 'golpe',
      confianca: 94,
      tipo: 'ola_pai_ola_mae',
      vezes_reportada: 19,
      teve_imagem: false,
      marca_mencionada: 'WhatsApp Familiar',
      canal_mencionado: 'WhatsApp',
      impersonation: true,
      risco_score: 88,
      alerta_link: null,
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 20 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000006',
      veredito: 'golpe',
      confianca: 97,
      tipo: 'phishing_bancario',
      vezes_reportada: 9,
      teve_imagem: false,
      marca_mencionada: 'Santander',
      canal_mencionado: 'SMS',
      impersonation: true,
      risco_score: 96,
      alerta_link: 'https://santander-totta-seguranca-actualizar.com',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 36 * 3600 * 1000).toISOString()
    },
    {
      id: '00000000-0000-4000-8000-400000000007',
      empresa_id: '00000000-0000-4000-8000-000000000004',
      veredito: 'golpe',
      confianca: 91,
      tipo: 'phishing_logistica',
      vezes_reportada: 4,
      teve_imagem: false,
      marca_mencionada: 'TechLog Ibérica',
      canal_mencionado: 'SMS',
      impersonation: true,
      risco_score: 85,
      alerta_link: 'https://techlog-express-taxa-entrega.me',
      canal: 'whatsapp',
      criado_em: new Date(Date.now() - 15 * 3600 * 1000).toISOString()
    }
  ];

  for (const an of analisesMock) {
    const res = await fetch(`${url}/rest/v1/analises`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'resolution=merge-duplicates' },
      body: JSON.stringify(an)
    });
    if (!res.ok) console.warn('Erro ao inserir analise:', await res.text());
  }

  console.log('\n✅ SEED CONCLUÍDO COM SUCESSO!');
  console.log('Métricas geradas para a demonstração:');
  console.log('- 4 Empresas Ativas com Selos e Pagamento Confirmado (€437 MRR / €5.244 ARR)');
  console.log('- 1 Empresa Em Verificação + 1 Empresa Lead comercial no funil');
  console.log('- 3 Leads captados no CRM');
  console.log('- 7 Alertas de Impersonation alimentando o Threat Radar (CTT, MB WAY, EDP, TechLog, etc.)');
  console.log('Todos os dados possuem IDs padronizados de teste e podem ser removidos a qualquer momento via:');
  console.log('  node scripts/limpar_mock_demo.mjs');
}

seed().catch(err => {
  console.error('Falha no seed:', err);
  process.exit(1);
});
