// api/admin.js — Dashboard & Gestão de Selos B2B
const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || 'zapadmin2026';

export default async function handler(req, res) {
  const secret = req.headers['x-admin-key'] || req.query.secret || (req.body && req.body.secret);
  if (secret !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Acesso não autorizado. Chave administrativa inválida.' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    return res.status(500).json({ error: 'Supabase não configurado no servidor.' });
  }

  const headers = {
    'Content-Type': 'application/json',
    apikey: key,
    Authorization: `Bearer ${key}`
  };

  // 1. ESTATÍSTICAS E DASHBOARD GERAL
  if (req.method === 'GET') {
    try {
      // Buscar análises
      const analisesResp = await fetch(`${url}/rest/v1/analises?select=*&order=criado_em.desc&limit=50`, { headers });
      const analises = analisesResp.ok ? await analisesResp.json() : [];

      // Buscar empresas verificadas
      const empresasResp = await fetch(`${url}/rest/v1/empresas_verificadas?select=*&order=criado_em.desc`, { headers });
      const empresas = empresasResp.ok ? await empresasResp.json() : [];

      // Buscar ameaças do radar
      const ameacasResp = await fetch(`${url}/rest/v1/ameacas_detectadas?select=*&order=criado_em.desc&limit=50`, { headers });
      const ameacas = ameacasResp.ok ? await ameacasResp.json() : [];

      // Buscar leads
      const leadsResp = await fetch(`${url}/rest/v1/leads_empresas?select=*&order=criado_em.desc&limit=50`, { headers });
      const leads = leadsResp.ok ? await leadsResp.json() : [];

      const totalAnalises = analises.length;
      const totalGolpes = analises.filter(a => a.veredito === 'golpe').length;
      const totalSuspeitos = analises.filter(a => a.veredito === 'suspeito').length;
      const totalLegitimos = analises.filter(a => a.veredito === 'legitimo').length;
      const totalEmpresasAtivas = empresas.filter(e => e.status === 'ativo').length;

      return res.status(200).json({
        kpis: {
          totalAnalises,
          totalGolpes,
          totalSuspeitos,
          totalLegitimos,
          totalEmpresasAtivas,
          totalEmpresas: empresas.length,
          totalAmeacas: ameacas.length,
          totalLeads: leads.length
        },
        empresas,
        ameacas,
        leads,
        analisesRecentes: analises.slice(0, 15)
      });
    } catch (err) {
      console.error('Erro ao buscar dados administrativos:', err);
      return res.status(500).json({ error: 'Falha ao buscar estatísticas do banco.' });
    }
  }

  // 2. CADASTRO DE NOVA EMPRESA E EMISSÃO DE SELO
  if (req.method === 'POST') {
    const { action, empresaData, empresaId, novoStatus } = req.body || {};

    if (action === 'create_empresa') {
      const { nome, dominio, cnpj_nif, whatsapp_oficial, instagram_oficial, plano, contato_email, contato_responsavel } = empresaData || {};
      
      if (!nome || !dominio) {
        return res.status(400).json({ error: 'Nome e Domínio da empresa são obrigatórios.' });
      }

      // Limpa o domínio (remove https://, http://, barras finais)
      const cleanDominio = dominio.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
      const slug = cleanDominio.replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');

      try {
        const crypto = await import('node:crypto');
        const seloToken = 'zap_' + crypto.randomBytes(12).toString('hex');

        const insertResp = await fetch(`${url}/rest/v1/empresas_verificadas`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            slug,
            nome,
            dominio: cleanDominio,
            cnpj_nif: cnpj_nif || null,
            whatsapp_oficial: whatsapp_oficial || null,
            instagram_oficial: instagram_oficial || null,
            plano: plano || 'pro',
            status: 'ativo',
            selo_token: seloToken,
            contato_email: contato_email || null,
            contato_responsavel: contato_responsavel || null
          })
        });

        if (!insertResp.ok) {
          const errText = await insertResp.text();
          throw new Error('Supabase erro: ' + errText);
        }

        const novaEmpresa = await insertResp.json();
        return res.status(200).json({ success: true, empresa: novaEmpresa[0] });
      } catch (err) {
        console.error('Erro ao cadastrar empresa:', err);
        return res.status(500).json({ error: err.message || 'Falha ao emitir selo para a empresa.' });
      }
    }

    if (action === 'update_status') {
      if (!empresaId || !novoStatus) {
        return res.status(400).json({ error: 'empresaId e novoStatus são obrigatórios.' });
      }

      try {
        const updateResp = await fetch(`${url}/rest/v1/empresas_verificadas?id=eq.${empresaId}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({ status: novoStatus })
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());
        return res.status(200).json({ success: true });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao alterar status da empresa.' });
      }
    }

    if (action === 'delete_empresa') {
      if (!empresaId) {
        return res.status(400).json({ error: 'empresaId é obrigatório.' });
      }

      try {
        const delResp = await fetch(`${url}/rest/v1/empresas_verificadas?id=eq.${empresaId}`, {
          method: 'DELETE',
          headers
        });

        if (!delResp.ok) throw new Error(await delResp.text());
        return res.status(200).json({ success: true });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao excluir empresa.' });
      }
    }

    return res.status(400).json({ error: 'Ação não reconhecida.' });
  }

  return res.status(405).json({ error: 'Método não permitido' });
}
