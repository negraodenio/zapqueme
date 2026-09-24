// api/empresa.js — API Pública de Verificação de Selo e Captação de Leads B2B

export default async function handler(req, res) {
  // CORS para permitir que lojas clientes chamem esta API de seus próprios domínios
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-requested-with');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
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

  // 1. CONSULTA PÚBLICA DE SELO DE EMPRESA
  if (req.method === 'GET') {
    const { slug, dominio } = req.query;

    if (!slug && !dominio) {
      return res.status(400).json({ error: 'Parâmetro slug ou dominio é obrigatório.' });
    }

    try {
      let queryParam = '';
      if (slug) {
        queryParam = `slug=eq.${encodeURIComponent(slug.trim().toLowerCase())}`;
      } else {
        const cleanDominio = dominio.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
        queryParam = `dominio=eq.${encodeURIComponent(cleanDominio)}`;
      }

      const resp = await fetch(`${url}/rest/v1/empresas_verificadas?${queryParam}&select=*&limit=1`, { headers });
      
      if (!resp.ok) {
        return res.status(404).json({ error: 'Empresa não encontrada ou serviço indisponível.' });
      }

      const data = await resp.json();
      if (!data || data.length === 0) {
        return res.status(404).json({ error: 'Empresa não cadastrada no Zap, quem é? Seguro.' });
      }

      const emp = data[0];

      // Incrementar visualização de forma assíncrona (não bloqueante)
      try {
        const novoTotal = (emp.visualizacoes_selo || 0) + 1;
        fetch(`${url}/rest/v1/empresas_verificadas?id=eq.${emp.id}`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ visualizacoes_selo: novoTotal })
        }).catch(() => {});
      } catch (e) {}

      // Retornar apenas dados públicos e seguros (ocultar token, e-mails internos de cobrança)
      return res.status(200).json({
        id: emp.id,
        slug: emp.slug,
        nome: emp.nome,
        dominio: emp.dominio,
        cnpj_nif: emp.cnpj_nif,
        whatsapp_oficial: emp.whatsapp_oficial,
        instagram_oficial: emp.instagram_oficial,
        status: emp.status,
        plano: emp.plano,
        valido_ate: emp.valido_ate,
        criado_em: emp.criado_em,
        visualizacoes_selo: (emp.visualizacoes_selo || 0) + 1,
        selo_valido: emp.status === 'ativo'
      });
    } catch (err) {
      console.error('Erro ao verificar empresa:', err);
      return res.status(500).json({ error: 'Erro interno ao consultar dados da empresa.' });
    }
  }

  // 2. CAPTAÇÃO DE LEADS B2B CORPORATIVOS (Formulário do site)
  if (req.method === 'POST') {
    const { action } = req.query;
    const body = req.body || {};

    if (action === 'lead' || body.action === 'lead') {
      const { nome, empresa, email, whatsapp, website, plano_interesse } = body;

      if (!nome || !empresa || !email) {
        return res.status(400).json({ error: 'Campos nome, empresa e email são obrigatórios.' });
      }

      try {
        const leadResp = await fetch(`${url}/rest/v1/leads_empresas`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            nome: nome.trim(),
            empresa: empresa.trim(),
            email: email.trim().toLowerCase(),
            whatsapp: whatsapp ? whatsapp.trim() : null,
            website: website ? website.trim().toLowerCase() : null,
            plano_interesse: plano_interesse || 'pro',
            status: 'novo'
          })
        });

        if (!leadResp.ok) {
          const errText = await leadResp.text();
          throw new Error('Supabase erro ao inserir lead: ' + errText);
        }

        return res.status(200).json({
          success: true,
          message: 'Solicitação recebida com sucesso! Nossa equipe entrará em contato em breve.'
        });
      } catch (err) {
        console.error('Erro ao registrar lead:', err);
        return res.status(500).json({ error: 'Falha ao processar solicitação. Tente novamente mais tarde.' });
      }
    }

    return res.status(400).json({ error: 'Ação não suportada.' });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}
