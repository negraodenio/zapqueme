// api/empresa.js — API Pública de Consulta de Empresas e Selos ZAP VERIFIED
// Suporta consultas por ?codigo= (ZQV-...), ?dominio= ou ?slug=

import crypto from 'node:crypto';

export default async function handler(req, res) {
  // CORS para permitir widgets em websites e e-commerces clientes
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-requested-with');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // 1. CONSULTA PÚBLICA DE SELO DE EMPRESA
  if (req.method === 'GET') {
    const { codigo, slug, dominio } = req.query || {};

    if (!codigo && !slug && !dominio) {
      return res.status(400).json({ error: 'Parâmetro codigo, dominio ou slug é obrigatório.' });
    }

    if (!url || !key) {
      return res.status(500).json({ error: 'Supabase não configurado no servidor.' });
    }

    const headers = {
      'Content-Type': 'application/json',
      apikey: key,
      Authorization: `Bearer ${key}`
    };

    try {
      // 1.1 Consulta prioritária por código do selo (ZQV-...)
      if (codigo) {
        const cleanCodigo = String(codigo).trim();
        const seloResp = await fetch(
          `${url}/rest/v1/selos?codigo=eq.${encodeURIComponent(cleanCodigo)}&select=*,empresas(*)&limit=1`,
          { headers }
        );

        if (!seloResp.ok) {
          return res.status(500).json({ error: 'Erro ao consultar registro de selo.' });
        }

        const selos = await seloResp.json();
        if (!selos || selos.length === 0) {
          return res.status(404).json({ error: 'Selo não encontrado no registro oficial ZAP VERIFIED.', selo_valido: false });
        }

        const selo = selos[0];
        const emp = selo.empresas || {};
        const agora = new Date();
        const expirado = selo.valido_ate ? new Date(selo.valido_ate) < agora : false;
        const isTeste = !!(emp.is_teste || selo.is_teste);
        const seloValido = !isTeste && selo.ativo !== false && emp.status === 'ativo' && !expirado;

        return res.status(200).json({
          id: emp.id || null,
          codigo: selo.codigo,
          nome: emp.nome || 'Empresa Registada',
          dominio_oficial: emp.dominio_oficial || null,
          email_oficial: emp.email_oficial || null,
          telefone_oficial: emp.telefone_oficial || null,
          dominio_verificado: !!emp.dominio_verificado,
          email_verificado: !!emp.email_verificado,
          telefone_verificado: !!emp.telefone_verificado,
          status: isTeste ? 'teste' : (emp.status || 'inativo'),
          valido_ate: selo.valido_ate || null,
          selo_valido: seloValido,
          is_teste: isTeste
        });
      }

      // 1.2 Consulta por domínio ou slug da empresa
      const queryDominio = (dominio || slug || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
      const empResp = await fetch(
        `${url}/rest/v1/empresas?dominio_oficial=eq.${encodeURIComponent(queryDominio)}&select=*,selos(*)&limit=1`,
        { headers }
      );

      if (!empResp.ok) {
        return res.status(500).json({ error: 'Erro ao consultar registro da empresa.' });
      }

      const empresas = await empResp.json();
      if (!empresas || empresas.length === 0) {
        return res.status(404).json({ error: 'Empresa não encontrada no registro oficial ZAP VERIFIED.', selo_valido: false });
      }

      const emp = empresas[0];
      const selos = Array.isArray(emp.selos) ? emp.selos : [];
      // Preferência pelo selo ativo mais recente
      const selo = selos.find(s => s.ativo !== false) || selos[0] || null;

      const agora = new Date();
      const expirado = selo?.valido_ate ? new Date(selo.valido_ate) < agora : false;
      const isTeste = !!(emp.is_teste || selo?.is_teste);
      const seloValido = !isTeste && !!selo && selo.ativo !== false && emp.status === 'ativo' && !expirado;

      return res.status(200).json({
        id: emp.id,
        codigo: selo?.codigo || null,
        nome: emp.nome,
        dominio_oficial: emp.dominio_oficial,
        email_oficial: emp.email_oficial,
        telefone_oficial: emp.telefone_oficial,
        dominio_verificado: !!emp.dominio_verificado,
        email_verificado: !!emp.email_verificado,
        telefone_verificado: !!emp.telefone_verificado,
        status: isTeste ? 'teste' : emp.status,
        valido_ate: selo?.valido_ate || null,
        selo_valido: seloValido,
        is_teste: isTeste
      });

    } catch (err) {
      console.error('[Empresa] Erro ao consultar empresa/selo:', err);
      return res.status(500).json({ error: 'Erro interno ao consultar dados da empresa.' });
    }
  }

  // 2. CAPTAÇÃO DE CONTATOS / LEADS B2B
  if (req.method === 'POST') {
    const body = req.body || {};
    const { nome, empresa, email, whatsapp, website, plano_interesse } = body;

    if (!nome || !empresa || !email) {
      return res.status(400).json({ error: 'Campos nome, empresa e email são obrigatórios.' });
    }

    const leadId = crypto.randomUUID();
    const leadData = {
      id: leadId,
      criado_em: new Date().toISOString(),
      nome: String(nome).trim(),
      empresa: String(empresa).trim(),
      email: String(email).trim().toLowerCase(),
      whatsapp: whatsapp ? String(whatsapp).trim() : null,
      website: website ? String(website).trim() : null,
      plano_interesse: plano_interesse || 'pro',
      status: 'novo'
    };

    // 1. Tentar salvar no Supabase (se configurado e online)
    if (url && key) {
      try {
        await fetch(`${url}/rest/v1/leads`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: key,
            Authorization: `Bearer ${key}`
          },
          body: JSON.stringify(leadData)
        });
      } catch (err) {
        console.warn('[Empresa] Supabase indisponível para gravar lead, salvando no Redis:', err.message);
      }
    }

    // 2. Sempre persistir no Upstash Redis para NUNCA perder um lead comercial
    const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
    const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
    if (redisUrl && redisToken) {
      try {
        await fetch(`${redisUrl}/pipeline`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${redisToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify([
            ['LPUSH', 'zapqueme:leads', JSON.stringify(leadData)],
            ['HSET', `zapqueme:lead:${leadId}`, 'data', JSON.stringify(leadData)]
          ])
        });
      } catch (redisErr) {
        console.warn('[Empresa] Falha ao persistir lead no Redis:', redisErr.message);
      }
    }

    return res.status(200).json({
      success: true,
      lead_id: leadId,
      message: 'Solicitação recebida com sucesso! Nossa equipe de segurança entrará em contato.'
    });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}
