// api/empresa.js — API Pública de Consulta de Empresas e Selos ZAP VERIFIED
// Suporta consultas por ?codigo= (ZQV-...), ?dominio= ou ?slug=

import crypto from 'node:crypto';
import { checkRateLimit } from '../lib/security.js';
import { LEAD_RETENTION_SECONDS, pruneRedisLeadFallback } from '../lib/retention.js';

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(204).end();
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // 1. CONSULTA PÚBLICA DE SELO DE EMPRESA
  if (req.method === 'GET') {
    // Leitura pública para o widget; o endpoint de escrita abaixo não recebe CORS cross-origin.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=60');
    const limit = await checkRateLimit(req, 'public-company-lookup', 60, 60);
    if (limit.unavailable && process.env.NODE_ENV === 'production') {
      return res.status(503).json({ error: 'A consulta está temporariamente indisponível.' });
    }
    if (!limit.allowed) return res.status(429).json({ error: 'Demasiadas consultas. Tenta novamente mais tarde.' });
    const { codigo, slug, dominio } = req.query || {};

    if ([codigo, slug, dominio].some(value => Array.isArray(value))) {
      return res.status(400).json({ error: 'Usa apenas um valor por parâmetro de consulta.' });
    }

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
        if (cleanCodigo.length > 100) return res.status(400).json({ error: 'Código de selo inválido.' });
        const seloResp = await fetch(
          `${url}/rest/v1/selos?codigo=eq.${encodeURIComponent(cleanCodigo)}&select=codigo,ativo,valido_ate,is_teste,arquivado_em,empresas(id,nome,dominio_oficial,email_oficial,telefone_oficial,dominio_verificado,email_verificado,telefone_verificado,status,is_teste,arquivado_em)&limit=1`,
          { headers }
        );

        if (!seloResp.ok) {
          return res.status(500).json({ error: 'Erro ao consultar registro de selo.' });
        }

        const selos = await seloResp.json();
        if (!selos || selos.length === 0) {
          return res.status(404).json({ error: 'Registo não encontrado.', selo_valido: false });
        }

        const selo = selos[0];
        const emp = selo.empresas || {};
        const agora = new Date();
        const dataValidade = selo.valido_ate ? new Date(selo.valido_ate).getTime() : NaN;
        const expirado = !Number.isFinite(dataValidade) || dataValidade < agora.getTime();
        const isTeste = !!(emp.is_teste || selo.is_teste);
        const seloValido = !isTeste && !selo.arquivado_em && !emp.arquivado_em && selo.ativo === true && emp.status === 'ativo' && !expirado;

        return res.status(200).json({
          codigo: selo.codigo,
          nome: emp.nome || 'Empresa Registada',
          dominio_oficial: seloValido ? (emp.dominio_oficial || null) : null,
          email_oficial: seloValido ? (emp.email_oficial || null) : null,
          telefone_oficial: seloValido ? (emp.telefone_oficial || null) : null,
          dominio_verificado: seloValido && !!emp.dominio_verificado,
          email_verificado: seloValido && !!emp.email_verificado,
          telefone_verificado: seloValido && !!emp.telefone_verificado,
          status: isTeste ? 'teste' : (seloValido ? (emp.status || 'ativo') : 'inativo'),
          valido_ate: selo.valido_ate || null,
          selo_valido: seloValido
        });
      }

      // 1.2 Consulta por domínio ou slug da empresa
      const domainParam = typeof dominio === 'string' ? dominio : (typeof slug === 'string' ? slug : '');
      const queryDominio = domainParam.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
      if (!queryDominio || queryDominio.length > 253 || /[\s?#]/.test(queryDominio)) {
        return res.status(400).json({ error: 'Domínio inválido.' });
      }
      const empResp = await fetch(
        `${url}/rest/v1/empresas?dominio_oficial=eq.${encodeURIComponent(queryDominio)}&select=id,nome,dominio_oficial,email_oficial,telefone_oficial,dominio_verificado,email_verificado,telefone_verificado,status,is_teste,arquivado_em,selos(codigo,ativo,valido_ate,is_teste,arquivado_em)&limit=1`,
        { headers }
      );

      if (!empResp.ok) {
        return res.status(500).json({ error: 'Erro ao consultar registro da empresa.' });
      }

      const empresas = await empResp.json();
      if (!empresas || empresas.length === 0) {
        return res.status(404).json({ error: 'Registo empresarial não encontrado.', selo_valido: false });
      }

      const emp = empresas[0];
      const selos = Array.isArray(emp.selos) ? emp.selos : [];
      // Preferência pelo selo ativo mais recente
      const selo = selos.find(s => s.ativo === true) || selos[0] || null;

      const agora = new Date();
      const dataValidade = selo?.valido_ate ? new Date(selo.valido_ate).getTime() : NaN;
      const expirado = !Number.isFinite(dataValidade) || dataValidade < agora.getTime();
      const isTeste = !!(emp.is_teste || selo?.is_teste);
      const seloValido = !isTeste && !emp.arquivado_em && !!selo && !selo.arquivado_em && selo.ativo === true && emp.status === 'ativo' && !expirado;

      return res.status(200).json({
        codigo: selo?.codigo || null,
        nome: emp.nome,
        dominio_oficial: seloValido ? emp.dominio_oficial : null,
        email_oficial: seloValido ? emp.email_oficial : null,
        telefone_oficial: seloValido ? emp.telefone_oficial : null,
        dominio_verificado: seloValido && !!emp.dominio_verificado,
        email_verificado: seloValido && !!emp.email_verificado,
        telefone_verificado: seloValido && !!emp.telefone_verificado,
        status: isTeste ? 'teste' : (seloValido ? emp.status : 'inativo'),
        valido_ate: selo?.valido_ate || null,
        selo_valido: seloValido
      });

    } catch (err) {
      console.error('[Empresa] Erro ao consultar empresa/selo:', err);
      return res.status(500).json({ error: 'Erro interno ao consultar dados da empresa.' });
    }
  }

  // 2. CAPTAÇÃO DE CONTATOS / LEADS B2B
  if (req.method === 'POST') {
    const limit = await checkRateLimit(req, 'lead', 3, 60 * 60);
    if (limit.unavailable && process.env.NODE_ENV === 'production') {
      return res.status(503).json({ error: 'O formulário está temporariamente indisponível. Tenta novamente mais tarde.' });
    }
    if (!limit.allowed) return res.status(429).json({ error: 'Foram enviados demasiados pedidos. Tenta novamente mais tarde.' });

    const body = req.body || {};
    // Campo invisível de honeypot: submissões automáticas são descartadas sem criar registo.
    if (String(body.company_fax || '').trim()) {
      return res.status(200).json({ success: true, message: 'Pedido recebido.' });
    }
    const { nome, empresa, email, whatsapp, website, plano_interesse } = body;

    const cleanName = typeof nome === 'string' ? nome.trim() : '';
    const cleanCompany = typeof empresa === 'string' ? empresa.trim() : '';
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const cleanWhatsapp = typeof whatsapp === 'string' ? whatsapp.trim() : '';
    const cleanWebsite = typeof website === 'string' ? website.trim() : '';
    const cleanPlan = typeof plano_interesse === 'string' ? plano_interesse : 'verified';

    if (!cleanName || !cleanCompany || !cleanEmail) {
      return res.status(400).json({ error: 'Campos nome, empresa e email são obrigatórios.' });
    }
    if (cleanName.length > 120 || cleanCompany.length > 160 || cleanEmail.length > 254 || cleanWhatsapp.length > 40 || cleanWebsite.length > 253) {
      return res.status(400).json({ error: 'Um ou mais campos excedem o tamanho permitido.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Endereço de email inválido.' });
    }
    if (!['verified', 'monitoring'].includes(cleanPlan)) {
      return res.status(400).json({ error: 'Opção de serviço inválida.' });
    }
    if (cleanWhatsapp && !/^[+\d\s().-]+$/.test(cleanWhatsapp)) {
      return res.status(400).json({ error: 'Número de telefone inválido.' });
    }
    if (cleanWebsite) {
      try {
        const websiteUrl = new URL(/^https?:\/\//i.test(cleanWebsite) ? cleanWebsite : `https://${cleanWebsite}`);
        if (!['http:', 'https:'].includes(websiteUrl.protocol)) throw new Error('scheme');
      } catch {
        return res.status(400).json({ error: 'Site ou domínio inválido.' });
      }
    }

    const leadId = crypto.randomUUID();
    const leadData = {
      id: leadId,
      criado_em: new Date().toISOString(),
      nome: cleanName,
      empresa: cleanCompany,
      email: cleanEmail,
      whatsapp: cleanWhatsapp || null,
      website: cleanWebsite || null,
      plano_interesse: cleanPlan,
      status: 'novo'
    };

    // O Supabase é o armazenamento primário; o Redis só recebe o lead se o primeiro falhar.
    let persisted = false;
    if (url && key) {
      try {
        const response = await fetch(`${url}/rest/v1/leads`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: key,
            Authorization: `Bearer ${key}`
          },
          body: JSON.stringify(leadData),
          signal: AbortSignal.timeout(5000)
        });
        persisted = response.ok;
        if (!response.ok) console.warn('[Empresa] Supabase lead insert failed with HTTP', response.status);
      } catch (err) {
        console.warn('[Empresa] Supabase unavailable for lead persistence:', err.message);
      }
    }

    if (!persisted) {
      const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
      const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
      try {
        if (redisUrl && redisToken) {
          await pruneRedisLeadFallback();
          const response = await fetch(`${redisUrl}/pipeline`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${redisToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify([
              ['HSET', `zapqueme:lead:${leadId}`, 'data', JSON.stringify(leadData)],
              ['EXPIRE', `zapqueme:lead:${leadId}`, LEAD_RETENTION_SECONDS],
              ['LPUSH', 'zapqueme:leads', leadId],
              ['LTRIM', 'zapqueme:leads', 0, 49],
              ['EXPIRE', 'zapqueme:leads', LEAD_RETENTION_SECONDS]
            ]),
            signal: AbortSignal.timeout(5000)
          });
          const results = response.ok ? await response.json() : [];
          persisted = response.ok && !results.some(item => item?.error);
        }
      } catch (redisErr) {
        console.warn('[Empresa] Redis fallback unavailable for lead persistence:', redisErr.message);
      }
    }

    if (!persisted) return res.status(503).json({ error: 'Não foi possível guardar o pedido. Tenta novamente mais tarde.' });

    return res.status(200).json({
      success: true,
      lead_id: leadId,
      message: 'Pedido recebido. Entraremos em contacto pelos dados fornecidos.'
    });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}
