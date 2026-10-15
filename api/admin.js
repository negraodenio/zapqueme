// api/admin.js — Dashboard & Gestão B2B (Empresas, Selos & Threat Radar)
// Especificação Fechada ZAP, QUEM É? — B2B
// Seções 6, 7, 8, 19, 20, 21

import { gerarCodigoSelo } from '../lib/radar.js';

// Campos de verificação comercial (migração 20261015). Se a migração ainda não
// tiver sido executada, o PostgREST rejeita colunas desconhecidas: nesse caso
// repetimos o pedido sem estes campos para não bloquear a operação.
const CAMPOS_VERIFICACAO = ['nif', 'nif_verificado', 'iban', 'iban_verificado', 'verificacao_notas', 'verificado_em'];

function extrairCamposVerificacao(body) {
  const out = {};
  if (body.nif !== undefined) out.nif = body.nif ? String(body.nif).replace(/\s+/g, '').toUpperCase() : null;
  if (body.nif_verificado !== undefined) out.nif_verificado = !!body.nif_verificado;
  if (body.iban !== undefined) out.iban = body.iban ? String(body.iban).replace(/\s+/g, '').toUpperCase() : null;
  if (body.iban_verificado !== undefined) out.iban_verificado = !!body.iban_verificado;
  if (body.verificacao_notas !== undefined) out.verificacao_notas = body.verificacao_notas ? String(body.verificacao_notas).trim() : null;
  if (out.nif_verificado || out.iban_verificado) out.verificado_em = new Date().toISOString();
  return out;
}

async function fetchComFallback(fetchUrl, options, payload) {
  let resp = await fetch(fetchUrl, { ...options, body: JSON.stringify(payload) });
  if (!resp.ok) {
    const errText = await resp.text();
    const temCamposNovos = CAMPOS_VERIFICACAO.some(c => c in payload);
    if (temCamposNovos && /column|schema cache/i.test(errText)) {
      console.warn('[Admin] Migração 20261015 ainda não aplicada; a gravar sem NIF/IBAN.');
      const semNovos = { ...payload };
      CAMPOS_VERIFICACAO.forEach(c => delete semNovos[c]);
      resp = await fetch(fetchUrl, { ...options, body: JSON.stringify(semNovos) });
      if (resp.ok) resp.migracaoPendente = true;
      return resp;
    }
    return { ok: false, text: async () => errText };
  }
  return resp;
}

export default async function handler(req, res) {
  const adminSecret = process.env.ADMIN_SECRET_KEY;
  if (!adminSecret) {
    return res.status(500).json({ error: 'ADMIN_SECRET_KEY não configurado no servidor.' });
  }

  // Autenticação: aceita apenas header x-admin-key ou campo secret no body (não via query string)
  const secret = req.headers['x-admin-key'] || (req.body && req.body.secret);
  if (secret !== adminSecret) {
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

  // 1. DADOS DO DASHBOARD (GET)
  if (req.method === 'GET') {
    let empresas = [];
    let selos = [];
    let radar = [];
    let ocorrencias = [];
    let leads = [];
    let marcas = [];
    let sinais = [];
    let isDbOnline = true;
    let dbErrorMessage = null;

    try {
      // 1. Buscar empresas
      const empresasResp = await fetch(`${url}/rest/v1/empresas?select=*&order=criado_em.desc`, { headers });
      empresas = empresasResp.ok ? await empresasResp.json() : [];

      // 2. Buscar selos com nome da empresa
      const selosResp = await fetch(`${url}/rest/v1/selos?select=*&order=criado_em.desc`, { headers });
      const selosRaw = selosResp.ok ? await selosResp.json() : [];

      const empMap = new Map(empresas.map(e => [e.id, e]));
      selos = selosRaw.map(s => {
        const emp = empMap.get(s.empresa_id);
        return {
          ...s,
          empresa_nome: emp ? emp.nome : 'Empresa não encontrada',
          empresa_status: emp ? emp.status : 'inativo'
        };
      });

      // 3. Buscar view Threat Radar (Seção 8 e 14)
      const radarResp = await fetch(`${url}/rest/v1/radar_ameacas?select=*&order=ocorrencias.desc`, { headers });
      radar = radarResp.ok ? await radarResp.json() : [];

      // 4. Buscar ocorrências de impersonation para o detalhe (Seção 21)
      const ocorrenciasResp = await fetch(
        `${url}/rest/v1/analises?impersonation=eq.true&select=id,criado_em,veredito,confianca,risco_score,tipo,canal_mencionado,marca_mencionada,alerta_link,vezes_reportada,empresa_id&order=criado_em.desc&limit=100`,
        { headers }
      );
      const ocorrenciasRaw = ocorrenciasResp.ok ? await ocorrenciasResp.json() : [];
      ocorrencias = ocorrenciasRaw.map(o => ({
        ...o,
        empresa_nome: empMap.get(o.empresa_id)?.nome || 'Empresa desconhecida'
      }));

      // 5. Buscar leads comerciais do Supabase
      try {
        const leadsResp = await fetch(`${url}/rest/v1/leads?select=*&order=criado_em.desc&limit=50`, { headers });
        if (leadsResp.ok) leads = await leadsResp.json();
      } catch {}

      // 6. Marcas mencionadas em denúncias (inclui não-clientes) — base do alerta gratuito
      try {
        const marcasResp = await fetch(`${url}/rest/v1/marcas_mencionadas?select=*&order=denuncias.desc&limit=200`, { headers });
        if (marcasResp.ok) marcas = await marcasResp.json();
      } catch {}

      // 7. Denúncias individuais com marca (evidência para os relatórios, últimos 90 dias)
      try {
        const desde = new Date(Date.now() - 90 * 24 * 3600 * 1000).toISOString();
        const sinaisResp = await fetch(
          `${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&criado_em=gte.${desde}` +
          `&select=id,criado_em,veredito,confianca,tipo,canal,canal_mencionado,marca_mencionada,alerta_link,vezes_reportada,empresa_id,impersonation` +
          `&order=criado_em.desc&limit=1000`,
          { headers }
        );
        if (sinaisResp.ok) sinais = await sinaisResp.json();
      } catch {}
    } catch (err) {
      isDbOnline = false;
      dbErrorMessage = err.message || 'Falha ao conectar ao banco de dados Supabase.';
      console.warn('[Admin] Supabase offline ou pausado:', err.message);
    }

    // Se Supabase não retornou leads ou está offline, busca leads persistidos no Upstash Redis
    if (!leads.length) {
      const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
      const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
      if (redisUrl && redisToken) {
        try {
          const redisResp = await fetch(`${redisUrl}/lrange/zapqueme:leads/0/50`, {
            headers: { Authorization: `Bearer ${redisToken}` }
          });
          if (redisResp.ok) {
            const rData = await redisResp.json();
            if (Array.isArray(rData.result)) {
              leads = rData.result.map(item => {
                try { return typeof item === 'string' ? JSON.parse(item) : item; }
                catch { return null; }
              }).filter(Boolean);
            }
          }
        } catch (rErr) {
          console.warn('[Admin] Erro ao buscar leads no Redis:', rErr.message);
        }
      }
    }

    // 5. Total de ocorrências
    const totalOcorrencias = radar.reduce((acc, r) => acc + (parseInt(r.ocorrencias, 10) || 0), 0);

    // KPIs Obrigatórios (Seção 19):
    const kpis = {
      totalEmpresas: empresas.length,
      totalSelos: selos.length,
      totalThreatRadar: radar.length,
      totalOcorrencias: totalOcorrencias || ocorrencias.length,
      totalLeads: leads.length
    };

    return res.status(200).json({
      kpis,
      empresas,
      selos,
      radar,
      ocorrencias,
      leads,
      marcas,
      sinais,
      database_online: isDbOnline,
      database_warning: isDbOnline ? null : `Supabase inacessível (${dbErrorMessage}). Verifique se o projeto está pausado em supabase.com.`
    });
  }

  // 2. AÇÕES ADMINISTRATIVAS (POST)
  if (req.method === 'POST') {
    const { action } = req.body || {};

    // 2.1 CRIAR EMPRESA (Seção 6.1)
    if (action === 'create_empresa') {
      const {
        nome,
        dominio_oficial,
        email_oficial,
        telefone_oficial,
        apelidos_marca,
        dominio_verificado,
        email_verificado,
        telefone_verificado,
        plano,
        status,
        monitorizacao_impersonation,
        criar_selo
      } = req.body;

      if (!nome || !nome.trim()) {
        return res.status(400).json({ error: 'O nome da empresa é obrigatório.' });
      }

      // Normaliza apelidos para array de strings
      let apelidosArray = [];
      if (Array.isArray(apelidos_marca)) {
        apelidosArray = apelidos_marca.map(a => String(a).trim()).filter(Boolean);
      } else if (typeof apelidos_marca === 'string' && apelidos_marca.trim()) {
        apelidosArray = apelidos_marca.split(',').map(a => a.trim()).filter(Boolean);
      }

      try {
        const empInsert = await fetchComFallback(`${url}/rest/v1/empresas`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
            nome: nome.trim(),
            dominio_oficial: dominio_oficial ? dominio_oficial.trim().toLowerCase() : null,
            email_oficial: email_oficial ? email_oficial.trim().toLowerCase() : null,
            telefone_oficial: telefone_oficial ? telefone_oficial.trim() : null,
            apelidos_marca: apelidosArray,
            dominio_verificado: !!dominio_verificado,
            email_verificado: !!email_verificado,
            telefone_verificado: !!telefone_verificado,
            plano: plano || 'business',
            status: status || 'ativo',
            ...extrairCamposVerificacao(req.body)
        });

        if (!empInsert.ok) {
          const errText = await empInsert.text();
          throw new Error('Erro ao cadastrar empresa: ' + errText);
        }

        const novaEmpresaRows = await empInsert.json();
        const novaEmpresa = novaEmpresaRows[0];

        // Se solicitado criação de selo inicial (padrão true)
        let novoSelo = null;
        if (criar_selo !== false) {
          const codigoSelo = gerarCodigoSelo();
          // Validade padrão: 1 ano
          const validoAte = new Date();
          validoAte.setFullYear(validoAte.getFullYear() + 1);

          const seloInsert = await fetch(`${url}/rest/v1/selos`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'return=representation' },
            body: JSON.stringify({
              empresa_id: novaEmpresa.id,
              codigo: codigoSelo,
              tipo: 'canal_verificado',
              valido_ate: validoAte.toISOString(),
              monitorizacao_impersonation: monitorizacao_impersonation !== false,
              ativo: true
            })
          });

          if (seloInsert.ok) {
            const seloRows = await seloInsert.json();
            novoSelo = seloRows[0];
          }
        }

        return res.status(200).json({
          success: true,
          empresa: novaEmpresa,
          selo: novoSelo,
          migracao_pendente: !!empInsert.migracaoPendente
        });
      } catch (err) {
        console.error('[Admin] Erro create_empresa:', err);
        return res.status(500).json({ error: err.message || 'Falha ao cadastrar empresa.' });
      }
    }

    // 2.2 EDITAR EMPRESA
    if (action === 'update_empresa') {
      const {
        id,
        nome,
        dominio_oficial,
        email_oficial,
        telefone_oficial,
        apelidos_marca,
        dominio_verificado,
        email_verificado,
        telefone_verificado,
        plano,
        status
      } = req.body;

      if (!id) {
        return res.status(400).json({ error: 'id da empresa é obrigatório.' });
      }

      let apelidosArray = [];
      if (Array.isArray(apelidos_marca)) {
        apelidosArray = apelidos_marca.map(a => String(a).trim()).filter(Boolean);
      } else if (typeof apelidos_marca === 'string') {
        apelidosArray = apelidos_marca.split(',').map(a => a.trim()).filter(Boolean);
      }

      try {
        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, {
            nome: nome ? nome.trim() : undefined,
            dominio_oficial: dominio_oficial !== undefined ? (dominio_oficial ? dominio_oficial.trim().toLowerCase() : null) : undefined,
            email_oficial: email_oficial !== undefined ? (email_oficial ? email_oficial.trim().toLowerCase() : null) : undefined,
            telefone_oficial: telefone_oficial !== undefined ? (telefone_oficial ? telefone_oficial.trim() : null) : undefined,
            apelidos_marca: apelidosArray,
            dominio_verificado: !!dominio_verificado,
            email_verificado: !!email_verificado,
            telefone_verificado: !!telefone_verificado,
            plano: plano || undefined,
            status: status || undefined,
            ...extrairCamposVerificacao(req.body)
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());
        return res.status(200).json({ success: true, migracao_pendente: !!updateResp.migracaoPendente });
      } catch (err) {
        console.error('[Admin] Erro update_empresa:', err);
        return res.status(500).json({ error: 'Falha ao atualizar dados da empresa.' });
      }
    }

    // 2.3 SUSPENDER / REATIVAR EMPRESA
    if (action === 'set_empresa_status') {
      const { id, status: novoStatus } = req.body;
      if (!id || !novoStatus) {
        return res.status(400).json({ error: 'id e status são obrigatórios.' });
      }

      try {
        const updateResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(id)}`, {
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

    // 2.4 CRIAR SELO (Seção 7 & Regra de Unicidade)
    if (action === 'create_selo') {
      const { empresa_id, valido_ate, monitorizacao_impersonation } = req.body;
      if (!empresa_id) {
        return res.status(400).json({ error: 'empresa_id é obrigatório.' });
      }

      try {
        // Desativa selos anteriores ativos desta empresa para garantir 1 selo ativo por empresa
        await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}&ativo=eq.true`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            ativo: false,
            desativado_em: new Date().toISOString(),
            motivo_desativacao: 'Substituído por novo selo'
          })
        });

        const codigoSelo = gerarCodigoSelo();
        const insertResp = await fetch(`${url}/rest/v1/selos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            codigo: codigoSelo,
            tipo: 'canal_verificado',
            valido_ate: valido_ate || null,
            monitorizacao_impersonation: monitorizacao_impersonation !== false,
            ativo: true
          })
        });

        if (!insertResp.ok) throw new Error(await insertResp.text());
        const rows = await insertResp.json();
        return res.status(200).json({ success: true, selo: rows[0] });
      } catch (err) {
        console.error('[Admin] Erro create_selo:', err);
        return res.status(500).json({ error: 'Falha ao criar selo.' });
      }
    }

    // 2.5 REGENERAR SELO (Seção 7 — Preservação de Histórico)
    if (action === 'regenerar_selo') {
      const { selo_id } = req.body;
      if (!selo_id) {
        return res.status(400).json({ error: 'selo_id é obrigatório.' });
      }

      try {
        // 1. Obter dados do selo atual
        const seloResp = await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}&select=*&limit=1`, { headers });
        if (!seloResp.ok) throw new Error(await seloResp.text());
        const selos = await seloResp.json();
        if (!selos || selos.length === 0) {
          return res.status(404).json({ error: 'Selo não encontrado.' });
        }
        const seloAntigo = selos[0];

        // 2. Soft-delete / desativar o selo antigo
        await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}`, {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            ativo: false,
            desativado_em: new Date().toISOString(),
            motivo_desativacao: 'Regeneração de código de segurança'
          })
        });

        // 3. Criar novo registro de selo com novo código
        const novoCodigo = gerarCodigoSelo();
        const insertResp = await fetch(`${url}/rest/v1/selos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id: seloAntigo.empresa_id,
            codigo: novoCodigo,
            tipo: seloAntigo.tipo || 'canal_verificado',
            valido_ate: seloAntigo.valido_ate,
            monitorizacao_impersonation: seloAntigo.monitorizacao_impersonation !== false,
            ativo: true
          })
        });

        if (!insertResp.ok) throw new Error(await insertResp.text());
        const rows = await insertResp.json();
        return res.status(200).json({ success: true, selo: rows[0] });
      } catch (err) {
        console.error('[Admin] Erro regenerar_selo:', err);
        return res.status(500).json({ error: 'Falha ao regenerar código do selo.' });
      }
    }

    // 2.6 DESATIVAR / SUSPENDER SELO (Soft-Delete para preservar histórico)
    if (action === 'delete_selo' || action === 'suspend_selo') {
      const { selo_id, motivo } = req.body;
      if (!selo_id) {
        return res.status(400).json({ error: 'selo_id é obrigatório.' });
      }

      try {
        const updateResp = await fetch(`${url}/rest/v1/selos?id=eq.${encodeURIComponent(selo_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            ativo: false,
            desativado_em: new Date().toISOString(),
            motivo_desativacao: motivo || 'Desativado pelo administrador'
          })
        });

        if (!updateResp.ok) throw new Error(await updateResp.text());
        return res.status(200).json({ success: true });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao desativar selo.' });
      }
    }

    return res.status(400).json({ error: 'Ação não reconhecida.' });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}
