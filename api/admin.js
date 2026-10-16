// api/admin.js — Dashboard & Gestão B2B (Empresas, Selos & Threat Radar)
// Especificação Fechada ZAP, QUEM É? — B2B
// Seções 6, 7, 8, 19, 20, 21

import { gerarCodigoSelo } from '../lib/radar.js';
import {
  limparTextoVitima,
  estruturarRelatorioMensal,
  renderRelatorioHtml
} from '../lib/report_generator.js';

// Campos de verificação comercial e CRM (migração 20261016 e 20261015).
const CAMPOS_VERIFICACAO = [
  'nif', 'nif_verificado', 'iban', 'iban_verificado', 'verificacao_notas', 'verificado_em',
  'nome_legal', 'nome_comercial', 'email_contacto', 'representante_nome', 'representante_cargo',
  'plano', 'estado', 'codigo_selo', 'data_emissao', 'data_validade', 'preco_acordado', 'notas', 'marca_aliases'
];

function extrairCamposVerificacao(body) {
  const out = {};
  if (body.nif !== undefined) out.nif = body.nif ? String(body.nif).replace(/\s+/g, '').toUpperCase() : null;
  if (body.nif_verificado !== undefined) out.nif_verificado = !!body.nif_verificado;
  if (body.iban !== undefined) out.iban = body.iban ? String(body.iban).replace(/\s+/g, '').toUpperCase() : null;
  if (body.iban_verificado !== undefined) out.iban_verificado = !!body.iban_verificado;
  if (body.verificacao_notas !== undefined) out.verificacao_notas = body.verificacao_notas ? String(body.verificacao_notas).trim() : null;
  if (out.nif_verificado || out.iban_verificado) out.verificado_em = new Date().toISOString();

  // Campos CRM 20261016
  if (body.nome_legal !== undefined) out.nome_legal = body.nome_legal ? String(body.nome_legal).trim() : null;
  if (body.nome_comercial !== undefined) out.nome_comercial = body.nome_comercial ? String(body.nome_comercial).trim() : null;
  if (body.email_contacto !== undefined) out.email_contacto = body.email_contacto ? String(body.email_contacto).trim().toLowerCase() : null;
  if (body.representante_nome !== undefined) out.representante_nome = body.representante_nome ? String(body.representante_nome).trim() : null;
  if (body.representante_cargo !== undefined) out.representante_cargo = body.representante_cargo ? String(body.representante_cargo).trim() : null;
  if (body.plano !== undefined) out.plano = body.plano;
  if (body.estado !== undefined) out.estado = body.estado;
  if (body.codigo_selo !== undefined) out.codigo_selo = body.codigo_selo;
  if (body.data_emissao !== undefined) out.data_emissao = body.data_emissao;
  if (body.data_validade !== undefined) out.data_validade = body.data_validade;
  if (body.preco_acordado !== undefined) out.preco_acordado = Number(body.preco_acordado) || 49.00;
  if (body.notas !== undefined) out.notas = body.notas ? String(body.notas).trim() : null;
  if (body.marca_aliases !== undefined) {
    out.marca_aliases = Array.isArray(body.marca_aliases)
      ? body.marca_aliases.map(a => String(a).trim()).filter(Boolean)
      : (typeof body.marca_aliases === 'string' ? body.marca_aliases.split(',').map(a => a.trim()).filter(Boolean) : []);
  }

  return out;
}

async function registrarHistorico(supabaseUrl, headers, { empresa_id, acao, antes, depois, por = 'admin', motivo = null }) {
  try {
    await fetch(`${supabaseUrl}/rest/v1/historico`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        empresa_id,
        acao,
        antes: antes || null,
        depois: depois || null,
        por,
        motivo: motivo || null
      })
    });
  } catch (err) {
    console.warn('[Admin Historico] Falha ao registar histórico:', err.message);
  }
}

async function fetchComFallback(fetchUrl, options, payload) {
  let resp = await fetch(fetchUrl, { ...options, body: JSON.stringify(payload) });
  if (!resp.ok) {
    const errText = await resp.text();
    const temCamposNovos = CAMPOS_VERIFICACAO.some(c => c in payload);
    if (temCamposNovos && /column|schema cache/i.test(errText)) {
      console.warn('[Admin] Migração pendente; a gravar com fallback retrocompatível.');
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

      // 8. Buscar verificações de empresas (Checklist 4 pilares)
      let verificacoes = [];
      try {
        const verifResp = await fetch(`${url}/rest/v1/verificacoes?select=*&order=criado_em.asc`, { headers });
        if (verifResp.ok) verificacoes = await verifResp.json();
      } catch {}

      // 9. Buscar registos financeiros de pagamentos
      let pagamentos = [];
      try {
        const pagResp = await fetch(`${url}/rest/v1/pagamentos?select=*&order=data.desc&limit=100`, { headers });
        if (pagResp.ok) pagamentos = await pagResp.json();
      } catch {}

      // 10. Buscar histórico de auditoria
      let historico = [];
      try {
        const histResp = await fetch(`${url}/rest/v1/historico?select=*&order=em.desc&limit=100`, { headers });
        if (histResp.ok) historico = await histResp.json();
      } catch {}

      // 11. Buscar contactos comerciais do funil
      let contactosComerciais = [];
      try {
        const contResp = await fetch(`${url}/rest/v1/contactos_comerciais?select=*&order=data.desc&limit=100`, { headers });
        if (contResp.ok) contactosComerciais = await contResp.json();
      } catch {}

      // 12. Buscar relatórios periciais gerados
      let relatorios = [];
      try {
        const relResp = await fetch(`${url}/rest/v1/relatorios_gerados?select=*&order=gerado_em.desc&limit=50`, { headers });
        if (relResp.ok) relatorios = await relResp.json();
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
      totalLeads: leads.length,
      totalPagamentos: (pagamentos || []).filter(p => p.estado === 'pago').length,
      totalSinais: sinais.length
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
      verificacoes: verificacoes || [],
      pagamentos: pagamentos || [],
      historico: historico || [],
      contactos_comerciais: contactosComerciais || [],
      relatorios: relatorios || [],
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

    // 2.7 ATUALIZAR CHECKLIST DE VERIFICAÇÃO (4 Pilares)
    if (action === 'update_verificacao') {
      const { empresa_id, tipo, estado, prova, verificado_por = 'admin' } = req.body;
      if (!empresa_id || !tipo || !estado) {
        return res.status(400).json({ error: 'empresa_id, tipo e estado são obrigatórios.' });
      }
      if (!['nif', 'dominio', 'telefone', 'representante'].includes(tipo)) {
        return res.status(400).json({ error: 'Tipo inválido. Permitidos: nif, dominio, telefone, representante.' });
      }
      if (!['pendente', 'ok', 'falhou'].includes(estado)) {
        return res.status(400).json({ error: 'Estado inválido. Permitidos: pendente, ok, falhou.' });
      }

      try {
        const verifResp = await fetch(`${url}/rest/v1/verificacoes`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'resolution=merge-duplicates,return=representation' },
          body: JSON.stringify({
            empresa_id,
            tipo,
            estado,
            prova: prova ? String(prova).trim() : null,
            verificado_por,
            verificado_em: new Date().toISOString()
          })
        });

        if (!verifResp.ok) throw new Error(await verifResp.text());
        const verifRows = await verifResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: `verificacao_${tipo}`,
          depois: { tipo, estado, prova },
          por: verificado_por,
          motivo: `Checklist ${tipo.toUpperCase()} atualizada para ${estado.toUpperCase()}`
        });

        return res.status(200).json({ success: true, verificacao: verifRows[0] });
      } catch (err) {
        console.error('[Admin] Erro update_verificacao:', err);
        return res.status(500).json({ error: 'Falha ao atualizar verificação: ' + err.message });
      }
    }

    // 2.8 ALTERAR ESTADO DA EMPRESA COM TRAVA ESTRITA DE ATIVAÇÃO (Critério 1)
    if (action === 'set_empresa_estado') {
      const { empresa_id, estado: novoEstado, motivo, por = 'admin' } = req.body;
      if (!empresa_id || !novoEstado) {
        return res.status(400).json({ error: 'empresa_id e estado são obrigatórios.' });
      }

      const estadosValidos = ['lead', 'contactado', 'proposta', 'em_verificacao', 'ativo', 'suspenso', 'revogado', 'expirado'];
      if (!estadosValidos.includes(novoEstado)) {
        return res.status(400).json({ error: `Estado inválido. Permitidos: ${estadosValidos.join(', ')}` });
      }

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresaAtual = emps[0];
        const estadoAnterior = empresaAtual.estado || empresaAtual.status;

        // CRITÉRIO 1 DE ACEITAÇÃO: Não é possível ativar selo sem 4 verificações OK e pagamento (ou isenção justificada)
        if (novoEstado === 'ativo') {
          // A) Checar 4 verificações
          const verifResp = await fetch(`${url}/rest/v1/verificacoes?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
          const verifs = verifResp.ok ? await verifResp.json() : [];
          const tiposOk = new Set(verifs.filter(v => v.estado === 'ok').map(v => v.tipo));
          const obrigatorios = ['nif', 'dominio', 'telefone', 'representante'];
          const faltantes = obrigatorios.filter(t => !tiposOk.has(t));

          if (faltantes.length > 0) {
            return res.status(400).json({
              error: `Bloqueio de ativação: as 4 verificações obrigatórias devem estar OK. Faltam: ${faltantes.join(', ')}.`
            });
          }

          // B) Checar pagamento válido ou isenção justificada
          const pagResp = await fetch(`${url}/rest/v1/pagamentos?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
          const pags = pagResp.ok ? await pagResp.json() : [];
          const temPagamentoValido = pags.some(p => p.estado === 'pago' || (p.estado === 'isento' && p.motivo_isencao && p.motivo_isencao.trim().length >= 4));

          if (!temPagamentoValido) {
            return res.status(400).json({
              error: 'Bloqueio de ativação: é obrigatório registrar pelo menos um pagamento "pago" ou uma isenção com motivo escrito antes de ativar o selo.'
            });
          }
        }

        // Suspensão ou revogação exige motivo escrito obrigatório
        if ((novoEstado === 'suspenso' || novoEstado === 'revogado') && (!motivo || motivo.trim().length < 4)) {
          return res.status(400).json({
            error: `A transição para ${novoEstado} exige obrigatoriamente um motivo escrito para arquivo no histórico de auditoria.`
          });
        }

        let codigoSelo = empresaAtual.codigo_selo;
        if (novoEstado === 'ativo' && !codigoSelo) {
          codigoSelo = gerarCodigoSelo();
        }

        const dataEmissao = novoEstado === 'ativo' ? (empresaAtual.data_emissao || new Date().toISOString()) : empresaAtual.data_emissao;
        let dataValidade = empresaAtual.data_validade;
        if (novoEstado === 'ativo' && !dataValidade) {
          const v = new Date();
          v.setFullYear(v.getFullYear() + 1);
          dataValidade = v.toISOString();
        }

        const patchPayload = {
          estado: novoEstado,
          status: novoEstado === 'ativo' ? 'ativo' : (novoEstado === 'suspenso' ? 'suspenso' : 'inativo'),
          codigo_selo: codigoSelo,
          data_emissao: dataEmissao,
          data_validade: dataValidade
        };

        const updateResp = await fetchComFallback(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' }
        }, patchPayload);

        if (!updateResp.ok) throw new Error(await updateResp.text());

        // Atualizar selos
        if (novoEstado === 'ativo') {
          await fetch(`${url}/rest/v1/selos`, {
            method: 'POST',
            headers: { ...headers, Prefer: 'resolution=merge-duplicates,return=representation' },
            body: JSON.stringify({
              empresa_id,
              codigo: codigoSelo,
              tipo: 'canal_verificado',
              valido_ate: dataValidade,
              ativo: true
            })
          });
        } else if (novoEstado === 'suspenso' || novoEstado === 'revogado' || novoEstado === 'expirado') {
          await fetch(`${url}/rest/v1/selos?empresa_id=eq.${encodeURIComponent(empresa_id)}`, {
            method: 'PATCH',
            headers,
            body: JSON.stringify({
              ativo: false,
              desativado_em: new Date().toISOString(),
              motivo_desativacao: motivo || `Empresa em estado ${novoEstado}`
            })
          });
        }

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: `mudanca_estado_${novoEstado}`,
          antes: { estado: estadoAnterior },
          depois: { estado: novoEstado, codigo_selo: codigoSelo },
          por,
          motivo: motivo || `Transição de estado para ${novoEstado}`
        });

        return res.status(200).json({ success: true, estado: novoEstado, codigo_selo: codigoSelo });
      } catch (err) {
        console.error('[Admin] Erro set_empresa_estado:', err);
        return res.status(500).json({ error: 'Falha ao alterar estado: ' + err.message });
      }
    }

    // 2.9 REGISTAR PAGAMENTO
    if (action === 'add_pagamento') {
      const { empresa_id, valor, data, metodo, referencia, fatura_numero, periodo_inicio, periodo_fim, estado, motivo_isencao } = req.body;
      if (!empresa_id || !estado) {
        return res.status(400).json({ error: 'empresa_id e estado são obrigatórios.' });
      }

      try {
        const pagResp = await fetch(`${url}/rest/v1/pagamentos`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            valor: Number(valor) || 0.00,
            data: data || new Date().toISOString(),
            metodo: metodo || 'transferencia',
            referencia: referencia ? String(referencia).trim() : null,
            fatura_numero: fatura_numero ? String(fatura_numero).trim() : null,
            periodo_inicio: periodo_inicio || null,
            periodo_fim: periodo_fim || null,
            estado: estado || 'pendente',
            motivo_isencao: motivo_isencao ? String(motivo_isencao).trim() : null
          })
        });

        if (!pagResp.ok) throw new Error(await pagResp.text());
        const pagRows = await pagResp.json();

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'registo_pagamento',
          depois: { valor, estado, metodo },
          motivo: `Pagamento registado: ${estado} (${valor}€)`
        });

        return res.status(200).json({ success: true, pagamento: pagRows[0] });
      } catch (err) {
        console.error('[Admin] Erro add_pagamento:', err);
        return res.status(500).json({ error: 'Falha ao registar pagamento: ' + err.message });
      }
    }

    // 2.10 REGISTAR CONTACTO COMERCIAL (Funil)
    if (action === 'add_contacto_comercial') {
      const { empresa_id, tipo, canal, data, resumo, resposta } = req.body;
      if (!empresa_id || !tipo) {
        return res.status(400).json({ error: 'empresa_id e tipo são obrigatórios.' });
      }

      try {
        const contResp = await fetch(`${url}/rest/v1/contactos_comerciais`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            tipo: tipo || 'seguimento',
            canal: canal || 'email',
            data: data || new Date().toISOString(),
            resumo: resumo ? String(resumo).trim() : '',
            resposta: resposta ? String(resposta).trim() : null
          })
        });

        if (!contResp.ok) throw new Error(await contResp.text());
        const contRows = await contResp.json();

        return res.status(200).json({ success: true, contacto: contRows[0] });
      } catch (err) {
        console.error('[Admin] Erro add_contacto_comercial:', err);
        return res.status(500).json({ error: 'Falha ao registar contacto comercial.' });
      }
    }

    // 2.11 GERAR ALERTA GRATUITO (Radar -> Empresa)
    if (action === 'gerar_alerta_gratuito') {
      const { empresa_id, marca } = req.body;
      if (!empresa_id && !marca) {
        return res.status(400).json({ error: 'empresa_id ou marca é obrigatório.' });
      }

      try {
        let empresa = null;
        let marcaNome = marca;
        if (empresa_id) {
          const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
          const emps = empResp.ok ? await empResp.json() : [];
          if (emps.length) {
            empresa = emps[0];
            marcaNome = empresa.nome_comercial || empresa.nome;
          }
        }

        const marcasFiltro = empresa?.marca_aliases?.length ? [marcaNome, ...empresa.marca_aliases] : [marcaNome];
        const sinaisResp = await fetch(
          `${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&order=criado_em.desc&limit=100`,
          { headers }
        );
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const sinaisMarca = allSinais.filter(s => {
          const m = (s.marca_mencionada || '').toLowerCase();
          return marcasFiltro.some(al => m.includes(al.toLowerCase()));
        });

        const totalSinais = sinaisMarca.length;
        const canais = [...new Set(sinaisMarca.map(s => s.canal || 'SMS/WhatsApp'))].join(', ') || 'SMS / WhatsApp';
        
        const exemplos = sinaisMarca.slice(0, 3).map(s => {
          const limpo = limparTextoVitima(s.texto_original || s.resumo || 'Tentativa de cobrança urgente com link não oficial.');
          return limpo.length > 100 ? limpo.slice(0, 97) + '...' : limpo;
        });

        const draftTexto = `Assunto: Alerta Preventivo de Segurança: Sinais de personificação da marca ${marcaNome}

Exma. Equipa de Segurança / Comunicação de ${marcaNome},

No âmbito da monitorização contínua da rede Confirme, Quem É? (confirmequeme.pt), detetámos recentemente ${totalSinais} sinal(is) de mensagens em circulação utilizando o nome da vossa marca.

Resumo dos sinais detetados:
• Total de ocorrências: ${totalSinais}
• Canais reportados: ${canais}
• Exemplos limpos (sem qualquer dado pessoal de utilizadores):
${exemplos.map(e => `  - "${e}"`).join('\n') || '  - Mensagens simulando notificações oficiais com links externos.'}

Recomendação preventiva:
Sugerimos avaliar a publicação de uma nota preventiva nos vossos canais oficiais, alertando os vossos utilizadores para não acederem a links não oficiais nem partilharem dados confidenciais.

Nota de integridade e utilidade pública:
Este alerta é estritamente informativo e não constitui proposta comercial.

Atenciosamente,
Equipa de Inteligência & Verificação — Confirme, Quem É?
https://confirmequeme.pt`;

        if (empresa_id) {
          await fetch(`${url}/rest/v1/contactos_comerciais`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              empresa_id,
              tipo: 'alerta_gratuito',
              canal: 'email',
              resumo: `Alerta gratuito gerado com ${totalSinais} sinais detetados`,
              resposta: 'Alerta pronto para envio'
            })
          });

          await registrarHistorico(url, headers, {
            empresa_id,
            acao: 'geracao_alerta_gratuito',
            depois: { total_sinais: totalSinais },
            motivo: 'Alerta preventivo gratuito gerado pelo operador'
          });
        }

        return res.status(200).json({
          success: true,
          total_sinais: totalSinais,
          alerta_texto: draftTexto
        });
      } catch (err) {
        console.error('[Admin] Erro gerar_alerta_gratuito:', err);
        return res.status(500).json({ error: 'Falha ao gerar alerta gratuito.' });
      }
    }

    // 2.12 GERAR RELATÓRIO MENSAL EM HTML/PDF
    if (action === 'gerar_relatorio_mensal') {
      const { empresa_id, periodo = new Date().toISOString().slice(0, 7), versao = '1.0' } = req.body;
      if (!empresa_id) return res.status(400).json({ error: 'empresa_id é obrigatório.' });

      try {
        const empResp = await fetch(`${url}/rest/v1/empresas?id=eq.${encodeURIComponent(empresa_id)}&select=*&limit=1`, { headers });
        const emps = empResp.ok ? await empResp.json() : [];
        if (!emps.length) return res.status(404).json({ error: 'Empresa não encontrada.' });
        const empresa = emps[0];

        const marcaNome = empresa.nome_comercial || empresa.nome;
        const aliases = empresa.marca_aliases || [];
        const allMarcas = [marcaNome, ...aliases].map(m => m.toLowerCase());

        const sinaisResp = await fetch(`${url}/rest/v1/analises?marca_mencionada=not.is.null&veredito=in.(golpe,suspeito)&limit=200`, { headers });
        const allSinais = sinaisResp.ok ? await sinaisResp.json() : [];
        const ocorrencias = allSinais.filter(s => {
          const m = (s.marca_mencionada || '').toLowerCase();
          return allMarcas.some(al => m.includes(al));
        });

        const usoResp = await fetch(`${url}/rest/v1/uso_selo?empresa_id=eq.${encodeURIComponent(empresa_id)}&select=*`, { headers });
        const usos = usoResp.ok ? await usoResp.json() : [];
        const metricas = {
          visitas_pagina: usos.reduce((a, b) => a + (b.visitas_pagina || 0), 0),
          verificacoes_widget: usos.reduce((a, b) => a + (b.verificacoes_widget || 0), 0)
        };

        const dadosRelatorio = estruturarRelatorioMensal({
          empresa,
          periodo,
          ocorrencias,
          metricasSelo: metricas,
          versao,
          geradoPor: 'admin'
        });

        const html = renderRelatorioHtml(dadosRelatorio);

        const relInsert = await fetch(`${url}/rest/v1/relatorios_gerados`, {
          method: 'POST',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            empresa_id,
            periodo,
            versao,
            hash_ficheiro: dadosRelatorio.hash_sha256,
            gerado_por: 'admin'
          })
        });

        const relRows = relInsert.ok ? await relInsert.json() : [];

        await registrarHistorico(url, headers, {
          empresa_id,
          acao: 'geracao_relatorio_mensal',
          depois: { periodo, versao, hash: dadosRelatorio.hash_sha256 },
          motivo: `Relatório mensal gerado para ${periodo}`
        });

        return res.status(200).json({
          success: true,
          relatorio: relRows[0] || null,
          hash_sha256: dadosRelatorio.hash_sha256,
          dados: dadosRelatorio,
          html
        });
      } catch (err) {
        console.error('[Admin] Erro gerar_relatorio_mensal:', err);
        return res.status(500).json({ error: 'Falha ao compilar relatório mensal.' });
      }
    }

    // 2.13 APROVAÇÃO MANUAL DE RELATÓRIO (Critério 6)
    if (action === 'aprovar_relatorio') {
      const { relatorio_id, aprovado_por = 'admin' } = req.body;
      if (!relatorio_id) return res.status(400).json({ error: 'relatorio_id é obrigatório.' });

      try {
        const patchResp = await fetch(`${url}/rest/v1/relatorios_gerados?id=eq.${encodeURIComponent(relatorio_id)}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({
            aprovado_por,
            aprovado_em: new Date().toISOString()
          })
        });

        if (!patchResp.ok) throw new Error(await patchResp.text());
        const rows = await patchResp.json();

        return res.status(200).json({ success: true, relatorio: rows[0] });
      } catch (err) {
        return res.status(500).json({ error: 'Falha ao aprovar relatório.' });
      }
    }

    return res.status(400).json({ error: 'Ação não reconhecida.' });
  }

  return res.status(405).json({ error: 'Método não permitido.' });
}
