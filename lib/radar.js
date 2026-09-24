// lib/radar.js — Motor de Detecção de Impersonation & Threat Radar
// Especificação Fechada ZAP, QUEM É? — B2B

import crypto from 'node:crypto';

/**
 * Normaliza strings para comparação de marcas (lowercase, sem acentos, sem pontuação, espaços normalizados)
 * Conforme Seção 10 da especificação.
 */
export function normalizarTexto(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // remove acentos
    .toLowerCase()
    .replace(/[^\w\s]/gi, ' ') // remove pontuação básica
    .replace(/\s+/g, ' ') // normaliza espaços
    .trim();
}

/**
 * Extrai o hostname limpo de uma URL, domínio ou endereço de email
 * Conforme Seção 11 da especificação.
 */
export function extrairHostname(str) {
  if (!str || typeof str !== 'string') return '';
  let clean = str.toLowerCase().trim();

  // Se tiver formato de email (ex: user@dominio.com), pega o domínio após o @
  if (clean.includes('@')) {
    clean = clean.split('@')[1] || clean;
  }

  // Remove protocolo http://, https://
  clean = clean.replace(/^[a-z0-9]+:\/\//, '');

  // Remove caminho /... e parâmetros ?...
  clean = clean.split('/')[0].split('?')[0].split('#')[0];

  // Remove porta :8080
  clean = clean.split(':')[0];

  return clean.trim();
}

/**
 * Verifica se um canal mencionado corresponde a algum canal oficial cadastrado da empresa.
 * Conforme Seção 11 da especificação.
 */
export function isCanalOficial(canalMencionado, empresa) {
  if (!canalMencionado || !empresa) return false;

  const canalLimpo = canalMencionado.trim();
  const canalLower = canalLimpo.toLowerCase();

  // 1. TELEFONE: comparar apenas os dígitos numéricos
  const canalDigitos = canalLimpo.replace(/\D/g, '');
  if (canalDigitos.length >= 8 && empresa.telefone_oficial) {
    const telOficialDigitos = empresa.telefone_oficial.replace(/\D/g, '');
    if (telOficialDigitos.length >= 8) {
      if (
        canalDigitos === telOficialDigitos ||
        canalDigitos.endsWith(telOficialDigitos) ||
        telOficialDigitos.endsWith(canalDigitos)
      ) {
        return true;
      }
    }
  }

  // 2. EMAIL: comparar email exato, domínio do email ou domínio oficial
  if (canalLower.includes('@')) {
    const canalEmailDomain = canalLower.split('@')[1];

    if (empresa.email_oficial) {
      const emailOficialLower = empresa.email_oficial.toLowerCase().trim();
      // Email exato
      if (canalLower === emailOficialLower) return true;

      // Domínio do email oficial
      const oficialEmailDomain = emailOficialLower.split('@')[1];
      if (oficialEmailDomain && canalEmailDomain === oficialEmailDomain) return true;
    }

    if (empresa.dominio_oficial) {
      const oficialHost = extrairHostname(empresa.dominio_oficial);
      if (oficialHost && (canalEmailDomain === oficialHost || canalEmailDomain.endsWith('.' + oficialHost))) {
        return true;
      }
    }
  }

  // 3. DOMÍNIO / HOSTNAME
  const canalHost = extrairHostname(canalLimpo);
  if (canalHost && empresa.dominio_oficial) {
    const oficialHost = extrairHostname(empresa.dominio_oficial);
    if (oficialHost) {
      // Aceita xpto.pt e subdomínio app.xpto.pt. Não aceita xpto.pt.fake.com
      if (canalHost === oficialHost || canalHost.endsWith('.' + oficialHost)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Busca empresas ativas no Supabase
 */
export async function getEmpresasAtivasFromDB() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return [];

  try {
    const resp = await fetch(`${url}/rest/v1/empresas?status=eq.ativo&select=*`, {
      headers: {
        'Content-Type': 'application/json',
        apikey: key,
        Authorization: `Bearer ${key}`
      }
    });
    if (!resp.ok) return [];
    return await resp.json();
  } catch (err) {
    console.warn('[Radar] Erro ao buscar empresas ativas:', err.message);
    return [];
  }
}

/**
 * Regras de detecção de Impersonation
 * Conforme Seção 9, 10, 11 da especificação.
 *
 * impersonation=true SOMENTE quando TODAS as 4 condições forem verdadeiras:
 * 1. marca_mencionada corresponde a exatamente UMA empresa ativa;
 * 2. veredito é: golpe OU suspeito;
 * 3. existe canal_mencionado;
 * 4. canal_mencionado NÃO corresponde a nenhum canal oficial cadastrado.
 * Se qualquer condição falhar: impersonation=false
 * Se houver ambiguidade entre empresas: não associar.
 */
export async function detectarImpersonation({
  marca_mencionada,
  canal_mencionado,
  veredito,
  empresasList = null
}) {
  // Condição 2: veredito deve ser 'golpe' ou 'suspeito'
  const isSuspeitoOuGolpe = veredito === 'golpe' || veredito === 'suspeito';

  // Se não houver marca mencionada, não há correspondência
  if (!marca_mencionada || typeof marca_mencionada !== 'string' || !marca_mencionada.trim()) {
    return { empresa_id: null, impersonation: false };
  }

  const normMarca = normalizarTexto(marca_mencionada);
  if (!normMarca) {
    return { empresa_id: null, impersonation: false };
  }

  // Lista de empresas ativas (passada explicitamente em testes ou buscada do banco)
  const empresas = empresasList !== null ? empresasList : await getEmpresasAtivasFromDB();

  // Condição 1: Correspondência de marca com exatamente UMA empresa ativa
  const matchingEmpresas = empresas.filter(emp => {
    if (emp.status && emp.status !== 'ativo') return false;

    // Compara nome oficial
    const normNome = normalizarTexto(emp.nome);
    if (normNome === normMarca) return true;

    // Compara apelidos / aliases da marca
    if (Array.isArray(emp.apelidos_marca)) {
      for (const alias of emp.apelidos_marca) {
        if (normalizarTexto(alias) === normMarca) return true;
      }
    }

    return false;
  });

  // Se nenhuma empresa ou ambiguidade (mais de uma empresa): não associar
  if (matchingEmpresas.length !== 1) {
    return { empresa_id: null, impersonation: false };
  }

  const matchedEmpresa = matchingEmpresas[0];

  // Se o veredito não for golpe nem suspeito, não é impersonation (mesmo que haja marca)
  if (!isSuspeitoOuGolpe) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Condição 3: existe canal_mencionado
  if (!canal_mencionado || typeof canal_mencionado !== 'string' || !canal_mencionado.trim()) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Condição 4: canal_mencionado NÃO corresponde a nenhum canal oficial cadastrado
  const ehOficial = isCanalOficial(canal_mencionado, matchedEmpresa);
  if (ehOficial) {
    return { empresa_id: matchedEmpresa.id, impersonation: false };
  }

  // Todas as 4 condições satisfeitas!
  return {
    empresa_id: matchedEmpresa.id,
    impersonation: true
  };
}

/**
 * Gera código de selo de alta entropia e imprevisível
 * Formato exemplo: ZQV-7K4M9X2P8R6T1 (Conforme Seção 4.3)
 */
export function gerarCodigoSelo() {
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const bytes = crypto.randomBytes(13);
  let randomStr = '';
  for (let i = 0; i < bytes.length; i++) {
    randomStr += chars[bytes[i] % chars.length];
  }
  return `ZQV-${randomStr}`;
}
