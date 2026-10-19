-- ==============================================================================
-- MIGRATION 2026-10-19 — Fase 1: Segurança, RLS Estrito, Soft-Delete & Dados de Teste
-- Aditiva, idempotente e segura: preserva 100% da integridade de dados existentes.
-- Executar no Supabase: SQL Editor → New query → Run.
-- ==============================================================================

-- 1. CAMPOS DE CONTROLO DE TESTE E SOFT-DELETE EM EMPRESAS
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS is_teste boolean NOT NULL DEFAULT false;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS arquivado_em timestamptz;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS arquivado_motivo text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS arquivado_por text;

CREATE INDEX IF NOT EXISTS idx_empresas_is_teste ON empresas (is_teste);
CREATE INDEX IF NOT EXISTS idx_empresas_arquivado ON empresas (arquivado_em);

-- 2. CAMPOS DE CONTROLO DE TESTE E SOFT-DELETE EM SELOS
ALTER TABLE selos ADD COLUMN IF NOT EXISTS is_teste boolean NOT NULL DEFAULT false;
ALTER TABLE selos ADD COLUMN IF NOT EXISTS arquivado_em timestamptz;
ALTER TABLE selos ADD COLUMN IF NOT EXISTS arquivado_motivo text;
ALTER TABLE selos ADD COLUMN IF NOT EXISTS arquivado_por text;

CREATE INDEX IF NOT EXISTS idx_selos_is_teste ON selos (is_teste);
CREATE INDEX IF NOT EXISTS idx_selos_arquivado ON selos (arquivado_em);

-- 3. MARCAR "BANCO XPTO" E SELOS DE DEMONSTRAÇÃO COMO TESTE
UPDATE empresas
SET is_teste = true
WHERE lower(nome) LIKE '%xpto%' 
   OR lower(nome) LIKE '%teste%'
   OR lower(nome_comercial) LIKE '%xpto%'
   OR lower(nome_legal) LIKE '%xpto%';

UPDATE selos
SET is_teste = true
WHERE empresa_id IN (SELECT id FROM empresas WHERE is_teste = true)
   OR lower(codigo) LIKE '%xpto%'
   OR lower(codigo) LIKE '%teste%';

-- 4. ÍNDICE DE UNICIDADE: IMPEDIR DOIS SELOS ATIVOS PARA A MESMA EMPRESA
-- (Já criado em supabase.sql, reforçado aqui com cláusula WHERE ativo = true e arquivado_em IS NULL)
DROP INDEX IF EXISTS idx_selos_um_ativo_por_empresa;
CREATE UNIQUE INDEX IF NOT EXISTS idx_selos_um_ativo_por_empresa
  ON selos (empresa_id)
  WHERE ativo = true AND arquivado_em IS NULL;

-- 5. SEGURANÇA E RLS ESTRITO — BLOQUEIO DE LEITURA PÚBLICA DE LEADS E AUDITORIA
-- Impede que chaves anónimas (anon key) leiam dados de leads ou auditoria pelo Supabase REST
ALTER TABLE leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE empresas ENABLE ROW LEVEL SECURITY;
ALTER TABLE selos ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Acesso estrito de servico para leads" ON leads;
DROP POLICY IF EXISTS "Leitura publica negada para leads" ON leads;
CREATE POLICY "Acesso estrito de servico para leads" ON leads FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Acesso estrito de servico para empresas" ON empresas;
CREATE POLICY "Acesso estrito de servico para empresas" ON empresas FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Acesso estrito de servico para selos" ON selos;
CREATE POLICY "Acesso estrito de servico para selos" ON selos FOR ALL TO service_role USING (true) WITH CHECK (true);
