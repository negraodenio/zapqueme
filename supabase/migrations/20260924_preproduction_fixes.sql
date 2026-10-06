-- ==============================================================================
-- ZAP, QUEM É? — MIGRATION: PRÉ-PRODUÇÃO B2B (PHASE 2)
-- Arquivo: supabase/migrations/20260924_preproduction_fixes.sql
-- Idempotente: seguro para ser executado múltiplas vezes.
-- Executar no Supabase: SQL Editor > New query > Run
-- ==============================================================================

-- ============================================================
-- MIGRATION 1 — Tabela ANALISES: campos em falta
-- ============================================================
ALTER TABLE analises
  ADD COLUMN IF NOT EXISTS risco_score   int,
  ADD COLUMN IF NOT EXISTS alerta_link   text,
  ADD COLUMN IF NOT EXISTS canal         text DEFAULT 'web';

CREATE INDEX IF NOT EXISTS idx_analises_canal ON analises (canal);
CREATE INDEX IF NOT EXISTS idx_analises_empresa_imp
  ON analises (empresa_id, impersonation)
  WHERE impersonation = true;

-- ============================================================
-- MIGRATION 2 — Tabela SELOS: soft-delete + unicidade
-- ============================================================
ALTER TABLE selos
  ADD COLUMN IF NOT EXISTS ativo              boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS desativado_em      timestamptz,
  ADD COLUMN IF NOT EXISTS motivo_desativacao text;

-- Desativa selos anteriores duplicados, preservando apenas o mais recente ativo por empresa
UPDATE selos
SET ativo = false,
    desativado_em = COALESCE(desativado_em, now()),
    motivo_desativacao = COALESCE(motivo_desativacao, 'Substituído por selo mais recente')
WHERE id NOT IN (
  SELECT DISTINCT ON (empresa_id) id
  FROM selos
  ORDER BY empresa_id, criado_em DESC
);

CREATE INDEX IF NOT EXISTS idx_selos_ativo
  ON selos (empresa_id, ativo);

CREATE UNIQUE INDEX IF NOT EXISTS idx_selos_um_ativo_por_empresa
  ON selos (empresa_id)
  WHERE ativo = true;

-- ============================================================
-- MIGRATION 3 — Tabela EMPRESAS: auditoria
-- ============================================================
ALTER TABLE empresas
  ADD COLUMN IF NOT EXISTS atualizado_em timestamptz;

CREATE OR REPLACE FUNCTION fn_update_atualizado_em()
RETURNS TRIGGER AS $$
BEGIN
  NEW.atualizado_em = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_empresas_atualizado_em ON empresas;
CREATE TRIGGER tr_empresas_atualizado_em
  BEFORE UPDATE ON empresas
  FOR EACH ROW EXECUTE FUNCTION fn_update_atualizado_em();

-- ============================================================
-- MIGRATION 4 — View RADAR_AMEACAS: sem ORDER BY na view
-- ============================================================
CREATE OR REPLACE VIEW radar_ameacas AS
SELECT
  e.id   AS empresa_id,
  e.nome AS empresa,
  count(*)                           AS ocorrencias,
  count(DISTINCT a.canal_mencionado) AS canais_distintos,
  min(a.criado_em)                   AS primeira_deteccao,
  max(a.criado_em)                   AS ultima_deteccao,
  CASE
    WHEN count(*) >= 20 THEN 'critica'
    WHEN count(*) >= 5  THEN 'suspeita'
    ELSE 'monitorar'
  END AS severidade
FROM analises a
JOIN empresas e ON e.id = a.empresa_id
WHERE a.impersonation = true
GROUP BY e.id, e.nome;
