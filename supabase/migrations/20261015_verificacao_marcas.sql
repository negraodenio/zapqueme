-- ==============================================================================
-- MIGRATION 2026-10-15 — Verificação comercial (NIF/IBAN) + Marcas mencionadas
-- Aditiva e idempotente: não apaga nem altera dados existentes.
-- Executar no Supabase: SQL Editor → New query → Run.
-- ==============================================================================

-- 1. Dados de verificação da empresa (Selo Zap Verified)
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nif text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nif_verificado boolean NOT NULL DEFAULT false;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS iban text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS iban_verificado boolean NOT NULL DEFAULT false;
-- Registo interno de como a verificação foi feita (ex.: "NIF confirmado no portal das Finanças em 15/10, print guardado")
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS verificacao_notas text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS verificado_em timestamptz;

-- 2. Marcas mencionadas em denúncias (inclui empresas que AINDA NÃO são clientes)
--    Base do "alerta gratuito": mostra quais marcas aparecem em mensagens classificadas
--    como golpe/suspeito. São denúncias, não fraudes confirmadas.
CREATE OR REPLACE VIEW marcas_mencionadas AS
SELECT
  lower(trim(marca_mencionada))            AS marca_norm,
  min(marca_mencionada)                    AS marca,
  count(*)                                 AS denuncias,
  count(*) FILTER (WHERE veredito = 'golpe')    AS golpe,
  count(*) FILTER (WHERE veredito = 'suspeito') AS suspeito,
  count(DISTINCT canal_mencionado)         AS canais_distintos,
  min(criado_em)                           AS primeira_denuncia,
  max(criado_em)                           AS ultima_denuncia
FROM analises
WHERE marca_mencionada IS NOT NULL
  AND trim(marca_mencionada) <> ''
  AND veredito IN ('golpe', 'suspeito')
GROUP BY lower(trim(marca_mencionada));

CREATE INDEX IF NOT EXISTS idx_analises_marca ON analises (lower(trim(marca_mencionada)));
