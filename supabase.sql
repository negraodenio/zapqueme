-- ==============================================================================
-- ZAP, QUEM É? — BANCO DE DADOS SUPABASE (B2C & B2B: ZAP VERIFIED & THREAT RADAR)
-- Idempotente: seguro para executar em bases novas ou já existentes.
-- Executar no Supabase: painel do projeto → SQL Editor → New query → Run.
-- ==============================================================================

-- 1. TABELA EMPRESAS (B2B)
CREATE TABLE IF NOT EXISTS empresas (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz DEFAULT now(),

  nome text NOT NULL,

  dominio_oficial text,
  email_oficial text,
  telefone_oficial text,

  apelidos_marca text[] DEFAULT '{}',

  dominio_verificado boolean NOT NULL DEFAULT false,
  email_verificado boolean NOT NULL DEFAULT false,
  telefone_verificado boolean NOT NULL DEFAULT false,

  plano text NOT NULL DEFAULT 'business',
  status text NOT NULL DEFAULT 'ativo',

  stripe_customer_id text
);

-- Trigger de atualização automática de data em empresas
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

-- 2. TABELA SELOS (ZAP VERIFIED)
CREATE TABLE IF NOT EXISTS selos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),

  empresa_id uuid NOT NULL
    REFERENCES empresas(id)
    ON DELETE CASCADE,

  codigo text NOT NULL UNIQUE,
  tipo text NOT NULL DEFAULT 'canal_verificado',
  valido_ate timestamptz,
  monitorizacao_impersonation boolean NOT NULL DEFAULT true,

  ativo boolean NOT NULL DEFAULT true,
  desativado_em timestamptz,
  motivo_desativacao text
);

CREATE INDEX IF NOT EXISTS idx_selos_codigo ON selos (codigo);
CREATE INDEX IF NOT EXISTS idx_selos_empresa ON selos (empresa_id);
CREATE INDEX IF NOT EXISTS idx_selos_ativo ON selos (empresa_id, ativo);

-- Garante no máximo 1 selo ativo por empresa
CREATE UNIQUE INDEX IF NOT EXISTS idx_selos_um_ativo_por_empresa
  ON selos (empresa_id)
  WHERE ativo = true;

-- 3. TABELA ANALISES (B2C + RADAR DE IMPERSONATION)
CREATE TABLE IF NOT EXISTS analises (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),
  veredito text NOT NULL,
  confianca int NOT NULL,
  risco_score int,
  alerta_link text,
  canal text DEFAULT 'web',
  tipo text,
  vezes_reportada int DEFAULT 1,
  teve_imagem boolean DEFAULT false,
  empresa_id uuid REFERENCES empresas(id),
  marca_mencionada text,
  canal_mencionado text,
  impersonation boolean DEFAULT false
);

-- Garantir colunas se tabela já existia antes
ALTER TABLE analises ADD COLUMN IF NOT EXISTS risco_score int;
ALTER TABLE analises ADD COLUMN IF NOT EXISTS alerta_link text;
ALTER TABLE analises ADD COLUMN IF NOT EXISTS canal text DEFAULT 'web';
ALTER TABLE analises ADD COLUMN IF NOT EXISTS empresa_id uuid REFERENCES empresas(id);
ALTER TABLE analises ADD COLUMN IF NOT EXISTS marca_mencionada text;
ALTER TABLE analises ADD COLUMN IF NOT EXISTS canal_mencionado text;
ALTER TABLE analises ADD COLUMN IF NOT EXISTS impersonation boolean DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_analises_criado_em ON analises (criado_em);
CREATE INDEX IF NOT EXISTS idx_analises_veredito ON analises (veredito);
CREATE INDEX IF NOT EXISTS idx_analises_canal ON analises (canal);
CREATE INDEX IF NOT EXISTS idx_analises_empresa ON analises (empresa_id);
CREATE INDEX IF NOT EXISTS idx_analises_impersonation ON analises (impersonation);
CREATE INDEX IF NOT EXISTS idx_analises_empresa_imp ON analises (empresa_id, impersonation) WHERE impersonation = true;

-- 4. VIEW THREAT RADAR
CREATE OR REPLACE VIEW radar_ameacas AS
SELECT
  e.id AS empresa_id,
  e.nome AS empresa,
  count(*) AS ocorrencias,
  count(DISTINCT a.canal_mencionado) AS canais_distintos,
  min(a.criado_em) AS primeira_deteccao,
  max(a.criado_em) AS ultima_deteccao,
  CASE
    WHEN count(*) >= 20 THEN 'critica'
    WHEN count(*) >= 5  THEN 'suspeita'
    ELSE 'monitorar'
  END AS severidade
FROM analises a
JOIN empresas e ON e.id = a.empresa_id
WHERE a.impersonation = true
GROUP BY e.id, e.nome;

-- 5. TABELA FEEDBACK (B2C)
CREATE TABLE IF NOT EXISTS feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),
  analise_id uuid REFERENCES analises(id),
  positivo boolean NOT NULL
);

-- 6. TABELA LEADS (B2B COMMERCIAL & VENDAS)
CREATE TABLE IF NOT EXISTS leads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),
  nome text NOT NULL,
  empresa text NOT NULL,
  email text NOT NULL,
  whatsapp text,
  website text,
  plano_interesse text DEFAULT 'pro',
  status text NOT NULL DEFAULT 'novo',
  notas text
);

CREATE INDEX IF NOT EXISTS idx_leads_criado_em ON leads (criado_em DESC);

-- 7. VERIFICAÇÃO COMERCIAL DA EMPRESA (NIF / IBAN) — ver supabase/migrations/20261015_verificacao_marcas.sql
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nif text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nif_verificado boolean NOT NULL DEFAULT false;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS iban text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS iban_verificado boolean NOT NULL DEFAULT false;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS verificacao_notas text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS verificado_em timestamptz;

-- 8. VIEW MARCAS MENCIONADAS (denúncias, inclui não-clientes)
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
