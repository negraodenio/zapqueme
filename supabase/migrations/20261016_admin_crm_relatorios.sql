-- ==============================================================================
-- MIGRATION 2026-10-16 — CRM Comercial, Checklist de Verificação, Auditoria & Relatórios
-- Aditiva, idempotente e segura: preserva 100% da integridade de dados existentes.
-- Executar no Supabase: SQL Editor → New query → Run.
-- ==============================================================================

-- 1. NOVOS CAMPOS NA TABELA EMPRESAS (Campos Comerciais e Selo Unificado)
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nome_legal text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nome_comercial text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS nif text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS email_contacto text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS representante_nome text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS representante_cargo text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS plano text DEFAULT 'selo';
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS estado text DEFAULT 'lead';
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS codigo_selo text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS data_emissao timestamptz;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS data_validade timestamptz;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS preco_acordado numeric(10,2) DEFAULT 49.00;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS notas text;
ALTER TABLE empresas ADD COLUMN IF NOT EXISTS marca_aliases text[] DEFAULT '{}';

-- Garante unicidade e indexação do codigo_selo em empresas
CREATE UNIQUE INDEX IF NOT EXISTS idx_empresas_codigo_selo ON empresas (codigo_selo) WHERE codigo_selo IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_empresas_estado ON empresas (estado);

-- 2. TABELA VERIFICACOES (Checklist Rigorosa dos 4 Pilares)
-- Tipos obrigatórios: 'nif', 'dominio', 'telefone', 'representante'
-- Estados: 'pendente', 'ok', 'falhou'
CREATE TABLE IF NOT EXISTS verificacoes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  criado_em timestamptz NOT NULL DEFAULT now(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  tipo text NOT NULL,
  estado text NOT NULL DEFAULT 'pendente',
  prova text,
  verificado_por text,
  verificado_em timestamptz,
  CONSTRAINT uq_empresa_tipo_verificacao UNIQUE (empresa_id, tipo)
);

CREATE INDEX IF NOT EXISTS idx_verificacoes_empresa ON verificacoes (empresa_id);

-- 3. TABELA HISTORICO (Audit Log Imutável de Auditoria Forense e Operacional)
CREATE TABLE IF NOT EXISTS historico (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  em timestamptz NOT NULL DEFAULT now(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  acao text NOT NULL,
  antes jsonb,
  depois jsonb,
  por text NOT NULL DEFAULT 'admin',
  motivo text
);

CREATE INDEX IF NOT EXISTS idx_historico_empresa ON historico (empresa_id, em DESC);

-- 4. TABELA PAGAMENTOS (Registo Financeiro de Mensalidades e Isenções)
-- Estados: 'pago', 'pendente', 'em_atraso', 'isento'
CREATE TABLE IF NOT EXISTS pagamentos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  valor numeric(10,2) NOT NULL DEFAULT 0.00,
  data timestamptz NOT NULL DEFAULT now(),
  metodo text DEFAULT 'transferencia',
  referencia text,
  fatura_numero text,
  periodo_inicio date,
  periodo_fim date,
  estado text NOT NULL DEFAULT 'pendente',
  motivo_isencao text,
  criado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pagamentos_empresa ON pagamentos (empresa_id, data DESC);
CREATE INDEX IF NOT EXISTS idx_pagamentos_estado ON pagamentos (estado);

-- 5. TABELA CONTACTOS_COMERCIAIS (Funil: Alerta Gratuito → Proposta → Seguimento)
CREATE TABLE IF NOT EXISTS contactos_comerciais (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  tipo text NOT NULL DEFAULT 'alerta_gratuito',
  canal text DEFAULT 'email',
  data timestamptz NOT NULL DEFAULT now(),
  resumo text,
  resposta text,
  criado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_contactos_empresa ON contactos_comerciais (empresa_id, data DESC);

-- 6. TABELA USO_SELO (Métricas Diárias Agregadas Sem Dados Pessoais / Sem IP)
CREATE TABLE IF NOT EXISTS uso_selo (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  data date NOT NULL DEFAULT CURRENT_DATE,
  visitas_pagina int NOT NULL DEFAULT 0,
  verificacoes_widget int NOT NULL DEFAULT 0,
  CONSTRAINT uq_uso_selo_empresa_data UNIQUE (empresa_id, data)
);

CREATE INDEX IF NOT EXISTS idx_uso_selo_empresa_data ON uso_selo (empresa_id, data DESC);

-- 7. TABELA RELATORIOS_GERADOS (Histórico, Versionamento e Hash SHA-256 de PDFs)
CREATE TABLE IF NOT EXISTS relatorios_gerados (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  empresa_id uuid NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
  periodo text NOT NULL,
  versao text NOT NULL DEFAULT '1.0',
  hash_ficheiro text NOT NULL,
  gerado_por text NOT NULL DEFAULT 'admin',
  gerado_em timestamptz NOT NULL DEFAULT now(),
  aprovado_por text,
  aprovado_em timestamptz,
  enviado_em timestamptz
);

CREATE INDEX IF NOT EXISTS idx_relatorios_empresa ON relatorios_gerados (empresa_id, periodo DESC);

-- 8. SEGURANÇA E PRIVACIDADE (RLS Estrito — Nenhuma leitura pública permitida)
ALTER TABLE verificacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE historico ENABLE ROW LEVEL SECURITY;
ALTER TABLE pagamentos ENABLE ROW LEVEL SECURITY;
ALTER TABLE contactos_comerciais ENABLE ROW LEVEL SECURITY;
ALTER TABLE uso_selo ENABLE ROW LEVEL SECURITY;
ALTER TABLE relatorios_gerados ENABLE ROW LEVEL SECURITY;

-- Remove políticas públicas prévias se existirem
DROP POLICY IF EXISTS "Acesso estrito de servico para verificacoes" ON verificacoes;
DROP POLICY IF EXISTS "Acesso estrito de servico para historico" ON historico;
DROP POLICY IF EXISTS "Acesso estrito de servico para pagamentos" ON pagamentos;
DROP POLICY IF EXISTS "Acesso estrito de servico para contactos_comerciais" ON contactos_comerciais;
DROP POLICY IF EXISTS "Acesso estrito de servico para uso_selo" ON uso_selo;
DROP POLICY IF EXISTS "Acesso estrito de servico para relatorios_gerados" ON relatorios_gerados;

-- Políticas de acesso exclusivo ao service_role
CREATE POLICY "Acesso estrito de servico para verificacoes" ON verificacoes FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Acesso estrito de servico para historico" ON historico FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Acesso estrito de servico para pagamentos" ON pagamentos FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Acesso estrito de servico para contactos_comerciais" ON contactos_comerciais FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Acesso estrito de servico para uso_selo" ON uso_selo FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Acesso estrito de servico para relatorios_gerados" ON relatorios_gerados FOR ALL TO service_role USING (true) WITH CHECK (true);
