-- ============================================================================
-- MIGRAÇÃO: MÓDULO DE ACOMPANHAMENTO DE GOLPES NOVOS (FASES 1 A 5)
-- Data: 2026-10-19
-- Regras de Privacidade (RGPD):
--   1. Nenhuma tabela guarda o texto bruto das mensagens.
--   2. Apenas resumos anonimizados, hashes de semelhança e indicadores técnicos.
--   3. Prazos de retenção: fila_revisao (90 dias), clusters (12 meses), amostras_teste (12 meses).
--   4. RLS ativo em todas as tabelas (acesso exclusivo via service_role no servidor).
-- ============================================================================

-- 1. AGRUPAMENTOS DE SEMELHANÇA / CLUSTERS (Fase 1 - Secção 3.2)
CREATE TABLE IF NOT EXISTS public.clusters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fingerprint TEXT NOT NULL UNIQUE,
  indicadores JSONB NOT NULL DEFAULT '{}'::jsonb,
  primeira_vez TIMESTAMPTZ NOT NULL DEFAULT now(),
  ultima_vez TIMESTAMPTZ NOT NULL DEFAULT now(),
  contagem INTEGER NOT NULL DEFAULT 1,
  contagem_24h INTEGER NOT NULL DEFAULT 1,
  velocidade_por_hora NUMERIC(8,2) NOT NULL DEFAULT 0.0,
  estado TEXT NOT NULL DEFAULT 'possivel_campanha'
    CHECK (estado IN ('possivel_campanha', 'ativa', 'encerrada', 'descartada')),
  revisor TEXT,
  revisto_em TIMESTAMPTZ,
  notas TEXT,
  expira_em TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '12 months'),
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_clusters_fingerprint ON public.clusters(fingerprint);
CREATE INDEX IF NOT EXISTS idx_clusters_estado ON public.clusters(estado);
CREATE INDEX IF NOT EXISTS idx_clusters_ultima_vez ON public.clusters(ultima_vez DESC);

-- 2. FILA DE REVISÃO HUMANA (Fase 1 - Secção 3.1)
CREATE TABLE IF NOT EXISTS public.fila_revisao (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analise_ref TEXT NOT NULL,
  motivo TEXT NOT NULL
    CHECK (motivo IN ('suspeito', 'confianca_baixa', 'ia_vs_regra', 'feedback_erro', 'possivel_campanha')),
  cluster_id UUID REFERENCES public.clusters(id) ON DELETE SET NULL,
  resumo JSONB NOT NULL DEFAULT '{}'::jsonb,
  estado TEXT NOT NULL DEFAULT 'novo'
    CHECK (estado IN ('novo', 'em_revisao', 'resolvido')),
  decisao TEXT
    CHECK (decisao IS NULL OR decisao IN ('esquema_novo', 'marca_nova', 'falso_alarme', 'sem_acao')),
  notas TEXT,
  revisor TEXT,
  resolvido_em TIMESTAMPTZ,
  expira_em TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '90 days'),
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fila_revisao_estado ON public.fila_revisao(estado);
CREATE INDEX IF NOT EXISTS idx_fila_revisao_motivo ON public.fila_revisao(motivo);
CREATE INDEX IF NOT EXISTS idx_fila_revisao_cluster ON public.fila_revisao(cluster_id);
CREATE INDEX IF NOT EXISTS idx_fila_revisao_criado_em ON public.fila_revisao(criado_em DESC);

-- 3. FONTES DE ALERTA OFICIAL (Fase 2 - Secção 3.3)
CREATE TABLE IF NOT EXISTS public.fontes_alerta (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  tipo TEXT NOT NULL CHECK (tipo IN ('autoridade', 'marca', 'imprensa')),
  ultimo_check TIMESTAMPTZ,
  ultimo_hash TEXT,
  estado TEXT NOT NULL DEFAULT 'ativa' CHECK (estado IN ('ativa', 'pausada', 'erro')),
  ultimo_erro TEXT,
  notas TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. BIBLIOTECA INTERNA DE ESQUEMAS (Fase 2 - Secção 3.4)
CREATE TABLE IF NOT EXISTS public.esquemas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome TEXT NOT NULL,
  descricao TEXT NOT NULL,
  canais JSONB NOT NULL DEFAULT '[]'::jsonb,
  marcas JSONB NOT NULL DEFAULT '[]'::jsonb,
  sinais JSONB NOT NULL DEFAULT '[]'::jsonb,
  estado TEXT NOT NULL DEFAULT 'rascunho'
    CHECK (estado IN ('rascunho', 'ativo', 'arquivado')),
  origem TEXT NOT NULL DEFAULT 'manual'
    CHECK (origem IN ('alerta', 'consulta', 'manual')),
  revisto_por TEXT,
  revisto_em TIMESTAMPTZ,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. ALERTAS OFICIAIS DETETADOS (Fase 2 - Secção 3.3)
CREATE TABLE IF NOT EXISTS public.alertas_oficiais (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fonte_id UUID REFERENCES public.fontes_alerta(id) ON DELETE CASCADE,
  titulo TEXT NOT NULL,
  url TEXT NOT NULL,
  data_publicacao TIMESTAMPTZ,
  detetado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
  estado TEXT NOT NULL DEFAULT 'novo'
    CHECK (estado IN ('novo', 'em_revisao', 'processado', 'ignorado')),
  esquema_id UUID REFERENCES public.esquemas(id) ON DELETE SET NULL,
  notas TEXT,
  revisor TEXT,
  revisto_em TIMESTAMPTZ
);

-- 6. DICIONÁRIO DE MARCAS E DOMÍNIOS COM APROVAÇÃO (Fase 3 - Secção 3.5)
-- Histórico append-only: cada alteração fica registada.
CREATE TABLE IF NOT EXISTS public.dicionario_alteracoes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  marca TEXT NOT NULL,
  dominio_oficial TEXT NOT NULL,
  acao TEXT NOT NULL CHECK (acao IN ('adicionar', 'alterar', 'remover')),
  origem TEXT NOT NULL DEFAULT 'manual',
  estado TEXT NOT NULL DEFAULT 'pendente'
    CHECK (estado IN ('pendente', 'aprovado', 'rejeitado')),
  aprovado_por TEXT,
  aprovado_em TIMESTAMPTZ,
  motivo TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 7. AMOSTRAS DE TESTE DO BENCHMARK ROTATIVO (Fase 4 - Secção 3.6)
CREATE TABLE IF NOT EXISTS public.amostras_teste (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  semana TEXT NOT NULL,
  resumo_ou_texto_anonimizado TEXT NOT NULL,
  origem TEXT NOT NULL CHECK (origem IN ('real', 'alerta_oficial', 'sintetico')),
  tipo_real TEXT CHECK (tipo_real IS NULL OR tipo_real IN ('Golpe', 'Legítimo')),
  classificado_por TEXT,
  classificado_em TIMESTAMPTZ,
  uso TEXT NOT NULL DEFAULT 'rotativo' CHECK (uso IN ('rotativo', 'regressao')),
  golpe_novo BOOLEAN NOT NULL DEFAULT false,
  expira_em TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '12 months'),
  criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 8. CORRIDAS DO BENCHMARK (Fase 4 - Secção 3.6)
CREATE TABLE IF NOT EXISTS public.corridas_benchmark (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  data_hora TIMESTAMPTZ NOT NULL DEFAULT now(),
  commit TEXT,
  hash_dataset TEXT NOT NULL,
  modelo TEXT,
  amostra_id UUID REFERENCES public.amostras_teste(id) ON DELETE CASCADE,
  veredito TEXT,
  pontuacao INTEGER,
  origem_veredito TEXT,
  fontes JSONB DEFAULT '[]'::jsonb,
  erro TEXT
);

-- 9. MÉTRICAS SEMANAIS E DERIVA (Fase 5 - Secção 3.7)
CREATE TABLE IF NOT EXISTS public.metricas_semanais (
  semana TEXT PRIMARY KEY,
  pct_suspeito NUMERIC(5,2) NOT NULL DEFAULT 0,
  taxa_erro_utilizadores NUMERIC(5,2) NOT NULL DEFAULT 0,
  decisoes_ia INTEGER NOT NULL DEFAULT 0,
  decisoes_regra INTEGER NOT NULL DEFAULT 0,
  decisoes_lista INTEGER NOT NULL DEFAULT 0,
  decisoes_fallback INTEGER NOT NULL DEFAULT 0,
  clusters_novos INTEGER NOT NULL DEFAULT 0,
  esquemas_novos INTEGER NOT NULL DEFAULT 0,
  tempo_medio_ate_cobertura_dias NUMERIC(6,2),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- SEGURANÇA RLS (ROW LEVEL SECURITY) — Secção 4
-- Nenhuma tabela pode ser lida ou escrita por chaves públicas (anon).
-- Apenas o backend autenticado com service_role tem acesso.
-- ============================================================================
ALTER TABLE public.clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fila_revisao ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fontes_alerta ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.esquemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alertas_oficiais ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dicionario_alteracoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.amostras_teste ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.corridas_benchmark ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.metricas_semanais ENABLE ROW LEVEL SECURITY;

-- Permite registar no histórico de auditoria decisões globais (fila de revisão, clusters, dicionário) sem empresa_id associado
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'historico' AND column_name = 'empresa_id') THEN
    ALTER TABLE public.historico ALTER COLUMN empresa_id DROP NOT NULL;
  END IF;
END $$;

