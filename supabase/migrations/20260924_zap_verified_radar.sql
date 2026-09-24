-- ==============================================================================
-- ZAP, QUEM É? — MIGRATION: ZAP VERIFIED & THREAT RADAR
-- Arquivo: supabase/migrations/20260924_zap_verified_radar.sql
-- Especificação Fechada de Implementação B2B
-- Idempotente: seguro para ser executado múltiplas vezes.
-- ==============================================================================

-- 1. TABELA EMPRESAS
create table if not exists empresas (
  id uuid primary key default gen_random_uuid(),
  criado_em timestamptz not null default now(),

  nome text not null,

  dominio_oficial text,
  email_oficial text,
  telefone_oficial text,

  apelidos_marca text[] default '{}',

  dominio_verificado boolean not null default false,
  email_verificado boolean not null default false,
  telefone_verificado boolean not null default false,

  plano text not null default 'business',
  status text not null default 'ativo',

  stripe_customer_id text
);

-- 2. TABELA SELOS
create table if not exists selos (
  id uuid primary key default gen_random_uuid(),

  criado_em timestamptz not null default now(),

  empresa_id uuid not null
    references empresas(id)
    on delete cascade,

  codigo text not null unique,

  tipo text not null default 'canal_verificado',

  valido_ate timestamptz,

  monitorizacao_impersonation boolean not null default true
);

create index if not exists idx_selos_codigo on selos (codigo);
create index if not exists idx_selos_empresa on selos (empresa_id);

-- 3. ALTERAÇÃO DA TABELA ANALISES
create table if not exists analises (
  id uuid primary key default gen_random_uuid(),
  criado_em timestamptz not null default now(),
  veredito text not null,
  confianca int not null,
  tipo text,
  vezes_reportada int default 1,
  teve_imagem boolean default false
);

alter table analises add column if not exists empresa_id uuid references empresas(id);
alter table analises add column if not exists marca_mencionada text;
alter table analises add column if not exists canal_mencionado text;
alter table analises add column if not exists impersonation boolean default false;

create index if not exists idx_analises_criado_em on analises (criado_em);
create index if not exists idx_analises_veredito on analises (veredito);
create index if not exists idx_analises_empresa on analises (empresa_id);
create index if not exists idx_analises_impersonation on analises (impersonation);

-- 4. VIEW THREAT RADAR
create or replace view radar_ameacas as
select
  e.id as empresa_id,
  e.nome as empresa,

  count(*) as ocorrencias,

  count(distinct a.canal_mencionado)
    as canais_distintos,

  min(a.criado_em)
    as primeira_deteccao,

  max(a.criado_em)
    as ultima_deteccao,

  case
    when count(*) >= 20 then 'critica'
    when count(*) >= 5 then 'suspeita'
    else 'monitorar'
  end as severidade

from analises a

join empresas e
  on e.id = a.empresa_id

where a.impersonation = true

group by e.id, e.nome

order by ocorrencias desc;
