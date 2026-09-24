-- Executa isto no Supabase: painel do projeto → SQL Editor → cola e clica "Run".

create table if not exists analises (
  id uuid primary key default gen_random_uuid(),
  criado_em timestamptz not null default now(),
  veredito text not null,          -- 'golpe' | 'suspeito' | 'legitimo'
  confianca int not null,          -- 0-100
  tipo text,                       -- 'falso banco' | 'entrega' | 'pix errado' | etc
  vezes_reportada int default 1,
  teve_imagem boolean default false
);

create table if not exists feedback (
  id uuid primary key default gen_random_uuid(),
  criado_em timestamptz not null default now(),
  analise_id uuid references analises(id),
  positivo boolean not null
);

-- Índices simples para consultas de métricas (ex: análises por dia, por veredito).
create index if not exists idx_analises_criado_em on analises (criado_em);
create index if not exists idx_analises_veredito on analises (veredito);
