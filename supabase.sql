-- ==============================================================================
-- ZAP, QUEM É? — BANCO DE DADOS SUPABASE (B2C & B2B CORPORATIVO)
-- Executa isto no Supabase: painel do projeto → SQL Editor → New query → Run.
-- ==============================================================================

-- 1. ANÁLISES DE GOLPES (B2C & BOT)
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

create index if not exists idx_analises_criado_em on analises (criado_em);
create index if not exists idx_analises_veredito on analises (veredito);


-- 2. CORPORATIVO: EMPRESAS COM SELO ZAP SEGURO VERIFICADO (B2B)
create table if not exists empresas_verificadas (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,               -- Identificador na URL (ex: 'lojadojoao')
  nome text not null,                      -- Nome da Marca / Razão Social
  cnpj_nif text,                           -- CNPJ (Brasil) ou NIF (Portugal)
  dominio text not null,                   -- Domínio oficial (ex: 'lojadojoao.com.br')
  whatsapp_oficial text,                   -- Número de suporte oficial verificado
  instagram_oficial text,                  -- Perfil oficial de rede social
  status text not null default 'ativo',    -- 'ativo', 'suspenso', 'em_analise'
  plano text not null default 'pro',       -- 'start', 'pro', 'enterprise'
  selo_token text unique not null default encode(gen_random_bytes(16), 'hex'),
  contato_email text,
  contato_responsavel text,
  visualizacoes_selo int default 0,
  criado_em timestamptz not null default now(),
  valido_ate timestamptz default (now() + interval '1 year')
);

create index if not exists idx_empresas_dominio on empresas_verificadas (dominio);
create index if not exists idx_empresas_slug on empresas_verificadas (slug);


-- 3. CORPORATIVO: RADAR DE AMEAÇAS (BRAND THREAT RADAR)
-- Notifica empresas clientes quando golpistas estão usando o nome da marca delas
create table if not exists ameacas_detectadas (
  id uuid primary key default gen_random_uuid(),
  empresa_id uuid references empresas_verificadas(id) on delete cascade,
  criado_em timestamptz not null default now(),
  canal text default 'WhatsApp',           -- 'WhatsApp', 'Web', 'SMS'
  link_suspeito text,
  mensagem_trecho text,
  tipo_golpe text,                         -- 'falso site', 'phishing', 'falso atendente'
  score_risco int,
  notificado boolean default false
);

create index if not exists idx_ameacas_empresa on ameacas_detectadas (empresa_id);


-- 4. CORPORATIVO: LEADS DE VENDAS DO SELO
create table if not exists leads_empresas (
  id uuid primary key default gen_random_uuid(),
  criado_em timestamptz not null default now(),
  nome text not null,
  empresa text not null,
  email text not null,
  whatsapp text,
  website text,
  plano_interesse text default 'pro',
  status text not null default 'novo'      -- 'novo', 'em_contato', 'fechado', 'perdido'
);

create index if not exists idx_leads_criado_em on leads_empresas (criado_em);


-- EMPRESA DEMO INICIAL PARA TESTES
insert into empresas_verificadas (slug, nome, cnpj_nif, dominio, whatsapp_oficial, instagram_oficial, status, plano, contato_email, contato_responsavel)
values (
  'lojaprotegida',
  'Loja Protegida Oficial',
  '12.345.678/0001-90',
  'lojaprotegida.com.br',
  '+55 11 98888-7777',
  '@lojaprotegida',
  'ativo',
  'enterprise',
  'seguranca@lojaprotegida.com.br',
  'Diretoria de E-commerce'
) on conflict (slug) do nothing;
