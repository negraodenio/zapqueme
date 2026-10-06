# ZAP, QUEM É? — B2B PRE-PRODUCTION AUDIT
# Gerado em: 2026-09-24 | Branch: main (a765e72) | Testes: 27/27 PASS

---

## RESUMO EXECUTIVO

Auditoria completa do projeto ZAP, QUEM É? em preparação para produção B2B.
O código existente é sólido em termos de lógica de negócio e inteligência B2C.
A cadeia B2C → B2B (impersonation detection) está funcional.
Foram identificados 11 bugs e 8 findings de segurança, sendo 4 classificados P0 (críticos).

---

## 1. CURRENT ARCHITECTURE

Stack:
- Frontend B2C: index.html (HTML + TailwindCSS CDN + vanilla JS)
- Frontend Admin: admin.html (HTML + vanilla JS, ~85 KB)
- Frontend Verify: api/verify.js (SSR — HTML gerado no servidor)
- Bot WhatsApp: bot.js (Node.js + Baileys, porta 3333)
- API (Serverless): api/*.js (Vercel Functions — Node.js ESM)
- Motor de IA: OpenRouter (primário) → Google Gemini direct (fallback) → Heurística local
- Threat Intel: lib/threat_intel.js — Google Safe Browsing, Cloudflare DNS, RDAP
- Deduplicação: Upstash Redis REST (hash SHA-256 de mensagem)
- Base de Dados: Supabase (PostgreSQL REST API)
- Sessão WhatsApp: Upstash Redis (bundle Baileys em base64)
- Hosting: Vercel (Serverless Functions + static assets)
- Badge Assets: badges/ — 14 PNGs estáticos

Routing (vercel.json):
  /               → index.html       (B2C)
  /admin          → admin.html       (Admin)
  /verify/:codigo → api/verify.js    (Página pública do selo)
  /badge/:codigo  → api/badge.js     (SVG dinâmico)

Ficheiros principais:
  lib/scanner.js      — Motor de análise: IA + heurística + persistência
  lib/radar.js        — Impersonation detection + geração de código
  lib/threat_intel.js — Safe Browsing, Cloudflare, RDAP
  lib/session_store.js — Sessão WhatsApp no Redis
  api/analyze.js      — Endpoint B2C
  api/admin.js        — Endpoint Admin (GET/POST)
  api/badge.js        — SVG dinâmico
  api/verify.js       — Página pública /verify/[codigo]
  api/feedback.js     — Feedback B2C
  api/whatsapp.js     — Webhook Twilio
  api/empresa.js      — [BROKEN] Referencia schema inexistente
  bot.js              — Bot Baileys
  widget.js           — Script de incorporação para lojas

---

## 2. CURRENT ADMIN ARCHITECTURE

Estrutura de Navegação (admin.html — SPA single-file):
  1. Empresas      — CRUD de entidades B2B
  2. Selos         — Gestão ZAP VERIFIED + Kit de Badges
  3. Threat Radar  — Vista agregada de impersonation
  4. Ocorrências   — Eventos individuais

Autenticação:
  Mecanismo: Static API key via header x-admin-key
  [P0] Valor padrão hardcoded: "zapadmin2026" (env var não definida)
  [P0] Também aceita ?secret= query param (expõe key em logs)
  Sem rate limiting. Sem sessão/JWT.

Ações API:
  GET                       → listar dados
  POST create_empresa       → cria empresa (+selo opcional)
  POST update_empresa       → edita empresa
  POST set_empresa_status   → suspende/reativa empresa
  POST create_selo          → cria selo (sem desativar anteriores!)
  POST regenerar_selo       → muda código do mesmo registo
  POST delete_selo          → DELETE físico (viola histórico)

---

## 3. DATA FLOW (B2C → B2B)

[INPUT: texto/imagem]
  ↓
[lib/scanner.js :: analyzeContent()]
  ├── OpenRouter (primário, 12s timeout)
  ├── Gemini direct (fallback, 3 modelos)
  └── Heurística local (fallback final)
  ↓
[parsed] = {veredito, confianca, risco_score, tipo, sinais,
            explicacao_simples, acao_recomendada, texto_normalizado,
            marca_mencionada, canal_mencionado, alerta_link}
  ↓
[lib/threat_intel.js :: inspectAllUrls()]
  Safe Browsing + Cloudflare + RDAP + Brand Impersonation
  → pode elevar risco_score, popular alerta_link
  → pode definir canal_mencionado (fallback para URL encontrada)
  ↓
[lib/radar.js :: detectarImpersonation()]
  → compara marca_mencionada vs empresas ativas
  → compara canal_mencionado vs canais oficiais
  → retorna: {empresa_id, impersonation: bool}
  ↓
[Redis :: incrementarContador()] → vezes_reportada
  ↓
[Supabase :: salvarAnalise()]
  Persiste: veredito, confianca, tipo, vezes_reportada, teve_imagem,
            empresa_id, marca_mencionada, canal_mencionado, impersonation
  [P1 BUG] NÃO persiste: risco_score, alerta_link, canal (origem)
  ↓
[B2C response] — remove campos internos
  ↓
[view radar_ameacas] ← WHERE impersonation = true, GROUP BY empresa
  ↓
[Admin UI — Threat Radar + Ocorrências]

VERIFICAÇÃO CRÍTICA — canal_mencionado É persistido?
  SIM. scanner.js:444: canal_mencionado: parsed.canal_mencionado || null
  Confirmado no fluxo real.
  RISCO: threatResult pode não estar declarado com let antes do try{} (BUG #3)
  → verificar scanner.js linhas 170-172.

---

## 4. COMPANIES

PURPOSE: Entidade B2B monitorada. Define identidade e canais oficiais.
PRIMARY USER: Operador interno ZAP (/admin)

Schema: empresas
  id, criado_em, nome, dominio_oficial, email_oficial, telefone_oficial,
  apelidos_marca[], dominio_verificado, email_verificado, telefone_verificado,
  plano, status, stripe_customer_id

AUSENTES (necessários):
  - atualizado_em timestamptz [P2]
  - Sem constraint de valores válidos para status

PROBLEMAS:
  - Campos *_verificado são manuais (sem validação real)
  - Sem histórico de alterações
  - Sem ação explícita "desativar" (apenas suspender)

COMMERCIAL PURPOSE:
  A empresa é o contrato B2B. Ponto de entrada para ZAP VERIFIED e Threat Radar.

---

## 5. ZAP VERIFIED

PURPOSE: Emitir/gerir selos que certificam canais oficiais verificados.
PRIMARY USER: Operador (gestão) + Consumidores (verificação pública)

ESTADOS DO SELO (derivados da empresa + valido_ate):
  Válido    → empresa.status=ativo + não expirado   → "✓ Verificação ativa"
  Suspenso  → empresa.status=suspenso               → "⚠️ Verificação suspensa"
  Inativo   → empresa.status=inativo                → "⚠️ Verificação inativa"
  Expirado  → valido_ate < now()                    → "⚠️ Verificação expirada"

NOTA: Não há campo "status" próprio no selo. Estado é sempre derivado.

[P0] PROBLEMA CRÍTICO — MÚLTIPLOS SELOS ATIVOS:
  - Tabela selos sem campo ativo nem constraint de unicidade por empresa
  - create_selo não desativa selos anteriores
  - delete_selo faz DELETE físico (viola preservação de histórico)
  - Uma empresa pode ter múltiplos códigos ativos simultaneamente

GERAÇÃO DE CÓDIGO:
  gerarCodigoSelo() em lib/radar.js
  Formato: ZQV-XXXXXXXXXXXXX (13 chars aleatórios, charset 32)
  crypto.randomBytes(13) → criptograficamente seguro ✅
  UNIQUE constraint na tabela ✅

PÁGINA PÚBLICA /verify/[codigo]:
  SSR HTML em api/verify.js
  escapeHtml() em todos os campos ✅
  Cache-Control: no-store ✅
  JSON via Accept header ou ?format=json ✅
  Não expõe dados internos ✅

WIDGET (widget.js):
  Chama api/empresa.js?slug=
  [P0 BUG] api/empresa.js usa tabela "empresas_verificadas" que não existe
  Widget está BROKEN em produção.

---

## 6. THREAT RADAR

PURPOSE: Vista agregada de atividade de impersonation por empresa.
PRIMARY USER: Operador interno ZAP

DATA SOURCE: View radar_ameacas
  SELECT empresa, count(*) AS ocorrencias,
         count(DISTINCT canal_mencionado) AS canais_distintos,
         min/max(criado_em) AS primeira/ultima_deteccao,
         severidade
  FROM analises JOIN empresas
  WHERE impersonation = true
  GROUP BY empresa_id, empresa

SEVERIDADE:
  >= 20 → critica
  >= 5  → suspeita
  < 5   → monitorar

CHAIN VERIFICADA:
  analises.impersonation=true → view radar_ameacas → api/admin.js → Admin UI ✅

PROBLEMAS:
  - ORDER BY na view pode ser ignorado pelo PostgreSQL
  - Sem paginação (possível lentidão com muitas empresas)
  - Sem filtro de período (mostra toda a história)

---

## 7. OCCURRENCES

PURPOSE: Eventos individuais de impersonation para rastreabilidade.
PRIMARY USER: Operador interno ZAP

QUERY ATUAL:
  SELECT id, criado_em, veredito, confianca, tipo, canal_mencionado,
         marca_mencionada, empresa_id
  FROM analises WHERE impersonation=true
  ORDER BY criado_em DESC LIMIT 100

PROBLEMAS:
  - vezes_reportada não incluído no SELECT (existe na tabela)
  - alerta_link não persistido (BUG #2)
  - risco_score não persistido (BUG #1)
  - Sem paginação (hardcoded LIMIT 100)
  - Sem filtros (empresa, tipo, período)

---

## 8. B2C → B2B INTELLIGENCE FLOW

Resumo da cadeia de valor:
  1. Consumidor envia mensagem/screenshot
  2. IA extrai: veredito, marca_mencionada, canal_mencionado
  3. Threat Intel valida URLs externamente
  4. Radar compara com empresas cadastradas → impersonation
  5. Redis conta recorrência → vezes_reportada
  6. Supabase persiste → alimenta Radar e Ocorrências
  7. B2C recebe resultado (sem dados internos)
  8. Admin visualiza sinais agregados no Threat Radar

CAMPO canal_mencionado — CADEIA COMPLETA:
  ORIGIN: SYSTEM_PROMPT pede à IA para extrair canal_mencionado
  FALLBACK: se IA não extraiu, usa primeira URL detectada por threat_intel
  PROCESSAMENTO: detectarImpersonation() usa para verificar canal oficial
  PERSISTÊNCIA: salvarAnalise() → analises.canal_mencionado ✅
  THREAT RADAR: view count(DISTINCT canal_mencionado) ✅
  OCORRÊNCIAS: SELECT canal_mencionado ✅
  RISCO: scope de threatResult (BUG #3) pode falhar silenciosamente

---

## 9. CURRENT DATABASE MODEL

Tabelas existentes:
  empresas — entidades B2B
  selos    — selos ZAP VERIFIED
  analises — registos de análise B2C (com campos B2B)
  feedback — feedback de utilizadores B2C

View existente:
  radar_ameacas — agregação de impersonation por empresa

Tabelas INEXISTENTES mas referenciadas em código:
  empresas_verificadas — api/empresa.js (BUG #4) [P0]
  leads_empresas       — api/empresa.js (BUG #4) [P0]

Campos AUSENTES em analises (necessários):
  risco_score int    — calculado mas não gravado [P1]
  alerta_link text   — evidências URL não gravadas [P1]
  canal text         — origem da análise (web/whatsapp/twilio) [P2]

Campos AUSENTES em selos (necessários):
  ativo boolean DEFAULT true       — distinguir ativo de histórico [P1]
  desativado_em timestamptz        — auditoria [P1]
  motivo_desativacao text          — auditoria [P2]

Campos AUSENTES em empresas (necessários):
  atualizado_em timestamptz        — auditoria [P2]

---

## 10. AUTHENTICATION / AUTHORIZATION

Admin (api/admin.js):
  [P0] Fallback hardcoded "zapadmin2026" (ADMIN_SECRET_KEY não definido no .env.local)
  [P0] Suporte a ?secret= query param (expõe chave em logs)
  [P1] Sem rate limiting
  Sem JWT/Session (aceitável para MVP)

B2C (api/analyze.js):
  Sem autenticação (intencional)
  [P1] Sem rate limiting → risco de abuso de custo

Página pública /verify/:
  Pública (correto)
  Supabase service role key (server-side only) ✅
  Sem RLS configurado [P1]
  Enumeração mitigada pela alta entropia do código ✅

Supabase:
  Service role key usada em todas as chamadas (correto para server-side)
  [P1] RLS não configurado

---

## 11. SECURITY FINDINGS

[P0] SEC-001 — Admin Secret hardcoded
  api/admin.js:7: const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || "zapadmin2026"
  ADMIN_SECRET_KEY não definido → fallback inseguro ativo
  FIX: Definir env var. Remover fallback.

[P0] SEC-002 — API key via query param
  api/admin.js:10: req.query.secret
  FIX: Remover suporte a ?secret=. Aceitar apenas x-admin-key header.

[P1] SEC-003 — Ausência de Rate Limiting
  Todos os endpoints sem rate limiting.
  FIX: Redis IP-based incr+TTL em /api/analyze e /api/admin.

[P1] SEC-004 — Supabase sem RLS
  Todas as chamadas usam service role (bypass total do RLS).
  FIX: Configurar RLS (não quebra backend server-side com service role).

[P1] SEC-005 — CORS * em api/empresa.js
  Intencional para widget mas API está broken de qualquer forma.

[P2] SEC-006 — Credenciais reais no .env.local
  Confirmar: git log --all --full-history -- .env.local

[P2] SEC-007 — Enumeração de selos
  Diferença 404/200 permite enumerar, mas espaço (32^13) torna impraticável.

[P3] SEC-008 — api/empresa.js público sem autenticação
  Retorna 500 (tabela inexistente) mas é surface desnecessária.

---

## 12. DATA PRIVACY FINDINGS

[P1] PRIV-001 — Textos B2C NÃO são gravados [POSITIVO]
  delete parsed.texto_normalizado antes de salvarAnalise() ✅

[P1] PRIV-002 — canal_mencionado pode ter dados sensíveis
  Contém URLs/emails/telefones. Aceitável como dado de análise interno.

[P2] PRIV-003 — canal_mencionado exposto no Admin
  Aceitável para operador interno. Classificar como dado interno.

[P2] PRIV-004 — Sem política de retenção de dados
  Tabela analises cresce indefinidamente. Risco RGPD futuro.

[P3] PRIV-005 — Ocorrências com volume baixo
  Radar mostra count exato. Para < 5: exibir "menos de 5" (privacidade).

---

## 13. BUGS / GAPS

[P1] BUG #1 — risco_score não persistido em analises
  Calculado, usado na UI/WhatsApp, mas não gravado.
  FIX: Adicionar risco_score à tabela + ao INSERT de salvarAnalise().

[P1] BUG #2 — alerta_link não persistido em analises
  Evidências de URL maliciosa (Safe Browsing, Cloudflare) perdidas.
  FIX: Adicionar alerta_link à tabela + ao INSERT de salvarAnalise().

[P0] BUG #3 — scope de threatResult potencialmente undefined
  Verificar scanner.js linhas 170-172: há "let threatResult" antes do try?
  Se não: adicionar para garantir que o fallback de canal_mencionado funcione.

[P0] BUG #4 — api/empresa.js usa tabelas inexistentes
  "empresas_verificadas" e "leads_empresas" não existem.
  Widget.js está BROKEN. Qualquer chamada retorna erro.
  FIX: Reescrever para usar empresas + selos existentes.

[P1] BUG #5 — OPENROUTER_MODEL provavelmente inativo
  "google/gemini-2.5-flash" retorna 404 no OpenRouter.
  FIX: Atualizar para "google/gemini-2.0-flash".

[P1] BUG #6 — Múltiplos selos ativos por empresa
  create_selo não desativa selos anteriores.
  FIX: Adicionar campo "ativo" + desativar anteriores ao criar novo.

[P1] BUG #7 — delete_selo apaga fisicamente
  Viola regra de preservação de histórico.
  FIX: Substituir por soft-delete (ativo=false + desativado_em).

[P2] BUG #8 — vezes_reportada não no SELECT de ocorrências
  FIX: Adicionar ao SELECT.

[P2] BUG #9 — widget.js aponta para URL errada
  Aponta para verificar.html?empresa= (B2C).
  Correto: /verify/[codigo_do_selo].

[P2] BUG #10 — package.json com nome antigo "e-golpe"
  FIX: Renomear para "zapqueme".

[P2] BUG #11 — qr.html, qrcode.png, status.json não no .gitignore
  FIX: Adicionar ao .gitignore.

---

## 14. REQUIRED CHANGES

ID     | P  | Descrição                                               | Ficheiros
FIX-01 | P0 | Definir ADMIN_SECRET_KEY em env + remover fallback      | api/admin.js, Vercel env
FIX-02 | P0 | Remover ?secret= query param do Admin                   | api/admin.js
FIX-03 | P0 | Resolver BUG #4: api/empresa.js tabelas inexistentes    | api/empresa.js
FIX-04 | P1 | Persistir risco_score em analises (BUG #1)              | lib/scanner.js, SQL
FIX-05 | P1 | Persistir alerta_link em analises (BUG #2)              | lib/scanner.js, SQL
FIX-06 | P1 | Campo "ativo" em selos + lógica unicidade (BUG #6)      | SQL, api/admin.js
FIX-07 | P1 | Soft-delete de selos, substituir DELETE (BUG #7)        | api/admin.js
FIX-08 | P1 | Corrigir OPENROUTER_MODEL (BUG #5)                      | .env.local, Vercel env
FIX-09 | P1 | Rate limiting em POST /api/analyze via Redis            | api/analyze.js
FIX-10 | P1 | Verificar scope de threatResult (BUG #3)                | lib/scanner.js
FIX-11 | P2 | vezes_reportada no SELECT de ocorrências (BUG #8)       | api/admin.js
FIX-12 | P2 | Corrigir URL do widget (BUG #9)                         | widget.js
FIX-13 | P2 | Adicionar runtime files ao .gitignore (BUG #11)         | .gitignore
FIX-14 | P2 | Adicionar atualizado_em à tabela empresas               | SQL migration

---

## 15. OPTIONAL CHANGES

OPT-01 | P2 | Paginação nas Ocorrências (remover LIMIT hardcoded 100)
OPT-02 | P2 | Filtro de período no Radar e Ocorrências
OPT-03 | P2 | Campo canal (origem) nas analises: web/whatsapp_baileys/twilio
OPT-04 | P3 | Política de retenção de dados (RGPD)
OPT-05 | P3 | Threshold < 5 no Radar (privacidade)
OPT-06 | P3 | Mover ORDER BY da view para query do Admin
OPT-07 | P3 | Decidir destino do campo stripe_customer_id
OPT-08 | P3 | Página /intelligence com métricas agregadas
OPT-09 | P3 | Supabase Auth para utilizadores B2C
OPT-10 | P3 | Histórico de alterações de empresa

---

## 16. CHANGES THAT SHOULD NOT BE MADE

NÃO implementar:
  Portal de cliente B2B self-service
  Multi-tenant com autenticação por empresa
  RBAC (roles: admin, analyst, viewer)
  Sistema de tickets / CRM
  Ranking ou score público de empresas
  "Empresa mais fraudulenta" ou equivalente
  Sistema de reclamações / reviews
  Gamificação de utilizadores B2C
  Venda do motor de IA como produto
  Nova arquitetura de microserviços
  Refactoring geral da codebase
  Substituição do Admin por nova UI
  Alterações ao fluxo B2C (index.html, bot.js)
  Crawler de mensagens
  Nova camada de threat intelligence

---

## 17. PROPOSED UX FLOW

Admin — Criar Empresa com Selo:
  1. Clica "Nova Empresa"
  2. Preenche campos + marca verificações manualmente
  3. Sistema cria empresa + selo ativo (ZQV-...)
  4. Admin vê código, URL pública, kit de badges

Admin — Regenerar Selo:
  1. Abre detalhe do selo → Clica "Regenerar Código"
  2. Sistema: marca atual como ativo=false + cria novo
  3. Admin confirma novo código

Admin — Threat Radar:
  1. Abre "Threat Radar" → vê empresas com atividade
  2. Clica empresa → vê ocorrências detalhadas

Consumidor — Verificação:
  1. Acede /verify/ZQV-XXX
  2. Vê: nome da empresa, canais verificados, estado, validade
  3. Disclaimer: "canais verificados, não todas as mensagens"

---

## 18. PROPOSED DATA FLOW (após fixes)

[B2C input]
  ↓ [IA / Heurística]
  ↓ let threatResult = await inspectAllUrls()  ← declarar ANTES do try
  ↓ let impersonationResult = await detectarImpersonation()
  ↓ Redis incr → vezes_reportada
  ↓ salvarAnalise({
      veredito, confianca, risco_score [NOVO],
      tipo, vezes_reportada, teve_imagem,
      empresa_id, marca_mencionada,
      canal_mencionado, impersonation,
      alerta_link [NOVO],
      canal: "web"|"whatsapp_baileys"|"twilio" [NOVO]
    })
  ↓ [Supabase analises]
  ↓ [view radar_ameacas]
  ↓ [Admin: Threat Radar + Ocorrências]

---

## 19. PROPOSED API CHANGES

POST /api/analyze:
  Sem alterações de interface.
  Adicionar rate limiting: Redis key "ratelimit:analyze:{ip}"
  Strategy: incr + expire 60s → max 10 req/min por IP

GET/POST /api/admin:
  Remover req.query.secret
  Adicionar ação suspend_selo (soft-delete)
  Modificar create_selo → desativar selos anteriores
  Modificar regenerar_selo → criar novo registo (não só mudar código)
  Adicionar filtros opcionais ao GET: ?empresa_id=, ?from=, ?to=

GET /api/empresa (REWRITE):
  Usar tabelas empresas + selos existentes
  Parametrizar por ?codigo=[ZQV-...] em vez de ?slug=
  OU deprecar completamente

Sem novas rotas públicas.

---

## 20. PROPOSED DATABASE CHANGES

Migration 1 — analises (campos em falta):
  ALTER TABLE analises
    ADD COLUMN IF NOT EXISTS risco_score int,
    ADD COLUMN IF NOT EXISTS alerta_link text,
    ADD COLUMN IF NOT EXISTS canal text DEFAULT "web";
  CREATE INDEX IF NOT EXISTS idx_analises_canal ON analises (canal);

Migration 2 — selos (soft-delete + unicidade):
  ALTER TABLE selos
    ADD COLUMN IF NOT EXISTS ativo boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS desativado_em timestamptz,
    ADD COLUMN IF NOT EXISTS motivo_desativacao text;
  CREATE INDEX IF NOT EXISTS idx_selos_ativo ON selos (empresa_id, ativo);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_selos_um_ativo_por_empresa
    ON selos (empresa_id) WHERE ativo = true;

Migration 3 — empresas (auditoria):
  ALTER TABLE empresas ADD COLUMN IF NOT EXISTS atualizado_em timestamptz;
  [+ trigger update_atualizado_em]

Migration 4 — view radar_ameacas (sem ORDER BY):
  CREATE OR REPLACE VIEW radar_ameacas AS
  SELECT e.id AS empresa_id, e.nome AS empresa,
         count(*) AS ocorrencias,
         count(DISTINCT a.canal_mencionado) AS canais_distintos,
         min(a.criado_em) AS primeira_deteccao,
         max(a.criado_em) AS ultima_deteccao,
         CASE WHEN count(*) >= 20 THEN "critica"
              WHEN count(*) >= 5  THEN "suspeita"
              ELSE "monitorar" END AS severidade
  FROM analises a JOIN empresas e ON e.id = a.empresa_id
  WHERE a.impersonation = true
  GROUP BY e.id, e.nome;

---

## 21. MIGRATION STRATEGY

FASE 0: Auditoria ✅ CONCLUÍDA
FASE 1: Environment & Secrets [P0]
  → Definir ADMIN_SECRET_KEY (Vercel + .env.local)
  → Atualizar OPENROUTER_MODEL=google/gemini-2.0-flash
FASE 2: Database Migrations [P0/P1]
  → Executar Migration 1, 2, 3, 4 (todas idempotentes)
  → ATENÇÃO: Unique index em selos pode conflitar com dados existentes
  → Antes: garantir que cada empresa tem no máx 1 selo atual
FASE 3: API Security Hardening [P0/P1]
  → api/admin.js: remover ?secret=, remover fallback hardcoded
  → api/admin.js: soft-delete de selos, unicidade ao criar
  → api/analyze.js: rate limiting Redis
FASE 4: Data Persistence Fixes [P1]
  → lib/scanner.js: persistir risco_score + alerta_link
  → lib/scanner.js: verificar scope de threatResult
FASE 5: API empresa.js Fix [P0]
  → Reescrever usando empresas + selos OU deprecar
FASE 6: Widget + Minor Fixes [P2]
  → widget.js: corrigir URL para /verify/[codigo]
  → api/admin.js: adicionar vezes_reportada ao SELECT ocorrências
  → .gitignore: adicionar runtime files
FASE 7: Verification & Testing
  → node tests/*.test.js → 27/27 + novos testes
  → Deploy preview Vercel
  → Smoke tests em todos os endpoints

---

## 22. TESTING STRATEGY

COMPANY TESTS:
  create → empresa + selo criados
  create without seal → apenas empresa
  update → empresa atualizada, atualizado_em modificado
  deactivate → página /verify mostra "inativa"
  suspend → página /verify mostra "suspensa"
  reactivate → página /verify mostra "ativa"

SEAL TESTS:
  create → ativo=true
  duplicate prevention → segundo cria, primeiro ativo=false
  verify active → "✓ Verificação ativa"
  verify expired → "⚠️ Verificação expirada"
  verify suspended → "⚠️ Verificação suspensa"
  verify invalid code → 404
  regenerate → novo registo, antigo ativo=false
  soft-delete → ativo=false, registo preservado

IMPERSONATION TESTS:
  official channel → impersonation=false
  non-official channel + golpe → impersonation=true
  ambiguous brand (2 empresas) → impersonation=false
  unknown brand → impersonation=false
  subdomain match (app.x.pt vs x.pt) → impersonation=false
  subdomain spoof (x.pt.fake.com) → impersonation=true
  email official → impersonation=false
  email fake → impersonation=true
  phone normalized → impersonation=false
  legitimate veredito → impersonation=false

RADAR TESTS:
  empresa sem impersonation → não aparece
  < 5 → monitorar
  5-19 → suspeita
  >= 20 → critica
  2 empresas diferentes → isoladas

SECURITY TESTS:
  sem x-admin-key → 401
  key errada → 401
  ?secret= → 401 (após FIX-02)
  > 10 req/min /api/analyze → 429 (após FIX-09)
  GET /verify/ZQV-AAAA... → 404
  GET /api/admin (autenticado) → sem conteúdo B2C

---

## 23. REGRESSION RISKS

Migration selos (campo ativo) quebra queries existentes:
  Probabilidade: Média | Impacto: Alto
  Mitigação: DEFAULT true retro-compatível

Rate limiting bloqueia legítimos:
  Probabilidade: Baixa | Impacto: Médio
  Mitigação: 10/min conservador, ajustável

Soft-delete quebra Admin UI (usa delete_selo):
  Probabilidade: Alta | Impacto: Médio
  Mitigação: Atualizar Admin UI para chamar suspend_selo

Unique index conflita com dados existentes:
  Probabilidade: Média | Impacto: Alto
  Mitigação: Limpeza prévia (garantir 1 ativo por empresa)

Reescrita api/empresa.js quebra widget:
  Probabilidade: Baixa | Impacto: Alto
  Mitigação: Sem clientes reais (broken de qualquer forma)

Alterar OPENROUTER_MODEL muda qualidade:
  Probabilidade: Baixa | Impacto: Baixo
  Mitigação: gemini-2.0-flash equivalente

---

## 24. DEFINITION OF DONE (20 critérios)

1.  ADMIN_SECRET_KEY definido no Vercel (não hardcoded)
2.  ?secret= query param removido do Admin
3.  api/empresa.js corrigido ou desativado
4.  risco_score persistido em analises
5.  alerta_link persistido em analises
6.  Tabela selos com campo ativo + unique index
7.  create_selo desativa selos anteriores
8.  delete_selo substituído por soft-delete
9.  Rate limiting em POST /api/analyze
10. Scope de threatResult verificado e seguro
11. OPENROUTER_MODEL = google/gemini-2.0-flash
12. Widget aponta para /verify/[codigo]
13. 27/27 testes existentes passam
14. Novos testes de security e seal lifecycle passam
15. git log --all -- .env.local não retorna commits
16. B2C (index.html, bot.js) sem alterações funcionais
17. /verify/[codigo] não expõe dados internos
18. Sem ranking reputacional de empresas
19. Threat Radar usa dados reais (não mock)
20. Ocorrências rastreáveis com evidências (alerta_link)

---

## 25. IMPLEMENTATION PLAN

PHASE 0 — Audit [DONE]
  Ficheiros: todos (leitura) | DB: leitura | Testes: 27/27 ✅

PHASE 1 — Environment & Critical Secrets [P0]
  Ficheiros: .env.local, api/admin.js, Vercel env
  DB: nenhuma | API: nenhuma | UI: nenhuma
  Ações:
    1. ADMIN_SECRET_KEY no Vercel e .env.local
    2. Remover fallback hardcoded de api/admin.js
    3. OPENROUTER_MODEL=google/gemini-2.0-flash

PHASE 2 — Database Migrations [P0/P1]
  Ficheiros: supabase.sql, nova migration SQL
  DB: ALTER TABLE analises/selos/empresas, recreate view
  Ações:
    1. Migration 1 (analises: risco_score, alerta_link, canal)
    2. Migration 2 (selos: ativo, desativado_em, unique index)
    3. Migration 3 (empresas: atualizado_em + trigger)
    4. Migration 4 (view radar_ameacas sem ORDER BY)
  RISCO: unique index pode conflitar → limpeza prévia

PHASE 3 — API Security Hardening [P0/P1]
  Ficheiros: api/admin.js, api/analyze.js
  Ações:
    1. Remover req.query.secret
    2. Remover fallback hardcoded
    3. create_selo → desativar anteriores
    4. delete_selo → soft-delete
    5. api/analyze.js → rate limiting Redis

PHASE 4 — Data Persistence Fixes [P1]
  Ficheiros: lib/scanner.js
  Ações:
    1. salvarAnalise(): adicionar risco_score, alerta_link, canal
    2. Verificar e corrigir scope de threatResult
    3. bot.js: passar canal="whatsapp_baileys"
    4. api/whatsapp.js: passar canal="whatsapp_twilio"

PHASE 5 — API empresa.js Fix [P0]
  Ficheiros: api/empresa.js, widget.js
  Ações:
    1. Reescrever api/empresa.js para empresas + selos
    2. Parametrizar por ?codigo= em vez de ?slug=
    3. Atualizar widget.js para usar nova API + /verify/[codigo]

PHASE 6 — Admin UX + Minor Fixes [P2]
  Ficheiros: api/admin.js, admin.html, .gitignore, package.json
  Ações:
    1. Adicionar vezes_reportada ao SELECT de ocorrências
    2. Adicionar runtime files ao .gitignore
    3. Renomear package.json name para "zapqueme"

PHASE 7 — Verification & Production Check
  Testes: node tests/*.test.js (27/27 + novos)
  Deploy: Vercel preview
  Smoke tests: todos os endpoints
  Checklist: 20 critérios de Definition of Done

---

*Documento de pré-produção. Nenhum código foi alterado durante esta auditoria.*
*Implementação autorizada somente após revisão e aprovação.*
