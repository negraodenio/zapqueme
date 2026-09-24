# É Golpe? — MVP

Verificador instantâneo: cola texto ou manda print de mensagem suspeita, a IA diz
se é golpe, porquê, e o que fazer.

## Deploy em 5 minutos (Vercel)

1. Cria conta grátis em https://vercel.com (login com GitHub é o mais rápido).
2. Cria um repositório novo no GitHub e sobe esta pasta inteira para lá
   (`git init && git add . && git commit -m "mvp" && git push`).
3. Na Vercel: **Add New Project** → importa o repositório.
4. Em **Settings → Environment Variables**, adiciona:
   - `ANTHROPIC_API_KEY` = a tua chave de https://console.anthropic.com/settings/keys
   - `UPSTASH_REDIS_REST_URL` e `UPSTASH_REDIS_REST_TOKEN` (opcional, mas recomendado — ver abaixo)
   - `SUPABASE_URL` e `SUPABASE_SERVICE_ROLE_KEY` (opcional, para guardar histórico e métricas — ver abaixo)
5. Clica **Deploy**. Em ~1 minuto tens um link tipo `e-golpe.vercel.app`.

### Configurar o backend de análise de dados (Supabase)

Isto guarda cada análise (veredito, confiança, tipo de golpe) e cada feedback 👍/👎
num banco de dados de verdade, para depois responder perguntas tipo "quantas análises
tivemos essa semana" ou "qual tipo de golpe é mais comum".

1. Cria conta grátis em https://supabase.com e cria um novo projeto (tier gratuito
   é suficiente pro MVP).
2. No painel do projeto, vai em **SQL Editor**, cola o conteúdo do ficheiro
   `supabase.sql` (incluído aqui do lado) e clica **Run**. Isso cria as tabelas
   `analises` e `feedback`.
3. Vai em **Project Settings → API**. Copia:
   - `Project URL` → cola como `SUPABASE_URL`
   - `service_role` key (não a `anon` key — esta função roda no servidor,
     não no navegador) → cola como `SUPABASE_SERVICE_ROLE_KEY`
4. Cola essas duas variáveis nas Environment Variables da Vercel (passo 4 acima) e
   faz redeploy.

Depois disso, dá pra abrir o **Table Editor** do Supabase a qualquer momento e ver
todas as análises e feedbacks em tempo real, ou usar o **SQL Editor** para consultas
tipo:

```sql
select veredito, count(*) from analises group by veredito;
select round(100.0 * sum(case when positivo then 1 else 0 end) / count(*), 1) as pct_positivo from feedback;
```

Se não configurar isso, o site continua funcionando normalmente — só não guarda
histórico nenhum (a análise por IA não depende disso).

### Configurar o contador "já verificada N vezes" (Upstash Redis)

Esta feature mostra "esta mensagem já foi verificada X vezes por outras pessoas" — é o
que mais deve viralizar, e funciona como proteção extra contra golpistas testando o
mesmo texto em várias vítimas.

1. Cria conta grátis em https://upstash.com (tier gratuito é suficiente pro MVP).
2. Cria uma database Redis (região mais perto do teu deploy da Vercel).
3. Na aba **REST API** da database, copia `UPSTASH_REDIS_REST_URL` e `UPSTASH_REDIS_REST_TOKEN`.
4. Cola essas duas variáveis nas Environment Variables da Vercel (passo 4 acima) e faz
   redeploy.

Se não configurar isso, o site continua funcionando normalmente — só não mostra o
contador de "já verificada N vezes" (a análise por IA não depende disso).

Não precisas configurar mais nada — a Vercel detecta a pasta `api/` automaticamente
como Serverless Functions.

## Testar localmente (opcional)

```bash
npm i -g vercel
vercel dev
```
Cria um ficheiro `.env.local` com `ANTHROPIC_API_KEY=sk-ant-...` antes de correr.

## Custo estimado

Cada análise custa poucos cêntimos em tokens de API (imagem + resposta curta).
Para controlar custo: considera trocar `claude-sonnet-5` por um modelo mais barato
se o volume crescer muito, ou limitar a 3 análises grátis por IP/dia (próximo passo).

## Próximos passos sugeridos (depois do dia 1)

- [x] Contador "já verificada N vezes" (Upstash Redis) — já implementado
- [x] Backend de análise de dados / histórico (Supabase) — já implementado
- [ ] Rate limit por IP (dá pra reusar a mesma database Upstash com um `INCR` + `EXPIRE` por IP)
- [ ] Link de partilha com resultado anonimizado (`/r/abc123`)
- [ ] Bot Telegram (reusa a mesma função `analyze.js`)
- [ ] Domínio próprio (ex: `egolpe.pt` ou `.com.br`) — mais fácil de partilhar de boca
- [ ] Analytics simples (Vercel Analytics é grátis e já vem pronto)

## Aviso legal a manter sempre visível

Este serviço dá um alerta automático, não substitui a polícia, o banco do utilizador,
ou uma autoridade oficial de proteção ao consumidor. Não guarda nem usa as mensagens
para treinar modelos.
