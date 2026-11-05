# Confirme, Quem É? — MVP

Aplicação para analisar mensagens suspeitas e permitir a consulta de canais empresariais submetidos para revisão manual. A análise automática é indicativa e pode falhar; não prova a identidade do remetente nem garante que uma mensagem é segura.

## Componentes

- `index.html` e `api/analyze.js`: verificador web de texto/imagens e função de análise.
- `bot.js`: servidor do bot WhatsApp (Baileys) e webhook SMS. O Baileys é uma biblioteca não oficial; não basear compromissos de disponibilidade neste canal.
- `api/empresa.js`: submissão e consulta de pedidos empresariais.
- `api/admin.js` e `admin.html`: operações internas. A chave administrativa é segredo de servidor e nunca deve ser publicada no browser.
- Supabase: metadados, CRM e feedback; Upstash Redis: limites, contadores, contingência de leads e sessão técnica.

## Configuração

1. Instala Node.js 22 e executa `npm install`.
2. Copia `.env.example` para `.env.local` para desenvolvimento e preenche apenas os serviços que vais usar. Não partilhes nem comites esse ficheiro.
3. Configura `OPENROUTER_API_KEY` e `OPENROUTER_MODEL` para análise via OpenRouter. A aplicação pede opções de privacidade por pedido, mas a disponibilidade depende do modelo e fornecedor escolhidos. Revê os termos e a configuração da conta antes de processar dados pessoais.
4. O fallback direto para Gemini fica desativado por omissão em produção. Só ativa `ALLOW_GEMINI_FALLBACK=true` depois de confirmar o fornecedor, modalidade e condições aplicáveis.
5. Configura `UPSTASH_REDIS_REST_URL` e `UPSTASH_REDIS_REST_TOKEN`. Em produção, limites de segurança dependem do Redis e as rotas relevantes recusam pedidos quando o serviço não está disponível.
6. Para persistência, configura `SUPABASE_URL` e `SUPABASE_SERVICE_ROLE_KEY` apenas no servidor. Nunca uses a chave `service_role` no HTML ou numa aplicação cliente. Revê [a tabela de retenção](docs/RETENCAO_DADOS.md), executa `supabase/retention_preview.sql`, confirma um backup recuperável e aplica as migrações SQL, incluindo `20261105_retencao_rgpd.sql`. Depois confirma no Supabase Cron que `zapqueme-retencao-dados` está ativo. A primeira execução elimina registos vencidos.
7. Configura uma chave aleatória de pelo menos 32 caracteres em `ADMIN_SECRET_KEY`. Para o Baileys em produção, configura também Redis e `WHATSAPP_SESSION_ENCRYPTION_KEY` com pelo menos 32 caracteres. Protege e guarda essa chave separadamente; sem Redis e cifragem, o estado de prontidão fica indisponível e a sessão pode perder-se num reinício do Render.
8. O bot WhatsApp usa Baileys e não depende de Twilio. O limite inicial é 12 mensagens por remetente/minuto (`WHATSAPP_MESSAGES_PER_MINUTE`); imagens acima de 8 MB e conversas de grupo são ignoradas. O webhook SMS é um fluxo separado e opcional.

## Desenvolvimento local

```sh
npm install
npm run dev
```

Para o processo WhatsApp, executa `npm start` depois de preencher as variáveis necessárias. Mantém `AUTO_PAIRING=false` salvo quando estás a executar conscientemente o processo de emparelhamento.

## Deploy

O site e as funções `api/` podem ser publicados na Vercel. O serviço WhatsApp é configurado em `render.yaml` para o Render. Define as variáveis secretas nos painéis dos fornecedores, nunca no repositório. O plano atual do manifesto é gratuito; confirma os limites e a disponibilidade do teu plano antes de prometer continuidade.

`GET /health/live` (também `GET /ping`) confirma apenas que o processo responde e é o health check do Render. `GET /health/ready` (também `GET /status`) devolve 200 apenas quando WhatsApp, Supabase e Redis estão operacionais e a persistência está cifrada/configurada; caso contrário devolve 503. O processo consulta Supabase a cada 10 minutos. Num plano gratuito, usa o monitor externo em `/health/live` para gerar tráfego de entrada e monitoriza `/health/ready` para alertas. Um pedido periódico não cria SLA nem confirma uma análise ponta a ponta.

## Dados e privacidade

O conteúdo enviado para análise pode ser encaminhado a fornecedores externos de IA e reputação de links. A aplicação guarda metadados da análise, não o texto integral na tabela principal. A migração `20261105_retencao_rgpd.sql` aplica a tabela de conservação e agenda a limpeza diária no Supabase; até ser aplicada e confirmada no projeto de produção, não anuncies a eliminação automática. Consulta `privacidade.html` e [a tabela de retenção](docs/RETENCAO_DADOS.md) antes de publicar ou alterar os fluxos de dados.

A sessão técnica WhatsApp contém credenciais sensíveis. As cópias cifradas no Redis expiram após 180 dias sem sincronização e são removidas no logout. Configura a chave de cifragem antes de reconectar e confirma a expiração das cópias antigas no Redis. Nunca copies credenciais de sessão para issues, mensagens ou logs.

O processamento ignora grupos, deduplica IDs de mensagem durante 24 horas (Redis, com fallback local temporário) e limita o volume por remetente. O fallback local não oferece deduplicação nem limites entre reinícios; confirma que Redis está configurado e acessível em produção.

## Custo e operação

Não existe um custo total fixo: depende do plano de alojamento, volume, fornecedor/modelo de IA, armazenamento, reputação de links e trabalho manual de revisão. Define limites de utilização e acompanha custos antes de abrir tráfego significativo.

## Dados de demonstração

`scripts/seed_mock_demo.mjs` só executa fora de `NODE_ENV=production` e exige uma confirmação explícita do identificador do projeto Supabase. `scripts/limpar_mock_demo.mjs` é destrutivo: além da confirmação do projeto, exige a variável `ALLOW_MOCK_DEMO_CLEANUP=true` e a frase exata `DELETE MOCK DATA <identificador-do-projeto>`. Usa estes scripts apenas num projeto de demonstração isolado e confirma os resultados no Supabase. Não os executes contra produção.

## Aviso

A ferramenta fornece sinais automatizados para apoio à decisão e não substitui confirmação direta com a empresa, banco, operadora, polícia ou autoridade competente. Não envies palavras-passe, códigos de autenticação, dados de cartão ou informação sensível.
