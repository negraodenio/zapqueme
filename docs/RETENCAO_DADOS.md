# Retenção e eliminação de dados

**Âmbito:** Confirme, Quem É? — tabelas Supabase, fallback Redis de leads e sessão técnica WhatsApp.

**Migração:** `supabase/migrations/20261105_retencao_rgpd.sql`
**Estado:** código preparado na cópia local; tem de ser aplicado e confirmado no Supabase de produção.

## Prazos definidos

| Categoria | Prazo | O que acontece |
|---|---:|---|
| Texto, imagem e links submetidos para análise | Só durante o pedido | Não são guardados como conteúdo integral na tabela principal. O conteúdo pode ser enviado aos fornecedores externos indicados na política. |
| Metadados de análise e feedback | 90 dias | A análise e o respetivo feedback são eliminados; feedback ligado a uma análise vencida é eliminado com ela. |
| Pedido comercial sem contrato (`leads`) | 12 meses após a última alteração registada, ou após a receção se não houver alteração | A coluna `atualizado_em` é atualizada quando o registo muda. Contactos comerciais registados para empresas também atualizam a ficha CRM. O fallback Redis tem TTL individual de 12 meses e a lista deixa de conter o conteúdo integral dos novos leads. |
| Fila de revisão | Máximo de 90 dias desde a criação | Usa o prazo `expira_em`, limitado a 90 dias. |
| Cluster de ameaça | 12 meses após a última ocorrência | A expiração acompanha `ultima_vez`. |
| Amostra de teste e corrida de benchmark | Máximo de 12 meses | Registos e resultados associados são eliminados após o limite operacional. |
| Alertas de fontes e uso diário de selo | 24 meses | Apagados após este período para limitar histórico operacional ligado a empresas. |
| Canais de contacto e evidência de verificação empresarial | 90 dias após expiração, desativação ou arquivo | Os canais e notas de verificação são apagados da ficha operacional; a verificação deixa de ser apresentada como atual. O NIF é mantido apenas enquanto houver pagamentos registados dentro do prazo contabilístico de 10 anos. |
| Pagamentos, correspondência comercial, histórico de operações e relatórios de suporte | 10 anos, quando a obrigação de arquivo se aplique | Conservados para arquivo comercial/fiscal. Registos com bloqueio de conservação ativo não são apagados. Após o fim dos prazos das dependências, a ficha empresarial expirada e sem dados dependentes pode ser removida. |
| Cópia da sessão WhatsApp no Redis | 180 dias desde a última sincronização | Cada sincronização renova o TTL; o logout apaga a sessão remota e os ficheiros locais. |
| Limites de pedidos no Redis | Duas vezes a janela do limite | Cada contador tem expiração curta e não constitui histórico de utilização. |

Os prazos operacionais de 90 dias, 12 meses e 24 meses são limites definidos por finalidade, não prazos fixados diretamente numa lei. A automação corre diariamente às **03:15 UTC**, regista apenas contagens agregadas de eliminação por 12 meses e tem uma exceção explícita para conservação legal documentada.

## Base legal e aplicação

- O artigo 5.º, n.º 1, alínea e), do [RGPD](https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX%3A32016R0679) exige conservar dados identificáveis apenas pelo tempo necessário à finalidade.
- O artigo 21.º da [Lei n.º 58/2019](https://diariodarepublica.pt/dr/detalhe/lei/58-2019-123815982) remete, na falta de prazo legal específico, para o período necessário à finalidade; permite conservar o que seja necessário para provar obrigações até à prescrição dos direitos correspondentes e exige destruição ou anonimização quando cesse a finalidade.
- Quando o responsável esteja sujeito às obrigações comerciais/fiscais correspondentes, o artigo 40.º do [Código Comercial](https://files.diariodarepublica.pt/1s/2006/03/063a01.pdf) e o artigo 19.º do [Decreto-Lei n.º 28/2019](https://diariodarepublica.pt/dr/detalhe/decreto-lei/28-2019-119622094) preveem conservação por 10 anos de correspondência comercial e de livros, registos e documentos de suporte, sem prejuízo de prazo especial superior.
- O prazo ordinário de prescrição civil é de 20 anos pelo artigo 309.º do [Código Civil](https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1966-34509075-49788675), mas existem prazos especiais mais curtos. Esse prazo não é usado como retenção geral de dados: se uma obrigação ou litígio concreto exigir mais tempo, bloqueiam-se apenas os registos pertinentes e documenta-se a razão.

Estes prazos pressupõem que os dados são tratados em Portugal e que a atividade fica sujeita às obrigações referidas. A categoria do documento, a qualidade jurídica do responsável, o regime fiscal e a existência de reclamação, inspeção ou litígio podem alterar a análise. Não se conserva toda a ficha de contacto por existir uma fatura: os campos operacionais são removidos quando deixam de ser necessários, e os elementos contabilísticos são mantidos no prazo aplicável.

## Aplicação e bloqueio legal

1. Executar `supabase/retention_preview.sql`, rever apenas os totais, confirmar backup recuperável e depois aplicar a migração no Supabase de produção.
2. Confirmar em **Integrations → Cron** que `zapqueme-retencao-dados` está ativo e rever o histórico em `cron.job_run_details`.
3. A primeira execução elimina dados que já ultrapassaram os prazos definidos. A migração não foi executada nesta cópia de trabalho e não acedeu a dados remotos.
4. Para conservar um registo concreto devido a reclamação, inspeção ou litígio, definir `retencao_bloqueada = true` apenas nesse registo. Quando o processo terminar e não houver outro fundamento, remover o bloqueio. A coluna existe nas tabelas abrangidas; para um caso empresarial com várias tabelas, bloquear também a ficha `empresas` e cada registo relacionado que seja necessário preservar.
5. As cópias de segurança e logs de Vercel, Render, Supabase, Upstash, OpenRouter, Google e serviços de reputação seguem também as configurações e períodos dos respetivos prestadores. A aplicação não controla a eliminação instantânea nesses sistemas; as contas e contratos precisam de ser verificados separadamente. O histórico técnico do Supabase Cron é limpo após 90 dias; os resultados agregados da rotina ficam por 12 meses.

Exemplo administrativo para preservar uma ficha empresarial durante um processo em curso:

```sql
UPDATE public.empresas
SET retencao_bloqueada = true
WHERE id = 'UUID-DA-EMPRESA';
```

Também se deve marcar `retencao_bloqueada = true` nos registos específicos de pagamento, correspondência ou histórico que sejam relevantes para o processo. A tabela `public.execucoes_retencao` contém apenas datas e contagens da limpeza, sem conteúdo de leads ou mensagens.
