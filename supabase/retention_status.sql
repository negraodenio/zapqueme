-- Verificação somente de leitura, para executar depois da migração.
-- Não executa a limpeza nem devolve dados pessoais.

SELECT
  jobid,
  jobname,
  schedule,
  active
FROM cron.job
WHERE jobname IN (
  'zapqueme-retencao-dados',
  'zapqueme-limpeza-historico-cron'
)
ORDER BY jobname;

SELECT
  executado_em,
  resultado
FROM public.execucoes_retencao
ORDER BY executado_em DESC
LIMIT 5;

SELECT
  j.jobname,
  d.status,
  d.start_time,
  d.end_time,
  d.return_message
FROM cron.job_run_details d
JOIN cron.job j USING (jobid)
WHERE j.jobname IN (
  'zapqueme-retencao-dados',
  'zapqueme-limpeza-historico-cron'
)
ORDER BY d.start_time DESC
LIMIT 10;
