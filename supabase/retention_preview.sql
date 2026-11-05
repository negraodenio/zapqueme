-- Pré-visualização sem dados pessoais: executar antes da migração de retenção.
-- Pressupõe que as migrações 20261016 e 20261019 já foram aplicadas.
-- Os totais são estimativas; a primeira execução do job pode mudar até ocorrer.

SELECT categoria, registos_afetados
FROM (
  SELECT 'analises_90_dias'::text AS categoria, count(*) AS registos_afetados
  FROM public.analises WHERE criado_em < now() - interval '90 days'
  UNION ALL
  SELECT 'feedback_90_dias', count(*)
  FROM public.feedback WHERE criado_em < now() - interval '90 days'
  UNION ALL
  SELECT 'leads_12_meses_inicial', count(*)
  FROM public.leads WHERE criado_em < now() - interval '12 months'
  UNION ALL
  SELECT 'fila_revisao_90_dias', count(*)
  FROM public.fila_revisao
  WHERE LEAST(expira_em, criado_em + interval '90 days') < now()
  UNION ALL
  SELECT 'clusters_12_meses', count(*)
  FROM public.clusters
  WHERE GREATEST(ultima_vez, criado_em) + interval '12 months' < now()
  UNION ALL
  SELECT 'amostras_12_meses', count(*)
  FROM public.amostras_teste
  WHERE LEAST(expira_em, criado_em + interval '12 months') < now()
  UNION ALL
  SELECT 'corridas_benchmark_12_meses', count(*)
  FROM public.corridas_benchmark WHERE data_hora < now() - interval '12 months'
  UNION ALL
  SELECT 'alertas_24_meses', count(*)
  FROM public.alertas_oficiais WHERE detetado_em < now() - interval '24 months'
  UNION ALL
  SELECT 'dicionario_pendente_ou_rejeitado_24_meses', count(*)
  FROM public.dicionario_alteracoes
  WHERE estado <> 'aprovado' AND criado_em < now() - interval '24 months'
  UNION ALL
  SELECT 'uso_selo_24_meses', count(*)
  FROM public.uso_selo WHERE data < (current_date - interval '24 months')::date
  UNION ALL
  SELECT 'verificacoes_empresariais_vencidas', count(*)
  FROM public.verificacoes v
  JOIN public.empresas e ON e.id = v.empresa_id
  WHERE NOT EXISTS (
    SELECT 1 FROM public.selos s
    WHERE s.empresa_id = e.id AND s.ativo = true AND s.arquivado_em IS NULL AND s.valido_ate > now()
  )
    AND NOT (e.status = 'ativo' AND e.estado = 'ativo' AND e.data_validade > now())
    AND CASE
      WHEN e.arquivado_em IS NOT NULL THEN e.arquivado_em + interval '90 days' < now()
      WHEN e.estado IN ('lead', 'contactado', 'proposta', 'em_verificacao')
        AND e.status NOT IN ('suspenso', 'revogado', 'expirado', 'arquivado')
        THEN COALESCE(e.atualizado_em, e.criado_em) + interval '12 months' < now()
      WHEN e.estado IN ('suspenso', 'revogado', 'expirado', 'arquivado')
        OR e.status IN ('suspenso', 'revogado', 'inativo', 'expirado', 'arquivado')
        THEN COALESCE(e.atualizado_em, e.criado_em) + interval '90 days' < now()
      ELSE COALESCE(
        e.data_validade,
        (SELECT max(s.valido_ate) FROM public.selos s WHERE s.empresa_id = e.id),
        e.atualizado_em,
        v.criado_em
      ) + interval '90 days' < now()
    END
  UNION ALL
  SELECT 'contactos_empresariais_a_redigir', count(*)
  FROM public.empresas e
  WHERE NOT EXISTS (
    SELECT 1 FROM public.selos s
    WHERE s.empresa_id = e.id AND s.ativo = true AND s.arquivado_em IS NULL AND s.valido_ate > now()
  )
    AND NOT (e.status = 'ativo' AND e.estado = 'ativo' AND e.data_validade > now())
    AND CASE
      WHEN e.arquivado_em IS NOT NULL THEN e.arquivado_em + interval '90 days' < now()
      WHEN e.estado IN ('lead', 'contactado', 'proposta', 'em_verificacao')
        AND e.status NOT IN ('suspenso', 'revogado', 'expirado', 'arquivado')
        THEN COALESCE(e.atualizado_em, e.criado_em) + interval '12 months' < now()
      WHEN e.estado IN ('suspenso', 'revogado', 'expirado', 'arquivado')
        OR e.status IN ('suspenso', 'revogado', 'inativo', 'expirado', 'arquivado')
        THEN COALESCE(e.atualizado_em, e.criado_em) + interval '90 days' < now()
      ELSE COALESCE(
        e.data_validade,
        (SELECT max(s.valido_ate) FROM public.selos s WHERE s.empresa_id = e.id),
        e.atualizado_em,
        e.criado_em
      ) + interval '90 days' < now()
    END
  UNION ALL
  SELECT 'pagamentos_10_anos', count(*)
  FROM public.pagamentos WHERE data < now() - interval '10 years'
  UNION ALL
  SELECT 'contactos_comerciais_10_anos', count(*)
  FROM public.contactos_comerciais WHERE data < now() - interval '10 years'
  UNION ALL
  SELECT 'historico_10_anos', count(*)
  FROM public.historico WHERE em < now() - interval '10 years'
  UNION ALL
  SELECT 'relatorios_10_anos', count(*)
  FROM public.relatorios_gerados WHERE gerado_em < now() - interval '10 years'
  UNION ALL
  SELECT 'selos_10_anos', count(*)
  FROM public.selos
  WHERE COALESCE(valido_ate, criado_em) < now() - interval '10 years'
    AND NOT (ativo = true AND valido_ate > now())
) AS estimativa
ORDER BY categoria;
