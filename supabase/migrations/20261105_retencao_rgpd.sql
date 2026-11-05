-- Política de conservação do Confirme, Quem É?
-- Executar depois das migrações de 20261016 e 20261019.
-- A rotina corre diariamente às 03:15 UTC via pg_cron.

-- Permite prorrogar registos específicos quando exista obrigação legal ou litígio.
ALTER TABLE public.empresas ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.empresas ADD COLUMN IF NOT EXISTS contactos_eliminados_em timestamptz;

ALTER TABLE public.selos ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.analises ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.feedback ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.leads ADD COLUMN IF NOT EXISTS atualizado_em timestamptz;
ALTER TABLE public.leads ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.verificacoes ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.historico ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.pagamentos ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.contactos_comerciais ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.uso_selo ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.relatorios_gerados ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;

ALTER TABLE public.clusters ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.fila_revisao ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.alertas_oficiais ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.dicionario_alteracoes ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.amostras_teste ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;
ALTER TABLE public.corridas_benchmark ADD COLUMN IF NOT EXISTS retencao_bloqueada boolean NOT NULL DEFAULT false;

UPDATE public.leads SET atualizado_em = criado_em WHERE atualizado_em IS NULL;
ALTER TABLE public.leads ALTER COLUMN atualizado_em SET DEFAULT now();
ALTER TABLE public.leads ALTER COLUMN atualizado_em SET NOT NULL;

CREATE OR REPLACE FUNCTION public.fn_leads_atualizado_em()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.atualizado_em := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_leads_atualizado_em ON public.leads;
CREATE TRIGGER tr_leads_atualizado_em
  BEFORE UPDATE ON public.leads
  FOR EACH ROW EXECUTE FUNCTION public.fn_leads_atualizado_em();

CREATE OR REPLACE FUNCTION public.fn_tocar_empresa_por_contacto_comercial()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE public.empresas
  SET atualizado_em = now()
  WHERE id = NEW.empresa_id;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_contactos_comerciais_tocar_empresa ON public.contactos_comerciais;
CREATE TRIGGER tr_contactos_comerciais_tocar_empresa
  AFTER INSERT OR UPDATE ON public.contactos_comerciais
  FOR EACH ROW EXECUTE FUNCTION public.fn_tocar_empresa_por_contacto_comercial();

CREATE INDEX IF NOT EXISTS idx_feedback_retencao ON public.feedback (criado_em);
CREATE INDEX IF NOT EXISTS idx_leads_retencao ON public.leads (atualizado_em);
CREATE INDEX IF NOT EXISTS idx_pagamentos_retencao ON public.pagamentos (data);
CREATE INDEX IF NOT EXISTS idx_contactos_comerciais_retencao ON public.contactos_comerciais (data);
CREATE INDEX IF NOT EXISTS idx_historico_retencao ON public.historico (em);
CREATE INDEX IF NOT EXISTS idx_relatorios_gerados_retencao ON public.relatorios_gerados (gerado_em);
CREATE INDEX IF NOT EXISTS idx_alertas_oficiais_retencao ON public.alertas_oficiais (detetado_em);
CREATE INDEX IF NOT EXISTS idx_uso_selo_retencao ON public.uso_selo (data);
CREATE INDEX IF NOT EXISTS idx_selos_retencao ON public.selos (valido_ate);
CREATE INDEX IF NOT EXISTS idx_corridas_benchmark_retencao ON public.corridas_benchmark (data_hora);
CREATE INDEX IF NOT EXISTS idx_dicionario_retencao ON public.dicionario_alteracoes (criado_em);
CREATE INDEX IF NOT EXISTS idx_clusters_retencao ON public.clusters (expira_em);
CREATE INDEX IF NOT EXISTS idx_fila_revisao_retencao ON public.fila_revisao (expira_em);
CREATE INDEX IF NOT EXISTS idx_amostras_teste_retencao ON public.amostras_teste (expira_em);

CREATE TABLE IF NOT EXISTS public.execucoes_retencao (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  executado_em timestamptz NOT NULL DEFAULT now(),
  resultado jsonb NOT NULL
);
ALTER TABLE public.execucoes_retencao ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.execucoes_retencao FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.aplicar_retencao_dados()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_resultado jsonb := '{}'::jsonb;
  v_count bigint;
BEGIN
  -- Feedback não pode ficar ligado a uma análise já vencida.
  DELETE FROM public.feedback f
  WHERE NOT f.retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.analises a
      LEFT JOIN public.empresas e ON e.id = a.empresa_id
      WHERE a.id = f.analise_id
        AND (a.retencao_bloqueada OR COALESCE(e.retencao_bloqueada, false))
    )
    AND (
      f.criado_em < now() - interval '90 days'
      OR EXISTS (
        SELECT 1 FROM public.analises a
        WHERE a.id = f.analise_id
          AND a.criado_em < now() - interval '90 days'
          AND NOT a.retencao_bloqueada
      )
    );
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('feedback', v_count);

  DELETE FROM public.analises
  WHERE criado_em < now() - interval '90 days'
    AND NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.feedback f
      WHERE f.analise_id = analises.id AND f.retencao_bloqueada
    )
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = analises.empresa_id AND e.retencao_bloqueada
    );
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('analises', v_count);

  DELETE FROM public.leads
  WHERE atualizado_em < now() - interval '12 months'
    AND NOT retencao_bloqueada;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('leads', v_count);

  -- Evidência de revisão deixa de ser necessária 90 dias após a validade/arquivo.
  DELETE FROM public.verificacoes v
  USING public.empresas e
  WHERE e.id = v.empresa_id
    AND NOT e.retencao_bloqueada
    AND NOT v.retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.selos s
      WHERE s.empresa_id = e.id
        AND s.ativo = true
        AND s.arquivado_em IS NULL
        AND s.valido_ate > now()
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
        e.criado_em,
        v.criado_em
      ) + interval '90 days' < now()
    END;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('verificacoes', v_count);

  -- Remove canais e evidência pessoal de registos expirados/inativos após 90 dias.
  UPDATE public.empresas e
  SET dominio_oficial = NULL,
      email_oficial = NULL,
      telefone_oficial = NULL,
      email_contacto = NULL,
      representante_nome = NULL,
      representante_cargo = NULL,
      stripe_customer_id = NULL,
      apelidos_marca = '{}',
      marca_aliases = '{}',
      verificacao_notas = NULL,
      notas = NULL,
      iban = NULL,
      dominio_verificado = false,
      email_verificado = false,
      telefone_verificado = false,
      nif = CASE
        WHEN EXISTS (
          SELECT 1 FROM public.pagamentos p
          WHERE p.empresa_id = e.id
            AND p.data >= now() - interval '10 years'
        ) THEN e.nif
        ELSE NULL
      END,
      nif_verificado = CASE
        WHEN EXISTS (
          SELECT 1 FROM public.pagamentos p
          WHERE p.empresa_id = e.id
            AND p.data >= now() - interval '10 years'
        ) THEN e.nif_verificado
        ELSE false
      END,
      contactos_eliminados_em = now()
  WHERE e.contactos_eliminados_em IS NULL
    AND NOT e.retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.selos s
      WHERE s.empresa_id = e.id
        AND s.ativo = true
        AND s.arquivado_em IS NULL
        AND s.valido_ate > now()
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
    END;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('registos_empresariais_redigidos', v_count);

  DELETE FROM public.fila_revisao
  WHERE NOT retencao_bloqueada
    AND LEAST(expira_em, criado_em + interval '90 days') < now();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('fila_revisao', v_count);

  DELETE FROM public.clusters
  WHERE NOT retencao_bloqueada
    AND GREATEST(ultima_vez, criado_em) + interval '12 months' < now();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('clusters', v_count);

  DELETE FROM public.amostras_teste
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.corridas_benchmark c
      WHERE c.amostra_id = amostras_teste.id AND c.retencao_bloqueada
    )
    AND LEAST(expira_em, criado_em + interval '12 months') < now();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('amostras_teste', v_count);

  DELETE FROM public.corridas_benchmark
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.amostras_teste a
      WHERE a.id = corridas_benchmark.amostra_id AND a.retencao_bloqueada
    )
    AND data_hora < now() - interval '12 months';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('corridas_benchmark', v_count);

  DELETE FROM public.alertas_oficiais
  WHERE NOT retencao_bloqueada
    AND detetado_em < now() - interval '24 months';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('alertas_oficiais', v_count);

  DELETE FROM public.dicionario_alteracoes
  WHERE estado <> 'aprovado'
    AND NOT retencao_bloqueada
    AND criado_em < now() - interval '24 months';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('propostas_dicionario', v_count);

  DELETE FROM public.uso_selo
  WHERE NOT retencao_bloqueada
    AND data < (current_date - interval '24 months')::date;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('uso_selo', v_count);

  -- Registos contabilísticos e correspondência comercial: prazo legal de 10 anos.
  DELETE FROM public.pagamentos
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = pagamentos.empresa_id AND e.retencao_bloqueada
    )
    AND data < now() - interval '10 years';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('pagamentos', v_count);

  DELETE FROM public.contactos_comerciais
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = contactos_comerciais.empresa_id AND e.retencao_bloqueada
    )
    AND data < now() - interval '10 years';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('contactos_comerciais', v_count);

  DELETE FROM public.historico
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = historico.empresa_id AND e.retencao_bloqueada
    )
    AND em < now() - interval '10 years';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('historico', v_count);

  DELETE FROM public.relatorios_gerados
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = relatorios_gerados.empresa_id AND e.retencao_bloqueada
    )
    AND gerado_em < now() - interval '10 years';
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('relatorios_gerados', v_count);

  DELETE FROM public.selos
  WHERE NOT retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.empresas e
      WHERE e.id = selos.empresa_id AND e.retencao_bloqueada
    )
    AND COALESCE(valido_ate, criado_em) < now() - interval '10 years'
    AND NOT (ativo = true AND valido_ate > now());
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('selos', v_count);

  -- Quando já não existe pagamento sujeito a arquivo, apaga o NIF da ficha operacional.
  UPDATE public.empresas e
  SET nif = NULL,
      nif_verificado = false
  WHERE e.contactos_eliminados_em IS NOT NULL
    AND NOT e.retencao_bloqueada
    AND e.nif IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM public.pagamentos p
      WHERE p.empresa_id = e.id AND p.data >= now() - interval '10 years'
    );
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('nif_operacional_apagado', v_count);

  DELETE FROM public.empresas e
  WHERE e.contactos_eliminados_em IS NOT NULL
    AND NOT e.retencao_bloqueada
    AND NOT EXISTS (
      SELECT 1 FROM public.selos s
      WHERE s.empresa_id = e.id AND s.ativo = true AND s.valido_ate > now()
    )
    AND NOT (e.status = 'ativo' AND e.estado = 'ativo' AND e.data_validade > now())
    AND NOT EXISTS (SELECT 1 FROM public.selos s WHERE s.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.analises a WHERE a.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.verificacoes v WHERE v.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.pagamentos p WHERE p.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.contactos_comerciais c WHERE c.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.historico h WHERE h.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.relatorios_gerados r WHERE r.empresa_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM public.uso_selo u WHERE u.empresa_id = e.id);
  GET DIAGNOSTICS v_count = ROW_COUNT;
  v_resultado := v_resultado || jsonb_build_object('empresas', v_count);

  INSERT INTO public.execucoes_retencao (resultado)
  VALUES (v_resultado || jsonb_build_object('concluido_em', clock_timestamp()));
  DELETE FROM public.execucoes_retencao
  WHERE executado_em < now() - interval '12 months';

  RETURN v_resultado;
END;
$$;

REVOKE ALL ON FUNCTION public.aplicar_retencao_dados() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.aplicar_retencao_dados() TO postgres;

-- Supabase Cron usa pg_cron; a migração deixa uma única tarefa diária ativa.
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;
GRANT USAGE ON SCHEMA cron TO postgres;
DO $$
DECLARE
  v_job_id bigint;
BEGIN
  FOR v_job_id IN
    SELECT jobid FROM cron.job WHERE jobname = 'zapqueme-retencao-dados'
  LOOP
    PERFORM cron.unschedule(v_job_id);
  END LOOP;

  PERFORM cron.schedule(
    'zapqueme-retencao-dados',
    '15 3 * * *',
    'SELECT public.aplicar_retencao_dados();'
  );

  FOR v_job_id IN
    SELECT jobid FROM cron.job WHERE jobname = 'zapqueme-limpeza-historico-cron'
  LOOP
    PERFORM cron.unschedule(v_job_id);
  END LOOP;

  PERFORM cron.schedule(
    'zapqueme-limpeza-historico-cron',
    '45 3 * * *',
    $job$DELETE FROM cron.job_run_details WHERE end_time < now() - interval '90 days'$job$
  );
END;
$$;
