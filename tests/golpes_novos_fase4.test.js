import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  validarConjuntoBenchmarkRotativo,
  calcularIntervaloWilson,
  executarBenchmarkRotativo,
  criarAmostraTeste,
  classificarAmostraTeste,
  promoverAmostraParaRegressao,
  AMOSTRAS_TESTE_INICIAIS
} from '../lib/golpes_novos.js';

describe('Módulo Golpes Novos - Fase 4: Benchmark Rotativo & Amostras de Teste', () => {

  it('Critério 5: Recusa-se a correr se faltar classificação humana prévia em qualquer amostra', () => {
    // 1. Amostra com tipo_real nulo
    const amostrasComNulo = [
      { id: 'a1', tipo_real: 'Golpe', classificado_por: 'Auditor A' },
      { id: 'a2', tipo_real: null, classificado_por: 'Auditor B' }
    ];

    assert.throws(
      () => validarConjuntoBenchmarkRotativo(amostrasComNulo),
      (err) => {
        assert.match(err.message, /Critério 5/);
        assert.match(err.message, /a2/);
        return true;
      },
      'Deveria ter lançado erro explícito de violação do Critério 5 para tipo_real nulo'
    );

    // 2. Amostra com classificado_por ausente
    const amostrasSemAuditor = [
      { id: 'a1', tipo_real: 'Golpe', classificado_por: 'Auditor A' },
      { id: 'a3', tipo_real: 'Legítimo', classificado_por: '' }
    ];

    assert.throws(
      () => validarConjuntoBenchmarkRotativo(amostrasSemAuditor),
      (err) => {
        assert.match(err.message, /Critério 5/);
        assert.match(err.message, /a3/);
        return true;
      },
      'Deveria ter lançado erro explícito de violação do Critério 5 para classificado_por vazio'
    );

    // 3. Validação bem-sucedida quando todas as amostras estão classificadas
    const amostrasValidas = [
      { id: 'a1', tipo_real: 'Golpe', classificado_por: 'Auditor Humano' },
      { id: 'a2', tipo_real: 'Legítimo', classificado_por: 'Auditor Humano' }
    ];
    assert.doesNotThrow(() => validarConjuntoBenchmarkRotativo(amostrasValidas));
  });

  it('Calcula corretamente o intervalo de confiança de Wilson (95%)', () => {
    // 10 acertos em 10 tentativas
    const w10 = calcularIntervaloWilson(10, 10);
    assert.strictEqual(w10.pct, 100);
    assert.ok(w10.inferior > 0.65 && w10.inferior < 1.0);
    assert.strictEqual(w10.superior, 1.0);

    // 0 acertos em 10 tentativas
    const w0 = calcularIntervaloWilson(0, 10);
    assert.strictEqual(w0.pct, 0);
    assert.strictEqual(w0.inferior, 0.0);
    assert.ok(w0.superior > 0.0 && w0.superior < 0.35);

    // 15 acertos em 16 tentativas (93.8%)
    const w15 = calcularIntervaloWilson(15, 16);
    assert.strictEqual(w15.pct, 93.8);
    assert.ok(w15.inferior > 0.68 && w15.inferior < 0.75);
    assert.ok(w15.superior > 0.95 && w15.superior < 1.0);
  });

  it('Executa o benchmark rotativo com rotulagem estrita e relatório de golpes novos', async () => {
    // Assegura que o conjunto inicial de 16 amostras cumpre o Critério 5
    assert.ok(AMOSTRAS_TESTE_INICIAIS.length >= 15);
    validarConjuntoBenchmarkRotativo(AMOSTRAS_TESTE_INICIAIS);

    const relatorio = await executarBenchmarkRotativo(AMOSTRAS_TESTE_INICIAIS, {
      commit: 'test-commit-sha'
    });

    // Rótulo obrigatório segundo a Secção 3.6
    assert.match(relatorio.rotulagem, /Teste interno com 16 amostras/);
    assert.strictEqual(relatorio.amostras_totais, 16);
    assert.ok(relatorio.hash_dataset && relatorio.hash_dataset.length === 64, 'SHA-256 do dataset obrigatório');
    assert.ok(relatorio.intervalo_wilson_95.includes('–'), 'Intervalo de Wilson formatado');

    // Relatório de Golpes Novos (< 14 dias)
    assert.ok(relatorio.relatorio_golpes_novos, 'Relatório de golpes novos deve existir');
    assert.ok(relatorio.relatorio_golpes_novos.total_golpes_novos > 0, 'Deve ter amostras de golpes novos');
    assert.ok(relatorio.relatorio_golpes_novos.intervalo_wilson_95, 'Deve ter intervalo de Wilson para golpes novos');

    // Regra da auditoria: Qualquer "suspeito" conta como alerta para sensibilidade
    assert.ok(relatorio.sensibilidade_golpes.total_golpes > 0);
    assert.ok(relatorio.sensibilidade_golpes.detetados > 0);
  });

  it('Cria amostra de teste com anonimização de PII', () => {
    const amostra = criarAmostraTeste({
      semana: 'Semana 42 - 2026',
      resumo_ou_texto_anonimizado: 'SMS de telemovel 912345678 com IBAN PT50000000000000000000000 e email vitima@exemplo.pt a pedir taxa',
      origem: 'real',
      tipo_real: 'Golpe',
      classificado_por: 'Auditor Externo',
      golpe_novo: true
    });

    assert.ok(!amostra.resumo_ou_texto_anonimizado.includes('912345678'), 'Telemóvel deve ser mascarado');
    assert.ok(!amostra.resumo_ou_texto_anonimizado.includes('PT50000000000000000000000'), 'IBAN deve ser mascarado');
    assert.ok(!amostra.resumo_ou_texto_anonimizado.includes('vitima@exemplo.pt'), 'Email deve ser mascarado');
    assert.strictEqual(amostra.uso, 'rotativo');
    assert.strictEqual(amostra.golpe_novo, true);
  });

  it('Classifica amostra humanamente e permite promoção para regressão permanente', () => {
    // 1. Amostra criada sem classificação
    const pendente = criarAmostraTeste({
      semana: 'Semana 42 - 2026',
      resumo_ou_texto_anonimizado: 'Email a fingir ser da Autoridade Tributária a notificar divergência',
      origem: 'real',
      tipo_real: null,
      classificado_por: null
    });
    assert.strictEqual(pendente.tipo_real, null);

    // 2. Classificação humana
    const classificada = classificarAmostraTeste(pendente, {
      tipo_real: 'Golpe',
      classificado_por: 'Auditor Qualificado B',
      golpe_novo: true
    });
    assert.strictEqual(classificada.tipo_real, 'Golpe');
    assert.strictEqual(classificada.classificado_por, 'Auditor Qualificado B');
    assert.strictEqual(classificada.golpe_novo, true);

    // 3. Promoção para regressão permanente
    const promovida = promoverAmostraParaRegressao(classificada);
    assert.strictEqual(promovida.uso, 'regressao');
  });

});
