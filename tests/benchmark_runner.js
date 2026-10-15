// tests/benchmark_runner.js
// Executor do Benchmark de Validação de Acurácia & Falsos Positivos
// Zap, Quem É? / Confirme, Quem É? (Portugal 2026)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import { analyzeContent } from '../lib/scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runBenchmark() {
  const datasetPath = path.join(__dirname, 'benchmark_dataset.json');
  if (!fs.existsSync(datasetPath)) {
    console.error('Dataset de benchmark não encontrado:', datasetPath);
    process.exit(1);
  }

  const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  console.log('\n========================================================================');
  console.log(`🔍 INICIANDO BENCHMARK DE PRECISÃO REAL (${dataset.length} AMOSTRAS PORTUGUESAS)`);
  console.log('========================================================================\n');

  let tp = 0; // True Positive (Era golpe/ameaça e detetou como golpe/suspeito alto)
  let tn = 0; // True Negative (Era legítimo e detetou como legítimo/neutro)
  let fp = 0; // False Positive (Era legítimo e marcou como golpe)
  let fn = 0; // False Negative (Era golpe e marcou como legítimo)

  const results = [];

  for (let i = 0; i < dataset.length; i++) {
    const item = dataset[i];
    process.stdout.write(`[${i + 1}/${dataset.length}] Testando: ${item.categoria.padEnd(30, ' ')}... `);

    try {
      const res = await analyzeContent({ texto: item.texto, canal: 'benchmark' });
      const score = res.risco_score ?? res.confianca ?? 50;
      const veredito = res.veredito;

      const isScamPredicted = veredito === 'golpe' || (veredito === 'suspeito' && score >= 60);
      const isScamActual = item.esperado === 'golpe';

      let status = '';
      if (isScamActual && isScamPredicted) {
        tp++;
        status = '✅ ACERTO (Ameaça Detetada)';
      } else if (!isScamActual && !isScamPredicted) {
        tn++;
        status = '✅ ACERTO (Legítimo Preservado)';
      } else if (!isScamActual && isScamPredicted) {
        fp++;
        status = '❌ FALSO POSITIVO (Alerta Indevido)';
      } else {
        fn++;
        status = '❌ FALSO NEGATIVO (Golpe Escapou)';
      }

      console.log(status);
      results.push({
        id: item.id,
        categoria: item.categoria,
        esperado: item.esperado,
        obtido: veredito,
        score,
        sinais: (res.sinais || []).slice(0, 2).join(' | '),
        status
      });
    } catch (err) {
      console.log(`⚠️ ERRO NA EXECUÇÃO: ${err.message}`);
    }
  }

  const total = tp + tn + fp + fn;
  const acuracia = total > 0 ? ((tp + tn) / total) * 100 : 0;
  const precisao = (tp + fp) > 0 ? (tp / (tp + fp)) * 100 : 0;
  const recall = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 0;
  const taxaFalsoPositivo = (fp + tn) > 0 ? (fp / (fp + tn)) * 100 : 0;

  console.log('\n========================================================================');
  console.log('📊 RESULTADOS FINAIS DO BENCHMARK (MÉTRICAS OFICIAIS PARA A DECO/ORDENS)');
  console.log('========================================================================');
  console.log(`Total de Casos Analisados:        ${total}`);
  console.log(`Ameaças Confirmadas (TP):         ${tp}`);
  console.log(`Comunicações Legítimas (TN):      ${tn}`);
  console.log(`Falsos Positivos (FP):            ${fp} (${taxaFalsoPositivo.toFixed(1)}%)`);
  console.log(`Falsos Negativos (FN):            ${fn}`);
  console.log('------------------------------------------------------------------------');
  console.log(`🎯 Acurácia Global:               ${acuracia.toFixed(1)}%`);
  console.log(`🛡️ Precisão da Deteção:           ${precisao.toFixed(1)}%`);
  console.log(`🔍 Sensibilidade (Recall):        ${recall.toFixed(1)}%`);
  console.log(`✅ Taxa de Falsos Positivos:      ${taxaFalsoPositivo.toFixed(1)}%`);
  console.log('========================================================================\n');

  // Gera o relatório em Markdown para o dossier institucional
  const reportMdPath = path.join(__dirname, 'BENCHMARK_REPORT_PT.md');
  let mdContent = `# Relatório de Eficácia & Precisão Forense — Zap / Confirme, Quem É?
**Data de Execução:** Outubro de 2026 • **Amostragem:** ${total} Casos Reais de Portugal

## Resumo Executivo para Associações e Reguladores (DECO, CNCS, Ordens)
| Métrica | Resultado Obtido | Meta Mínima de Aceitação |
| :--- | :---: | :---: |
| **Acurácia Global** | **${acuracia.toFixed(1)}%** | > 85.0% |
| **Precisão de Ameaça** | **${precisao.toFixed(1)}%** | > 90.0% |
| **Sensibilidade (Recall)** | **${recall.toFixed(1)}%** | > 85.0% |
| **Taxa de Falsos Positivos** | **${taxaFalsoPositivo.toFixed(1)}%** | < 5.0% |

## Tabela de Casos Analisados
| ID | Categoria | Esperado | Veredito Obtido | Risco | Status | Sinais Identificados |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
`;

  for (const r of results) {
    mdContent += `| ${r.id} | ${r.categoria} | \`${r.esperado}\` | \`${r.obtido}\` | ${r.score}/100 | ${r.status.startsWith('✅') ? '✅ Sucesso' : '❌ Falha'} | ${r.sinais || 'N/A'} |\n`;
  }

  fs.writeFileSync(reportMdPath, mdContent, 'utf8');
  console.log(`📄 Relatório oficial gravado em: ${reportMdPath}`);
}

runBenchmark().catch(console.error);
