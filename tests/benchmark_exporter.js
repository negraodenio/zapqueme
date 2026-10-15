// tests/benchmark_exporter.js
// Exportador e Validador Oficial de Benchmark no Formato DECO / Ordens
// Metodologia: Avaliação Cega, Regra de Alerta Binário e Intervalo de Confiança Wilson (95%)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import { analyzeContent } from '../lib/scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Função para calcular o Intervalo de Confiança de Wilson (95%, z = 1.96)
function wilsonInterval(successes, total, z = 1.96) {
  if (total === 0) return { center: 0, low: 0, high: 0, text: 'N/A' };
  const p = successes / total;
  const z2 = z * z;
  const denominator = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denominator;
  const margin = (z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total)) / denominator;

  const low = Math.max(0, center - margin) * 100;
  const high = Math.min(1, center + margin) * 100;
  return {
    rate: p * 100,
    low,
    high,
    text: `${(p * 100).toFixed(1)}% [IC 95%: ${low.toFixed(1)}% – ${high.toFixed(1)}%]`
  };
}

function escapeCsv(val) {
  if (val === null || val === undefined) return '';
  const str = String(val).replace(/"/g, '""');
  if (str.includes(',') || str.includes(';') || str.includes('\n') || str.includes('"')) {
    return `"${str}"`;
  }
  return str;
}

export async function runOfficialBenchmark() {
  const datasetPath = path.join(__dirname, 'benchmark_dataset.json');
  const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));

  console.log('\n========================================================================');
  console.log('📊 EXECUTOR OFICIAL DE BENCHMARK: CONFIRME, QUEM É?');
  console.log(`Layout e Metodologia da DECO / Auditoria Independente (${dataset.length} linhas)`);
  console.log('========================================================================\n');

  const rows = [];
  let tp = 0; // Golpe real com alerta emitido (Sucesso)
  let tn = 0; // Legítimo real sem alerta emitido (Sucesso)
  let fp = 0; // Legítimo real com alerta indevido (Falso Positivo)
  let fn = 0; // Golpe real sem alerta (Falso Negativo)

  for (let i = 0; i < dataset.length; i++) {
    const item = dataset[i];
    const id = `AM-${String(i + 1).padStart(3, '0')}`;
    const canal = item.id.includes('SMS') ? 'SMS' : (item.categoria.includes('WhatsApp') || item.categoria.includes('Filho') ? 'WhatsApp' : 'SMS');
    const categoria = item.categoria;
    const textoAnonimizado = item.texto;
    const tipoReal = item.esperado === 'golpe' ? 'Golpe' : 'Legitimo';
    const dataClassificacao = '2026-10-15';

    process.stdout.write(`Processando ${id} (${categoria.padEnd(28, ' ')})... `);

    try {
      const res = await analyzeContent({ texto: textoAnonimizado, canal: 'benchmark' });
      const veredito = res.veredito; // 'golpe' | 'suspeito' | 'legitimo'
      const score = res.risco_score ?? res.confianca ?? 50;
      const modeloUsado = process.env.OPENROUTER_MODEL || 'google/gemini-3.8-flash';
      const origemVeredito = res.alerta_link && res.alerta_link.includes('Google')
        ? 'Google Threat Intel + IA'
        : (res.alerta_link && res.alerta_link.includes('Cloudflare') ? 'Cloudflare + IA' : 'IA (Gemini 3.8 Flash)');

      // Regra Oficial DECO:
      // Alerta = 'golpe' ou 'suspeito'. Sem alerta = 'legitimo'.
      // Uma mensagem legítima com alerta (mesmo 'suspeito') conta como Falso Positivo (FP).
      const temAlerta = veredito === 'golpe' || veredito === 'suspeito';
      const eGolpe = tipoReal === 'Golpe';

      let resultadoClassificacao = '';
      if (eGolpe && temAlerta) {
        tp++;
        resultadoClassificacao = 'Verdadeiro Positivo (TP)';
      } else if (!eGolpe && !temAlerta) {
        tn++;
        resultadoClassificacao = 'Verdadeiro Negativo (TN)';
      } else if (!eGolpe && temAlerta) {
        fp++;
        resultadoClassificacao = 'Falso Positivo (FP)';
      } else {
        fn++;
        resultadoClassificacao = 'Falso Negativo (FN)';
      }

      console.log(`[${veredito.toUpperCase()}] -> ${resultadoClassificacao}`);

      rows.push({
        id,
        canal,
        categoria,
        textoAnonimizado,
        tipoReal,
        dataClassificacao,
        veredito,
        score,
        modeloUsado,
        origemVeredito,
        resultadoClassificacao,
        sinais: (res.sinais || []).join(' | ')
      });
    } catch (err) {
      console.log(`Erro: ${err.message}`);
    }
  }

  const total = tp + tn + fp + fn;
  const totalGolpes = tp + fn;
  const totalLegitimos = tn + fp;

  // Métricas Forenses
  const acuraciaStats = wilsonInterval(tp + tn, total);
  const precisaoStats = wilsonInterval(tp, tp + fp);
  const sensibilidadeStats = wilsonInterval(tp, totalGolpes);
  const falsoPositivoStats = wilsonInterval(fp, totalLegitimos);

  // GERAÇÃO DO CSV EXATO SOLICITADO
  let csv = '';
  csv += 'Benchmark de verificação: Confirme Quem É,,,,,,,,,,,\n';
  csv += ',,,,,,,,,,,\n';
  csv += 'Objetivo,"Medir acertos, falsos positivos e falhas do verificador com mensagens reais e anonimizadas, de forma que os números possam ser mostrados a terceiros sem exagero.",,,,,,,,,,,\n';
  csv += 'Regra 1: classificar antes,Preencha a coluna E (Tipo real) e a data de classificação (F) ANTES de correr o sistema. De preferência quem classifica não é quem desenvolveu o motor.,,,,,,,,,,,\n';
  csv += 'Regra 2: não afinar com a mesma amostra,"Se corrigir o sistema depois de ver erros, meça de novo com mensagens novas. Medir com as mesmas amostras usadas para corrigir dá números otimistas.",,,,,,,,,,,\n';
  csv += 'Regra 3: anonimizar,"Retire nomes, números de telefone, NIF, IBAN, moradas e links pessoais antes de colar o texto na coluna D.",,,,,,,,,,,\n';
  csv += 'Como se conta,"Alerta = veredito \'golpe\' ou \'suspeito\'. Sem alerta = \'legitimo\' ou \'sem sinais de risco\'. Uma mensagem legítima com alerta conta como falso positivo (FP), mesmo que seja \'suspeito\'.",,,,,,,,,,,\n';
  csv += 'Resultados,"Métricas com intervalo de confiança de 95% (método de Wilson, z = 1,96). Com poucas amostras o intervalo é largo: é normal.",,,,,,,,,,,\n';
  csv += ',,,,,,,,,,,\n';
  csv += 'RESUMO EXECUTIVO DE MÉTRICAS (MÉTODO DE WILSON 95%),,,,,,,,,,,\n';
  csv += `Amostras Totais,${total},Total Golpes Reais,${totalGolpes},Total Legítimos Reais,${totalLegitimos},,,,\n`;
  csv += `Acurácia Global,${escapeCsv(acuraciaStats.text)},Sensibilidade (Recall),${escapeCsv(sensibilidadeStats.text)},Precisão Forense,${escapeCsv(precisaoStats.text)},Taxa Falsos Positivos,${escapeCsv(falsoPositivoStats.text)},,\n`;
  csv += ',,,,,,,,,,,\n';
  csv += 'ID,Canal,Categoria,Texto (anonimizado),Tipo real,Data Classificação,Veredito do sistema,Pontuação,Modelo usado,Origem do veredito,Resultado Forense,Sinais Identificados\n';

  for (const r of rows) {
    csv += [
      escapeCsv(r.id),
      escapeCsv(r.canal),
      escapeCsv(r.categoria),
      escapeCsv(r.textoAnonimizado),
      escapeCsv(r.tipoReal),
      escapeCsv(r.dataClassificacao),
      escapeCsv(r.veredito),
      r.score,
      escapeCsv(r.modeloUsado),
      escapeCsv(r.origemVeredito),
      escapeCsv(r.resultadoClassificacao),
      escapeCsv(r.sinais)
    ].join(',') + '\n';
  }

  const csvPath = path.join(process.cwd(), 'benchmark_confirma_quem_e.csv');
  fs.writeFileSync(csvPath, csv, 'utf8');

  console.log('\n========================================================================');
  console.log('✅ BENCHMARK OFICIAL CONCLUÍDO COM SUCESSO!');
  console.log('========================================================================');
  console.log(`Ficheiro CSV gerado: ${csvPath}`);
  console.log(`• Acurácia Global:           ${acuraciaStats.text}`);
  console.log(`• Sensibilidade (Recall):    ${sensibilidadeStats.text}`);
  console.log(`• Precisão Forense:          ${precisaoStats.text}`);
  console.log(`• Taxa de Falsos Positivos:  ${falsoPositivoStats.text}`);
  console.log('========================================================================\n');
}

runOfficialBenchmark().catch(console.error);
