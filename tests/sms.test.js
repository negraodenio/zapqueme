// tests/sms.test.js — Suíte de testes do Canal de SMS e Gateways
import assert from 'assert';
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import { formatSmsMessage } from '../lib/scanner.js';
import smsHandler from '../api/sms.js';

console.log('\n============================================================');
console.log('TESTES DO CANAL SMS & GATEWAY ANTI-SMISHING (B2B & TELCO)');
console.log('============================================================\n');

// TESTE 1: Formatação de SMS para Golpe (ex: falsa taxa de entrega)
{
  const golpeData = {
    veredito: 'golpe',
    risco_score: 95,
    confianca: 90,
    marca_mencionada: 'Galp',
    alerta_link: 'Link falso imitando portal oficial da Galp',
    explicacao_simples: 'Tentativa de phishing de credenciais e fatura falsa.'
  };

  const smsText = formatSmsMessage(golpeData);
  assert(smsText.includes('ZAP ALERTA: GOLPE (95/100)'), 'Deve conter identificador de golpe e score');
  assert(smsText.includes('GALP'), 'Deve mencionar a marca imitada');
  assert(smsText.includes('NAO clique no link'), 'Deve conter orientação de segurança');
  assert(!smsText.includes('*'), 'SMS não deve conter formatação markdown com asteriscos');
  assert(smsText.length < 320, 'SMS deve respeitar limite de segmentos SMS');
  console.log('✅ [PASS] TESTE SMS-01: formatSmsMessage formata golpe adequadamente sem markdown');
}

// TESTE 2: Formatação de SMS para Mensagem Legítima
{
  const legitimoData = {
    veredito: 'legitimo',
    risco_score: 10,
    confianca: 90,
    marca_mencionada: 'MEO'
  };

  const smsText = formatSmsMessage(legitimoData);
  assert(smsText.includes('ZAP VERIFICADO: SEGURO (10/100)'), 'Deve conter selo seguro no SMS');
  assert(smsText.includes('MEO'), 'Deve citar a entidade oficial');
  console.log('✅ [PASS] TESTE SMS-02: formatSmsMessage formata mensagem legítima com selo seguro');
}

// TESTE 3: Formatação de SMS para Mensagem Suspeita
{
  const suspeitoData = {
    veredito: 'suspeito',
    risco_score: 65,
    confianca: 70,
    explicacao_simples: 'Abordagem atipica com link externo.'
  };

  const smsText = formatSmsMessage(suspeitoData);
  assert(smsText.includes('ZAP ATENCAO: RISCO MODERADO (65/100)'), 'Deve conter alerta de atenção moderada');
  console.log('✅ [PASS] TESTE SMS-03: formatSmsMessage formata suspeito com prudência');
}

// TESTE 4: Webhook api/sms com solicitação de Ajuda / Vazio
{
  let statusCode = 200;
  let headers = {};
  let sentBody = '';

  const mockRes = {
    status(code) { statusCode = code; return this; },
    setHeader(k, v) { headers[k] = v; },
    send(body) { sentBody = body; return this; },
    json(body) { sentBody = JSON.stringify(body); return this; }
  };

  const mockReq = {
    method: 'POST',
    body: { Body: 'ajuda', From: '+351912345678' },
    query: {}
  };

  await smsHandler(mockReq, mockRes);
  assert.strictEqual(statusCode, 200);
  assert(sentBody.includes('<Response>') && sentBody.includes('<Message>') && sentBody.includes('<Body>'), 'Deve conter estrutura XML TwiML');
  assert(sentBody.includes('Reencaminhe para este numero'), 'Deve orientar reencaminhamento de SMS');
  console.log('✅ [PASS] TESTE SMS-04: api/sms responde TwiML para comando de ajuda');
}

// TESTE 5: Webhook api/sms com formato JSON para integração B2B / API da Telco
{
  let statusCode = 200;
  let jsonResponse = null;

  const mockRes = {
    status(code) { statusCode = code; return this; },
    setHeader() {},
    send(b) { sentBody = b; return this; },
    json(obj) { jsonResponse = obj; return this; }
  };

  const mockReq = {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { text: 'Boa tarde, tudo bem?', sender: '+351922334455' },
    query: { format: 'json' }
  };

  await smsHandler(mockReq, mockRes);
  assert.strictEqual(statusCode, 200);
  assert.strictEqual(jsonResponse.success, true);
  assert.strictEqual(jsonResponse.canal, 'sms');
  assert.strictEqual(jsonResponse.from, '+351922334455');
  assert(jsonResponse.sms_resposta.length > 0, 'Deve conter texto pronto para envio por SMS');
  console.log('✅ [PASS] TESTE SMS-05: api/sms suporta resposta JSON estruturada para operadoras B2B');
}

console.log('\n============================================================');
console.log('RESULTADO DOS TESTES DE SMS: 5/5 PASSARAM COM SUCESSO! 🎉');
console.log('============================================================\n');
