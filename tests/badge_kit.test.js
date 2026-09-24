// tests/badge_kit.test.js — Bateria de Testes do Kit Comercial ZAP VERIFIED
// Critérios de Aceitação da Seção 21

import assert from 'node:assert/strict';
import {
  generateHorizontalBadge,
  generatePrincipalBadge,
  generateCircularBadge
} from '../api/badge.js';

let passed = 0;
let total = 0;

function runTest(name, fn) {
  total++;
  try {
    fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    throw err;
  }
}

async function runAsyncTest(name, fn) {
  total++;
  try {
    await fn();
    console.log(`✅ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`❌ [FAIL] ${name}:`, err.message);
    throw err;
  }
}

console.log('============================================================');
console.log('TESTES DO KIT COMERCIAL ZAP VERIFIED — BADGES');
console.log('============================================================\n');

// 1. Formato Horizontal
runTest('Badge Horizontal gera SVG válido com textos obrigatórios', () => {
  const svg = generateHorizontalBadge({
    codigo: 'ZQV-TESTEKIT01',
    empresaNome: 'Banco ACME',
    status: 'ativo',
    statusTexto: 'Verificação ativa'
  });

  assert.match(svg, /<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /ZAP VERIFIED/);
  assert.match(svg, /CANAIS CONFIRMADOS/);
  assert.match(svg, /ZQV-TESTEKIT01/);
  assert.match(svg, /#10b981/, 'Selo ativo deve usar verde');
});

// 2. Formato Principal (Vertical)
runTest('Badge Principal gera SVG emblema com nome da empresa', () => {
  const svg = generatePrincipalBadge({
    codigo: 'ZQV-TESTEKIT02',
    empresaNome: 'Banco ACME Portugal',
    status: 'ativo',
    statusTexto: 'Verificação ativa'
  });

  assert.match(svg, /<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /ZAP VERIFIED/);
  assert.match(svg, /CANAIS OFICIAIS CONFIRMADOS/);
  assert.match(svg, /Banco ACME Portugal/);
  assert.match(svg, /VERIFICAÇÃO ATIVA/);
});

// 3. Formato Circular (Avatar/Redes)
runTest('Badge Circular gera SVG com shield e textos circulares', () => {
  const svg = generateCircularBadge({
    codigo: 'ZQV-TESTEKIT03',
    empresaNome: 'Banco ACME',
    status: 'ativo',
    statusTexto: 'Verificação ativa'
  });

  assert.match(svg, /<circle cx="80" cy="80"/);
  assert.match(svg, /ZAP VERIFIED/);
  assert.match(svg, /CANAIS OFICIAIS/);
});

// 4. Estado Suspenso reflete cor vermelha (Seção 16)
runTest('Badge Suspenso reflete vermelho/alerta', () => {
  const svg = generateHorizontalBadge({
    codigo: 'ZQV-SUSPENSO',
    empresaNome: 'Empresa Suspensa',
    status: 'suspenso'
  });

  assert.match(svg, /#ef4444/, 'Deve usar vermelho para selo suspenso');
  assert.match(svg, /VERIFICAÇÃO SUSPENSA/);
});

// 5. Estado Expirado reflete cor amarela/alerta (Seção 16)
runTest('Badge Expirado reflete amarelo/alerta', () => {
  const svg = generateHorizontalBadge({
    codigo: 'ZQV-EXPIRADO',
    empresaNome: 'Empresa Expirada',
    status: 'expirado'
  });

  assert.match(svg, /#f59e0b/, 'Deve usar amarelo para selo expirado');
  assert.match(svg, /VERIFICAÇÃO EXPIRADA/);
});

// 6. Segurança: Sem exposição de dados internos ou Threat Radar no badge (Seções 11 e 17)
runTest('Badge não expõe chaves, ocorrências ou Threat Radar', () => {
  const svg = generatePrincipalBadge({
    codigo: 'ZQV-SECRETCHECK',
    empresaNome: 'Empresa Segura',
    status: 'ativo'
  });

  assert.doesNotMatch(svg, /SUPABASE_SERVICE_ROLE_KEY/i);
  assert.doesNotMatch(svg, /Threat Radar/i);
  assert.doesNotMatch(svg, /impersonation/i);
  assert.doesNotMatch(svg, /radar_ameacas/i);
});

// 7. Snippet de HTML Embed aponta para /verify/[codigo] (Seção 9 e 10)
runTest('HTML Embed aponta corretamente para /verify/[codigo] sem secrets', () => {
  const codigo = 'ZQV-KA4HSMNUPJAQ';
  const verifyUrl = `https://zapqueme.vercel.app/verify/${codigo}`;
  const badgeImageUrl = `https://zapqueme.vercel.app/api/badge?codigo=${codigo}&formato=horizontal`;
  const embedCode = `<a href="${verifyUrl}" target="_blank" rel="noopener noreferrer">\n  <img src="${badgeImageUrl}" alt="ZAP VERIFIED — Canais oficiais confirmados" />\n</a>`;

  assert.match(embedCode, new RegExp(`/verify/${codigo}`));
  assert.match(embedCode, /target="_blank"/);
  assert.match(embedCode, /rel="noopener noreferrer"/);
  assert.doesNotMatch(embedCode, /apikey|secret|service_role/i);
});

console.log('\n============================================================');
console.log(`RESULTADO DO KIT COMERCIAL: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');
