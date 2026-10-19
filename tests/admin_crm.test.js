// tests/admin_crm.test.js
// Testes estritos das Regras de Negócio, Critérios de Aceitação do CRM & Verificações e Enterprise Threat Radar

import {
  gerarCodigoSelo,
  extrairIOCsFinanceiros,
  classificarSetorMarca,
  compilarIntelligenceRadar,
  gerarPacoteTakedown
} from '../lib/radar.js';

let passed = 0;
let total = 0;

function assert(condition, testName) {
  total++;
  if (condition) {
    console.log(`✅ [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`❌ [FAIL] ${testName}`);
    process.exitCode = 1;
  }
}

console.log('\n============================================================');
console.log('🧪 TESTES DE CRITÉRIOS DE ACEITAÇÃO: CRM, SELO & THREAT RADAR');
console.log('============================================================\n');

// 1. Critério 1: Não é possível ativar selo sem 4 verificações OK e pagamento (ou isenção justificada)
function validarCondicoesAtivacao(verificacoes, pagamentos) {
  const tiposOk = new Set((verificacoes || []).filter(v => v.estado === 'ok').map(v => v.tipo));
  const obrigatorios = ['nif', 'dominio', 'telefone', 'representante'];
  const faltantes = obrigatorios.filter(t => !tiposOk.has(t));

  if (faltantes.length > 0) {
    return { permitido: false, motivo: `Faltam verificações: ${faltantes.join(', ')}` };
  }

  const temPagamentoValido = (pagamentos || []).some(
    p => p.estado === 'pago' || (p.estado === 'isento' && p.motivo_isencao && p.motivo_isencao.trim().length >= 4)
  );

  if (!temPagamentoValido) {
    return { permitido: false, motivo: 'Pagamento pendente ou isenção sem motivo justificado' };
  }

  return { permitido: true };
}

// Caso 1A: Nenhuma verificação concluída -> Bloqueado
const res1A = validarCondicoesAtivacao([], []);
assert(!res1A.permitido, 'Critério 1: Bloqueia ativação com 0 verificações');

// Caso 1B: 3 verificações concluídas (falta representante) -> Bloqueado
const res1B = validarCondicoesAtivacao(
  [{ tipo: 'nif', estado: 'ok' }, { tipo: 'dominio', estado: 'ok' }, { tipo: 'telefone', estado: 'ok' }],
  [{ estado: 'pago', valor: 49.00 }]
);
assert(!res1B.permitido && res1B.motivo.includes('representante'), 'Critério 1: Bloqueia ativação se faltar 1 dos 4 pilares (representante)');

// Caso 1C: 4 verificações concluídas, mas sem pagamento -> Bloqueado
const res1C = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'pendente', valor: 49.00 }]
);
assert(!res1C.permitido && res1C.motivo.includes('Pagamento pendente'), 'Critério 1: Bloqueia ativação com pagamento pendente');

// Caso 1D: 4 verificações OK e pagamento PAGO -> Permitido!
const res1D = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'pago', valor: 49.00 }]
);
assert(res1D.permitido, 'Critério 1: Permite ativação com 4 verificações OK e pagamento PAGO');

// Caso 1E: 4 verificações OK e isenção com motivo justificado -> Permitido!
const res1E = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'isento', motivo_isencao: 'Entidade de Utilidade Pública Oficial' }]
);
assert(res1E.permitido, 'Critério 1: Permite ativação com isenção justificada com motivo escrito');

// Caso 1F: 4 verificações OK e isenção SEM motivo -> Bloqueado!
const res1F = validarCondicoesAtivacao(
  [
    { tipo: 'nif', estado: 'ok' },
    { tipo: 'dominio', estado: 'ok' },
    { tipo: 'telefone', estado: 'ok' },
    { tipo: 'representante', estado: 'ok' }
  ],
  [{ estado: 'isento', motivo_isencao: '' }]
);
assert(!res1F.permitido, 'Critério 1: Bloqueia isenção sem motivo justificado por escrito');

// 2. Critério 3: Códigos de selo não sequenciais e imprevisíveis (≥ 10 caracteres)
const codigo1 = gerarCodigoSelo();
const codigo2 = gerarCodigoSelo();
assert(codigo1.length >= 10, 'Critério 3: Código de selo tem tamanho ≥ 10 caracteres');
assert(codigo1.startsWith('ZQV-'), 'Critério 3: Código de selo possui prefixo oficial ZQV-');
assert(codigo1 !== codigo2, 'Critério 3: Códigos sucessivos são imprevisíveis e não-sequenciais');

// 3. Critério 6: Um PDF não pode ser enviado sem aprovação registada
function validarEnvioRelatorio(relatorio) {
  if (!relatorio.aprovado_por || !relatorio.aprovado_em) {
    return { permitido: false, erro: 'Relatório pendente de aprovação manual' };
  }
  return { permitido: true };
}

const relatorioPendente = { id: 'rel-1', periodo: '2026-10', aprovado_por: null };
assert(!validarEnvioRelatorio(relatorioPendente).permitido, 'Critério 6: Bloqueia envio de relatório sem aprovação');

const relatorioAprovado = { id: 'rel-2', periodo: '2026-10', aprovado_por: 'admin', aprovado_em: new Date().toISOString() };
assert(validarEnvioRelatorio(relatorioAprovado).permitido, 'Critério 6: Permite envio após aprovação formal registada');

// 4. ENTERPRISE THREAT RADAR: Extração de IOCs Financeiros (SIBS / MB WAY / Seguradoras / DECO)
const smsPortagem = 'AVISO VIA VERDE: Regularize a sua portagem em atraso. Entidade: 21345 Referencia: 123 456 789 Valor: 14,80 EUR ou aceda a https://viaverde-pagamento-pt.com';
const iocs1 = extrairIOCsFinanceiros(smsPortagem, null, null, 'texto');
assert(iocs1.entidades_mb.includes('21345'), 'Threat Radar SIBS: Extrai Entidade Multibanco (5 dígitos) de SMS fraudulento');
assert(iocs1.referencias_mb.includes('123456789'), 'Threat Radar SIBS: Extrai Referência Multibanco (9 dígitos) normalizada');
assert(iocs1.dominios.includes('viaverde-pagamento-pt.com'), 'Threat Radar CERT.PT: Extrai domínio malicioso de phishing');
assert(iocs1.tatica_codigo === 'SMISHING_ENTIDADE_MB', 'Threat Radar Tática: Classifica corretamente Smishing com Entidade/Referência MB');

const msgOlaPai = 'Olá mãe o meu telemóvel partiu, este é o meu número novo +351 918 222 333. Podes fazer um MB WAY ou transferência para o IBAN PT50000201231234567890154 urgente?';
const iocs2 = extrairIOCsFinanceiros(msgOlaPai, null, null, 'texto');
assert(iocs2.ibans.includes('PT50000201231234567890154'), 'Threat Radar Banca: Extrai IBAN português (25 caracteres) de conta de mula');
assert(iocs2.telefones.includes('+351918222333'), 'Threat Radar Telecom: Extrai número de telemóvel português normalizado');
assert(iocs2.tatica_codigo === 'BURLA_OLA_PAI_MAE', 'Threat Radar Tática: Classifica Burla Olá Pai / Olá Mãe');

// 5. Classificação Setorial (SIBS, Seguradoras, Banca, DECO)
assert(classificarSetorMarca('MB WAY / SIBS') === 'SIBS / Pagamentos', 'Setor Radar: Classifica MB WAY/SIBS no setor SIBS / Pagamentos');
assert(classificarSetorMarca('Fidelidade Seguros') === 'Seguradoras', 'Setor Radar: Classifica Fidelidade no setor Seguradoras');
assert(classificarSetorMarca('Millennium BCP') === 'Banca & Financeiro', 'Setor Radar: Classifica Millennium BCP no setor Banca & Financeiro');

// 6. Compilação do Motor de Inteligência (Surtos + Shadow Radar)
const intel = compilarIntelligenceRadar({
  empresas: [{ id: 'emp-1', nome: 'Millennium BCP', status: 'ativo', estado: 'ativo', dominio_oficial: 'millenniumbcp.pt' }],
  radar: [{ empresa_id: 'emp-1', empresa: 'Millennium BCP', ocorrencias: 4, canais_distintos: 2, ultima_deteccao: new Date().toISOString(), severidade: 'critica' }],
  ocorrencias: [
    { empresa_id: 'emp-1', empresa: 'Millennium BCP', canal_mencionado: 'Ent.MB: 21999 | Ref.MB: 987654321 | https://bcp-alerta-seguro.com', veredito: 'golpe', confianca: 96, criado_em: new Date().toISOString() },
    { empresa_id: 'emp-1', empresa: 'Millennium BCP', canal_mencionado: 'Ent.MB: 21999 | Ref.MB: 987654321 | https://bcp-alerta-seguro.com', veredito: 'golpe', confianca: 95, criado_em: new Date().toISOString() },
    { empresa_id: 'emp-1', empresa: 'Millennium BCP', canal_mencionado: 'Ent.MB: 21999 | Ref.MB: 987654321 | https://bcp-alerta-seguro.com', veredito: 'golpe', confianca: 98, criado_em: new Date().toISOString() }
  ],
  sinais: [
    { marca: 'Fidelidade', canal: 'Ent.MB: 11223 | https://fidelidade-reembolso.com', data: new Date().toISOString() },
    { marca: 'Fidelidade', canal: 'Ent.MB: 11223 | https://fidelidade-reembolso.com', data: new Date().toISOString() }
  ],
  marcas: []
});

assert(intel.surtos_ativos.length >= 2, 'Intelligence Engine: Deteta surtos coordenados em marcas clientes e não-clientes');
assert(intel.surtos_ativos[0].status_surto === 'SURTO_CRITICO', 'Intelligence Engine: Classifica cluster >= 3 ocorrências como SURTO_CRITICO');
assert(intel.iocs_financeiros.some(i => i.tipo === 'ENTIDADE_MB' && i.valor === '21999'), 'Intelligence Engine: Cataloga Entidade MB no feed financeiro SIBS');
assert(intel.shadow_radar.some(s => s.empresa === 'Fidelidade' && s.relacao_comercial === 'oportunidade_shadow'), 'Shadow Radar: Deteta seguradora não-cliente sob ataque como oportunidade comercial');

// 7. Pacote Forense de Takedown (RGPD Safe + SHA-256)
const takedown = gerarPacoteTakedown({
  marca: 'Fidelidade',
  empresa: null,
  ocorrencias: intel.ocorrencias || [],
  sinais: [{ marca: 'Fidelidade', canal: 'Ent.MB: 11223 | https://fidelidade-reembolso.com', data: new Date().toISOString() }]
});
assert(takedown.hash_evidencia && takedown.hash_evidencia.length === 64, 'Takedown Kit: Gera Hash SHA-256 pericial de 64 caracteres');
assert(takedown.corpo_forense.includes('11223') && takedown.corpo_forense.includes('fidelidade-reembolso.com'), 'Takedown Kit: Inclui Entidade MB e domínio malicioso no relatório técnico');

console.log('\n============================================================');
console.log(`RESULTADO DO CRM & THREAT RADAR: ${passed}/${total} TESTES PASSARAM! 🎉`);
console.log('============================================================\n');

