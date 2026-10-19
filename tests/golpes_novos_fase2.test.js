// tests/golpes_novos_fase2.test.js
// Testes automáticos de aceitação — Módulo de Acompanhamento de Golpes Novos (Fase 2: Alertas Oficiais & Esquemas)
// Cobre:
// - Critério 3: Se o `robots.txt` de uma fonte proibir o caminho, o coletor NÃO faz o pedido à página e regista o motivo.
// - Secção 3.3: Não recolhe redes sociais, não silencia erros HTTP/rede e guarda apenas título, ligação e data (sem copiar conteúdo).
// - Secção 3.4: Biblioteca de esquemas escrita nas nossas palavras (com limpeza de PII) e exigência de revisão humana para ativar.

import assert from 'node:assert/strict';
import {
  avaliarRobotsTxt,
  verificarFonteAlertaOficial,
  criarOuAtualizarEsquema,
  reverAlertaOficial
} from '../lib/golpes_novos.js';

console.log('🧪 Iniciando Testes da Fase 2: Alertas Oficiais (robots.txt) e Biblioteca de Esquemas...\n');

// =========================================================================
// CRITÉRIO 3: Se o `robots.txt` proibir o caminho, o coletor NÃO faz o pedido e regista o motivo
// =========================================================================
{
  const urlsChamados = [];
  const mockFetchProibido = async (url) => {
    urlsChamados.push(url);
    if (url.endsWith('/robots.txt')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return `User-agent: *\nDisallow: /privado/\nDisallow: /alertas-internos/\nAllow: /publico/`;
        }
      };
    }
    // Se chegasse aqui seria uma violação do Critério 3
    return {
      ok: true,
      status: 200,
      async text() {
        return '<html><body><a href="/alertas-internos/1">Alerta Secreto</a></body></html>';
      }
    };
  };

  const fonteProibida = {
    id: 'fonte-robots-1',
    nome: 'Autoridade Teste Bloqueada',
    url: 'https://autoridade-exemplo.pt/alertas-internos/lista',
    tipo: 'autoridade',
    estado: 'ativa'
  };

  const resultado = await verificarFonteAlertaOficial(fonteProibida, { fetchFn: mockFetchProibido });

  assert.equal(resultado.ok, false, 'Deve recusar a recolha quando robots.txt proíbe o caminho');
  assert.equal(resultado.bloqueado_robots, true, 'Deve sinalizar bloqueado_robots = true');
  assert.equal(urlsChamados.length, 1, 'Deve ter consultado APENAS o /robots.txt e NUNCA a página proibida');
  assert.ok(urlsChamados[0].endsWith('/robots.txt'), 'O único pedido feito deve ser ao robots.txt');
  assert.ok(resultado.motivo && resultado.motivo.includes('robots.txt'), 'Deve registar o motivo explícito do bloqueio por robots.txt');
  assert.ok(resultado.fonteAtualizada.ultimo_erro.includes('robots.txt'), 'A fonte atualizada deve guardar o motivo em ultimo_erro');

  console.log('✅ Critério 3 validado: Quando o robots.txt proíbe o caminho, o coletor NÃO faz o pedido à página e regista o motivo.');
}

// =========================================================================
// SECÇÃO 3.3: Leitura permitida guarda APENAS título, ligação e data (sem copiar conteúdo do artigo)
// =========================================================================
{
  const mockFetchPermitido = async (url) => {
    if (url.endsWith('/robots.txt')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return `User-agent: *\nAllow: /noticias/`;
        }
      };
    }
    return {
      ok: true,
      status: 200,
      async text() {
        return `
          <html>
            <body>
              <article>
                <a href="/noticias/alerta-smishing-banca-2026">Alerta sobre nova campanha de smishing bancário em Portugal</a>
                <p>Texto longo do corpo da notícia com parágrafos protegidos por direitos de autor que NUNCA devem ser copiados nem republicados pelo sistema.</p>
              </article>
            </body>
          </html>
        `;
      }
    };
  };

  const fonteValida = {
    id: 'fonte-ok-1',
    nome: 'CERT.PT Teste',
    url: 'https://www.cncs.gov.pt/pt/noticias/',
    tipo: 'autoridade',
    ultimo_hash: null,
    estado: 'ativa'
  };

  const resOk = await verificarFonteAlertaOficial(fonteValida, { fetchFn: mockFetchPermitido });
  assert.equal(resOk.ok, true, 'Leitura permitida por robots.txt deve concluir com sucesso');
  assert.equal(resOk.novosAlertas.length, 1, 'Deve extrair 1 alerta oficial');

  const alerta = resOk.novosAlertas[0];
  assert.equal(alerta.titulo, 'Alerta sobre nova campanha de smishing bancário em Portugal');
  assert.equal(alerta.url, 'https://www.cncs.gov.pt/noticias/alerta-smishing-banca-2026');
  assert.ok(alerta.data_publicacao, 'Deve incluir data');
  assert.equal(alerta.conteudo, undefined, 'Nunca deve ter campo conteudo');
  assert.equal(alerta.texto, undefined, 'Nunca deve ter campo texto');
  assert.ok(!JSON.stringify(alerta).includes('direitos de autor'), 'Nunca copia o parágrafo do corpo da notícia');

  console.log('✅ Secção 3.3 (recolha mínima) validada: Guarda apenas título, ligação e data; nunca copia o corpo da notícia.');
}

// =========================================================================
// SECÇÃO 3.3: Erros de página nunca são silenciados e redes sociais são bloqueadas
// =========================================================================
{
  const mockFetchErro503 = async (url) => {
    if (url.endsWith('/robots.txt')) {
      return { ok: true, status: 200, async text() { return 'User-agent: *\nAllow: /'; } };
    }
    return { ok: false, status: 503, async text() { return 'Service Unavailable'; } };
  };

  const resErro = await verificarFonteAlertaOficial({
    id: 'fonte-erro-1',
    nome: 'Fonte Indisponível',
    url: 'https://autoridade-indisponivel.pt/alertas',
    tipo: 'autoridade'
  }, { fetchFn: mockFetchErro503 });

  assert.equal(resErro.ok, false, 'Falha HTTP 503 deve devolver ok = false');
  assert.equal(resErro.fonteAtualizada.estado, 'erro', 'Estado da fonte deve passar a "erro"');
  assert.ok(resErro.fonteAtualizada.ultimo_erro.includes('503'), 'Erro HTTP 503 deve ficar registado e nunca silenciado');

  // Teste de bloqueio de redes sociais
  const resRedeSocial = await verificarFonteAlertaOficial({
    id: 'fonte-social-1',
    nome: 'Página Facebook',
    url: 'https://www.facebook.com/policiajudiciaria',
    tipo: 'autoridade'
  });
  assert.equal(resRedeSocial.ok, false, 'Redes sociais devem ser recusadas');
  assert.ok(resRedeSocial.erro.includes('redes sociais proibida'), 'Deve registar que redes sociais são proibidas');

  console.log('✅ Secção 3.3 (erros e redes sociais) validada: Erros HTTP nunca são silenciados e redes sociais são bloqueadas.');
}

// =========================================================================
// SECÇÃO 3.4: Biblioteca de Esquemas e Revisão de Alertas Oficiais
// =========================================================================
{
  // Bloqueia ativação de esquema sem revisor humano
  assert.throws(() => {
    criarOuAtualizarEsquema({
      nome: 'Falsa portagem via SMS',
      descricao: 'SMS sobre pagamento de portagem em atraso com link externo.',
      estado: 'ativo',
      revisto_por: ''
    });
  }, /revisor humano/, 'Não permite criar esquema no estado "ativo" sem revisor humano');

  // Cria esquema válido e sanitiza eventual PII acidental
  const esquema = criarOuAtualizarEsquema({
    nome: 'Falsa portagem via SMS',
    descricao: 'SMS sobre pagamento de portagem em atraso (ex: telefone 912345678 removido) com referência MB.',
    canais: 'sms, whatsapp',
    marcas: 'Via Verde, Ascendi',
    sinais: 'valor baixo urgente, link não oficial',
    estado: 'ativo',
    origem: 'alerta',
    revisto_por: 'Denio'
  });

  assert.equal(esquema.estado, 'ativo');
  assert.equal(esquema.revisto_por, 'Denio');
  assert.ok(!esquema.descricao.includes('912345678'), 'Descrição do esquema também passa por sanitização de PII');

  const alertaRevisto = reverAlertaOficial({
    id: 'al-1',
    titulo: 'Aviso sobre falsas mensagens de portagens',
    url: 'https://www.cncs.gov.pt/pt/noticias/aviso-portagens',
    estado: 'novo'
  }, {
    estado: 'processado',
    revisor: 'Denio',
    notas: 'Coberto pelo esquema de falsa portagem',
    esquema_id: esquema.id
  });

  assert.equal(alertaRevisto.estado, 'processado');
  assert.equal(alertaRevisto.esquema_id, esquema.id);
  assert.equal(alertaRevisto.revisor, 'Denio');

  console.log('✅ Secção 3.4 validada: Biblioteca de esquemas exige revisão humana e associa-se aos alertas oficiais.');
}

console.log('\n🎉 TODOS OS TESTES DA FASE 2 (ALERTAS OFICIAIS & BIBLIOTECA DE ESQUEMAS) PASSARAM COM SUCESSO!');
