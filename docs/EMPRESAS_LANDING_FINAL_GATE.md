# B2B LANDING PAGE FINAL GATE — AUDITORIA DE PRONTIDÃO
**Data:** 2026-10-20  
**Ficheiro Auditado:** `empresas.html`  
**Destino Comercial:** Mercado Português (PMEs e E-commerces)  
**Marca:** Confirme, Quem É? (`confirmequeme.pt`)  
**Modo:** READ-ONLY / AUDITORIA PRÉ-DEPLOY  

---

## 1. Resumo Executivo

A landing page B2B (`empresas.html`) foi inspecionada minuciosamente após as alterações de higienização cultural e remoção de termos e moedas brasileiras (R$, Pix, DDD). 

A auditoria comprovou que:
- O formulário preserva integralmente os IDs, nomes de campos e integração assíncrona com `/api/empresa?action=lead`.
- O payload gerado pelo cliente envia rigorosamente os valores internos esperados pelo backend (`start`, `pro`, `enterprise`).
- Todos os preços visíveis na página estão em euros (€) com a tabela provisória de **29€**, **49€** e **290€**.
- Não existem credenciais expostas no código do cliente nem vulnerabilidades evidentes de injeção XSS no tratamento de respostas.
- Existem, no entanto, **divergências de preços entre páginas** e **afirmações comerciais estatísticas sem evidência empírica interna** que exigem atenção antes de ações agressivas de marketing.

---

## 2. Testes Realizados e Resultados

| Teste / Verificação | Âmbito | Resultado | Detalhe |
| :--- | :--- | :--- | :--- |
| **Integridade do DOM do Formulário** | Elementos HTML | ✅ **APROVADO** | IDs `#leadForm`, `#leadNome`, `#leadEmpresa`, `#leadEmail`, `#leadWhatsApp`, `#leadWebsite`, `#leadPlano`, `#btnLeadSubmit`, `#leadFeedback` presentes e íntegros. |
| **Compatibilidade do Endpoint de Leads** | Contrato de API | ✅ **APROVADO** | Endpoint acionado é `/api/empresa?action=lead` via `POST` com cabeçalho `Content-Type: application/json`. |
| **Suites de Regressão do CRM e Selos** | `tests/admin_crm.test.js` | ✅ **27/27 PASS** | Trava dos 4 pilares, geração de selos ZQV, IOCs e Threat Radar operacionais. |
| **Suites de Segurança e Dados de Teste** | `tests/admin_security.test.js` | ✅ **13/13 PASS** | Proteção de endpoints com 401, isolamento de entidades de teste e exigência de justificativa. |
| **Suites de Correções de Pré-Produção** | `tests/preproduction_fixes.test.js` | ✅ **7/7 PASS** | Validação de query parameters obrigatórios em `api/empresa.js` e métodos HTTP. |
| **Rastreio de Moeda e Termos Residuais** | Busca Textual Estrita | ✅ **0 ENCONTRADOS** | Zero ocorrências de `R$`, `Pix`, `DDD`, `reais` ou do termo legado `Zap` em `empresas.html`. |

---

## 3. Compatibilidade com a API

A função `handleLeadSubmit` em `empresas.html` recolhe e submete o seguinte objeto:
```javascript
const payload = {
  nome: document.getElementById('leadNome').value,
  empresa: document.getElementById('leadEmpresa').value,
  email: document.getElementById('leadEmail').value,
  whatsapp: document.getElementById('leadWhatsApp').value,
  website: document.getElementById('leadWebsite').value,
  plano_interesse: document.getElementById('leadPlano').value
};
```

Em `api/empresa.js` (linhas 117-175):
- Os campos obrigatórios validados são `!nome || !empresa || !email`. O formulário possui os três inputs com atributo HTML `required`.
- O campo `plano_interesse` aceita os valores do `<select>`:
  - `start` -> Plano Start (29€/mês)
  - `pro` -> Plano Pro (49€/mês)
  - `enterprise` -> Plano Enterprise (290€/mês)
- **Persistência Dupla:** Se o Supabase estiver online, o lead é inserido na tabela `leads`. Em paralelo ou como redundância, o lead é enfileirado na lista Redis `zapqueme:leads`.
- **Tratamento de Sucesso:** A interface exibe a mensagem de sucesso e limpa o formulário (`leadForm.reset()`). O botão é desabilitado durante o envio (`btn.disabled = true`) para prevenir duplo clique.
- **Tratamento de Erro:** `feedback.textContent = 'Erro ao enviar: ' + err.message` utiliza `textContent`, prevenindo qualquer vetor de injeção XSS vindo da mensagem de erro da API.

---

## 4. Auditoria de Preços e Divergências Comerciais

Identificou-se que diferentes páginas do projeto apresentam estruturas de preços não harmonizadas:

| Página / Documento | Ficheiro | Preço Entrada (Start) | Preço Intermédio (Pro) | Preço Alto / Intel | Moeda |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Landing Page B2B** | `empresas.html` | **29€ / mês** | **49€ / mês** | **290€ / mês** | Euros (€) |
| **Simulador de Receita Admin** | `admin.html` | — | **39€ / mês** (Verified) | **700€ / mês** (Threat Intel) | Euros (€) |
| **Pitch Deck Executivo** | `pitch.html` | **19€ / mês** | **49€ / mês** | **299€ / 990€ / 3.500€** | Euros (€) |
| **Plano de Negócio 2026** | `plano-negocio.html` | **29€ - 49€ / mês** | **490€ - 990€ / mês** | **2.500€ - 5.000€ / mês** | Euros (€) |

### Recomendação de Fonte Única da Verdade:
Fixar oficialmente a tabela da Landing Page B2B para o produto **Verified PME** (29€ Start / 49€ Pro) e adotar os escalões de 290€ (Starter B2B) e 700€–990€ (Threat Intel Avançado) como grelha comercial definitiva em todos os documentos.

---

## 5. Afirmações Comerciais e Evidência no Projeto

| Afirmação na Landing Page | Linha em `empresas.html` | Evidência no Código / Projeto | Recomendação |
| :--- | :--- | :--- | :--- |
| *"84% dos consumidores desistem de fechar compra por medo de golpe ou site clonado."* | L. 570 | ⚠️ **Sem evidência interna.** Trata-se de estatística de mercado externa genérica sem fonte ou estudo citado. | Suavizar para: *"Estudos de mercado indicam que a grande maioria dos consumidores hesita em comprar em lojas sem validação de autenticidade."* ou citar estudo específico (ex: Eurostat/DECO). |
| *"+23% de aumento na confiança e conversão no checkout"* | L. 581-582 | ⚠️ **Sem evidência empírica interna.** Não há testes A/B nem telemetria de conversão implementada no projeto. | Ajustar para: *"Maior conversão no checkout ao transmitir confiança e validação em tempo real."* |
| *"Instalação < 2 min com 1 linha de código (Shopify, Nuvemshop, WooCommerce)"* | L. 585-587 | ✅ **Verificada.** O script `widget.js` e os badges SVG gerados em `/badge/:codigo` são inseríveis via tag `<script>` ou `<img>`. | Manter. |
| *"Monitorização 24/7 de tentativas de clonagem no WhatsApp, SMS e MB WAY"* | L. 588-592 | ✅ **Verificada.** O `lib/radar.js` extrai IOCs e deteta surtos automaticamente a partir das mensagens recebidas. | Manter. |
| *"Radar Anti-Clonagem / Alertas em tempo real"* | L. 699-700 | ✅ **Verificada.** O módulo Threat Radar e as rotinas de agregação catalogam impersonations por marca. | Manter. |

---

## 6. Auditoria de UX, Localização e Segurança

1. **Localização e Idioma:**
   - Tag `<html lang="pt-PT">` configurada.
   - Textos adaptados para terminologia portuguesa: *"burlas"* em vez de *"golpes"*, *"equipa"* em vez de *"equipe"*, *"contacto"* em vez de *"contato"*, *"telemóvel"* em vez de *"celular"*.
2. **Contactos Telefónicos:**
   - Todos os links para WhatsApp apontam para o número nacional português: `https://wa.me/351927618142`.
3. **Links e Destinos:**
   - Âncoras internas funcionais (`#como-funciona`, `#radar`, `#planos`, `#contato`).
   - Links institucionais preservados (`/`, `/admin.html`, `/termos`, `/privacidade`, `/verificar.html?empresa=lojaprotegida`).
4. **Segurança (XSS e Segredos):**
   - Não há chaves secretas ou tokens de API hardcoded em `empresas.html`.
   - `leadFeedback` utiliza `textContent` para mensagens de erro originadas do servidor.
   - O formulário usa método `POST` com cabeçalho JSON estruturado.

---

## 7. Alterações Recomendadas (Não Bloqueantes para Testes, Recomendadas para Go-Live)

1. **Suavização das Estatísticas Não Comprovadas:** Substituir os valores absolutos *"84%"* e *"+23%"* por formulações institucionais de valor acrescentado ou referenciar o estudo específico da DECO Proteste / CNCS.
2. **Harmonização do Simulador Admin:** Ajustar o simulador em `admin.html` para refletir os valores de 29€ e 49€ nos sliders.
3. **Adição de Validação Regex no Input de Telemóvel:** No input `#leadWhatsApp`, adicionar opcionalmente `pattern="^(\+351)?[9][1236][0-9]{7}$"` para guiar utilizadores portugueses a preencher o telemóvel no formato correto.

---

## 8. Decisão Final

# 🟢 READY FOR DEPLOY (COM RESSALVAS COMERCIAIS)

* **Prontidão Técnica:** **100% APROVADO.** O formulário, os endpoints, as suites de regressão do CRM, a segurança de inputs e a eliminação de termos brasileiros estão perfeitamente consolidados.
* **Ação Bloqueada:** Nenhum commit ou deploy foi realizado nesta intervenção, em cumprimento rigoroso da regra de auditoria READ-ONLY. O código local está pronto para ser enviado assim que houver autorização explícita.
