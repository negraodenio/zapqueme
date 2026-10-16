# Relatório de Eficácia & Precisão Forense — Zap / Confirme, Quem É?
**Data de Execução:** Outubro de 2026 • **Amostragem:** 20 Casos Reais de Portugal

## Resumo Executivo para Associações e Reguladores (DECO, CNCS, Ordens)
| Métrica | Resultado Obtido | Meta Mínima de Aceitação |
| :--- | :---: | :---: |
| **Acurácia Global** | **95.0%** | > 85.0% |
| **Precisão de Ameaça** | **90.9%** | > 90.0% |
| **Sensibilidade (Recall)** | **100.0%** | > 85.0% |
| **Taxa de Falsos Positivos** | **10.0%** | < 5.0% |

## Tabela de Casos Analisados
| ID | Categoria | Esperado | Veredito Obtido | Risco | Status | Sinais Identificados |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| PT-01 | Phishing CTT | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [CTT], mas o site [ctt-desalfandega.top] NÃO é o domínio oficial verificado (ctt.pt). | Link suspeito que não pertence ao domínio oficial dos CTT (ctt.pt) |
| PT-02 | Falso Filho / MB WAY | `golpe` | `golpe` | 95/100 | ✅ Sucesso | Pretexto clássico de telemóvel avariado ou perdido e uso de número provisório | Urgência fabricada com ameaça de cancelamento ou corte de serviço |
| PT-03 | Saúde Legítima CUF | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | Mensagem puramente informativa sem links externos ou suspeitos | Ausência de pedidos de dinheiro, transferências ou dados bancários |
| PT-04 | Banca 2FA Santander Legítimo | `legitimo` | `legitimo` | 15/100 | ✅ Sucesso | Estrutura padrão de código de autenticação única (OTP) para autorização de transação. | Ausência de links externos, números de retorno suspeitos ou pedidos de dados pessoais. |
| PT-05 | Phishing Millennium BCP | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [MILLENNIUM], mas o site [millennium-seguranca-acesso.com] NÃO é o domínio oficial verificado (millenniumbcp.pt, ind.millenniumbcp.pt). | Criação de falso sentido de urgência com bloqueio do cartão |
| PT-06 | Fatura EDP Entidade Neutra | `legitimo` | `suspeito` | 65/100 | ❌ Falha | Abordagem com características atípicas | Recomendada checagem antes de compartilhar dados |
| PT-07 | Logística DPD Legítimo | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | O endereço indicado pertence ao domínio oficial da transportadora (dpd.pt) | Mensagem meramente informativa de acompanhamento sem pedidos de pagamento de taxas ou dados bancários |
| PT-08 | Falso Suporte MEO Smishing | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [MEO], mas o site [meo-faturas-atraso.xyz] NÃO é o domínio oficial verificado (meo.pt). | Utilização de domínio falso e suspeito (.xyz) em vez do site oficial da MEO |
| PT-09 | SMS Diário Familiar | `legitimo` | `legitimo` | 8/100 | ✅ Sucesso | Comunicação pessoal e natural do quotidiano | Ausência de pedidos de dinheiro, transferências ou dados pessoais |
| PT-10 | Burla Sinal Imobiliária | `golpe` | `suspeito` | 65/100 | ✅ Sucesso | Abordagem com características atípicas | Recomendada checagem antes de compartilhar dados |
| PT-11 | Saúde Hospital da Luz Legítimo | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | Uso do domínio oficial e legítimo da instituição de saúde | Mensagem meramente informativa sem pressão psicológica ou urgência |
| PT-12 | Phishing Autoridade Tributária (AT) | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [FINANCAS], mas o site [at-portaldasfinancas-reembolso.live] NÃO é o domínio oficial verificado (portaldasfinancas.gov.pt, at.gov.pt). | Uso de endereço web falso (at-portaldasfinancas-reembolso.live) em vez do domínio governamental legítimo (portaldasfinancas.gov.pt). |
| PT-13 | Institucional Ordem dos Advogados | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | Domínio oficial da Ordem dos Advogados de Portugal (oa.pt) | Comunicação puramente informativa sem caráter de urgência ou ameaça |
| PT-14 | Smishing Via Verde | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [VIA_VERDE], mas o site [viaverde-portagens-pagamento.online] NÃO é o domínio oficial verificado (viaverde.pt). | Uso de endereço web fraudulento que tenta imitar a marca oficial |
| PT-15 | Operadora NOS Legítimo | `legitimo` | `legitimo` | 8/100 | ✅ Sucesso | Mensagem meramente informativa sem hiperligações externas | Ausência de pedidos de pagamento ou dados confidenciais |
| PT-16 | Falso Reembolso Segurança Social | `golpe` | `golpe` | 95/100 | ✅ Sucesso | Endereço de website não oficial (.click em vez do portal oficial seg-social.pt) | Criação de falso sentido de urgência ('antes que expire') |
| PT-17 | Água Municipal Multibanco Legítimo | `legitimo` | `legitimo` | 15/100 | ✅ Sucesso | Formato padrão de aviso de cobrança de serviços municipais | Ausência de links externos suspeitos ou pedidos de dados confidenciais |
| PT-18 | Burla Investimento Crypto WhatsApp | `golpe` | `golpe` | 98/100 | ✅ Sucesso | Promessa de lucro garantido de 15% ao dia sem risco, o que é financeiramente impossível | Pressão para depósito imediato com promessa de retorno no próprio dia |
| PT-19 | Saudação Comercial Comum | `legitimo` | `legitimo` | 5/100 | ✅ Sucesso | Ausência de links ou pedidos de transferência | Comunicação direta sem tom de urgência ou ameaça |
| PT-20 | Phishing Galp Energia | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [GALP], mas o site [galp-regularizacao-faturas.site] NÃO é o domínio oficial verificado (galp.pt, galpenergia.com). | Uso de endereço web falso (galp-regularizacao-faturas.site) alheio ao domínio oficial da Galp |
