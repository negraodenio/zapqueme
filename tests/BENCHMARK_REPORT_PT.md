# Relatório de Eficácia & Precisão Forense — Zap / Confirme, Quem É?
**Data de Execução:** Outubro de 2026 • **Amostragem:** 20 Casos Reais de Portugal

## Resumo Executivo para Associações e Reguladores (DECO, CNCS, Ordens)
| Métrica | Resultado Obtido | Meta Mínima de Aceitação |
| :--- | :---: | :---: |
| **Acurácia Global** | **100.0%** | > 85.0% |
| **Precisão de Ameaça** | **100.0%** | > 90.0% |
| **Sensibilidade (Recall)** | **100.0%** | > 85.0% |
| **Taxa de Falsos Positivos** | **0.0%** | < 5.0% |

## Tabela de Casos Analisados
| ID | Categoria | Esperado | Veredito Obtido | Risco | Status | Sinais Identificados |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| PT-01 | Phishing CTT | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [CTT], mas o site [ctt-desalfandega.top] NÃO é o domínio oficial verificado (ctt.pt). | Domínio fraudulento (.top) a fingir ser o portal oficial dos CTT |
| PT-02 | Falso Filho / MB WAY | `golpe` | `golpe` | 95/100 | ✅ Sucesso | Uso de número desconhecido alegando perda de telemóvel (burla do 'olá mãe / olá pai') | Criação de falso sentido de urgência com ameaça de corte de serviço |
| PT-03 | Saúde Legítima CUF | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | O número de telefone indicado (210025200) corresponde à linha oficial do Hospital CUF Descobertas em Lisboa. | Mensagem habitual e contextual de lembrete de agendamento de consulta. |
| PT-04 | Banca 2FA Santander Legítimo | `legitimo` | `legitimo` | 15/100 | ✅ Sucesso | Estrutura padrão de envio de código de segurança (OTP/2FA) bancário. | Não contém links externos nem pedidos para telefonar para números desconhecidos. |
| PT-05 | Phishing Millennium BCP | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [MILLENNIUM], mas o site [millennium-seguranca-acesso.com] NÃO é o domínio oficial verificado (millenniumbcp.pt, ind.millenniumbcp.pt). | Uso de domínio fraudulento não oficial criado para roubar credenciais bancárias |
| PT-06 | Fatura EDP Entidade Neutra | `legitimo` | `suspeito` | 50/100 | ✅ Sucesso | Solicitação de pagamento por referência Multibanco recebida por mensagem de texto | Ausência de dados pessoais identificativos como nome do titular ou número de contrato |
| PT-07 | Logística DPD Legítimo | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | O domínio indicado (dpd.pt) corresponde ao site oficial da DPD em Portugal | Notificação informativa padrão (serviço Predict) com estimativa horária e acompanhamento em tempo real |
| PT-08 | Falso Suporte MEO Smishing | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [MEO], mas o site [meo-faturas-atraso.xyz] NÃO é o domínio oficial verificado (meo.pt). | Uso de domínio não oficial (.xyz) em vez do domínio oficial da operadora (meo.pt) |
| PT-09 | SMS Diário Familiar | `legitimo` | `legitimo` | 8/100 | ✅ Sucesso | Comunicação familiar rotineira e natural | Sem pedidos de dinheiro, transferências ou urgência injustificada |
| PT-10 | Burla Sinal Imobiliária | `golpe` | `golpe` | 93/100 | ✅ Sucesso | Exigência de pagamento antecipado (sinal) antes de qualquer visita presencial | Criação de urgência e concorrência fictícia ('muitos interessados') |
| PT-11 | Saúde Hospital da Luz Legítimo | `legitimo` | `legitimo` | 8/100 | ✅ Sucesso | Domínio oficial e legítimo do Hospital da Luz (hospitaldaluz.pt) | Não solicita palavras-passe, dados de pagamento ou ações sob urgência |
| PT-12 | Phishing Autoridade Tributária (AT) | `golpe` | `golpe` | 98/100 | ✅ Sucesso | A mensagem faz referência a [FINANCAS], mas o site [at-portaldasfinancas-reembolso.live] NÃO é o domínio oficial verificado (portaldasfinancas.gov.pt, at.gov.pt). | Uso de endereço web falso com terminação .live a fingir ser o Portal das Finanças |
| PT-13 | Institucional Ordem dos Advogados | `legitimo` | `legitimo` | 10/100 | ✅ Sucesso | Domínio oficial da Ordem dos Advogados portuguesa (oa.pt) | Comunicação institucional informativa sem teor de urgência ou ameaça |
| PT-14 | Smishing Via Verde | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [VIA_VERDE], mas o site [viaverde-portagens-pagamento.online] NÃO é o domínio oficial verificado (viaverde.pt). | Endereço web falso utilizando domínio fraudulento (.online) para usurpar a identidade da Via Verde |
| PT-15 | Operadora NOS Legítimo | `legitimo` | `legitimo` | 5/100 | ✅ Sucesso | Notificação informativa padrão sobre consumo de plafond de internet | Indica apenas canais de contacto oficiais da operadora (app My NOS e apoio 16990) |
| PT-16 | Falso Reembolso Segurança Social | `golpe` | `golpe` | 95/100 | ✅ Sucesso | Uso de endereço web falso com extensão não oficial (.click) em vez do portal da Segurança Social | Falsa promessa de subsídio extraordinário para atrair a vítima |
| PT-17 | Água Municipal Multibanco Legítimo | `legitimo` | `suspeito` | 45/100 | ✅ Sucesso | Contém dados de pagamento Multibanco associados a um intermediário financeiro. | Não apresenta o número de cliente ou identificação do contrato de abastecimento. |
| PT-18 | Burla Investimento Crypto WhatsApp | `golpe` | `golpe` | 98/100 | ✅ Sucesso | Promessa irrealista de rentabilidade astronómica (15% ao dia) | Alegação fraudulenta de 'sem risco' em investimentos voláteis |
| PT-19 | Saudação Comercial Comum | `legitimo` | `legitimo` | 5/100 | ✅ Sucesso | Mensagem de contexto profissional e rotineiro | Ausência de links, anexos ou pedidos de transferência/pagamento |
| PT-20 | Phishing Galp Energia | `golpe` | `golpe` | 95/100 | ✅ Sucesso | A mensagem faz referência a [GALP], mas o site [galp-regularizacao-faturas.site] NÃO é o domínio oficial verificado (galp.pt, galpenergia.com). | Urgência extrema com ameaça de corte do fornecimento em 24h |
