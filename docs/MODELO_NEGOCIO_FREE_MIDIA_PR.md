# 🎯 ZAP, QUEM É? — MANUAL PRÁTICO DE MONETIZAÇÃO 2026
## Objetivo único: 3 clientes pagantes, sem prometer mais do que o produto entrega

> **Regra para a engenharia / Antigravity:** O código B2C e a infraestrutura atual estão **congelados**. Não construir portais, logins ou sistemas corporativos. A energia agora é comercial. Exceções só para lacunas que impeçam cumprir o que se vende (ver secção 3).

---

## 1. O QUE É O PRODUTO

* **O verificador gratuito (site + WhatsApp)** é o canal de distribuição e de recolha de sinais. Não é o negócio.
* **Volume sem qualidade não paga contas.** Poucas denúncias reais e verificáveis com o nome de uma empresa valem mais do que milhares de consultas soltas.
* **O que a empresa compra:** um contacto oficial verificado que os clientes conseguem confirmar, e (para quem já sofreu imitação) acompanhamento dos casos.
* **O que o selo NÃO faz:** não impede burlas. Ajuda o cliente a confirmar se está a falar com o contacto oficial. Isto já está escrito na página `/verify` e deve ser dito também na venda.

---

## 2. AS 2 OFERTAS

| | **Oferta A — Zap Verified** | **Oferta B — Acompanhamento de Imitações** |
| :-- | :-- | :-- |
| **Preço [HIPÓTESE]** | €49/mês, sem fidelização | €290/mês |
| **Para quem** | Clínicas, imobiliárias, advogados, PMEs | **Só** empresas onde já existe evidência real de imitação no Radar |
| **Entrega** | Página pública `/verify/CODIGO` com os contactos oficiais (após verificação), selo para site/redes, texto-modelo para a equipa enviar aos clientes | Tudo da Oferta A + revisão periódica do Radar à procura do nome da empresa + aviso por WhatsApp/e-mail quando surgir um caso + resumo mensal |
| **Como funciona hoje** | Emissão manual no `admin.html` | **Manual**: o fundador revê o painel e avisa à mão. Sem tempo de resposta garantido. Viável para 1–2 clientes. |

* **Nunca vender a Oferta B a frio.** Só a quem já viu evidência concreta.
* **Plano anual (€490/ano)** só é oferecido **depois** de o cliente ter dito sim ao mensal.

---

## 3. CHECKLIST ANTES DO PRIMEIRO PAYMENT LINK

| # | Item | Estado |
| :-- | :-- | :-- |
| 1 | **Atividade aberta nas Finanças** e capacidade de emitir fatura (IVA tratado) | ⬜ Fazer antes de cobrar |
| 2 | **Procedimento de verificação** documentado: NIF (portal das Finanças / certidão), site/domínio, número oficial, cédula na Ordem (advogados) | ⬜ Manual, registar evidência por empresa |
| 3 | **Página curta de Termos do Selo**: o que é, o que não é, limitação de responsabilidade, cancelamento | ⬜ Não existe ainda |
| 4 | **Política de privacidade** visível no site (RGPD) | ⬜ Não existe ainda |
| 5 | **Stripe Payment Link** ou IBAN/MB WAY da atividade | ⬜ |
| 6 | **Campo IBAN oficial na página `/verify`** (necessário para o script de imobiliárias) | ⚠️ **Não suportado no código atual** — não prometer IBAN até ser adicionado |

> [!NOTE]
> Hoje a tabela `empresas` **não guarda NIF nem IBAN**. A verificação do NIF pode ser feita manualmente (guardar print/nota fora do sistema). Exibir o IBAN na página pública exige uma pequena alteração de código.

---

## 4. SCRIPTS DE ABORDAGEM (PT-PT)

**Regras para todos:**
* Trechos entre **[colchetes]** só entram se forem verdade. Cada **[N]** tem de vir do painel, com data. Se não conseguir mostrar a evidência quando pedirem, remova a frase.
* Proibido: "certeza absoluta", "auditado", "paga sem medo", escassez falsa ("estamos a selecionar 5...").

### 4.1 Alerta gratuito (empresas que apareceram no Radar) — **o contacto mais forte**

> Olá [Nome], sou [Nome], do Zap, Quem É?, uma ferramenta gratuita de verificação de mensagens suspeitas.
>
> Recebemos [N] denúncias esta semana de mensagens que se faziam passar por [empresa], com [descrição: pedido de pagamento por MB WAY, link falso, etc.]. Não vendo nada com este aviso: preparei um resumo com exemplos, sem dados pessoais das vítimas, para poderem avisar os vossos clientes e, se quiserem, reportar às autoridades. Posso enviar?

Se responderem: enviar o resumo e **esperar uns dias** antes de falar do selo. Depois: *"Como continuamos a detetar casos, criámos o Zap Verified…"*

### 4.2 Clínicas

> Olá [Nome], tudo bem? Sou [Nome], do Zap, Quem É?, uma ferramenta gratuita onde as pessoas verificam mensagens suspeitas.
>
> Muitas clínicas estão a ser imitadas em burlas por WhatsApp e MB WAY, com falsas cobranças a pacientes. [Esta semana vimos [N] casos com o nome da vossa clínica.]
>
> Criámos o Zap Verified: uma página pública com o contacto oficial da clínica (verificamos o NIF e o número antes de emitir) e um texto-modelo para a vossa equipa enviar aos pacientes ao confirmar marcações. Assim o paciente consegue confirmar que está mesmo a falar convosco.
>
> Custa €49/mês, sem fidelização. Posso preparar a página da vossa clínica para verem como fica, sem compromisso?

### 4.3 Imobiliárias

> Olá [Nome], tudo bem? Sou [Nome], do Zap, Quem É?, uma ferramenta gratuita onde as pessoas verificam mensagens e números suspeitos.
>
> No setor imobiliário, as burlas mais comuns são pedidos de sinal ou reserva por MB WAY ou transferência a quem diz representar a agência, e anúncios copiados com o contacto trocado. [Esta semana detetámos [N] casos com o nome da vossa agência.] / [Sem casos: "É um risco que afeta qualquer agência com anúncios online."]
>
> Criámos o Zap Verified: uma página pública com os contactos [e o IBAN — só após suporte no código] oficiais da agência (verificamos o NIF e os dados antes de emitir) e um texto-modelo para os vossos consultores enviarem aos clientes antes de qualquer pagamento.
>
> Custa €49/mês, sem fidelização. Posso preparar a página da vossa agência para verem como fica, sem compromisso?

*Gancho:* o risco concreto é o cliente pagar um sinal à pessoa errada.

### 4.4 Advogados

> Olá Dr./Dra. [Nome], tudo bem? Sou [Nome], do Zap, Quem É?, uma ferramenta gratuita onde as pessoas verificam mensagens suspeitas.
>
> Há burlas em que alguém se faz passar por escritórios de advogados para pedir honorários, custas ou "taxas urgentes" por MB WAY ou transferência. [Detetámos [N] casos com o nome de escritórios na última semana.] / [Sem casos: "É um risco crescente para quem comunica com clientes por WhatsApp."]
>
> O Zap Verified dá ao escritório uma página pública com os contactos oficiais (verificamos o NIF e a cédula antes de emitir) e um texto-modelo para incluir nas comunicações com clientes. O serviço não acede a nenhuma comunicação do escritório.
>
> Custa €49/mês, sem fidelização. Posso preparar a página do escritório para verem como fica, sem compromisso?

*Cuidado:* nunca mencionar clientes nem processos.

---

## 5. RISCOS E REGRAS DE CONDUTA

1. **Baileys (WhatsApp não oficial):** risco real de banimento do número. O **site é o canal principal** em toda a comunicação; o WhatsApp é complementar. Plano B antes de crescer: WhatsApp Business API oficial.
2. **Sem extorsão:** o alerta é sempre gratuito e nunca condicionado à compra.
3. **Sem acusações:** uma denúncia é um sinal, não uma prova. Não atribuir culpa a pessoas nem afirmar campanhas contra marcas sem evidência.
4. **RGPD:** nunca mostrar dados de vítimas/denunciantes. Hash não equivale a anonimização. Revisão jurídica profissional antes de escalar.
5. **Responsabilidade:** os Termos do Selo devem deixar claro que o selo não garante a inexistência de burlas.

---

## 6. METAS

| Meta | Composição | Receita mensal | Anualizado* |
| :-- | :-- | :-- | :-- |
| **Validação** | 3 Selos | €147 | €1.764 |
| **Tração** | 10 Selos + 1 Acompanhamento | €780 | €9.360 |
| **Independência** | 30 Selos + 2 Acompanhamento | €2.050 | €24.600 |

\* Pressupõe 12 meses de retenção. Antes de impostos, comissões (~2,5%) e horas de operação. Pagar a infraestrutura ≠ ponto de equilíbrio do negócio.

**Medir desde o primeiro contacto:** contactados → respostas → páginas de demonstração → pagantes; horas gastas por cliente; cancelamentos.

---

## 7. DIRETIVA PARA O ANTIGRAVITY

* **Código:** estável e congelado.
* **Alterações permitidas:** apenas as do checklist (secção 3): página de Termos, política de privacidade, campo IBAN/NIF se necessário à venda.
* **Foco:** apoiar contactos comerciais e o registo das primeiras empresas.
