# Guia Prático: Recolha, Anonimização e Validação Cega de Mensagens
**Objetivo:** Obter 50 a 100 mensagens reais em Portugal para construir uma base de benchmark estatisticamente independente e defensável perante a DECO e Ordens Profissionais.

---

### 1. Onde Obter Amostras Reais

#### A. Tentativas de Burla (Golpes) — Recolha de 25 a 40 casos:
1. **Comunicações da PSP e GNR:** Avisos públicos de campanhas ativas de smishing partilhados nas páginas oficiais das forças de segurança.
2. **Alertas do CERT.PT / CNCS:** Boletins de ameaças de phishing em Portugal.
3. **Rede Pessoal (Amigos, Família, Colegas):** Mensagens recentes de falso filho por WhatsApp, SMS de falsas portagens da Via Verde, encomendas alfandegárias de CTT e faturas simuladas.

#### B. Comunicações Legítimas — Recolha de 25 a 60 casos:
1. **Saúde:** Lembretes autênticos de consultas (CUF, Hospital da Luz, Trofa, SNS24, clínicas locais).
2. **Banca e Pagamentos:** Notificações de segurança 2FA/OTP (Santander, CGD, Millennium, ActivoBank, MB WAY legítimo).
3. **Logística:** Mensagens reais de entrega da DPD, CTT Expresso, DHL com links oficiais de tracking.
4. **Utilities & Serviços:** Avisos de fatura da EDP, Galp, Endesa, SMAS com referências Multibanco autênticas.
5. **Telecomunicações:** Avisos de consumo de dados móveis de MEO, NOS, Vodafone.
6. **Mensagens Banais:** Conversas informais do quotidiano sem teor comercial.

---

### 2. Checklist Obrigatória de Anonimização (Conformidade RGPD)

Antes de colar qualquer mensagem na **Coluna D** do [template_benchmark_100_amostras.csv](file:///c:/Users/denio/Documents/Denio/Zapqueme/files%20(11)/template_benchmark_100_amostras.csv):

| Dado Sensível | O que fazer | Exemplo |
| :--- | :--- | :--- |
| **Nome da Vítima** | Substituir por `[Nome]` | *"Olá Maria"* ➔ *"Olá [Nome]"* |
| **Número Particular** | Substituir por `[Telemóvel]` | *"ligue para 912345678"* ➔ *"ligue para [Telemóvel]"* |
| **NIF / Contribuinte** | Substituir por `[NIF]` | *"NIF 123456789"* ➔ *"[NIF]"* |
| **IBAN Pessoal** | Substituir por `[IBAN]` | *"PT50 0035..."* ➔ *"[IBAN]"* |
| **Morada / Código Postal** | Substituir por `[Morada]` | *"Rua das Flores 12"* ➔ *"[Morada]"* |
| **Linhas Oficiais Úteis** | **MANTER** (ex: 210025200, 16990, 808...) | São úteis para contexto. |
| **Links e Domínios** | **MANTER EXATAMENTE IGUAL** | O motor precisa da URL para verificar no RDAP, Google e DNS. |

---

### 3. Minuta de Pedido de Colaboração (Copiar e Enviar no WhatsApp)

Envie esta mensagem para 10 a 15 amigos ou colegas para recolher casos reais em 24 horas:

> *"Olá! Estou a realizar um estudo técnico independente sobre a prevalência e tipos de mensagens fraudulentas (burlas de MB WAY, SMS de encomendas e faturas falsas) que circulam em Portugal.*  
>  
> *Podes reencaminhar-me (ou mandar print de) 2 ou 3 SMS/mensagens suspeitas que tenhas recebido recentemente, e também 1 ou 2 notificações legítimas normais (ex: lembrete de consulta médica ou aviso de entrega)?*  
>  
> *Todos os nomes, telemóveis e dados pessoais são imediatamente apagados e anonimizados para efeitos de estudo de segurança. Muito obrigado pela ajuda!"*

---

### 4. Como Executar a Validação Cega (Passo a Passo)

1. **Passo 1 (Recolha):** Cole as mensagens anonimizadas na Coluna D do caderno.
2. **Passo 2 (Classificação Cega):** Peça a uma pessoa que **não participou no desenvolvimento** (ex: colega, familiar ou auditor) para ler cada mensagem e preencher:
   * Coluna E: `Golpe` ou `Legítimo` (ground truth).
   * Coluna F: O seu nome próprio real (ex: *"Mariana Silva"*).
   * Coluna G: A data e hora exata em que fez a classificação (ex: *"2026-10-16 11:30"*).
3. **Passo 3 (Execução do Sistema):** Só após a folha estar classificada e guardada é que o motor corre o teste (via `node tests/benchmark_exporter.js`).
4. **Passo 4 (Resultados):** O sistema regista a `Data do Teste`, o `Modelo Usado (Runtime)`, a `Origem Real do Veredito` e calcula as métricas com o Intervalo de Confiança de Wilson (95%).
