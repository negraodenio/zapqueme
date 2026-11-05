# Estado da landing empresarial — revisão de 5 de novembro de 2026

Este documento substitui o gate anterior de 20 de outubro. A decisão anterior “READY FOR DEPLOY / 100% aprovado” era uma conclusão de snapshot e não deve ser usada como aprovação atual: incluía afirmações sem suporte sobre conversão, monitorização 24/7, Radar em tempo real e integração com feeds; também citava testes que não foram executados nesta revisão.

## Estado observado nesta cópia local

- A página descreve a oferta como consulta de canais submetidos para revisão manual e identifica os dados ilustrativos como fictícios.
- O preço de €49/mês está assinalado como indicativo. O formulário não cria subscrição nem pagamento.
- A página declara que não há monitorização de redes móveis, API em lote, feed SOC, bloqueio de pagamentos ou pedidos automáticos de remoção.
- O pedido empresarial tem campos limitados, honeypot e rate limit no backend. O lead é guardado num destino primário e o Redis serve como contingência, sem duplicação deliberada.
- A página e os documentos legais foram alterados apenas na cópia de trabalho. Nenhum deploy foi feito.

## Antes de publicar

1. Confirmar a configuração das variáveis de ambiente e o comportamento no ambiente de produção.
2. Rever endereço do responsável, prestadores, modalidade de IA, retenção e condições comerciais.
3. Confirmar procedimento de revisão e autorização para publicar dados empresariais.
4. Fazer validação visual, de acessibilidade, dos formulários e da navegação no domínio publicado.

Esta é uma revisão estática, não uma aprovação legal, teste de produção ou garantia de prontidão comercial.
