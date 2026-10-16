// scripts/generate_mobile_preview.js
import fs from 'fs';
import path from 'path';
import { buildDataContract, renderWhatsAppResponse } from '../lib/renderer.js';

const testCases = [
  {
    category: '1. MB WAY Vendedor OLX / Multibanco',
    parsed: {
      veredito: 'golpe',
      risco_score: 95,
      sinais: ['Tentativa de manipular a vítima para ir ao multibanco associar número']
    },
    text: 'Quero comprar o artigo no OLX. Vá a uma caixa Multibanco, selecione outras operações e coloque o meu número.'
  },
  {
    category: '2. Falso Apoio Bancário por Telefone',
    parsed: {
      veredito: 'golpe',
      risco_score: 90,
      sinais: ['Alerta de segurança forjado para induzir chamada telefónica']
    },
    text: 'Alerta de segurança: cartão bloqueado por suspeita de fraude. Ligue já para 912345678.'
  },
  {
    category: '3. Falsa Notificação Policial / Judicial',
    parsed: {
      veredito: 'golpe',
      risco_score: 95,
      sinais: ['Ameaça de prisão da Polícia Judiciária para cobrança de multa']
    },
    text: 'Polícia Judiciária e Europol: mandado de detenção iminente por infração na internet. Pague a caução de 500€.'
  },
  {
    category: '4. Criptomoedas / Lucro Garantido',
    parsed: {
      veredito: 'golpe',
      risco_score: 92,
      sinais: ['Promessa irreal de retorno financeiro diário']
    },
    text: 'Ganhe 500 euros por dia com retornos garantidos no nosso canal VIP de criptomoedas'
  }
];

function formatWhatsAppTextToHtml(rawText) {
  // Converte formatação WhatsApp (*bold*, _italic_) para HTML
  return rawText
    .split('\n')
    .map(line => {
      let l = line
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\*(.*?)\*/g, '<strong>$1</strong>')
        .replace(/_(.*?)_/g, '<em>$1</em>');
      return l;
    })
    .join('<br>');
}

const cardsHtml = testCases.map(tc => {
  const contract = buildDataContract(tc.parsed, tc.text);
  const rendered = renderWhatsAppResponse(contract);
  const formattedHtml = formatWhatsAppTextToHtml(rendered);
  const charLen = rendered.length;
  const lineCount = rendered.split('\n').filter(l => l.trim().length > 0).length;

  return `
    <div class="phone-wrapper">
      <div class="phone-label">${tc.category}</div>
      <div class="phone-meta">Tamanho: <strong>${charLen} chars</strong> | Linhas de conteúdo: <strong>${lineCount}</strong> | Veredito: <strong>${contract.level.toUpperCase()}</strong></div>
      <div class="phone-mockup">
        <div class="phone-notch"></div>
        <div class="wa-header">
          <div class="wa-back">‹</div>
          <div class="wa-avatar">🛡️</div>
          <div class="wa-contact">
            <div class="wa-name">Zap, quem é?</div>
            <div class="wa-status">online</div>
          </div>
        </div>
        <div class="wa-chat-area">
          <div class="wa-date-pill">HOJE</div>
          <div class="wa-bubble-in">
            <div class="wa-bubble-text">${formattedHtml}</div>
            <div class="wa-time">10:45</div>
          </div>
        </div>
        <div class="wa-input-bar">
          <div class="wa-input-placeholder">Mensagem</div>
        </div>
      </div>
    </div>
  `;
}).join('\n');

const fullHtml = `<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <title>Simulação Telemóvel Real — WhatsApp (Confirme, Quem É?)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0f172a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #f8fafc;
      padding: 30px 20px;
    }
    h1 { text-align: center; font-size: 24px; margin-bottom: 8px; color: #38bdf8; }
    p.subtitle { text-align: center; font-size: 14px; color: #94a3b8; margin-bottom: 30px; }
    
    .grid {
      display: flex;
      flex-wrap: wrap;
      gap: 30px;
      justify-content: center;
      max-width: 1600px;
      margin: 0 auto;
    }
    .phone-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .phone-label {
      font-weight: 700;
      font-size: 15px;
      color: #38bdf8;
      margin-bottom: 4px;
      text-align: center;
    }
    .phone-meta {
      font-size: 12px;
      color: #94a3b8;
      margin-bottom: 12px;
    }
    .phone-mockup {
      width: 375px;
      height: 720px;
      background: #efeae2;
      border: 10px solid #1e293b;
      border-radius: 40px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
      position: relative;
    }
    .phone-notch {
      position: absolute;
      top: 0;
      left: 50%;
      transform: translateX(-50%);
      width: 140px;
      height: 20px;
      background: #1e293b;
      border-bottom-left-radius: 14px;
      border-bottom-right-radius: 14px;
      z-index: 10;
    }
    .wa-header {
      background: #008069;
      color: #fff;
      padding: 26px 12px 10px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .wa-back { font-size: 22px; cursor: pointer; }
    .wa-avatar {
      width: 36px;
      height: 36px;
      background: #fff;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
    }
    .wa-name { font-size: 15px; font-weight: 600; }
    .wa-status { font-size: 11px; opacity: 0.85; }
    
    .wa-chat-area {
      flex: 1;
      padding: 12px;
      overflow-y: hidden;
      background-image: radial-gradient(#d1d7db 1px, transparent 1px);
      background-size: 16px 16px;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
    }
    .wa-date-pill {
      align-self: center;
      background: #ffffff;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      color: #54656f;
      margin-bottom: 12px;
      box-shadow: 0 1px 1px rgba(0,0,0,0.1);
      text-transform: uppercase;
      font-weight: 500;
    }
    .wa-bubble-in {
      align-self: flex-start;
      background: #ffffff;
      padding: 9px 12px 20px 12px;
      border-radius: 10px;
      border-top-left-radius: 0;
      max-width: 96%;
      box-shadow: 0 1px 1.5px rgba(11,20,26,0.13);
      position: relative;
      font-size: 13.6px;
      line-height: 18px;
      color: #111b21;
    }
    .wa-bubble-text strong {
      color: #0b141a;
      font-weight: 700;
    }
    .wa-bubble-text em {
      color: #667781;
      font-size: 12px;
      line-height: 16px;
      display: inline-block;
      margin-top: 2px;
    }
    .wa-time {
      position: absolute;
      right: 8px;
      bottom: 4px;
      font-size: 10.5px;
      color: #667781;
    }
    .wa-input-bar {
      background: #f0f2f5;
      padding: 10px 14px;
      display: flex;
      align-items: center;
    }
    .wa-input-placeholder {
      background: #fff;
      border-radius: 20px;
      padding: 8px 14px;
      font-size: 14px;
      color: #8696a0;
      width: 100%;
    }
  </style>
</head>
<body>
  <h1>📱 Validação Visual em Ecrã de Telemóvel Real (375 × 720 px)</h1>
  <p class="subtitle">Demonstração das 4 novas categorias — Comprovativo de ausência de corte "Ler mais" e adaptação ao ecrã</p>
  <div class="grid">
    ${cardsHtml}
  </div>
</body>
</html>`;

const outPath = path.resolve('tests/mobile_preview.html');
fs.writeFileSync(outPath, fullHtml, 'utf8');
console.log('✅ Visual mobile simulator generated at:', outPath);
