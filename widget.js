/**
 * Zap, quem é? — Selo de Verificação & Confiança para E-commerce (B2B)
 * Versão: 1.0.0
 * Uso: <script src="https://zapqueme.vercel.app/widget.js" data-empresa="SEU_SLUG" async></script>
 */
(function() {
  if (window.__ZAPQUEME_WIDGET_LOADED__) return;
  window.__ZAPQUEME_WIDGET_LOADED__ = true;

  const currentScript = document.currentScript || (function() {
    const scripts = document.getElementsByTagName('script');
    for (let i = scripts.length - 1; i >= 0; i--) {
      if (scripts[i].src && scripts[i].src.indexOf('widget.js') !== -1) return scripts[i];
    }
    return null;
  })();

  const empresaSlug = currentScript ? (currentScript.getAttribute('data-empresa') || '').trim() : '';
  const position = currentScript ? (currentScript.getAttribute('data-position') || 'bottom-right').trim() : 'bottom-right';
  const customHost = currentScript && currentScript.src ? new URL(currentScript.src).origin : 'https://zapqueme.vercel.app';

  if (!empresaSlug) {
    console.warn('[Zap, quem é?] data-empresa não configurado no script.');
    return;
  }

  // Buscar status da empresa
  fetch(`${customHost}/api/empresa?slug=${encodeURIComponent(empresaSlug)}`)
    .then(res => {
      if (!res.ok) throw new Error('Não verificado');
      return res.json();
    })
    .then(data => {
      if (!data || data.status !== 'ativo') return;
      renderWidget(data);
    })
    .catch(err => {
      // Falha silenciosa para não quebrar a loja do cliente
      console.debug('[Zap, quem é?] Verificação de selo:', err.message);
    });

  function renderWidget(empresa) {
    // Injetar estilos
    const style = document.createElement('style');
    style.innerHTML = `
      .zq-badge-container {
        position: fixed;
        z-index: 999990;
        bottom: 20px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        box-sizing: border-box;
      }
      .zq-badge-container * {
        box-sizing: border-box;
      }
      .zq-badge-container.zq-pos-bottom-right {
        right: 20px;
      }
      .zq-badge-container.zq-pos-bottom-left {
        left: 20px;
      }
      .zq-badge-link {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid rgba(16, 185, 129, 0.4);
        padding: 7px 12px;
        border-radius: 9999px;
        text-decoration: none;
        box-shadow: 0 4px 14px rgba(0,0,0,0.25), 0 0 10px rgba(16, 185, 129, 0.15);
        cursor: pointer;
        transition: all 0.2s ease-in-out;
      }
      .zq-badge-link:hover {
        background: #1e293b;
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.35), 0 0 15px rgba(16, 185, 129, 0.3);
        border-color: rgba(16, 185, 129, 0.8);
      }
      .zq-badge-shield {
        width: 18px;
        height: 18px;
        fill: none;
        stroke: #10b981;
        stroke-width: 2.2;
        stroke-linecap: round;
        stroke-linejoin: round;
        flex-shrink: 0;
      }
      .zq-badge-content {
        display: flex;
        flex-direction: column;
        line-height: 1.1;
      }
      .zq-badge-title {
        font-size: 11px;
        font-weight: 700;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 4px;
      }
      .zq-badge-title span {
        color: #10b981;
      }
      .zq-badge-sub {
        font-size: 9px;
        color: #94a3b8;
        font-weight: 500;
      }
      .zq-badge-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 6px #10b981;
        display: inline-block;
        animation: zq-pulse 2s infinite;
      }
      @keyframes zq-pulse {
        0% { opacity: 0.6; transform: scale(0.9); }
        50% { opacity: 1; transform: scale(1.15); }
        100% { opacity: 0.6; transform: scale(0.9); }
      }
      @media (max-width: 480px) {
        .zq-badge-container {
          bottom: 12px;
        }
        .zq-badge-container.zq-pos-bottom-right {
          right: 12px;
        }
        .zq-badge-container.zq-pos-bottom-left {
          left: 12px;
        }
      }
    `;
    document.head.appendChild(style);

    // Criar elemento
    const container = document.createElement('div');
    container.className = `zq-badge-container zq-pos-${position}`;

    const verifyUrl = `${customHost}/verificar.html?empresa=${encodeURIComponent(empresa.slug)}`;

    container.innerHTML = `
      <a href="${verifyUrl}" target="_blank" rel="noopener noreferrer" class="zq-badge-link" title="Selo Oficial de Segurança Zap, quem é?">
        <svg class="zq-badge-shield" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
        <div class="zq-badge-content">
          <div class="zq-badge-title">
            Loja Verificada <span class="zq-badge-dot"></span>
          </div>
          <div class="zq-badge-sub">Zap, quem é? Seguro</div>
        </div>
      </a>
    `;

    // Se o cliente colocou um div com id="zapqueme-selo", renderizar inline também
    const inlineContainer = document.getElementById('zapqueme-selo');
    if (inlineContainer) {
      inlineContainer.innerHTML = container.innerHTML;
    } else {
      document.body.appendChild(container);
    }
  }
})();
