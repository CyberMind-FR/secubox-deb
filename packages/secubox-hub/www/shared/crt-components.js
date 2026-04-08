/**
 * ═══════════════════════════════════════════════════════════════
 *  SECUBOX COMPONENTS v2.0
 *  Based on Charte Graphique Six-Module Color System
 *  CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie
 * ═══════════════════════════════════════════════════════════════
 */

// ══════════════════════════════════════════════════════════════
//  DESIGN TOKEN HELPER
//  Gets computed CSS custom property values from document
// ══════════════════════════════════════════════════════════════
const getToken = (name, fallback) => {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
};

// 6-Module Color System fallbacks (in case design-tokens.css not loaded)
const TOKENS = {
  // Module colors
  authMain: '#C04E24',
  authLight: '#E8845A',
  authXlt: '#FAECE7',
  authDark: '#7A2A10',

  wallMain: '#9A6010',
  wallLight: '#CC8820',
  wallXlt: '#FDF3E0',
  wallDark: '#5A3808',

  bootMain: '#803018',
  bootLight: '#C06040',
  bootXlt: '#FAECE7',
  bootDark: '#5A1E0A',

  mindMain: '#3D35A0',
  mindLight: '#7068D0',
  mindXlt: '#EEEDFE',
  mindDark: '#241D6A',

  rootMain: '#0A5840',
  rootLight: '#148C66',
  rootXlt: '#E1F5EE',
  rootDark: '#063828',

  meshMain: '#104A88',
  meshLight: '#2C70C0',
  meshXlt: '#E6F1FB',
  meshDark: '#08305A',

  // Base colors
  bgDark: '#0A0E14',
  surfaceDark: '#141A24',
  borderDark: '#2A3444',
  textDark: '#E8E6E0',
  mutedDark: '#8A9AA8'
};

// ══════════════════════════════════════════════════════════════
//  TYPEWRITER ENGINE
// ══════════════════════════════════════════════════════════════
class CRTTypewriter {
  constructor(element, options = {}) {
    this.el = element;
    this.speed = options.speed || 40;
    this.delay = options.delay || 0;
    this.cursor = options.cursor !== false;
    this.onComplete = options.onComplete || (() => {});
  }

  async type(text) {
    this.el.textContent = '';
    if (this.cursor) this.el.classList.add('cursor');

    await this.wait(this.delay);

    for (const char of text) {
      this.el.textContent += char;
      await this.wait(this.speed);
    }

    if (this.cursor) {
      await this.wait(500);
      this.el.classList.remove('cursor');
    }

    this.onComplete();
  }

  wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ══════════════════════════════════════════════════════════════
//  SHARED STYLES (imported into all shadow DOMs)
// ══════════════════════════════════════════════════════════════
const sharedStyles = `
  /* Inherit design tokens from document */
  :host {
    --root-main: var(--root-main, ${TOKENS.rootMain});
    --root-light: var(--root-light, ${TOKENS.rootLight});
    --root-xlt: var(--root-xlt, ${TOKENS.rootXlt});
    --root-dark: var(--root-dark, ${TOKENS.rootDark});

    --wall-main: var(--wall-main, ${TOKENS.wallMain});
    --wall-light: var(--wall-light, ${TOKENS.wallLight});
    --wall-xlt: var(--wall-xlt, ${TOKENS.wallXlt});
    --wall-dark: var(--wall-dark, ${TOKENS.wallDark});

    --boot-main: var(--boot-main, ${TOKENS.bootMain});
    --boot-light: var(--boot-light, ${TOKENS.bootLight});
    --boot-xlt: var(--boot-xlt, ${TOKENS.bootXlt});
    --boot-dark: var(--boot-dark, ${TOKENS.bootDark});

    --mind-main: var(--mind-main, ${TOKENS.mindMain});
    --mind-light: var(--mind-light, ${TOKENS.mindLight});
    --mind-xlt: var(--mind-xlt, ${TOKENS.mindXlt});
    --mind-dark: var(--mind-dark, ${TOKENS.mindDark});

    --auth-main: var(--auth-main, ${TOKENS.authMain});
    --auth-light: var(--auth-light, ${TOKENS.authLight});
    --auth-xlt: var(--auth-xlt, ${TOKENS.authXlt});
    --auth-dark: var(--auth-dark, ${TOKENS.authDark});

    --mesh-main: var(--mesh-main, ${TOKENS.meshMain});
    --mesh-light: var(--mesh-light, ${TOKENS.meshLight});
    --mesh-xlt: var(--mesh-xlt, ${TOKENS.meshXlt});
    --mesh-dark: var(--mesh-dark, ${TOKENS.meshDark});

    --bg-dark: var(--bg-dark, ${TOKENS.bgDark});
    --surface-dark: var(--surface-dark, ${TOKENS.surfaceDark});
    --border-dark: var(--border-dark, ${TOKENS.borderDark});
    --text-dark: var(--text-dark, ${TOKENS.textDark});
    --muted-dark: var(--muted-dark, ${TOKENS.mutedDark});

    --font-mono: var(--font-mono, 'JetBrains Mono', monospace);
    --font-display: var(--font-display, 'Space Grotesk', sans-serif);
  }
`;

// ══════════════════════════════════════════════════════════════
//  CRT BUTTON COMPONENT
// ══════════════════════════════════════════════════════════════
class CRTButton extends HTMLElement {
  static get observedAttributes() {
    return ['variant', 'size', 'disabled', 'loading', 'module'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const variant = this.getAttribute('variant') || 'default';
    const module = this.getAttribute('module') || 'root';
    const size = this.getAttribute('size') || 'md';
    const disabled = this.hasAttribute('disabled');
    const loading = this.hasAttribute('loading');

    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display: inline-block; }

        button {
          font-family: var(--font-display);
          border: 1px solid var(--border-dark);
          background: var(--surface-dark);
          color: var(--text-dark);
          padding: ${size === 'sm' ? '0.25rem 0.5rem' : size === 'lg' ? '0.75rem 1.5rem' : '0.5rem 1rem'};
          font-size: ${size === 'sm' ? '0.75rem' : size === 'lg' ? '1rem' : '0.875rem'};
          letter-spacing: 0.05em;
          cursor: pointer;
          transition: all 0.2s ease;
          text-transform: uppercase;
          position: relative;
          overflow: hidden;
          border-radius: 6px;
        }

        button:hover:not(:disabled) {
          border-color: var(--root-main);
          color: var(--root-light);
          box-shadow: 0 0 12px rgba(20,140,102,0.15);
        }

        button:active:not(:disabled) {
          background: rgba(20,140,102,0.1);
        }

        button:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        /* Primary - ROOT green */
        button.primary {
          border-color: var(--root-main);
          background: rgba(20,140,102,0.15);
          color: var(--root-light);
        }
        button.primary:hover:not(:disabled) {
          background: rgba(20,140,102,0.25);
          box-shadow: 0 0 20px rgba(20,140,102,0.2);
        }

        /* Warning - WALL amber */
        button.amber, button.warning {
          border-color: var(--wall-main);
          color: var(--wall-light);
        }
        button.amber:hover:not(:disabled), button.warning:hover:not(:disabled) {
          background: rgba(204,136,32,0.15);
          box-shadow: 0 0 16px rgba(204,136,32,0.2);
        }

        /* Danger - BOOT red */
        button.danger {
          border-color: var(--boot-main);
          color: var(--boot-light);
        }
        button.danger:hover:not(:disabled) {
          background: rgba(192,96,64,0.15);
          box-shadow: 0 0 16px rgba(192,96,64,0.2);
        }

        /* Info - MESH blue */
        button.info {
          border-color: var(--mesh-main);
          color: var(--mesh-light);
        }
        button.info:hover:not(:disabled) {
          background: rgba(44,112,192,0.15);
          box-shadow: 0 0 16px rgba(44,112,192,0.2);
        }

        /* Mind - MIND violet */
        button.mind {
          border-color: var(--mind-main);
          color: var(--mind-light);
        }
        button.mind:hover:not(:disabled) {
          background: rgba(112,104,208,0.15);
          box-shadow: 0 0 16px rgba(112,104,208,0.2);
        }

        /* Auth - AUTH orange */
        button.auth {
          border-color: var(--auth-main);
          color: var(--auth-light);
        }
        button.auth:hover:not(:disabled) {
          background: rgba(232,132,90,0.15);
          box-shadow: 0 0 16px rgba(232,132,90,0.2);
        }

        /* Loading spinner */
        .spinner {
          display: ${loading ? 'inline-block' : 'none'};
          width: 12px;
          height: 12px;
          border: 2px solid transparent;
          border-top-color: currentColor;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
          margin-right: 0.5rem;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      </style>
      <button class="${variant}" ${disabled ? 'disabled' : ''}>
        <span class="spinner"></span>
        <slot></slot>
      </button>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT CARD COMPONENT
// ══════════════════════════════════════════════════════════════
class CRTCard extends HTMLElement {
  static get observedAttributes() {
    return ['variant', 'glow', 'module'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const variant = this.getAttribute('variant') || 'default';
    const module = this.getAttribute('module') || '';
    const glow = this.hasAttribute('glow');

    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display: block; }

        .card {
          background: var(--surface-dark);
          border: 1px solid var(--border-dark);
          padding: 1.25rem;
          border-radius: 14px;
          box-shadow: inset 0 0 20px rgba(0,0,0,0.3);
        }

        .card.lit {
          border-color: var(--root-dark);
          box-shadow: 0 0 8px rgba(20,140,102,0.1), inset 0 0 20px rgba(0,0,0,0.2);
        }

        .card.hot {
          border-color: var(--root-main);
          box-shadow: 0 0 12px rgba(20,140,102,0.15), 0 0 30px rgba(20,140,102,0.06), inset 0 0 20px rgba(0,0,0,0.2);
        }

        .card.glow {
          animation: pulse-glow 3s ease-in-out infinite;
        }

        /* Module-specific borders */
        .card.auth { border-left: 4px solid var(--auth-main); }
        .card.wall { border-left: 4px solid var(--wall-main); }
        .card.boot { border-left: 4px solid var(--boot-main); }
        .card.mind { border-left: 4px solid var(--mind-main); }
        .card.root { border-left: 4px solid var(--root-main); }
        .card.mesh { border-left: 4px solid var(--mesh-main); }

        @keyframes pulse-glow {
          0%, 100% { box-shadow: 0 0 8px rgba(20,140,102,0.08), inset 0 0 20px rgba(0,0,0,0.3); }
          50% { box-shadow: 0 0 16px rgba(20,140,102,0.15), inset 0 0 20px rgba(0,0,0,0.2); }
        }

        .header {
          font-size: 0.75rem;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--wall-light);
          margin-bottom: 1rem;
          padding-bottom: 0.5rem;
          border-bottom: 1px solid var(--border-dark);
          font-family: var(--font-mono);
        }

        .content {
          color: var(--text-dark);
        }

        .footer {
          margin-top: 1rem;
          padding-top: 0.5rem;
          border-top: 1px solid var(--border-dark);
        }
      </style>
      <div class="card ${variant} ${module} ${glow ? 'glow' : ''}">
        <div class="header"><slot name="header"></slot></div>
        <div class="content"><slot></slot></div>
        <div class="footer"><slot name="footer"></slot></div>
      </div>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT BADGE COMPONENT
// ══════════════════════════════════════════════════════════════
class CRTBadge extends HTMLElement {
  static get observedAttributes() {
    return ['variant', 'pulse', 'module'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const variant = this.getAttribute('variant') || 'default';
    const module = this.getAttribute('module') || '';
    const pulse = this.hasAttribute('pulse');

    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display: inline-block; }

        .badge {
          padding: 0.2rem 0.6rem;
          font-size: 0.7rem;
          font-family: var(--font-mono);
          letter-spacing: 0.1em;
          text-transform: uppercase;
          border-radius: 3px;
        }

        .badge.pulse {
          animation: badge-pulse 2s ease-in-out infinite;
        }

        /* Default - ROOT green */
        .badge.default, .badge.success {
          background: rgba(20,140,102,0.2);
          color: var(--root-light);
          border: 1px solid rgba(20,140,102,0.3);
        }

        /* Warning - WALL amber */
        .badge.amber, .badge.warning {
          background: rgba(204,136,32,0.2);
          color: var(--wall-light);
          border: 1px solid rgba(204,136,32,0.3);
        }

        /* Danger - BOOT red */
        .badge.danger, .badge.error {
          background: rgba(192,96,64,0.2);
          color: var(--boot-light);
          border: 1px solid rgba(192,96,64,0.3);
        }

        /* Info - MESH blue */
        .badge.info {
          background: rgba(44,112,192,0.2);
          color: var(--mesh-light);
          border: 1px solid rgba(44,112,192,0.3);
        }

        /* Mind - MIND violet */
        .badge.mind {
          background: rgba(112,104,208,0.2);
          color: var(--mind-light);
          border: 1px solid rgba(112,104,208,0.3);
        }

        /* Auth - AUTH orange */
        .badge.auth {
          background: rgba(232,132,90,0.2);
          color: var(--auth-light);
          border: 1px solid rgba(232,132,90,0.3);
        }

        /* Module-specific badges */
        .badge.root { background: var(--root-xlt); color: var(--root-dark); border: 1px solid var(--root-light); }
        .badge.wall-mod { background: var(--wall-xlt); color: var(--wall-dark); border: 1px solid var(--wall-light); }
        .badge.boot-mod { background: var(--boot-xlt); color: var(--boot-dark); border: 1px solid var(--boot-light); }
        .badge.mind-mod { background: var(--mind-xlt); color: var(--mind-dark); border: 1px solid var(--mind-light); }
        .badge.auth-mod { background: var(--auth-xlt); color: var(--auth-dark); border: 1px solid var(--auth-light); }
        .badge.mesh-mod { background: var(--mesh-xlt); color: var(--mesh-dark); border: 1px solid var(--mesh-light); }

        /* Dim */
        .badge.dim {
          background: rgba(20,140,102,0.08);
          color: var(--muted-dark);
          border: 1px solid var(--border-dark);
        }

        @keyframes badge-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      </style>
      <span class="badge ${variant} ${module} ${pulse ? 'pulse' : ''}"><slot></slot></span>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT PROGRESS BAR
// ══════════════════════════════════════════════════════════════
class CRTProgress extends HTMLElement {
  static get observedAttributes() {
    return ['value', 'max', 'variant', 'animated', 'module'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const value = parseFloat(this.getAttribute('value')) || 0;
    const max = parseFloat(this.getAttribute('max')) || 100;
    const variant = this.getAttribute('variant') || 'default';
    const animated = this.hasAttribute('animated');
    const percent = Math.min(100, (value / max) * 100);

    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display: block; }

        .track {
          background: rgba(20,140,102,0.08);
          border: 1px solid var(--border-dark);
          height: 12px;
          position: relative;
          overflow: hidden;
          border-radius: 6px;
        }

        .fill {
          height: 100%;
          width: ${percent}%;
          transition: width 0.8s ease;
          border-radius: 4px;
        }

        /* Default - ROOT green */
        .fill.default { background: var(--root-main); box-shadow: 0 0 8px rgba(20,140,102,0.4); }

        /* Warning - WALL amber */
        .fill.amber, .fill.warning { background: var(--wall-main); box-shadow: 0 0 8px rgba(204,136,32,0.4); }

        /* Danger - BOOT red */
        .fill.danger { background: var(--boot-main); box-shadow: 0 0 8px rgba(192,96,64,0.4); }

        /* Info - MESH blue */
        .fill.info { background: var(--mesh-main); box-shadow: 0 0 8px rgba(44,112,192,0.4); }

        /* Mind - MIND violet */
        .fill.mind { background: var(--mind-main); box-shadow: 0 0 8px rgba(112,104,208,0.4); }

        .fill.animated {
          animation: fill-scan 2s linear infinite;
          background-size: 200% 100%;
        }

        @keyframes fill-scan {
          0% { background-position: 100% 0; }
          100% { background-position: -100% 0; }
        }

        .label {
          position: absolute;
          right: 8px;
          top: 50%;
          transform: translateY(-50%);
          font-size: 0.6rem;
          font-family: var(--font-mono);
          color: var(--muted-dark);
          letter-spacing: 0.1em;
        }
      </style>
      <div class="track">
        <div class="fill ${variant} ${animated ? 'animated' : ''}"></div>
        <span class="label">${Math.round(percent)}%</span>
      </div>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT STAT CARD
// ══════════════════════════════════════════════════════════════
class CRTStat extends HTMLElement {
  static get observedAttributes() {
    return ['value', 'label', 'variant', 'icon', 'module'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const value = this.getAttribute('value') || '0';
    const label = this.getAttribute('label') || '';
    const variant = this.getAttribute('variant') || 'default';
    const icon = this.getAttribute('icon') || '';

    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display: block; }

        .stat {
          background: var(--surface-dark);
          border: 1px solid var(--border-dark);
          padding: 1rem;
          text-align: center;
          border-radius: 14px;
        }

        .icon {
          font-size: 1.5rem;
          margin-bottom: 0.5rem;
          filter: grayscale(0.3);
        }

        .value {
          font-size: 2rem;
          font-weight: bold;
          font-family: var(--font-mono);
          line-height: 1;
        }

        /* Default - ROOT green */
        .value.default { color: var(--root-light); text-shadow: 0 0 10px rgba(20,140,102,0.5); }

        /* Warning - WALL amber */
        .value.amber, .value.warning { color: var(--wall-light); text-shadow: 0 0 10px rgba(204,136,32,0.5); }

        /* Danger - BOOT red */
        .value.danger { color: var(--boot-light); text-shadow: 0 0 10px rgba(192,96,64,0.5); }

        /* Info - MESH blue */
        .value.info { color: var(--mesh-light); text-shadow: 0 0 10px rgba(44,112,192,0.5); }

        /* Mind - MIND violet */
        .value.mind { color: var(--mind-light); text-shadow: 0 0 10px rgba(112,104,208,0.5); }

        /* Auth - AUTH orange */
        .value.auth { color: var(--auth-light); text-shadow: 0 0 10px rgba(232,132,90,0.5); }

        /* Dim */
        .value.dim { color: var(--muted-dark); text-shadow: none; }

        .label {
          font-size: 0.7rem;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--muted-dark);
          margin-top: 0.5rem;
          font-family: var(--font-mono);
        }
      </style>
      <div class="stat">
        ${icon ? `<div class="icon">${icon}</div>` : ''}
        <div class="value ${variant}">${value}</div>
        <div class="label">${label}</div>
      </div>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT MODAL
// ══════════════════════════════════════════════════════════════
class CRTModal extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
    this.shadowRoot.querySelector('.backdrop').addEventListener('click', (e) => {
      if (e.target.classList.contains('backdrop')) this.close();
    });
  }

  open() {
    this.setAttribute('open', '');
  }

  close() {
    this.removeAttribute('open');
    this.dispatchEvent(new CustomEvent('close'));
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host {
          display: none;
        }

        :host([open]) {
          display: block;
        }

        .backdrop {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.85);
          z-index: 10000;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }

        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        .modal {
          background: var(--surface-dark);
          border: 1px solid var(--root-dark);
          box-shadow: 0 0 30px rgba(20,140,102,0.1), inset 0 0 30px rgba(0,0,0,0.3);
          max-width: 90vw;
          max-height: 90vh;
          overflow: auto;
          animation: modal-in 0.3s ease;
          border-radius: 14px;
        }

        @keyframes modal-in {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }

        .header {
          padding: 1rem 1.5rem;
          border-bottom: 1px solid var(--border-dark);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .title {
          font-size: 0.85rem;
          letter-spacing: 0.1em;
          text-transform: uppercase;
          color: var(--wall-light);
          font-family: var(--font-mono);
        }

        .close {
          background: none;
          border: 1px solid var(--border-dark);
          color: var(--muted-dark);
          width: 28px;
          height: 28px;
          cursor: pointer;
          font-family: monospace;
          font-size: 1rem;
          line-height: 1;
          border-radius: 4px;
        }

        .close:hover {
          border-color: var(--boot-main);
          color: var(--boot-light);
        }

        .body {
          padding: 1.5rem;
          color: var(--text-dark);
        }

        .footer {
          padding: 1rem 1.5rem;
          border-top: 1px solid var(--border-dark);
          display: flex;
          justify-content: flex-end;
          gap: 0.75rem;
        }
      </style>
      <div class="backdrop">
        <div class="modal">
          <div class="header">
            <span class="title"><slot name="title"></slot></span>
            <button class="close" onclick="this.getRootNode().host.close()">×</button>
          </div>
          <div class="body">
            <slot></slot>
          </div>
          <div class="footer">
            <slot name="footer"></slot>
          </div>
        </div>
      </div>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT TOAST NOTIFICATIONS
// ══════════════════════════════════════════════════════════════
class CRTToast {
  static container = null;

  static init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'crt-toast-container';
      this.container.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 10001;
        display: flex;
        flex-direction: column;
        gap: 10px;
      `;
      document.body.appendChild(this.container);
    }
  }

  static show(message, type = 'info', duration = 3000) {
    this.init();

    // Use 6-module colors
    const colors = {
      info: { border: TOKENS.meshLight, text: TOKENS.meshLight, bg: 'rgba(44,112,192,0.15)' },
      success: { border: TOKENS.rootLight, text: TOKENS.rootLight, bg: 'rgba(20,140,102,0.15)' },
      warning: { border: TOKENS.wallLight, text: TOKENS.wallLight, bg: 'rgba(204,136,32,0.15)' },
      error: { border: TOKENS.bootLight, text: TOKENS.bootLight, bg: 'rgba(192,96,64,0.15)' }
    };

    const c = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
      background: var(--surface-dark, ${TOKENS.surfaceDark});
      border: 1px solid ${c.border};
      color: ${c.text};
      padding: 0.75rem 1.25rem;
      font-family: var(--font-mono, 'JetBrains Mono', monospace);
      font-size: 0.85rem;
      letter-spacing: 0.05em;
      box-shadow: 0 0 15px ${c.border}44;
      animation: toast-in 0.3s ease;
      max-width: 400px;
      border-radius: 6px;
    `;
    toast.textContent = message;

    this.container.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toast-out 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  static info(msg, duration) { this.show(msg, 'info', duration); }
  static success(msg, duration) { this.show(msg, 'success', duration); }
  static warning(msg, duration) { this.show(msg, 'warning', duration); }
  static error(msg, duration) { this.show(msg, 'error', duration); }
}

// Add toast animations
const toastStyles = document.createElement('style');
toastStyles.textContent = `
  @keyframes toast-in {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes toast-out {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(toastStyles);

// ══════════════════════════════════════════════════════════════
//  REGISTER COMPONENTS
// ══════════════════════════════════════════════════════════════
customElements.define('crt-button', CRTButton);
customElements.define('crt-card', CRTCard);
customElements.define('crt-badge', CRTBadge);
customElements.define('crt-progress', CRTProgress);
customElements.define('crt-stat', CRTStat);
customElements.define('crt-modal', CRTModal);

// ══════════════════════════════════════════════════════════════
//  EXPORTS
// ══════════════════════════════════════════════════════════════
window.CRT = {
  Typewriter: CRTTypewriter,
  Toast: CRTToast,
  TOKENS: TOKENS
};
