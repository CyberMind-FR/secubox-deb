/**
 * ═══════════════════════════════════════════════════════════════
 *  CRT COMPONENTS v1.0 — SecuBox Edition
 *  Reusable encapsulated Web Components
 * ═══════════════════════════════════════════════════════════════
 */

// ══════════════════════════════════════════════════════════════
//  TYPEWRITER ENGINE
// ══════════════════════════════════════════════════════════════
class CRTTypewriter {
  constructor(element, options = {}) {
    this.el = element;
    this.speed = options.speed || 40; // ms per char
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
//  CRT BUTTON COMPONENT
// ══════════════════════════════════════════════════════════════
class CRTButton extends HTMLElement {
  static get observedAttributes() {
    return ['variant', 'size', 'disabled', 'loading'];
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
    const size = this.getAttribute('size') || 'md';
    const disabled = this.hasAttribute('disabled');
    const loading = this.hasAttribute('loading');

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: inline-block; }

        button {
          font-family: 'Courier Prime', monospace;
          border: 1px solid var(--p31-dim, #0f8822);
          background: var(--tube-deep, #080d05);
          color: var(--p31-mid, #22cc44);
          padding: ${size === 'sm' ? '0.25rem 0.5rem' : size === 'lg' ? '0.75rem 1.5rem' : '0.5rem 1rem'};
          font-size: ${size === 'sm' ? '0.75rem' : size === 'lg' ? '1rem' : '0.875rem'};
          letter-spacing: 0.1em;
          cursor: pointer;
          transition: all 0.2s ease;
          text-transform: uppercase;
          position: relative;
          overflow: hidden;
        }

        button:hover:not(:disabled) {
          border-color: var(--p31-peak, #33ff66);
          color: var(--p31-peak, #33ff66);
          text-shadow: 0 0 6px var(--p31-peak, #33ff66);
          box-shadow: 0 0 12px rgba(51,255,102,0.15);
        }

        button:active:not(:disabled) {
          background: rgba(51,255,102,0.1);
        }

        button:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        /* Variants */
        button.primary {
          border-color: var(--p31-peak, #33ff66);
          color: var(--p31-peak, #33ff66);
          text-shadow: 0 0 4px var(--p31-peak, #33ff66);
        }
        button.primary:hover:not(:disabled) {
          background: rgba(51,255,102,0.15);
          box-shadow: 0 0 20px rgba(51,255,102,0.25);
        }

        button.amber {
          border-color: var(--p31-decay, #ffb347);
          color: var(--p31-decay, #ffb347);
          text-shadow: 0 0 4px var(--p31-decay, #ffb347);
        }
        button.amber:hover:not(:disabled) {
          background: rgba(255,179,71,0.1);
          box-shadow: 0 0 16px rgba(255,179,71,0.2);
        }

        button.danger {
          border-color: #ff4466;
          color: #ff4466;
        }
        button.danger:hover:not(:disabled) {
          background: rgba(255,68,102,0.1);
          box-shadow: 0 0 16px rgba(255,68,102,0.2);
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
    return ['variant', 'glow'];
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
    const glow = this.hasAttribute('glow');

    this.shadowRoot.innerHTML = `
      <style>
        :host {
          display: block;
        }

        .card {
          background: var(--tube-deep, #080d05);
          border: 1px solid var(--p31-ghost, #052210);
          padding: 1.25rem;
          box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
        }

        .card.lit {
          border-color: var(--p31-dim, #0f8822);
          box-shadow: 0 0 8px rgba(51,255,102,0.08), inset 0 0 20px rgba(0,0,0,0.4);
        }

        .card.hot {
          border-color: var(--p31-mid, #22cc44);
          box-shadow: 0 0 12px rgba(51,255,102,0.15), 0 0 30px rgba(51,255,102,0.06), inset 0 0 20px rgba(0,0,0,0.3);
        }

        .card.glow {
          animation: pulse-glow 3s ease-in-out infinite;
        }

        @keyframes pulse-glow {
          0%, 100% { box-shadow: 0 0 8px rgba(51,255,102,0.08), inset 0 0 20px rgba(0,0,0,0.4); }
          50% { box-shadow: 0 0 16px rgba(51,255,102,0.15), inset 0 0 20px rgba(0,0,0,0.3); }
        }

        .header {
          font-size: 0.75rem;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--p31-decay, #ffb347);
          text-shadow: 0 0 6px rgba(255,179,71,0.4);
          margin-bottom: 1rem;
          padding-bottom: 0.5rem;
          border-bottom: 1px solid var(--p31-ghost, #052210);
        }

        .content {
          color: var(--p31-mid, #22cc44);
        }

        .footer {
          margin-top: 1rem;
          padding-top: 0.5rem;
          border-top: 1px solid var(--p31-ghost, #052210);
        }
      </style>
      <div class="card ${variant} ${glow ? 'glow' : ''}">
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
    return ['variant', 'pulse'];
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
    const pulse = this.hasAttribute('pulse');

    const colors = {
      default: { bg: 'rgba(51,255,102,0.15)', color: '#33ff66', shadow: 'rgba(51,255,102,0.4)' },
      amber: { bg: 'rgba(255,179,71,0.15)', color: '#ffb347', shadow: 'rgba(255,179,71,0.4)' },
      danger: { bg: 'rgba(255,68,102,0.15)', color: '#ff4466', shadow: 'rgba(255,68,102,0.4)' },
      dim: { bg: 'rgba(51,255,102,0.05)', color: '#0f8822', shadow: 'none' }
    };

    const c = colors[variant] || colors.default;

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: inline-block; }

        .badge {
          background: ${c.bg};
          color: ${c.color};
          text-shadow: 0 0 6px ${c.shadow};
          padding: 0.2rem 0.6rem;
          font-size: 0.7rem;
          font-family: 'Courier Prime', monospace;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          border: 1px solid ${c.color}33;
        }

        .badge.pulse {
          animation: badge-pulse 2s ease-in-out infinite;
        }

        @keyframes badge-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      </style>
      <span class="badge ${pulse ? 'pulse' : ''}"><slot></slot></span>
    `;
  }
}

// ══════════════════════════════════════════════════════════════
//  CRT PROGRESS BAR
// ══════════════════════════════════════════════════════════════
class CRTProgress extends HTMLElement {
  static get observedAttributes() {
    return ['value', 'max', 'variant', 'animated'];
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

    const colors = {
      default: { fill: '#22cc44', glow: 'rgba(51,255,102,0.4)' },
      amber: { fill: '#ffb347', glow: 'rgba(255,179,71,0.4)' },
      danger: { fill: '#ff4466', glow: 'rgba(255,68,102,0.4)' }
    };

    const c = colors[variant] || colors.default;

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }

        .track {
          background: rgba(51,255,102,0.06);
          border: 1px solid var(--p31-ghost, #052210);
          height: 12px;
          position: relative;
          overflow: hidden;
        }

        .fill {
          height: 100%;
          width: ${percent}%;
          background: ${c.fill};
          box-shadow: 0 0 8px ${c.glow};
          transition: width 0.8s ease;
        }

        .fill.animated {
          animation: fill-scan 2s linear infinite;
          background: linear-gradient(90deg, ${c.fill} 0%, ${c.fill}88 50%, ${c.fill} 100%);
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
          font-family: 'Courier Prime', monospace;
          color: var(--p31-dim, #0f8822);
          letter-spacing: 0.1em;
        }
      </style>
      <div class="track">
        <div class="fill ${animated ? 'animated' : ''}"></div>
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
    return ['value', 'label', 'variant', 'icon'];
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

    const colors = {
      default: '#33ff66',
      amber: '#ffb347',
      danger: '#ff4466',
      dim: '#0f8822'
    };

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }

        .stat {
          background: var(--tube-deep, #080d05);
          border: 1px solid var(--p31-ghost, #052210);
          padding: 1rem;
          text-align: center;
        }

        .icon {
          font-size: 1.5rem;
          margin-bottom: 0.5rem;
          filter: grayscale(0.3);
        }

        .value {
          font-size: 2rem;
          font-weight: bold;
          font-family: 'Courier Prime', monospace;
          color: ${colors[variant] || colors.default};
          text-shadow: 0 0 10px ${colors[variant] || colors.default}66;
          line-height: 1;
        }

        .label {
          font-size: 0.7rem;
          letter-spacing: 0.2em;
          text-transform: uppercase;
          color: var(--p31-dim, #0f8822);
          margin-top: 0.5rem;
        }
      </style>
      <div class="stat">
        ${icon ? `<div class="icon">${icon}</div>` : ''}
        <div class="value">${value}</div>
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
          background: var(--tube-deep, #080d05);
          border: 1px solid var(--p31-dim, #0f8822);
          box-shadow: 0 0 30px rgba(51,255,102,0.1), inset 0 0 30px rgba(0,0,0,0.5);
          max-width: 90vw;
          max-height: 90vh;
          overflow: auto;
          animation: modal-in 0.3s ease;
        }

        @keyframes modal-in {
          from { transform: scale(0.95); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }

        .header {
          padding: 1rem 1.5rem;
          border-bottom: 1px solid var(--p31-ghost, #052210);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .title {
          font-size: 0.85rem;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: var(--p31-decay, #ffb347);
          text-shadow: 0 0 6px rgba(255,179,71,0.4);
        }

        .close {
          background: none;
          border: 1px solid var(--p31-ghost, #052210);
          color: var(--p31-dim, #0f8822);
          width: 28px;
          height: 28px;
          cursor: pointer;
          font-family: monospace;
          font-size: 1rem;
          line-height: 1;
        }

        .close:hover {
          border-color: #ff4466;
          color: #ff4466;
        }

        .body {
          padding: 1.5rem;
          color: var(--p31-mid, #22cc44);
        }

        .footer {
          padding: 1rem 1.5rem;
          border-top: 1px solid var(--p31-ghost, #052210);
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

    const colors = {
      info: { border: '#33ff66', text: '#33ff66', bg: 'rgba(51,255,102,0.1)' },
      success: { border: '#33ff66', text: '#33ff66', bg: 'rgba(51,255,102,0.15)' },
      warning: { border: '#ffb347', text: '#ffb347', bg: 'rgba(255,179,71,0.1)' },
      error: { border: '#ff4466', text: '#ff4466', bg: 'rgba(255,68,102,0.1)' }
    };

    const c = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
      background: var(--tube-deep, #080d05);
      border: 1px solid ${c.border};
      color: ${c.text};
      padding: 0.75rem 1.25rem;
      font-family: 'Courier Prime', monospace;
      font-size: 0.85rem;
      letter-spacing: 0.05em;
      box-shadow: 0 0 15px ${c.border}44;
      animation: toast-in 0.3s ease;
      max-width: 400px;
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

  // Initialize CRT overlays
  init(options = {}) {
    document.body.classList.add('crt-body');

    if (options.scanlines !== false) {
      document.body.classList.add('crt-scanlines');
    }
    if (options.flicker !== false) {
      document.body.classList.add('crt-screen');
    }
    if (options.bloom) {
      const bloom = document.createElement('div');
      bloom.className = 'crt-bloom';
      document.body.appendChild(bloom);
    }
    if (options.noise) {
      const noise = document.createElement('div');
      noise.className = 'crt-noise';
      document.body.appendChild(noise);
    }
  }
};
