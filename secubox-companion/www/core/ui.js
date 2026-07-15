// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/ui — minimal DOM helpers (no framework)

/** el('div.card', {onclick}, [children|text]) → HTMLElement */
export function el(spec, props = {}, children = []) {
  const [tag, ...cls] = spec.split('.');
  const node = document.createElement(tag || 'div');
  if (cls.length) node.className = cls.join(' ');
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'html') node.innerHTML = v;         // caller-sanitised only
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k in node && k !== 'list') { try { node[k] = v; } catch { node.setAttribute(k, v); } }
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** Escape for safe text interpolation. */
export const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

let _t;
export function toast(msg, kind = '') {
  let t = document.getElementById('sbx-toast');
  if (!t) { t = el('div.toast', { id: 'sbx-toast' }); document.body.append(t); }
  t.className = 'toast on' + (kind ? ' ' + kind : '');
  t.textContent = msg;
  clearTimeout(_t); _t = setTimeout(() => t.classList.remove('on'), 3200);
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

/** confirm dialog (native, keeps the bundle tiny) */
export const confirmAction = (msg) => window.confirm(msg);

/** relative time for feeds */
export function ago(ts) {
  if (!ts) return '';
  const d = (typeof ts === 'number' ? ts : Date.parse(ts));
  if (!d) return String(ts);
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
