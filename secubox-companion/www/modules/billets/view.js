// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: billets — write/publish billets + moderate comments.
//
// Endpoints below are the clean interface the Companion consumes. Where the
// exact box route/shape is unconfirmed it is marked TODO(api); the box may need
// a JWT-authed admin API for billets (its web admin is session-based). Reads use
// the public feed and work today; writes go through these paths + auto-queue.
const EP = {
  feed:     (b) => `${b}/feed.json`,                     // public JSON Feed (jsonfeed.org)
  create:   (b) => `${b}/admin/api/billets`,             // TODO(api): confirm JWT create route
  update:   (b, id) => `${b}/admin/api/billets/${id}`,   // TODO(api)
  remove:   (b, id) => `${b}/admin/api/billets/${id}`,   // TODO(api)
  comments: (b) => `${b}/admin/api/comments?status=pending`, // TODO(api)
  cApprove: (b, id) => `${b}/admin/api/comments/${id}/approve`, // TODO(api)
  cDelete:  (b, id) => `${b}/admin/api/comments/${id}`,   // TODO(api)
};

export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, toast, ago, clear, confirmAction } = ui;

  const tabs = el('div.row', { style: 'gap:6px;margin-bottom:14px;flex-wrap:wrap' });
  const body = el('div');
  root.append(tabs, body);

  const TABS = [['', 'Billets'], ['new', 'New billet'], ['comments', 'Comments']];
  let active = (location.hash.split('/')[4]) || '';
  function renderTabs() {
    clear(tabs);
    for (const [k, label] of TABS)
      tabs.append(el(`button.btn.sm${k === active ? '.primary' : ''}`, {
        text: label, onclick: () => { active = k; navigate(`#/m/billets/${k}`); renderTabs(); render(); },
      }));
  }
  function render() {
    if (active === 'new') return editor();
    if (active === 'comments') return comments();
    if (active.startsWith('edit:')) return editor(active.slice(5));
    return list();
  }

  // ── list ────────────────────────────────────────────────────────
  async function list() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading…' }));
    try {
      const d = await api.get(EP.feed(base));
      const items = d.billets || d.items || d.feed || (Array.isArray(d) ? d : []);
      clear(host);
      if (d.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));
      if (!items.length) return host.append(el('div.empty', { text: 'No billets yet.' }));
      for (const b of items) {
        const title = (b.title || b.body || '').replace(/\s+/g, ' ').slice(0, 70) || '(untitled)';
        host.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: title }),
            el('span', { text: `${b.status || 'published'} · ${ago(b.date_published || b.published_at || b.created_at)} · ${b.style || 'default'}` }),
          ]),
          el('div.actions', {}, [
            el('button.btn.sm', { text: 'Edit', onclick: () => { active = 'edit:' + (b.id || b.slug); renderTabs(); editor(b.id || b.slug, b); } }),
            el('button.btn.sm.danger', { text: 'Del', onclick: () => remove(b) }),
          ]),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
  }

  async function remove(b) {
    if (!confirmAction('Delete this billet?')) return;
    try {
      const r = await api.del(EP.remove(base, b.id || b.slug));
      toast(r.queued ? 'Delete queued (offline)' : 'Deleted');
      list();
    } catch (e) { toast('Delete failed: ' + e.message, 'err'); }
  }

  // ── editor ──────────────────────────────────────────────────────
  function editor(id = null, seed = {}) {
    const host = clear(body);
    const bodyIn = el('textarea.mono', { rows: 8, placeholder: 'Billet body (restricted markdown)…', value: seed.body || '' });
    const refIn = el('input', { type: 'url', placeholder: 'Source / ref URL (optional)', value: seed.ref_url || '' });
    const embedIn = el('input', { type: 'url', placeholder: 'Embed URL (oEmbed, optional)', value: seed.embed_url || '' });
    const styleIn = el('select', {}, [opt('default', 'Default'), opt('communique', 'Communiqué')]);
    styleIn.value = seed.style || 'default';
    const statusIn = el('select', {}, [opt('published', 'Publish'), opt('draft', 'Save as draft')]);
    statusIn.value = seed.status || 'published';

    const save = el('button.btn.primary', {
      text: id ? 'Update billet' : 'Publish billet',
      onclick: async () => {
        if (!bodyIn.value.trim()) return toast('Body required', 'err');
        const payload = { body: bodyIn.value, ref_url: refIn.value || null, embed_url: embedIn.value || null, style: styleIn.value, status: statusIn.value };
        save.disabled = true;
        try {
          const r = id ? await api.put(EP.update(base, id), payload) : await api.post(EP.create(base), payload);
          toast(r.queued ? 'Saved offline — will sync' : (id ? 'Updated ✓' : 'Published ✓'));
          active = ''; renderTabs(); list();
        } catch (e) { toast('Save failed: ' + e.message, 'err'); save.disabled = false; }
      },
    });

    host.append(el('div.card', {}, [
      el('h3', { text: id ? 'Edit billet' : 'New billet' }),
      el('label', { text: 'Body' }), bodyIn,
      el('label', { text: 'Source URL' }), refIn,
      el('label', { text: 'Embed URL' }), embedIn,
      el('div.row', { style: 'gap:12px' }, [
        el('div.stack', { style: 'flex:1' }, [el('label', { text: 'Style' }), styleIn]),
        el('div.stack', { style: 'flex:1' }, [el('label', { text: 'Status' }), statusIn]),
      ]),
      el('div.row', { style: 'margin-top:14px;gap:8px' }, [save,
        el('button.btn.sm', { text: 'Cancel', onclick: () => { active = ''; renderTabs(); list(); } })]),
    ]));
  }

  // ── comment moderation ──────────────────────────────────────────
  async function comments() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading pending comments…' }));
    try {
      const d = await api.get(EP.comments(base));
      const items = d.comments || d.items || (Array.isArray(d) ? d : []);
      clear(host);
      if (!items.length) return host.append(el('div.empty', { text: 'No comments awaiting moderation.' }));
      for (const c of items) {
        host.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: (c.author || 'anon') + ': ' + (c.body || c.text || '').slice(0, 60) }),
            el('span', { text: `on ${c.billet_slug || c.billet_id || '?'} · ${ago(c.created_at)}` }),
          ]),
          el('div.actions', {}, [
            el('button.btn.sm.primary', { text: '✓', title: 'Approve', onclick: () => moderate('approve', c) }),
            el('button.btn.sm.danger', { text: '✕', title: 'Delete', onclick: () => moderate('delete', c) }),
          ]),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) + ' (comment moderation API may need enabling — see TODO(api))' })); }
  }
  async function moderate(action, c) {
    try {
      const r = action === 'approve' ? await api.post(EP.cApprove(base, c.id)) : await api.del(EP.cDelete(base, c.id));
      toast(r.queued ? `${action} queued` : `${action}d ✓`);
      comments();
    } catch (e) { toast(`${action} failed: ` + e.message, 'err'); }
  }

  const opt = (v, l) => el('option', { value: v, text: l });
  renderTabs(); render();
}
