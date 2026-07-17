// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: billets — write/publish billets + moderate comments.
//
// Every route below is served by billets' JWT/SSO admin surface
// (routes/jwt_admin.py), which trusts the SecuBox session.
//
// The list deliberately uses the ADMIN route, not the public JSON Feed: the
// feed's item `id` is a permalink URL rather than the billet id (so edit/delete
// could not address a row) and the feed omits drafts, which an authoring client
// must see.
const EP = {
  list:     (b) => `${b}/admin/api/billets`,                  // GET  {billets:[{id,summary,status,tags[]}]}
  tags:     (b) => `${b}/admin/api/tags`,                     // GET  {tags:[{slug,emoji,count}]}
  create:   (b) => `${b}/admin/api/billets`,                 // POST {body,ref_url,embed_url,style,status}
  update:   (b, id) => `${b}/admin/api/billets/${id}`,        // PUT
  remove:   (b, id) => `${b}/admin/api/billets/${id}`,        // DELETE
  media:    (b, id) => `${b}/admin/api/billets/${id}/media`,  // POST multipart file (EXIF-stripped server-side)
  comments: (b) => `${b}/admin/api/comments?status=pending`,  // GET
  cApprove: (b, id) => `${b}/admin/api/comments/${id}/approve`, // POST
  cDelete:  (b, id) => `${b}/admin/api/comments/${id}`,        // DELETE
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
  let tagFilter = '';   // '' = all; otherwise a tag slug (the quick view)

  async function list() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading…' }));
    try {
      const d = await api.get(EP.list(base));
      const items = d.billets || [];
      clear(host);
      if (d.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));

      // Quick-view chip bar. Tags come from the #hashtags authors type in the
      // body; failing to load them must not hide the billets themselves.
      const td = await api.get(EP.tags(base)).catch(() => null);
      const tags = (td && td.tags) || [];
      if (tags.length) {
        const bar = el('div.row', { style: 'gap:6px;margin-bottom:12px;flex-wrap:wrap' });
        const chip = (label, slug) => el(`button.btn.sm${tagFilter === slug ? '.primary' : ''}`, {
          text: label,
          onclick: () => { tagFilter = tagFilter === slug ? '' : slug; list(); },
        });
        bar.append(chip('🌀 All', ''));
        for (const t of tags) bar.append(chip(`${t.emoji} #${t.slug} ${t.count}`, t.slug));
        host.append(bar);
      }

      const shown = tagFilter
        ? items.filter(b => (b.tags || []).some(t => t.slug === tagFilter))
        : items;
      if (!shown.length) {
        return host.append(el('div.empty', {
          text: tagFilter ? `No billets tagged #${tagFilter}.` : 'No billets yet.',
        }));
      }

      for (const b of shown) {
        // Show a few words, not the whole billet — `summary` is the box-side
        // excerpt; fall back to a clipped body if it is ever absent.
        const excerpt = b.summary || (b.body || '').replace(/\s+/g, ' ').slice(0, 140) || '(empty)';
        const chips = el('span', { style: 'margin-left:6px' });
        for (const t of (b.tags || []))
          chips.append(el('span.badge', { text: `${t.emoji} ${t.slug}`, style: 'margin-right:4px' }));
        const draft = b.status === 'draft';
        host.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: excerpt }),
            el('span', {}, [
              el('span', { text: `${draft ? '📝 draft' : '✅ published'} · ${ago(b.published_at || b.created_at)}${b.style === 'communique' ? ' · 📢 communiqué' : ''}` }),
              chips,
            ]),
          ]),
          el('div.actions', {}, [
            el('button.btn.sm', { text: 'Edit', onclick: () => { active = 'edit:' + b.id; renderTabs(); editor(b.id, b); } }),
            el('button.btn.sm.danger', { text: 'Del', onclick: () => remove(b) }),
          ]),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
  }

  async function remove(b) {
    if (!confirmAction('Delete this billet?')) return;
    try {
      const r = await api.del(EP.remove(base, b.id));
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
    // Image attachment — the box re-encodes + strips EXIF server-side (services.media).
    const imgIn = el('input', { type: 'file', accept: 'image/*' });

    const save = el('button.btn.primary', {
      text: id ? 'Update billet' : 'Publish billet',
      onclick: async () => {
        if (!bodyIn.value.trim()) return toast('Body required', 'err');
        const payload = { body: bodyIn.value, ref_url: refIn.value || null, embed_url: embedIn.value || null, style: styleIn.value, status: statusIn.value };
        save.disabled = true;
        try {
          const r = id ? await api.put(EP.update(base, id), payload) : await api.post(EP.create(base), payload);
          const bid = id || r.id || (r.billet && r.billet.id);
          // Upload the image AFTER the billet exists (media attaches to a billet id).
          const file = imgIn.files && imgIn.files[0];
          if (file && bid) {
            try {
              const fd = new FormData(); fd.append('file', file);
              await api.post(EP.media(base, bid), fd, { form: true });
            } catch (e) { toast('Billet saved — image upload failed: ' + e.message, 'err'); }
          }
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
      el('label', { text: 'Image (optional)' }), imgIn,
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
