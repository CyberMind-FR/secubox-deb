// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: podcasteur — containers → episodes, publish/download.
// Uses the confirmed secubox-podcaster API (feeds/episodes/download/import).
const EP = {
  status:   (b) => `${b}/status`,
  feeds:    (b) => `${b}/feeds`,
  episodes: (b, fid) => `${b}/episodes?feed_id=${fid}`,
  addFeed:  (b) => `${b}/feeds`,
  download: (b, id) => `${b}/episodes/${id}/download`,
  importUrl:(b) => `${b}/import/url`,
  media:    (b, id) => `${b}/media/${id}`,
};

export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, toast, ago, clear } = ui;

  const tabs = el('div.row', { style: 'gap:6px;margin-bottom:14px;flex-wrap:wrap' });
  const bodyEl = el('div');
  root.append(tabs, bodyEl);
  let active = (location.hash.split('/')[4]) || '';

  function renderTabs() {
    clear(tabs);
    for (const [k, l] of [['', 'Containers'], ['add', 'Add feed / URL']])
      tabs.append(el(`button.btn.sm${k === active ? '.primary' : ''}`, {
        text: l, onclick: () => { active = k; navigate(`#/m/podcasteur/${k}`); renderTabs(); render(); },
      }));
  }
  function render() { return active === 'add' ? addPane() : active.startsWith('feed:') ? episodes(active.slice(5)) : feeds(); }

  // ── containers (feeds) ──────────────────────────────────────────
  async function feeds() {
    const host = clear(bodyEl);
    host.append(el('p.muted', { text: 'Loading containers…' }));
    try {
      const d = await api.get(EP.feeds(base));
      const items = d.feeds || (Array.isArray(d) ? d : []);
      clear(host);
      if (d.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));
      if (!items.length) return host.append(el('div.empty', { text: 'No containers. Add a feed or import a URL.' }));
      for (const f of items) {
        host.append(el('div.item.card.link', {
          style: 'cursor:pointer', onclick: () => { active = 'feed:' + f.id; renderTabs(); episodes(f.id); },
        }, [
          el('div.meta', {}, [
            el('b', { text: f.title || f.url }),
            el('span', { text: `${f.downloaded ?? 0}/${f.episodes ?? 0} local${f.auto_dl ? ' · auto-dl' : ''}` }),
          ]),
          el('span.badge', { text: '›' }),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
  }

  // ── episodes of a container ─────────────────────────────────────
  async function episodes(fid) {
    const host = clear(bodyEl);
    host.append(el('button.btn.sm', { text: '← Containers', onclick: () => { active = ''; renderTabs(); feeds(); } }),
                el('p.muted', { text: 'Loading episodes…' }));
    try {
      const d = await api.get(EP.episodes(base, fid));
      const eps = d.episodes || [];
      clear(host);
      host.append(el('button.btn.sm', { text: '← Containers', onclick: () => { active = ''; renderTabs(); feeds(); } }));
      if (!eps.length) return host.append(el('div.empty', { text: 'No episodes.' }));
      for (const e of eps) host.append(episodeRow(e));
    } catch (err) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(err.message) })); }
  }

  function episodeRow(e) {
    const act = el('div.actions');
    if (e.state === 'done') {
      act.append(el('a.btn.sm', { href: api.isReady() ? undefined : '#', text: '▶', title: 'Play',
        onclick: () => playAudio(e) }));
    } else if (e.state === 'downloading' || e.state === 'queued') {
      act.append(el('span.badge.pending', { text: e.state }));
    } else if (e.state === 'error') {
      act.append(el('span.badge.err', { text: 'error' }), el('button.btn.sm', { text: '↻', onclick: () => download(e) }));
    } else {
      act.append(el('button.btn.sm.primary', { text: '⬇', title: 'Download', onclick: () => download(e) }));
    }
    return el('div.item', {}, [
      el('div.meta', {}, [el('b', { text: e.title }), el('span', { text: `${e.state || 'new'} · ${ago(e.pubdate ? e.pubdate * 1000 : e.pubdate)}${e.duration ? ' · ' + e.duration : ''}` })]),
      act,
    ]);
  }

  async function download(e) {
    try { const r = await api.post(EP.download(base, e.id)); toast(r.queued ? 'Queued (offline)' : 'Download queued'); }
    catch (err) { toast('Failed: ' + err.message, 'err'); }
  }

  function playAudio(e) {
    const existing = document.getElementById('sbx-audio');
    if (existing) existing.remove();
    const a = el('audio', { id: 'sbx-audio', controls: true, autoplay: true, style: 'position:fixed;bottom:10px;left:50%;transform:translateX(-50%);width:min(92vw,600px);z-index:200' });
    // media needs the bearer token; use fetch→blob so the <audio> gets an authorised stream
    api.get(EP.media(base, e.id).replace('/api', '/api'), { cache: false }).catch(() => {});
    a.src = (api.base || '') + EP.media(base, e.id); // TODO(api): if media needs auth header, stream via fetch+blob URL
    document.body.append(a);
    toast('Playing: ' + (e.title || '').slice(0, 40));
  }

  // ── add feed / import URL ───────────────────────────────────────
  function addPane() {
    const host = clear(bodyEl);
    const rss = el('input', { type: 'url', placeholder: 'RSS feed URL (or Apple Podcasts link)' });
    const auto = el('input', { type: 'checkbox', checked: true });
    const addBtn = el('button.btn.primary', { text: 'Add feed', onclick: async () => {
      if (!rss.value) return toast('URL required', 'err');
      try { const r = await api.post(EP.addFeed(base), { url: rss.value, auto_dl: auto.checked });
        toast(r.queued ? 'Queued (offline)' : `Added ${r.title || ''} (${r.episodes ?? '?'} eps)`); active = ''; renderTabs(); feeds(); }
      catch (e) { toast('Failed: ' + e.message, 'err'); }
    } });

    const url = el('input', { type: 'url', placeholder: 'YouTube video/playlist or any yt-dlp URL' });
    const mirror = el('input', { type: 'checkbox', checked: true });
    const billets = el('input', { type: 'checkbox', checked: true });
    const impBtn = el('button.btn.primary', { text: 'Import from URL', onclick: async () => {
      if (!url.value) return toast('URL required', 'err');
      try { const r = await api.post(EP.importUrl(base), { url: url.value, mirror_peertube: mirror.checked, create_billets: billets.checked });
        toast(r.queued ? 'Queued (offline)' : 'Import started — watch the box webui for progress'); }
      catch (e) { toast('Failed: ' + e.message, 'err'); }
    } });

    host.append(
      el('div.card', {}, [
        el('h3', { text: 'Add RSS feed' }),
        el('label', { text: 'Feed URL' }), rss,
        el('label.row', { style: 'text-transform:none;letter-spacing:0', }, [auto, el('span', { style: 'margin-left:6px', text: 'auto-download new episodes' })]),
        el('div.row', { style: 'margin-top:10px' }, [addBtn]),
      ]),
      el('div.card', {}, [
        el('h3', { text: 'Import from URL (yt-dlp)' }),
        el('p.muted', { style: 'font-size:.78rem', text: 'Video/playlist → audio episode(s), optionally mirrored to PeerTube + a billet each.' }),
        el('label', { text: 'URL' }), url,
        el('label.row', { style: 'text-transform:none;letter-spacing:0' }, [mirror, el('span', { style: 'margin-left:6px', text: '📺 Mirror to PeerTube' })]),
        el('label.row', { style: 'text-transform:none;letter-spacing:0' }, [billets, el('span', { style: 'margin-left:6px', text: '📝 Create a billet per item' })]),
        el('div.row', { style: 'margin-top:10px' }, [impBtn]),
      ]),
    );
  }

  renderTabs(); render();
}
