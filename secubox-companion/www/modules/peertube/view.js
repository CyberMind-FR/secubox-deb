// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: peertube — video instance: library, channels, federation.
//
// Every route below was probed live on the box and its shape read from
// packages/secubox-peertube/api/main.py — none are guessed.
//
// Two box-side facts drive this view:
//  * The list routes answer {<key>: [...], total, error?} and set `error`
//    (rather than failing) when the instance is unreachable — so `error` must be
//    surfaced, not silently rendered as "empty".
//  * `lxc_state` reads "absent" on this box even while PeerTube serves fine:
//    lxc-info can't see an unprivileged container from the API's context. The
//    box's own is_running() trusts http_reachable(), and so do we — reporting
//    "down" off lxc_state would be a lie the backend itself doesn't tell.
const EP = {
  status:    (b) => `${b}/status`,                    // {container_status,http_reachable,video_count,disk_usage,server_version,…}
  videos:    (b, n = 15) => `${b}/videos?count=${n}`, // {videos:[…],total}
  channels:  (b) => `${b}/channels`,                  // {channels:[…],total}
  storage:   (b) => `${b}/storage/stats`,             // {stats:{total,videos,thumbnails,torrents,streaming_playlists}}
  jobs:      (b) => `${b}/transcoding/jobs`,          // {jobs:[…],total}
  backlog:   (b) => `${b}/transcoding/backlog`,       // {available,states:[…],pending,unplayable,cache_age_seconds}
  followers: (b) => `${b}/federation/followers`,      // {followers:[…],total}
  following: (b) => `${b}/federation/following`,      // {following:[…],total}
};

// PeerTube reports durations in seconds. 0 is a legitimate value (a still being
// processed), so only null/undefined fall back to the dash.
function fmtDuration(sec) {
  if (sec == null || Number.isNaN(sec)) return '—';
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
               : `${m}:${String(s).padStart(2, '0')}`;
}

const fmtCount = (n) => (n == null ? '—' : Number(n).toLocaleString('fr-FR'));

export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, clear, ago } = ui;

  const tabs = el('div.row', { style: 'gap:6px;margin-bottom:14px;flex-wrap:wrap' });
  const body = el('div');
  root.append(tabs, body);

  const TABS = [['', 'Overview'], ['videos', 'Videos'], ['federation', 'Federation']];
  let active = (location.hash.split('/')[4]) || '';
  function renderTabs() {
    clear(tabs);
    for (const [k, label] of TABS)
      tabs.append(el(`button.btn.sm${k === active ? '.primary' : ''}`, {
        text: label,
        onclick: () => { active = k; navigate(`#/m/peertube/${k}`); renderTabs(); render(); },
      }));
  }
  function render() {
    if (active === 'videos') return videos();
    if (active === 'federation') return federation();
    return overview();
  }

  /** A section that must never take the whole module down with it. */
  async function section(host, fetch, build) {
    try {
      const d = await fetch();
      if (d && d.error) return host.append(el('div.card', {}, [
        el('p.muted', { text: `⚠️ ${esc(d.error)}` })]));
      host.append(build(d));
    } catch (e) {
      host.append(el('div.card', {}, [el('p.muted', { text: `⚠️ ${esc(e.message)}` })]));
    }
  }

  const stat = (emoji, value, label) => el('div.card', { style: 'text-align:center' }, [
    el('div', { style: 'font-size:1.3rem;line-height:1', text: emoji }),
    el('div.data', { style: 'font-size:1.35rem;font-weight:700;margin:3px 0', text: String(value ?? '—') }),
    el('div.kicker', { text: label }),
  ]);

  // ── overview ────────────────────────────────────────────────────
  async function overview() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading PeerTube…' }));
    try {
      const s = await api.get(EP.status(base));
      clear(host);
      if (s.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));

      // Trust the port probe, not lxc_state (see header note).
      const up = s.http_reachable === true || s.container_status === 'running';
      host.append(el('div.card', {}, [
        el('div.row', { style: 'justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap' }, [
          el('h3', { style: 'margin:0', text: `🎬 ${esc(s.instance_name || 'PeerTube')}` }),
          el(`span.badge.${up ? 'ok' : 'err'}`, { text: up ? '🟢 running' : '🔴 down' }),
        ]),
        el('p.muted', { style: 'margin:.4rem 0 0', text: `v${esc(s.server_version || '?')} · ${esc(s.runtime || s.deployment || '')}` }),
        s.public_url ? el('a.btn.sm', { href: s.public_url, target: '_blank', rel: 'noopener',
                                        text: '🔗 Open instance', style: 'margin-top:8px' }) : null,
      ]));

      host.append(el('div.grid', {}, [
        stat('🎞️', fmtCount(s.video_count), 'Videos'),
        stat('💾', s.disk_usage || '—', 'Disk used'),
        stat(s.transcoding_enabled ? '⚙️' : '🚫', s.transcoding_enabled ? 'on' : 'off', 'Transcoding'),
        stat(s.federation_enabled ? '🌐' : '🚫', s.federation_enabled ? 'on' : 'off', 'Federation'),
      ]));

      // Channels + storage + active transcoding, each independent.
      await section(host, () => api.get(EP.channels(base)), (d) => {
        const items = d.channels || [];
        const card = el('div.card', {}, [el('h3', { text: `📺 Channels (${d.total ?? items.length})` })]);
        if (!items.length) card.append(el('div.empty', { text: 'No channels.' }));
        for (const c of items.slice(0, 20)) card.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: c.displayName || c.name || '(unnamed)' }),
            el('span', { text: `${fmtCount(c.followersCount)} followers` }),
          ]),
        ]));
        return card;
      });

      await section(host, () => api.get(EP.storage(base)), (d) => {
        const st = d.stats || {};
        const card = el('div.card', {}, [el('h3', { text: '💽 Storage' })]);
        const rows = [['🎬 videos', st.videos], ['🖼️ thumbnails', st.thumbnails],
                      ['🧲 torrents', st.torrents], ['📡 streaming', st.streaming_playlists],
                      ['📦 total', st.total]];
        for (const [label, v] of rows)
          if (v) card.append(el('div.item', {}, [
            el('div.meta', {}, [el('b', { text: label }), el('span', { text: v })])]));
        return card;
      });

      // The backlog comes BEFORE the job list on purpose: an empty job queue
      // with 88 videos still lacking an HLS playlist reads as "all good" while
      // nothing is actually watchable. web_videos is disabled on this box, so
      // PeerTube serves HLS only — no playlist means unplayable, not merely
      // un-optimised.
      await section(host, () => api.get(EP.backlog(base)), (d) => {
        if (!d.available) return el('div.card', {}, [
          el('h3', { text: '📼 Backlog' }),
          el('p.muted', { text: `Indisponible — ${esc(d.reason || 'cache absent')}` }),
        ]);
        const card = el('div.card', {}, [el('h3', { text: '📼 Backlog' })]);
        // #943: counters claiming pending jobs while nothing runs means PeerTube
        // will 409 every relaunch — the queue is frozen, not busy.
        if (d.stuck) card.append(el('div.badge.err', {
          text: `🧊 File gelée — ${d.pending_counters} compteur(s) sans job. peertubectl unstick --apply`,
        }));
        card.append(d.unplayable > 0
          ? el('div.badge.err', { text: `⚠️ ${fmtCount(d.unplayable)} vidéo(s) sans playlist HLS — injouables` })
          : el('div.badge.ok', { text: '✅ Toutes les vidéos ont une playlist HLS' }));
        for (const s of d.states || [])
          card.append(el('div.item', {}, [
            el('div.meta', {}, [
              el('b', { text: s.label }),
              el('span', { text: s.without_hls
                ? `${fmtCount(s.videos)} · ${fmtCount(s.without_hls)} sans HLS`
                : fmtCount(s.videos) }),
            ]),
          ]));
        if (d.cache_age_seconds != null)
          card.append(el('p.muted', { style: 'font-size:.75rem;margin:.4rem 0 0',
                                      text: `mesuré il y a ${d.cache_age_seconds}s` }));
        return card;
      });

      await section(host, () => api.get(EP.jobs(base)), (d) => {
        const items = d.jobs || [];
        // A quiet queue is the normal state — say so rather than showing nothing.
        const card = el('div.card', {}, [el('h3', { text: `⚙️ Transcoding (${d.total ?? items.length})` })]);
        if (!items.length) card.append(el('p.muted', { text: '✅ Queue empty — nothing transcoding.' }));
        for (const j of items.slice(0, 10)) card.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: j.type || j.data?.type || 'job' }),
            el('span', { text: j.state || '' }),
          ]),
        ]));
        return card;
      });
    } catch (e) {
      clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) }));
    }
  }

  // ── videos ──────────────────────────────────────────────────────
  async function videos() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading videos…' }));
    try {
      const d = await api.get(EP.videos(base, 30));
      clear(host);
      if (d.error) return host.append(el('div.empty', { text: `⚠️ ${esc(d.error)}` }));
      const items = d.videos || [];
      if (!items.length) return host.append(el('div.empty', { text: 'No videos yet.' }));
      host.append(el('p.muted', { text: `🎞️ ${fmtCount(d.total ?? items.length)} videos` }));
      for (const v of items) {
        host.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: v.name || '(untitled)' }),
            el('span', { text: `👁️ ${fmtCount(v.views)} · ⏱️ ${fmtDuration(v.duration)} · ${ago(v.publishedAt)}` +
                               (v.channel?.displayName ? ` · 📺 ${v.channel.displayName}` : '') +
                               (v.isLive ? ' · 🔴 live' : '') }),
          ]),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
  }

  // ── federation ──────────────────────────────────────────────────
  async function federation() {
    const host = clear(body);
    host.append(el('p.muted', { text: 'Loading federation…' }));
    clear(host);
    const peerCard = (title, emoji, items, pick) => {
      const card = el('div.card', {}, [el('h3', { text: `${emoji} ${title} (${items.length})` })]);
      if (!items.length) card.append(el('div.empty', { text: 'None.' }));
      for (const p of items.slice(0, 40)) {
        const h = pick(p) || {};
        card.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: h.host || h.name || '(unknown)' }),
            el('span', { text: p.state || '' }),
          ]),
        ]));
      }
      return card;
    };
    // PeerTube's follow rows nest the peer under follower/following.
    await section(host, () => api.get(EP.followers(base)),
      (d) => peerCard('Followers', '📥', d.followers || [], (p) => p.follower));
    await section(host, () => api.get(EP.following(base)),
      (d) => peerCard('Following', '📤', d.following || [], (p) => p.following));
  }

  renderTabs();
  render();
}
