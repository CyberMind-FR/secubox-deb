// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: bbs — lire les fils du noeud, repondre, ecouter.
//
// Les routes consommees ici sont celles des MEMBRES (`/m/…`), pas celles de la
// console d'administration. Elles agissent AU NOM DU PORTEUR du jeton : le BBS
// resout le `sub` vers un compte, et ce qu'elles rendent depend de ce que CE
// compte a le droit de voir. Un jeton sans membre reconnu ne voit que le
// public et ne peut rien ecrire — le meme traitement qu'un visiteur du site.
const EP = {
  salons:  (b) => `${b}/m/salons`,
  fils:    (b) => `${b}/m/fils`,
  fil:     (b, id) => `${b}/m/fils/${id}`,
  reponse: (b, id) => `${b}/m/fils/${id}/reponse`,
};

export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, toast, ago, clear } = ui;

  const onglets = el('div.row', { style: 'gap:6px;margin-bottom:14px;flex-wrap:wrap' });
  const corps = el('div');
  root.append(onglets, corps);

  const ONGLETS = [['', 'Fils'], ['salons', 'Salons']];
  let actif = (location.hash.split('/')[4]) || '';

  function rendreOnglets() {
    clear(onglets);
    for (const [k, label] of ONGLETS)
      onglets.append(el(`button.btn.sm${k === actif && !actif.startsWith('fil:') ? '.primary' : ''}`, {
        text: label,
        onclick: () => { actif = k; navigate(`#/m/bbs/${k}`); rendreOnglets(); rendre(); },
      }));
  }

  function rendre() {
    if (actif.startsWith('fil:')) return fil(actif.slice(4));
    if (actif === 'salons') return salons();
    return fils();
  }

  // ── liste des fils ──────────────────────────────────────────────
  async function fils() {
    const hote = clear(corps);
    hote.append(el('p.muted', { text: 'Chargement…' }));
    try {
      const d = await api.get(EP.fils(base));
      clear(hote);
      if (d.__cached) hote.append(el('div.badge.warn', { text: 'hors ligne (en cache)' }));
      // Le dire franchement plutot que de laisser croire que le noeud est vide :
      // sans membre reconnu, seuls les fils publics remontent.
      if (!d.membre) hote.append(el('div.badge.warn', {
        text: 'compte non reconnu sur ce BBS — vue publique seulement',
      }));
      const items = d.fils || [];
      if (!items.length) return hote.append(el('div.empty', { text: 'Aucun fil.' }));
      for (const t of items) hote.append(ligneFil(t));
    } catch (e) { clear(hote); hote.append(el('div.empty', { text: e.message })); }
  }

  function ligneFil(t) {
    const badges = el('div.row', { style: 'gap:5px;flex-wrap:wrap' });
    badges.append(el(`div.badge${t.visibilite === 'public' ? '' : '.warn'}`, {
      text: t.visibilite === 'public' ? 'public' : 'local',
    }));
    if (t.source) badges.append(el('div.badge', { text: t.source }));
    if (t.media_type === 'video') badges.append(el('div.badge', { text: '▶ video' }));
    if (t.media_type === 'audio') badges.append(el('div.badge', { text: '♪ audio' }));
    if (t.billet) badges.append(el('div.badge', { text: '✦ billet' }));

    return el('div.item', {
      onclick: () => { actif = 'fil:' + t.id; navigate(`#/m/bbs/fil:${t.id}`); rendreOnglets(); rendre(); },
    }, [
      el('b', { text: t.titre || '(sans titre)' }),
      badges,
      el('div.meta', { text: `${esc(t.auteur || '')} · ${t.messages} message(s) · ${ago(t.date * 1000)}` }),
    ]);
  }

  // ── un fil ──────────────────────────────────────────────────────
  async function fil(id) {
    const hote = clear(corps);
    hote.append(el('button.btn.sm', {
      text: '← Fils',
      onclick: () => { actif = ''; navigate('#/m/bbs'); rendreOnglets(); rendre(); },
    }));
    hote.append(el('p.muted', { text: 'Chargement…' }));
    let d;
    try { d = await api.get(EP.fil(base, id)); }
    catch (e) { return hote.append(el('div.empty', { text: e.message })); }

    clear(hote);
    hote.append(el('button.btn.sm', {
      text: '← Fils',
      onclick: () => { actif = ''; navigate('#/m/bbs'); rendreOnglets(); rendre(); },
    }));
    const t = d.fil || {};
    hote.append(el('h3', { text: t.titre || '' }));

    // ── le media, joue sur place ──────────────────────────────────
    // On ECOUTE ET ON REGARDE la ou l'on en discute : renvoyer vers un autre
    // ecran perd la conversation en chemin.
    if (t.media && t.media_type === 'audio') {
      const a = el('audio', { style: 'width:100%;margin:10px 0' });
      a.controls = true; a.preload = 'none'; a.src = absolu(t.media);
      hote.append(a);
    } else if (t.media && t.media_type === 'video') {
      const cadre = el('div', { style: 'position:relative;aspect-ratio:16/9;margin:10px 0;background:#000' });
      const f = el('iframe', { style: 'position:absolute;inset:0;width:100%;height:100%;border:0' });
      f.src = t.media; f.allowFullscreen = true; f.loading = 'lazy';
      f.referrerPolicy = 'no-referrer';
      cadre.append(f); hote.append(cadre);
    }

    for (const m of (d.messages || [])) {
      hote.append(el('div.card', { style: 'margin-bottom:8px' }, [
        el('div.meta', {
          text: `${esc(m.auteur)} · ${ago(m.date * 1000)}${m.visibilite === 'local' ? ' · local' : ''}`,
        }),
        el('div', { text: m.corps }),
      ]));
    }

    // ── repondre ──────────────────────────────────────────────────
    const zone = el('textarea', {
      style: 'width:100%;min-height:80px;margin-top:10px', placeholder: 'Répondre…',
    });
    // LOCAL PAR DEFAUT, et « public » seulement offert dans un fil public :
    // une application mobile ne doit pas publier plus largement que le site, et
    // un doigt sur un petit ecran se trompe plus facilement qu'une souris.
    const pub = el('label.row', { style: 'gap:6px;margin:8px 0;font-size:12px' });
    const coche = el('input'); coche.type = 'checkbox';
    if (t.visibilite === 'public') {
      pub.append(coche, el('span', { text: 'publier ce message publiquement' }));
    } else {
      pub.append(el('span.muted', { text: 'fil local — la réponse reste dans la maison' }));
    }
    hote.append(zone, pub, el('button.btn.primary', {
      text: 'Envoyer',
      onclick: async (ev) => {
        const texte = zone.value.trim();
        if (!texte) return toast('message vide', 'err');
        ev.target.disabled = true;
        try {
          await api.post(EP.reponse(base, id), {
            corps: texte,
            visibilite: (t.visibilite === 'public' && coche.checked) ? 'public' : 'local',
          });
          zone.value = '';
          toast('envoyé');
          fil(id);
        } catch (e) { toast(e.message, 'err'); }
        finally { ev.target.disabled = false; }
      },
    }));
  }

  // ── salons ──────────────────────────────────────────────────────
  async function salons() {
    const hote = clear(corps);
    hote.append(el('p.muted', { text: 'Chargement…' }));
    try {
      const d = await api.get(EP.salons(base));
      clear(hote);
      for (const c of (d.salons || []))
        hote.append(el('div.item', {}, [
          el('b', { text: c.titre }),
          el('div.meta', { text: `${esc(c.description || '')} · ${c.fils} fil(s)` }),
        ]));
    } catch (e) { clear(hote); hote.append(el('div.empty', { text: e.message })); }
  }

  // L'audio est servi par la board, sous une adresse RELATIVE : elle doit etre
  // resolue contre l'hote configure, sinon l'application la chercherait chez
  // elle-meme et ne trouverait rien.
  function absolu(u) {
    if (/^https?:\/\//.test(u)) return u;
    const b = (api.origin || '').replace(/\/$/, '');
    return b + u;
  }

  rendreOnglets();
  rendre();
}
