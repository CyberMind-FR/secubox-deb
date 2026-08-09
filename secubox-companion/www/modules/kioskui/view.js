// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: kioskui — piloter l'ecran attache a la board.
//
// CE MODULE AGIT SUR UN ECRAN QU'ON NE VOIT PAS depuis le telephone. C'est ce
// qui gouverne toutes les decisions d'interface ici :
//
//   - l'etat est TOUJOURS relu apres une action, jamais suppose. Un bouton qui
//     se colore parce qu'on l'a touche, alors que rien n'a change sur l'ecran,
//     ment a quelqu'un qui n'est pas dans la piece.
//
//   - couper le kiosque demande une confirmation. Sur un affichage ambiant —
//     une TV de salon, un miroir — c'est le seul moyen de le rallumer, et il
//     n'y a personne devant pour s'en apercevoir.
const EP = {
  status:  (b) => `${b}/kiosk/status`,
  enable:  (b) => `${b}/kiosk/enable`,
  disable: (b) => `${b}/kiosk/disable`,
  board:   (b) => `${b}/board`,
  caps:    (b) => `${b}/board/capabilities`,
};

export default async function mount(ctx) {
  const { root, api, base, ui, navigate } = ctx;
  const { el, esc, toast, clear, confirmAction } = ui;

  const onglets = el('div.row', { style: 'gap:6px;margin-bottom:14px;flex-wrap:wrap' });
  const corps = el('div');
  root.append(onglets, corps);

  const ONGLETS = [['', 'Kiosque'], ['board', 'Matériel']];
  let actif = (location.hash.split('/')[4]) || '';

  function rendreOnglets() {
    clear(onglets);
    for (const [k, label] of ONGLETS)
      onglets.append(el(`button.btn.sm${k === actif ? '.primary' : ''}`, {
        text: label,
        onclick: () => { actif = k; navigate(`#/m/kioskui/${k}`); rendreOnglets(); rendre(); },
      }));
  }
  function rendre() { return actif === 'board' ? materiel() : kiosque(); }

  // ── kiosque ─────────────────────────────────────────────────────
  async function kiosque() {
    const hote = clear(corps);
    hote.append(el('p.muted', { text: 'Lecture de l’état…' }));
    let s;
    try { s = await api.get(EP.status(base)); }
    catch (e) { clear(hote); return hote.append(el('div.empty', { text: e.message })); }

    clear(hote);
    if (s.__cached) hote.append(el('div.badge.warn', { text: 'hors ligne (en cache)' }));

    // L'ETAT DU SERVICE ET L'ETAT DEMANDE SONT DEUX CHOSES. Un kiosque
    // « active » dont le service ne tourne pas laisse un ecran noir : les
    // confondre enverrait chercher la panne du cote de l'ecran.
    const allume = !!s.service_active;
    hote.append(el('div.card', {}, [
      el('div.row', { style: 'gap:8px;align-items:center' }, [
        el(`div.badge${allume ? '' : '.warn'}`, { text: allume ? '● à l’écran' : '○ éteint' }),
        el('div.badge', { text: `mode ${esc(s.mode || 'inconnu')}` }),
        el(`div.badge${s.service_enabled ? '' : '.warn'}`, {
          text: s.service_enabled ? 'au démarrage' : 'pas au démarrage',
        }),
      ]),
      el('div.meta', {
        text: allume
          ? 'L’écran attaché affiche le tableau de bord.'
          : (s.enabled
              ? 'Activé mais le service ne tourne pas — l’écran est noir.'
              : 'Aucun affichage sur l’écran attaché.'),
      }),
    ]));

    const modes = (s.display_modes && s.display_modes.length) ? s.display_modes : ['x11', 'wayland'];
    const actions = el('div.row', { style: 'gap:8px;margin-top:12px;flex-wrap:wrap' });

    for (const m of modes)
      actions.append(el(`button.btn${s.mode === m && allume ? '' : '.primary'}`, {
        text: `Allumer en ${m}`,
        onclick: async (ev) => {
          ev.target.disabled = true;
          try {
            await api.post(EP.enable(base), { mode: m });
            toast(`kiosque demandé en ${m}`);
          } catch (e) { toast(e.message, 'err'); }
          // ON RELIT TOUJOURS. L'appel a pu reussir sans que l'ecran suive —
          // service qui refuse de demarrer, sortie video absente. Afficher le
          // resultat demande plutot que l'etat reel tromperait quelqu'un qui
          // n'est pas devant l'ecran.
          finally { kiosque(); }
        },
      }));

    if (s.enabled || allume)
      actions.append(el('button.btn.danger', {
        text: 'Éteindre',
        onclick: async () => {
          // Sur un affichage ambiant, le telephone est souvent le SEUL moyen
          // de rallumer : il n'y a ni clavier ni personne devant.
          // `confirmAction` du coeur prend UN seul argument : on n'etend pas le
          // coeur pour un module, on s'y conforme.
          const ok = await confirmAction(
            'Éteindre le kiosque ?\n\n' +
            'L’écran attaché n’affichera plus rien. Il n’y a pas de clavier ' +
            'devant : cette application sera le seul moyen de le rallumer.');
          if (!ok) return;
          try { await api.post(EP.disable(base), {}); toast('kiosque éteint'); }
          catch (e) { toast(e.message, 'err'); }
          finally { kiosque(); }
        },
      }));

    hote.append(actions);
    hote.append(el('button.btn.sm', { text: '↻ Relire l’état', onclick: () => kiosque() }));
  }

  // ── materiel ────────────────────────────────────────────────────
  async function materiel() {
    const hote = clear(corps);
    hote.append(el('p.muted', { text: 'Chargement…' }));
    // Les capacites peuvent manquer sans que la fiche materielle soit
    // inutilisable : on n'abandonne pas les deux parce que l'une echoue.
    const [b, c] = await Promise.all([
      api.get(EP.board(base)).catch(() => null),
      api.get(EP.caps(base)).catch(() => null),
    ]);
    clear(hote);
    if (!b && !c) return hote.append(el('div.empty', { text: 'Matériel non lisible.' }));

    if (b) {
      const lignes = el('div.stack');
      for (const [k, v] of Object.entries(b)) {
        if (v === null || typeof v === 'object') continue;
        lignes.append(el('div.item', {}, [
          el('b', { text: k }), el('div.meta', { text: String(v) }),
        ]));
      }
      hote.append(el('div.card', {}, [el('h3', { text: 'Carte' }), lignes]));
    }
    if (c) {
      const caps = el('div.row', { style: 'gap:6px;flex-wrap:wrap' });
      for (const [k, v] of Object.entries(c)) {
        if (typeof v !== 'boolean') continue;
        caps.append(el(`div.badge${v ? '' : '.warn'}`, { text: `${v ? '✓' : '✗'} ${k}` }));
      }
      if (caps.children.length)
        hote.append(el('div.card', {}, [el('h3', { text: 'Capacités' }), caps]));
    }
  }

  rendreOnglets();
  rendre();
}
