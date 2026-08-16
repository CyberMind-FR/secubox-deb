'use strict';
// Le panneau parle a l'API PAR L'AGREGATEUR : meme origine, prefixe complet.
var API = '/api/v1/radio';

function toast(m) {
  var t = document.getElementById('toast');
  t.textContent = m; t.style.display = 'block';
  setTimeout(function () { t.style.display = 'none'; }, 3200);
}

function api(chemin, options) {
  options = options || {};
  options.headers = Object.assign({ 'X-Sbx-Radio': '1' }, options.headers || {});
  if (options.body) options.headers['Content-Type'] = 'application/json';
  return fetch(API + chemin, options).then(function (r) {
    return r.json().catch(function () { return {}; })
      .then(function (d) { return { code: r.status, corps: d }; });
  });
}

// `textContent` PARTOUT : titres et pseudonymes viennent d'un service tiers ou
// d'un membre. Les injecter en balisage ferait de ce panneau la porte d'entree.
function ligne(p, actions) {
  var d = document.createElement('div');
  d.className = 'row';
  var sp = document.createElement('span');
  sp.className = 'sp';
  var nm = document.createElement('div');
  nm.className = 'nm';
  nm.textContent = p.titre || p.source;
  var su = document.createElement('div');
  su.className = 'su';
  var qui = (p.aimeurs || []).map(function (a) { return a.pseudo; }).filter(Boolean);
  su.textContent = '♥ ' + p.coeurs + (qui.length ? ' — ' + qui.join(', ') : '');
  sp.appendChild(nm); sp.appendChild(su);
  d.appendChild(sp);
  (actions || []).forEach(function (a) { d.appendChild(a); });
  return d;
}

function bouton(texte, classe, clic) {
  var b = document.createElement('button');
  b.className = 'btn ' + classe;
  b.textContent = texte;
  b.addEventListener('click', clic);
  return b;
}

function tag(texte, classe) {
  var s = document.createElement('span');
  s.className = 'tag ' + (classe || '');
  s.textContent = texte;
  return s;
}

// LES MORCEAUX D'UNE LISTE SONT GROUPES. Cinquante lignes melees au reste
// seraient illisibles : on ne saurait plus ce qui vient d'ou, ni combien il
// reste a trancher dans une liste donnee.
function enteteLot(titre, n) {
  var d = document.createElement('div');
  d.className = 'row';
  d.style.borderBottom = '1px solid var(--cyan)';
  var t = document.createElement('span');
  t.className = 'sp';
  t.style.color = 'var(--cyan)';
  t.textContent = '📃 ' + titre;
  d.appendChild(t);
  d.appendChild(tag(n + ' à trancher', 'c'));
  return d;
}

function ligneProposition(p) {
  return ligne(p, [
    bouton('✓ Valider', 'good', function () {
      api('/propositions/' + p.id + '/valider', { method: 'POST' }).then(function (r) {
        toast(r.code === 200 ? 'Validée — elle entre à l’antenne.'
                             : (r.corps.error || 'Refusé'));
        rafraichir();
      });
    }),
    bouton('✕ Refuser', 'danger', function () {
      // LE MOTIF EST DEMANDE, PAS FACULTATIF : sans lui, la question
      // « pourquoi pas celle-la » se repose chaque semaine.
      var motif = prompt('Motif du refus (il sera conservé) :');
      if (motif === null) return;
      api('/propositions/' + p.id + '/refuser',
          { method: 'POST', body: JSON.stringify({ motif: motif }) }).then(function () {
        toast('Refusée — la reproposer ne la fera pas revenir.');
        rafraichir();
      });
    }),
    boutonSupprimer(p)
  ]);
}

function rendPropositions(l) {
  var z = document.getElementById('propositions');
  z.innerHTML = '';
  if (!l || !l.length) { z.innerHTML = '<div class="vide">rien à valider</div>'; return; }
  var lots = {}, seules = [];
  l.forEach(function (p) {
    if (p.lot) {
      // LE TITRE DE LA LISTE peut manquer : on montre alors son identifiant
      // plutot qu'une cle technique nue, qui ne dit rien a qui doit trancher.
      if (!lots[p.lot]) {
        var t = p.lot_titre && p.lot_titre !== p.lot ? p.lot_titre
              : 'Playlist ' + p.lot.replace(/^ytpl:/, '');
        lots[p.lot] = { titre: t, items: [] };
      }
      lots[p.lot].items.push(p);
    } else {
      seules.push(p);
    }
  });
  Object.keys(lots).forEach(function (k) {
    z.appendChild(enteteLot(lots[k].titre, lots[k].items.length));
    lots[k].items.forEach(function (p) { z.appendChild(ligneProposition(p)); });
  });
  seules.forEach(function (p) { z.appendChild(ligneProposition(p)); });
}

function rendPlaylist(pistes, enCours) {
  var z = document.getElementById('playlist');
  if (!z) return;
  z.innerHTML = '';
  if (!pistes || !pistes.length) { z.innerHTML = '<div class="vide">rien a l antenne</div>'; return; }
  pistes.forEach(function (p) {
    var etat = p.ecarte ? tag(p.raison || 'écarté', 'r')
             : (p.en_cache ? tag(p.id === enCours ? 'en lecture' : 'prête',
                                 p.id === enCours ? 'c' : 'g')
                           : tag('récupération…', 'o'));
    z.appendChild(ligne(p, [etat, boutonDevalider(p), boutonSupprimer(p)]));
  });
}

function rendEcartes(pistes) {
  var z = document.getElementById('ecartes');
  z.innerHTML = '';
  var l = (pistes || []).filter(function (p) { return p.ecarte; });
  if (!l.length) { z.innerHTML = '<div class="vide">aucun</div>'; return; }
  l.forEach(function (p) { z.appendChild(ligne(p, [tag(p.raison || 'écarté', 'r')])); });
}

function stat(valeur, libelle, classe) {
  var d = document.createElement('div');
  d.className = 'stat-card ' + (classe || '');
  var v = document.createElement('div'); v.className = 'value'; v.textContent = valeur;
  var l = document.createElement('div'); l.className = 'label'; l.textContent = libelle;
  d.appendChild(v); d.appendChild(l);
  return d;
}

function rafraichir() {
  Promise.all([api('/playlist'), api('/propositions'), api('/current')])
    .then(function (r) {
      var pistes = (r[0].corps.pistes) || [];
      var props = (r[1].corps.propositions) || [];
      var cur = r[2].corps || {};
      var enCours = cur.piste ? cur.piste.id : 0;

      var g = document.getElementById('stats');
      g.innerHTML = '';
      g.appendChild(stat(pistes.length, 'à l’antenne', 'cyan'));
      g.appendChild(stat(props.length, 'à valider', 'purple'));
      g.appendChild(stat(pistes.filter(function (p) { return p.en_cache; }).length, 'en cache', 'green'));
      g.appendChild(stat(pistes.filter(function (p) { return p.ecarte; }).length, 'écartés', 'orange'));

      document.getElementById('subline').textContent = cur.silence
        ? 'silence — aucune piste prête'
        : 'en lecture : ' + (cur.piste ? (cur.piste.titre || cur.piste.source) : '?');

      rendPropositions(props);
      rendPlaylist(pistes, enCours);
      rendProbas(pistes, enCours);
      rendEcartes(pistes);
    })
    .catch(function () { toast('API injoignable'); });
}

function suivante() {
  api('/suivante', { method: 'POST' }).then(function (r) {
    toast(r.code === 200 ? 'Titre suivant.' : (r.corps.error || 'Refusé'));
    rafraichir();
  });
}

rafraichir();
setInterval(rafraichir, 30000);
