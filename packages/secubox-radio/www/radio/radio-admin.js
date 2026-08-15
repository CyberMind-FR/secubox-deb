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

function rendPropositions(l) {
  var z = document.getElementById('propositions');
  z.innerHTML = '';
  if (!l || !l.length) { z.innerHTML = '<div class="vide">rien à valider</div>'; return; }
  l.forEach(function (p) {
    z.appendChild(ligne(p, [
      bouton('✓ Valider', 'good', function () {
        api('/propositions/' + p.id + '/valider', { method: 'POST' }).then(function (r) {
          toast(r.code === 200 ? 'Validée — elle entre à l’antenne.' : (r.corps.error || 'Refusé'));
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
      })
    ]));
  });
}

function rendProbas(pistes, enCours) {
  var z = document.getElementById('probas');
  z.innerHTML = '';
  var jouables = (pistes || []).filter(function (p) { return p.en_cache && !p.ecarte; });
  if (!jouables.length) { z.innerHTML = '<div class="vide">aucune piste jouable</div>'; return; }
  // LE PANNEAU N'INVENTE PAS LES POIDS : il montre ce que le serveur retient,
  // c'est-a-dire les coeurs et l'etat. Le calcul exact vit dans le demon —
  // le dupliquer ici garantirait que les deux divergent un jour.
  var total = jouables.reduce(function (s, p) { return s + (p.coeurs + 1); }, 0);
  jouables.sort(function (a, b) { return b.coeurs - a.coeurs; }).slice(0, 8).forEach(function (p) {
    var part = p.id === enCours ? 0 : (p.coeurs + 1) / total;
    var d = document.createElement('div');
    d.className = 'jauge';
    var nm = document.createElement('span');
    nm.className = 'nm2'; nm.textContent = p.titre || p.source;
    var bb = document.createElement('span');
    bb.className = 'bb';
    var i = document.createElement('i');
    i.style.width = Math.round(part * 100) + '%';
    bb.appendChild(i);
    var pc = document.createElement('span');
    pc.className = 'pc';
    pc.textContent = p.id === enCours ? 'au repos' : (part * 100).toFixed(1) + ' %';
    d.appendChild(nm); d.appendChild(bb); d.appendChild(pc);
    z.appendChild(d);
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
