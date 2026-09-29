/*
  domaine.js — le domaine de la box, DÉDUIT de l'hôte au lieu d'être écrit (#1493).

  POURQUOI. Le Hall, le relais et les cartes portaient « gk2.secubox.in » en
  dur : sur une autre box (VM de bêta, image neuve), « Connexion SecuBox… »
  envoyait la personne s'authentifier… chez gk2. La connexion réussissait,
  mais ailleurs, et le Hall local restait déconnecté.

  LA RÈGLE, en trois cas :
    · hall.<dom>        -> session sur <dom> : admin.<dom>, hall.<dom> ;
    · hall.<alias>      -> domaine public SANS le témoin de session (gk2.net) :
                           on relaie vers le domaine de session ;
    · IP, localhost,
      tout autre nom    -> MÊME ORIGINE : c'est le serveur par défaut de la box
                           qui répond, /login.html et /relais.html compris.

  Les sources gardent « gk2.secubox.in » comme domaine de référence ; `hote()`
  le réécrit vers le domaine réel. Sur gk2, rien ne change : c'est l'identité.
*/
(function (w) {
  'use strict';
  var REFERENCE = 'gk2.secubox.in';
  // Domaine public -> domaine qui porte le témoin de session.
  var ALIAS = { 'gk2.net': 'gk2.secubox.in' };

  var h = location.hostname.toLowerCase();
  var base = h.indexOf('hall.') === 0 ? h.slice(5) : null;
  // hall.localhost = le kiosque de la box (#1668) : MÊME ORIGINE, comme localhost.
  if (base === 'localhost') base = null;
  var session = base ? (ALIAS[base] || base) : null;

  function hote(s) {
    if (s == null || !session || session === REFERENCE) return s;
    return String(s).replace(/\.gk2\.secubox\.in\b/g, '.' + session);
  }

  // LIEN PARTAGEABLE (#1579). Le viewer copiait son adresse telle quelle :
  // « /api/v1/ytsas/stream/<id> », un chemin du Hall sans hôte, inutilisable
  // ailleurs. Un service qui sert sa propre API sur son vhost public (le flux
  // y part en 206 video/mp4) est partagé sur CET hôte ; tout autre chemin
  // relatif prend l'origine du Hall. Une adresse absolue reste telle quelle.
  var SERVIS_CHEZ_EUX = { ytsas: 1, podcaster: 1 };
  function partageable(u) {
    u = String(u == null ? '' : u).trim();
    if (!u || /^[a-z][a-z0-9+.-]*:/i.test(u)) return u;
    if (u.charAt(0) !== '/' || u.charAt(1) === '/') return u;
    var m = /^\/api\/v1\/([a-z0-9-]+)\//.exec(u);
    if (m && SERVIS_CHEZ_EUX[m[1]]) return 'https://' + hote(m[1] + '.gk2.secubox.in') + u;
    return location.origin + u;
  }

  w.SBX_DOMAINE = {
    // Domaine du témoin de session, ou null en mode « même origine ».
    session: session,
    // Le témoin de session arrive-t-il ici ? Faux seulement sur un alias.
    meme: !base || !ALIAS[base],
    // Origines de la connexion et du relais.
    admin: session ? 'https://admin.' + session : location.origin,
    hall: session ? 'https://hall.' + session : location.origin,
    // Origines acceptées en retour du relais (liste close).
    retours: (function () {
      if (!session) return [location.origin];
      var r = ['https://hall.' + session];
      for (var a in ALIAS) if (ALIAS[a] === session) r.push('https://hall.' + a);
      return r;
    })(),
    hote: hote,
    partageable: partageable
  };

  // Le HTML statique (liens de pied de carte, nom d'hôte affiché) suit la
  // même règle : réécrit une fois le document lu. Rien à faire sur gk2.
  if (session && session !== REFERENCE) {
    document.addEventListener('DOMContentLoaded', function () {
      var a = document.querySelectorAll('a[href*=".gk2.secubox.in"]');
      for (var i = 0; i < a.length; i++) a[i].setAttribute('href', hote(a[i].getAttribute('href')));
      var t = document.querySelectorAll('[data-sbx-hote]');
      for (var j = 0; j < t.length; j++) t[j].textContent = hote(t[j].textContent);
    });
  }
})(window);
