// SecuBox-Deb :: BBS — le rail dépliable de la coquille.
//
// SANS JAVASCRIPT, LE RAIL RESTE UTILISABLE : à partir de la tablette il est
// affiché en permanence par la feuille de style, et sur téléphone la barre
// basse porte déjà les cinq destinations principales. Ce script n'ajoute qu'un
// confort — dérouler les salons sur un petit écran — jamais un passage obligé.
(function () {
  var bascule = document.querySelector('.menu-bascule');
  var rail = document.getElementById('rail');
  if (!bascule || !rail) return;

  function pose(ouvert) {
    document.body.classList.toggle('rail-ouvert', ouvert);
    bascule.setAttribute('aria-expanded', String(ouvert));
  }

  bascule.addEventListener('click', function () {
    pose(!document.body.classList.contains('rail-ouvert'));
  });

  // Refermer après avoir choisi : sur téléphone le rail recouvre la lecture,
  // et le laisser ouvert obligerait à un second geste pour voir ce qu'on vient
  // de demander.
  rail.addEventListener('click', function (e) {
    if (e.target.closest('a')) pose(false);
  });

  // Échap referme — c'est ce qu'on essaie d'abord devant un panneau ouvert.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.body.classList.contains('rail-ouvert')) {
      pose(false);
      bascule.focus();
    }
  });
})();

// ── Envoi d'une piece jointe depuis l'editeur ────────────────────────────
//
// SANS JAVASCRIPT, L'ENVOI RESTE POSSIBLE : la page « Mon compte » porte un
// formulaire classique, et l'adresse rendue se colle a la main dans le message.
// Ce script ne fait qu'eviter cet aller-retour.
(function () {
  function poser(zone, url) {
    var i = zone.selectionStart;
    // Une ligne a soi : colle en fin de phrase, l'adresse se retrouverait dans
    // le texte et le lecteur s'afficherait au milieu d'une ligne.
    var av = zone.value.slice(0, i).replace(/\s*$/, '');
    var ap = zone.value.slice(i);
    zone.value = av + (av ? '\n\n' : '') + url + '\n' + ap;
    zone.focus();
    zone.setSelectionRange(av.length + url.length + 2, av.length + url.length + 2);
  }

  document.querySelectorAll('.editor').forEach(function (bloc) {
    var bouton = bloc.querySelector('.joindre');
    var zone = bloc.querySelector('textarea');
    var champ = bloc.querySelector('input[type=file]');
    if (!bouton || !zone || !champ) return;

    bouton.addEventListener('click', function () { champ.click(); });

    champ.addEventListener('change', function () {
      if (!champ.files || !champ.files[0]) return;
      var f = new FormData();
      f.append('fichier', champ.files[0]);
      f.append('csrf', bouton.dataset.csrf || '');
      bouton.disabled = true;
      var libelle = bouton.textContent;
      bouton.textContent = '…';
      fetch('/f/envoi', {
        method: 'POST', body: f, headers: { 'Accept': 'application/json' },
      }).then(function (r) { return r.json(); })
        .then(function (j) {
          if (j.ok) poser(zone, j.url);
          // L'ERREUR EST DITE, pas avalee : un envoi refuse en silence donne
          // l'impression que le bouton ne marche pas.
          else alert('Envoi refusé : ' + (j.error || 'raison inconnue'));
        })
        .catch(function (e) { alert('Envoi impossible : ' + e.message); })
        .finally(function () {
          bouton.disabled = false;
          bouton.textContent = libelle;
          champ.value = '';
        });
    });
  });
})();
