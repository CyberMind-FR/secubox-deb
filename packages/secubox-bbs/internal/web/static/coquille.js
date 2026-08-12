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
