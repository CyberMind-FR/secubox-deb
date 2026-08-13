/* SPDX-License-Identifier: LicenseRef-CMSD-1.0
 * SecuBox-Deb :: zipjointes — cote navigateur (#1029)
 *
 * LE BOUTON EST DESACTIVE TANT QU'IL N'Y A PAS DEUX PIECES. Le laisser
 * cliquable pour n'afficher ensuite qu'un « rien a grouper » ferait faire un
 * aller-retour au serveur pour apprendre ce que la page savait deja.
 */
window.rcmail && rcmail.addEventListener('init', function () {
  rcmail.register_command('plugin.zipjointes.grouper', function () {
    // L'identifiant de composition vit dans le formulaire ; sans lui le
    // serveur ne saurait pas de quel brouillon on parle.
    var id = rcmail.env.compose_id || $('input[name="_id"]').val();
    rcmail.http_post('plugin.zipjointes.grouper', { _id: id }, true);
  }, true);

  function majEtat() {
    var n = $('#attachment-list > li').length;
    rcmail.enable_command('plugin.zipjointes.grouper', n >= 2);
    $('#zipjointes-grouper').toggleClass('disabled', n < 2);
  }

  majEtat();
  // La liste bouge a chaque ajout ou retrait : on suit, plutot que de figer
  // l'etat au chargement.
  rcmail.addEventListener('fileuploaded', majEtat);
  $(document).on('click', '#attachment-list a.delete', function () {
    setTimeout(majEtat, 300);
  });
});
