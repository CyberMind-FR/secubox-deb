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
    // LA ZONE DE TEXTE SEULE EST INDISPENSABLE : c'est la que l'adresse se pose.
    // Le trombone et l'enregistreur sont deux outils independants — exiger les
    // deux, comme le faisait la garde precedente, aurait fait taire
    // l'enregistreur sur tout editeur livre sans trombone.
    if (!zone) return;

    // ── ENVOI D'UN FICHIER DEJA SUR LA MACHINE ──────────────────────────────
    if (bouton && champ) {
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
    }

    // ── NOTE VOCALE ET NOTE VIDEO ───────────────────────────────────────────
    //
    // MEME CHEMIN QUE LE TROMBONE : meme envoi vers `/f/envoi`, meme insertion
    // de l'adresse par `poser`. Enregistrer produit un fichier comme un autre —
    // ouvrir un second chemin d'envoi aurait double les garde-fous a tenir, et
    // l'un des deux aurait fini par diverger de l'autre.
    bloc.querySelectorAll('.enregistrer').forEach(function (b) {
      var video = b.dataset.mode === 'video';
      var rec = null, flux = null, morceaux = [], tic = null;
      var icone = b.textContent;

      // LE FORMAT EST NEGOCIE, PAS SUPPOSE. Firefox sait ecrire de l'Ogg/Opus,
      // Chrome souvent seulement du WebM. On prend le premier format que le
      // navigateur declare savoir produire, plutot que d'en imposer un qui
      // echouerait chez la moitie des gens.
      function choisi() {
        var l = video
          ? ['video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm']
          : ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/webm'];
        for (var i = 0; i < l.length; i++) {
          if (window.MediaRecorder && MediaRecorder.isTypeSupported(l[i])) return l[i];
        }
        return '';
      }

      // LE MICRO ET LA CAMERA SE RELACHENT EXPLICITEMENT. Sans cela la diode
      // reste allumee apres l'envoi, et c'est le genre de detail qui fait
      // douter de tout le reste.
      function libere() {
        if (flux) { flux.getTracks().forEach(function (t) { t.stop(); }); flux = null; }
        if (tic) { clearInterval(tic); tic = null; }
        b.classList.remove('en-cours');
        b.textContent = icone;
      }

      b.addEventListener('click', function () {
        if (rec && rec.state === 'recording') { rec.stop(); return; }
        if (!navigator.mediaDevices || !window.MediaRecorder) {
          alert("Ce navigateur ne sait pas enregistrer. Le trombone reste "
              + "disponible pour envoyer un fichier deja enregistre.");
          return;
        }
        var type = choisi();
        navigator.mediaDevices
          .getUserMedia(video ? { audio: true, video: true } : { audio: true })
          .then(function (s) {
            flux = s;
            morceaux = [];
            rec = new MediaRecorder(flux, type ? { mimeType: type } : undefined);
            rec.ondataavailable = function (e) { if (e.data.size) morceaux.push(e.data); };
            rec.onstop = function () {
              var mime = rec.mimeType || type || (video ? 'video/webm' : 'audio/ogg');
              libere();
              if (!morceaux.length) return;
              var ext = mime.indexOf('ogg') >= 0 ? 'ogg' : 'webm';
              var nom = (video ? 'video-' : 'vocal-') + Date.now() + '.' + ext;
              var f = new FormData();
              f.append('fichier', new Blob(morceaux, { type: mime }), nom);
              f.append('csrf', b.dataset.csrf || (bouton && bouton.dataset.csrf) || '');
              b.disabled = true;
              b.textContent = '…';
              fetch('/f/envoi', {
                method: 'POST', body: f, headers: { 'Accept': 'application/json' },
              }).then(function (r) { return r.json(); })
                .then(function (j) {
                  if (j.ok) poser(zone, j.url);
                  else alert('Envoi refusé : ' + (j.error || 'raison inconnue'));
                })
                .catch(function (e) { alert('Envoi impossible : ' + e.message); })
                .finally(function () { b.disabled = false; b.textContent = icone; });
            };
            rec.start();
            var t0 = Date.now();
            b.classList.add('en-cours');
            tic = setInterval(function () {
              var n = Math.floor((Date.now() - t0) / 1000);
              b.textContent = '■ ' + Math.floor(n / 60) + ':'
                            + String(n % 60).padStart(2, '0');
            }, 250);
          })
          .catch(function () {
            // ON DIT OU AUTORISER, pas « erreur ». Le refus de permission est le
            // cas de loin le plus frequent, et le seul sur lequel on peut agir.
            alert("Micro ou caméra refusé. Autorisez l'accès à ce site dans les "
                + "réglages du navigateur, puis réessayez.");
          });
      });
    });
  });
})();
