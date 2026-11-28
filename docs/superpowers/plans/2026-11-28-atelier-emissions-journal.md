<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
See LICENCE-CMSD-1.0.md for terms.
-->
# Atelier des émissions — journal des décisions (#4058)

## Vague 1

- **Task 4** — Décision : `amorcer` lit les réponses de `GET /rapports/{genre}/{id}` et retient celles dont
  `ia.etat == "fait"` (« ia » aussi accepté) et non `perimee` — parce que gk2 (`rapports.rediger`) écrit
  `etat: "fait"`, jamais `"ia"` comme l'écrit le plan — coût si faux : amorçage vide, à corriger d'un mot.
- **Task 4** — Décision : `statut` gk2 « retenue » devient « verifiee » ; les retirées ne sont jamais stockées ;
  `Magasin` prend un `maintenant` facultatif (tests) — parce que le schéma du plan n'admet que
  `verifiee|hypothese` — coût si faux : nul (paramètre facultatif).
- **Task 4** — Décision : empreinte = sha256 du JSON trié tronqué à 16 caractères, comme `rapports.signature` —
  parce que le plan dit « signature-like » — coût si faux : comparaison d'empreinte avec gk2 à adapter.
- **Task 8** — Décision : « bans par jour » rendu par semaine (`serie_semaine`), plus un graphique « vague-N » par
  vague (fenêtre mise en avant) — parce que le dossier de gk2 ne transmet que `serie_semaine` (`serie_jour` reste
  dans `h`) — coût si faux : ajouter `serie_jour` au dossier côté gk2 puis un graphique.
- **Task 8** — Décision : association par termes = graphique partageant le plus de termes (égalité : le premier) —
  parce que « bans » est cité partout et capterait toutes les répliques — coût si faux : réglage du score.
- **Task 8** — Note : `rsvg-convert` et `oxipng` absents de gk0 ; `png()` lève `RuntimeError` sans rsvg, son test
  est sauté (rien installé). À installer avant la vague 3 (montage) : `librsvg2-bin`, `oxipng`.
- **Task 9** — Décision : arrêt et relance de Gemma par les routes locales du relais (`/moteur/arreter`,
  `/moteur/demarrer`, fabrique `gpu.par_relais()`), pas par `systemctl --user` — parce que `poc-llama` est une unité
  TRANSITOIRE (systemd-run par le relais) : arrêtée, elle disparaît et `systemctl start` ne la recrée pas — coût si
  faux : fournir à `VerrouGPU` deux autres fonctions, l'interface ne change pas.
- **Task 9** — Décision : routes gardées en 503 = chat (`/v1/chat/completions`, avec ou sans préfixe), `essai/flux`,
  `agents/{nom}`, `documents/{id}/analyser`, `moteur/demarrer`, `jarvis/*` (relevées dans relais.py de gk0) ;
  seule la relance portant la clé du verrou (`X-Emissions-Cle`, fichier 0600) passe — parce que le relais réveille
  le moteur à la première requête : sans cela une conversation relancerait Gemma en pleine voix — coût si faux : une
  route oubliée réveille le GPU (contention, pas de fuite).
- **Task 9** — Décision : le verrou est retiré même si la relance échoue (l'erreur remonte, journalisée) — parce
  qu'un verrou resté posé couperait le relais indéfiniment — coût si faux : Gemma reste arrêté jusqu'au prochain
  réveil normal (le relais le relance à la demande).
- **Task 9** — Note : `emissions_relais.py` n'est PAS copié dans `~/poc-secubox-ai/relais/` (relais en marche
  intouché) ; branchement à faire à la Task 14.
- **Task 12** — Décision : `balayer(..., ocr=None)` prend un lecteur OCR remplaçable (défaut : `tesseract -l
  fra+eng`) ; tesseract absent ou en erreur → `ocr_echec` (bloquant) — parce que tesseract n'est pas installé sur
  gk0 (rien installé par sudo) — coût si faux : aucun ; en production sans tesseract, rien d'illustré n'est publiable
  tant que `tesseract-ocr tesseract-ocr-fra` n'est pas installé.
- **Task 12** — Note : `test_balayage_bloque_ip_dans_png` tourne avec un FAUX OCR (texte dessiné rangé dans un bloc
  tEXt du PNG) ; la variante « tesseract » s'ajoute d'elle-même quand l'outil est présent. À rejouer après
  installation de tesseract.
- **Task 12** — Décision : liste par défaut des noms internes (gk0…gk7, `.lan`, `.local`, `.internal`,
  `.home.arpa`) quand le fichier manque ; un nom commençant par « . » est un suffixe — parce que le fichier peut ne
  pas exister au premier lancement — coût si faux : un nom interne non listé passe (à ajouter au fichier).
- **Task 12** — Décision : toute suite ≥ 32 caractères base64/hex est un `jeton`, empreintes sha256 comprises —
  parce que la consigne est stricte — coût si faux : faux positif, l'auteur reformule.
- **Task 13** — Décision : `capturer(url, zone, sortie, *, navigateur=None, ocr=None, masques=None,
  noms_internes=None)` — prise de vue et OCR remplaçables, défaut chromium headless par Playwright — parce que ni
  Playwright ni chromium ne sont sur gk0 (rien installé) — coût si faux : aucun sur l'interface (arguments nommés
  facultatifs). Les tests utilisent un faux navigateur (masquage simulé) et un faux OCR ; le chemin Playwright réel
  n'est PAS testé : à rejouer après installation (`playwright` dans le venv + `playwright install chromium`).
- **Task 13** — Décision : registre des captures = `<brouillon>/captures.json` (`enregistrer_capture`,
  `valider_capture(brouillon, id, accord)` → `validee`/`rejetee`, `captures_validees`) ; une capture `refusee` ne se
  valide jamais (ValueError) — parce que le plan ne fixe pas le format du brouillon — coût si faux : la Task 14
  adapte l'emplacement du registre.
- **Task 13** — Décision : liste blanche par défaut `127.0.0.1`, `localhost` (`masques.toml`, section `[hotes]`) —
  parce que l'hôte local du tunnel vers l'admin de gk2 n'est pas connu ici — coût si faux : capture refusée tant que
  l'hôte n'est pas ajouté.

## Vague 2

- **Task 2** — Décision : fonctions dans `api/services/media.py` (pas `api/media.py`, inexistant) et outil
  `sbin/secubox-billets-auteur-emissions` (installé dans `/usr/sbin`) qui appelle `python -m api.manage
  auteur-emissions` sous `secubox` — parce que le module média du paquet vit dans `services/` — coût si faux : nul.
- **Task 2** — Décision : le jeton `billets-emissions.jeton` est un secret propre aux billets, accepté en
  `Authorization: Bearer` par la seule écriture de `/admin/api/billets` (comparaison en temps constant), à côté de la
  session `billets.publish` ; l'auteur `emissions` a un mot de passe aléatoire jamais montré — parce que l'API JSON
  n'accepte qu'un JWT SecuBox qu'on ne peut pas frapper depuis gk0, et que créer un auteur sans jeton ne servait à
  rien — coût si faux : remplacer par une capacité JWT dédiée ; la Task 17 lit le jeton d'un fichier 0600 sur gk0
  (copie à poser par le propriétaire, jamais en clair dans le dépôt).
- **Task 2** — Décision : garde d'espace par `UploadFile.size` AVANT `create_billet` (formulaire) et par `len(raw)`
  à `POST /admin/api/billets/{id}/media` ; réponse 507 — parce que « rien écrit » doit couvrir le billet lui-même —
  coût si faux : nul.
- **Task 2** — Décision : « la minuterie existante du paquet » n'existe pas : nouvelle `secubox-billets-purge-mp4.timer`
  (quotidienne 04:20, `Persistent`) → `api.manage purger-mp4`, qui retire aussi les lignes média dont le MP4 a disparu ;
  la vignette JPEG d'un MP4 purgé reste (image) — coût si faux : quelques vignettes orphelines.
- **Task 2** — Note : 52 échecs/erreurs de la suite billets sont préexistants et identiques sur `origin/master`
  (connexion d'administration du banc, jar de cookies httpx) ; la garde est testée par une session simulée.
- **Task 5** — Décision : « actif » = dernier ban (fin de dernière vague ou dernière semaine non nulle) à moins de 7
  jours de la date de lecture (`genere_le` pour le précédent, `maintenant` pour le courant) ; `retour_acteur` exclut
  `nouvelle_vague` pour la même vague — parce que le dossier ne transmet pas de « dernier ban » explicite — coût si
  faux : un retour ou une extinction décalés de quelques jours.
- **Task 5** — Décision : `operateur_nouveau` non marquant, `phase`/`nouvelle_vague`/`extinction`/`retour_acteur`
  marquants, `chiffre` marquant si écart ≥ 25 % (base nulle = 100 %) ; chiffres comparés : bans, adresses, /24, jours
  actifs, vagues — coût si faux : seuil hebdo (Task 16) atteint plus ou moins souvent.
- **Graphiques (suite Task 8)** — Décision : compression PNG facultative, oxipng sinon `optipng -o2`, sinon rien —
  parce qu'oxipng n'est pas dans les dépôts de gk0 — coût si faux : PNG plus lourds.
- **Task 6** — Décision : `lister()` rend la liste `sujets` de `GET /rapports` (vide si `disponible` est faux), pas
  l'objet entier — parce que le plan type la sortie `list[dict]` — coût si faux : `age_s`/`complet` à relire par un
  second accès si la page veut les montrer.
- **Task 6** — Décision : identifiant filtré par le motif de gk2 (`[A-Za-z0-9_:.-]{1,80}`) plus refus de `..` ; jeton
  relu à chaque appel par `jeton_fichier()`, refusé s'il n'est pas 0600 ; client httpx `trust_env=False` — parce
  qu'un mandataire d'environnement ne doit pas voir le jeton — coût si faux : nul.
- **Task 10** — Décision : `dire_tout(..., *, moteur=None, verrou=None)` — arguments nommés facultatifs en plus de la
  signature du plan (défauts : `MoteurVoix()` vers `127.0.0.1:7443`, `gpu.par_relais()`) — parce que le plan ne dit pas
  comment injecter le worker et le verrou — coût si faux : nul (l'appel du plan reste valide).
- **Task 10** — Décision : client minimal propre (`MoteurVoix`, contrat OpenAI `POST /v1/audio/speech`), pas d'import de
  `secubox-voicestudio/api/moteur.py` ; clé du worker lue de `~/.config/secubox-ai-jeton/voicestudio` (0600 exigé) —
  parce que les deux paquets ne s'installent pas ensemble sur gk0 — coût si faux : chemin de clé à adapter au worker
  #4057 quand il sera prêt.
- **Task 10** — Décision : validation de toutes les répliques AVANT le verrou ; rien à faire → Gemma n'est pas
  suspendu ; voix périmées (`<rang>-*` d'une empreinte ancienne ou réplique retirée) ôtées après un passage réussi ;
  écriture atomique 0600 — parce qu'une voix restée d'une réplique retirée pourrait finir au montage — coût si faux : nul.
- **Task 10** — Note : testé contre un FAUX worker HTTP sur socket Unix ; le worker GPU réel (#4057, CUDA en panne sur
  gk0) n'est PAS testé : à rejouer contre lui (`rang`/`voix` nova/onyx, durée réelle, délai 120 s suffisant ?).
- **Rejeu fin de vague 2** — tesseract (fra+eng), rsvg-convert et optipng présents sur gk0 : `test_png` et
  `test_balayage_bloque_ip_dans_png[tesseract]` passent (plus sautés). Playwright/chromium présents dans le venv mais le
  chemin de capture réelle n'est pas encore testé (vague 3). Seul échec de la suite ai-agents : `test_voix_4000.py::
  test_transcription_reelle` (whisper réel, « jarvi » au lieu de « jarvis »), préexistant et hors #4058.

## Vague 3

- **Task 7** — Décision : rangs à partir de 0 (comme les tests de la Task 10) ; une ligne sans préfixe V1/V2 prolonge
  la réplique en cours, le texte avant la première est ignoré ; gras et « V2 : » tolérés — coût si faux : nul.
- **Task 7** — Décision : une réplique est ✗ dès qu'une de ses phrases est retirée par `verif_rapport.verifier`, SAUF
  si les seuls motifs sont « phrase non adossée » ou « ne redit que la fenêtre » (question, transition : règle
  assouplie de la spec) ; une supposition (même non ancrée) donne ⚠ `ia_seule` ; champ `marque` ∈ ✓/⚠/✗ ajouté —
  parce que l'essai réel du 28/11 a montré « Cela suggère … probablement … » sans chiffre passer ✓ — coût si faux :
  une phrase d'opinion sans chiffre ni supposition passe ✓ (le relecteur la voit au brouillon).
- **Task 7** — Décision : `ecrire(consigne, *, socket=None, …)` POST `/v1/chat/completions` non diffusé sur le socket
  `SECUBOX_AI_AGENTS_MOTEUR` (défaut `~/poc-secubox-ai/run/llama.sock`), httpx `trust_env=False`, délai 300 s ;
  `associer_diapos(repliques, graphs)` = `graphiques.associer` sur les seules répliques dites — coût si faux : nul.
- **Task 7** — Note : essai réel unique (≈300 jetons) sur Gemma par le socket, rien arrêté : 4 répliques V1/V2
  découpées, 2 retirées à juste titre (« 900 », « 90 » absents du dossier). Gemma tend à citer des chiffres hors
  dossier : prévoir à la Task 14 un affichage clair des ✗ et une consigne de réécriture.
- **Task 11** — Décision : `replique` de la chronologie = TEXTE dit (≤ 500 caractères, blancs repliés), pas un rang
  entier comme l'écrit le plan — parce que le modèle des billets fusionné (`api/models.py:Replique`, Task 1) type
  `replique: str` ; `test_chronologie_acceptee_par_billets` passe la sortie au `valider_chronologie` des billets —
  coût si faux : nul (format imposé par le consommateur).
- **Task 11** — Décision : `diapo` = rang de l'image dans l'ordre de première apparition des ids de graphiques parmi
  les répliques dites ; `ordre_images(repliques, diapos)` rend cet ordre : la Task 17 DOIT joindre les images au billet
  dans cet ordre (le billet compte les seules images) — coût si faux : diapositives décalées.
- **Task 11** — Décision : durée = durée DÉCODÉE (échantillons à 44,1 kHz), chaque voix coupée à cette durée
  (`atrim`) puis `apad` 0,45 s (sauf la dernière) : chronologie exacte par construction — parce que ffprobe annonce
  1,056 s pour un MP3 de 1,0 s (remplissage d'encodeur), écart de 0,16 s mesuré sur 3 répliques — coût si faux : nul.
- **Task 11** — Décision : `loudnorm=I=-16:TP=-1.5:LRA=11` en une passe ; fichiers écrits par fichier temporaire puis
  `os.replace`, 0600 ; `video()` = concat d'images (chaque image du début de sa réplique au début de la suivante),
  H.264 `stillimage` + AAC 128k, `-shortest`, `faststart` ; `monter` n'écrit jamais de MP4 — coût si faux : nul.
- **Task 11** — Note : tests sur de VRAIS MP3 produits par ffmpeg (sinus), MP4 vérifié par ffprobe ; ffmpeg 7 de gk0
  avec libmp3lame et libx264. Suite du paquet : 62 réussis, 4 sautés (`test_voix_4000::test_transcription_reelle`
  instable : un échec puis une réussite au rejeu, hors #4058).

## Vague 4

- **Task 14** — Décision : voix = Voice Studio LOCAL de gk0 (`voicestudio-worker`, `http://127.0.0.1:3910`, réglage
  `voix_url`) et plus le tunnel 7443 vers gk3 ; clé du worker FACULTATIVE (fichier absent → aucun en-tête : le worker
  n'exige pas de clé sur la boucle locale) — décision du propriétaire du 28/11 — coût si faux : poser
  `~/.config/secubox-ai-jeton/voicestudio`.
- **Task 14** — Décision : suspension de Gemma conditionnelle au réglage `voix_gpu` (défaut `false`, CUDA en panne) ;
  `gpu.SansSuspension` (aucun verrou, relais disponible) sinon `par_relais()` ; mécanisme gardé intact — coût si faux :
  contention GPU si quelqu'un passe la voix sur CUDA sans basculer le réglage.
- **Task 14** — Décision : réseau de l'unité = boucle locale + adresses de `admin.gk2.secubox.in` et
  `billets.gk2.secubox.in` résolues à l'installation (drop-in `reseau.conf`), pas « 127.0.0.1 seul » comme le plan —
  parce qu'il n'existe pas de tunnel vers l'API de gk2 : le relais lui-même lit gk2 en HTTPS public — coût si faux :
  relancer l'installateur si l'adresse publique de gk2 change (sinon gk2 injoignable, rien d'autre).
- **Task 14** — Décision : le service tourne sur le venv du dépôt (celui du relais : fastapi, httpx, uvicorn,
  playwright), code copié par `installer-emissions.sh` dans `~/.local/lib/secubox-ai-emissions/src` — parce que
  `/opt/secubox-ai-agents/venv` est à root et n'a pas playwright (pas de sudo) ; `secubox-ai-agents-construire` copie
  aussi `emissions/` pour la suite — coût si faux : nul.
- **Task 14** — Décision : jeton local = le même que `secubox-ai-agents` (`~/.config/secubox-ai-jeton/jeton`), garde
  recopiée (pas d'import de `agents/`) — coût si faux : nul.
- **Task 14** — Décision : synthèse à plusieurs sujets → chaque réplique garde le MEILLEUR verdict contre l'un des
  dossiers ; graphiques préfixés `s<k>-` ; titre/chapeau automatiques, modifiables (`POST {id}/entete`, route ajoutée) ;
  `POST {id}/replique/{rang}/reecrire` ajoutée (Gemma invente des chiffres : proposition vérifiée, appliquée seulement
  par le propriétaire) ; captures validées posées sur une réplique (`rang`) → elles entrent au diaporama, seul le montage
  est refait.
- **Task 14** — Décision : « client non local » → c'est le `local` du relais qui répond (404 dans le relais réel, 403
  dans le test qui le simule) ; le relais ne touche ni au relais en marche ni à poc-llama : branchement par
  `installer-emissions.sh` (2 lignes en fin de relais.py, onglet « Émissions » après « Filtres WAF » dans
  `index.html` = entrée `['emissions', 'Émissions']` dans `ONGLETS` + `<section data-o="emissions">` contenant une
  iframe `/emissions`, sauvegardes `.avant-emissions`) — NON exécuté, à lancer par le propriétaire.
- **Task 14** — Note : `lecture-gk2` (jeton de lecture des dossiers) ABSENT de `~/.config/secubox-ai-jeton/` sur gk0 :
  sans lui, `GET sources` répond 502. Chromium par Playwright sous le durcissement de l'unité (ProtectHome=read-only,
  sans PrivateUsers) non essayé.
- **Task 15** — Décision : page fidèle à la maquette (trois colonnes, chaîne 7 étapes, lecteur + diapo synchronisée,
  dialogue, validation, rythme hebdo) mais SANS Google Fonts (aucun CDN : polices système en repli) ; ✗ sur fond rouge
  avec leurs motifs, boutons « Modifier » et « Réécrire cette réplique » (proposition vérifiée → Accepter/Écarter) ;
  « Publier » désactivé tant que le brouillon n'est pas prêt, que `GET {id}/controle` (balayage, Task 17) n'est pas vide
  ou qu'une capture attend sa validation ; aucun `innerHTML` (textes de gk2 et du LLM par textContent) — coût si faux : nul.
- **Task 15** — Décision : l'onglet « Émissions » de la barre du relais = iframe `/emissions` (même origine, Host local)
  ajoutée par l'installateur, plutôt qu'une copie du panneau dans `index.html` (fichier vivant du POC, hors dépôt) —
  coût si faux : une hauteur d'iframe fixe (calc(100vh − 140px)).
