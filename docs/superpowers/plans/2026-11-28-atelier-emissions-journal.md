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
