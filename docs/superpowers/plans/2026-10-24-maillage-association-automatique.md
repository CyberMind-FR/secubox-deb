<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Association automatique au maillage — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** une box flashée par le netboot d'un maître le rejoint seule au premier démarrage et n'accepte que lui ; une
box déjà associée reçoit l'ancre a posteriori ; une box non flashée entre par le panneau premier-pas du maître.

**Architecture :** une « ancre » (clé publique WireGuard du maillage du maître, adresse, nom, empreinte) gardée sur la
box et vérifiée par `sbx-mesh-join`. Le maître émet, pour chaque flash, un lot signé avec sa clé netboot (code
d'invitation + ancre + nom + domaine) ; `sbx-netflash` le récupère, le vérifie, l'écrit dans le système flashé avec un
profil premier-pas. Le reflash d'un nom connu remplace l'ancienne clé en gardant l'adresse maillée.

**Tech Stack :** Python 3.13 (FastAPI, pytest), bash, systemd, WireGuard, OpenSSL (signature RSA SHA-256 existante du
netboot), argon2 (`python3-argon2`), paquets Debian (`secubox-p2p`, `secubox-netboot`, `secubox-premier-pas`).

**Spec :** `docs/superpowers/specs/2026-10-24-maillage-association-automatique-design.md`

## Global Constraints

- Fichier d'ancre sur la box : `/etc/secubox/p2p/ancre-maitre.json`, root, 0644 ; jamais écrasé s'il existe, sauf par un lot de flash.
- Code d'invitation au format automesh : `sbxmesh1.<b64url{"a":adresse,"t":jeton}>.<sha256[:4]>`, jeton de **64** hexadécimaux.
- Code déposé : `/var/lib/secubox/p2p/automesh.code`, root, 0600 ; `automesh` le jette 24 h après dépôt.
- Durée de validité d'un code de flash : **48 h** (172800 s).
- Domaine d'une box flashée : `<nom>.` + parent du domaine du maître (`gk2.secubox.in` → `gk1.secubox.in`).
- Racine écrite : `/dev/mmcblk0p2` (ext4) ; partition de démarrage : `/dev/mmcblk0p1` (vfat), profil dans `secubox/profil.toml`.
- `[admin] mot_de_passe` du profil : empreinte argon2 seulement (`$argon2id$…`), jamais du clair.
- Signature des lots : même clé et même commande que les images netboot (`openssl dgst -sha256 -sign` / `-verify`, clé publique embarquée dans le live `/etc/secubox/netboot-image.pub`).
- Journal d'audit : une ligne JSON par décision, ajoutée à `/var/log/secubox/audit.log`, sans jamais un code ni un jeton.
- Le port 7331 reste limité au LAN et au maillage ; la route du lot de flash aussi (nginx `allow` privés, `deny all`).
- Versions montées par paquet touché (`X.Y.Z-1~trixie1`), paquet déployé sur gk2 et publié sur apt.

## Review Focus

1. Lot de flash dont la signature ne vérifie pas (MITM sur le LAN) : `sbx-netflash` refuse et n'écrit rien sur l'eMMC.
2. Maître qui répond avec une `master_public_key` différente de l'ancre : `sbx-mesh-join` échoue, n'écrit pas `wg_mesh.json`, journalise.
3. Reflash d'un nom déjà présent sans code de flash : refusé comme aujourd'hui ; avec code de flash : remplace la clé, même `mesh_ip`.
4. Échec de dépôt après le `dd` (montage impossible) : la box est flashée mais non associée, message à la console, rien d'effacé.
5. Rattrapage sur une box sans tunnel actif ou dont le pair maître n'est pas unique : n'écrit aucune ancre.

---

### Task 1 : module d'ancre (secubox-p2p)

**Files :**
- Create : `packages/secubox-p2p/api/ancre.py`
- Test : `packages/secubox-p2p/tests/test_ancre_3100.py`

**Interfaces :**
- Produces :
  - `CHEMIN = "/etc/secubox/p2p/ancre-maitre.json"`
  - `lire(chemin: str = CHEMIN) -> dict | None` — `None` si absent ou illisible.
  - `ecrire(cle_publique: str, adresse: str, nom: str, empreinte: str, chemin: str = CHEMIN, ecraser: bool = False) -> bool` — `False` sans rien écrire si le fichier existe et `ecraser` est faux ; écriture atomique, 0644.
  - `accepte(ancre: dict | None, cle_maitre: str) -> bool` — vrai si pas d'ancre, ou si `ancre["cle_publique"] == cle_maitre`.
  - `audit(evenement: str, chemin: str = "/var/log/secubox/audit.log", **champs) -> None` — ligne JSON `{"ts", "module": "p2p", "evenement", ...}` ; refuse (lève `ValueError`) tout champ nommé `code`, `jeton` ou `token`.

- [ ] **Step 1 : tests qui échouent** — `test_ecrire_puis_lire`, `test_ecrire_n_ecrase_pas_sans_le_demander`, `test_accepte_sans_ancre_et_meme_cle_refuse_autre_cle`, `test_audit_refuse_un_jeton` (avec `tmp_path`).
- [ ] **Step 2 :** `pytest packages/secubox-p2p/tests/test_ancre_3100.py -v` → FAIL (module absent).
- [ ] **Step 3 :** implémenter `api/ancre.py`.
- [ ] **Step 4 :** relancer → PASS ; `pytest packages/secubox-p2p/tests -q` vert.
- [ ] **Step 5 :** commit `feat: p2p, ancre du maître sur la box (ref #3100)`.

### Task 2 : `sbx-mesh-join` vérifie l'ancre ; `sbx-mesh-up` attend l'adresse

**Files :**
- Modify : `packages/secubox-p2p/scripts/sbx-mesh-join` (après la réponse du maître, avant l'écriture de `wg_mesh.json`)
- Modify : `packages/secubox-p2p/scripts/sbx-mesh-up` (avant `render_wg_conf`)
- Test : `packages/secubox-p2p/tests/test_jonction_ancre_3100.py`

**Interfaces :**
- Consumes : `ancre.lire`, `ancre.accepte`, `ancre.audit` (Task 1).
- Produces : code de sortie **3** de `sbx-mesh-join` = « maître refusé (clé différente de l'ancre) ».

- [ ] **Step 1 : tests qui échouent** — en suivant le patron de `tests/test_jonction_tunnel_2885.py` (maître simulé) :
  `test_jonction_refusee_si_cle_differente_de_l_ancre` (sortie 3, `wg_mesh.json` non modifié, ligne d'audit
  `maitre_refuse`), `test_jonction_acceptee_si_meme_cle`, `test_sbx_mesh_up_sans_adresse_sort_proprement` (état sans
  `address` : sortie 0, message « adresse maillée pas encore attribuée », aucun `KeyError`).
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** dans `sbx-mesh-join`, après lecture de `master_public_key`, appel `python3 -c` sur `ancre.accepte` ; refus → audit + `exit 3`. Dans `sbx-mesh-up`, sortie 0 si `address` absent de l'état.
- [ ] **Step 4 :** relancer → PASS, suite p2p verte.
- [ ] **Step 5 :** commit `fix: p2p, la jonction n'accepte que le maître ancré ; sbx-mesh-up attend l'adresse (ref #3100)`.

### Task 3 : émission des codes et remplacement au reflash (maître)

**Files :**
- Create : `packages/secubox-p2p/api/jetons.py` (cœur de `ml_token_generate` extrait de `api/main.py:302`, qui y délègue)
- Replace : `packages/secubox-p2p/scripts/sbx-mesh-invite` (shell 32 hex → Python, format automesh)
- Modify : `packages/secubox-p2p/api/main.py` — `ml_join` (`:2075`) et `_add_mesh_peer` (`:2210`)
- Test : `packages/secubox-p2p/tests/test_invite_flash_3100.py`

**Interfaces :**
- Produces :
  - `jetons.generer(ttl: int, auto_approve: bool, nom_prevu: str | None = None, flash: bool = False) -> dict` — `{"token": <64 hex>, "expires": …}` ; persiste comme `ml_token_generate` (empreinte du jeton seulement) avec `nom_prevu` et `flash`.
  - CLI root `sbx-mesh-invite --code [--nom NOM] [--flash] [--ttl SECONDES] [--json]` — `--json` imprime `{"code": "sbxmesh1.…", "nom": NOM, "expire": …}` ; audit `code_emis` (nom, durée, jamais le code).
  - Règle de `ml_join` : jeton `flash` avec `nom_prevu == hostname` demandé et pair existant de ce nom → remplace la clé, garde `mesh_ip`, retire l'ancienne clé de l'état ; hors `flash`, un nom déjà pris reste refusé.

- [ ] **Step 1 : tests qui échouent** — `test_code_au_format_automesh_64_hex` (décodé par `automesh.decoder`),
  `test_cli_json_sans_le_jeton_dans_l_audit`, `test_reflash_remplace_la_cle_et_garde_l_adresse`,
  `test_doublon_sans_flash_refuse`, `test_jeton_flash_pour_un_autre_nom_refuse`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** extraire `jetons.py`, réécrire `sbx-mesh-invite`, étendre `ml_join`/`_add_mesh_peer`.
- [ ] **Step 4 :** relancer → PASS ; `tests/test_masterlink.py` et `tests/test_securite_invite_2476.py` toujours verts.
- [ ] **Step 5 :** commit `feat: p2p, codes de flash au format automesh, reflash qui remplace la clé (ref #3100)`.

### Task 4 : rattrapage de l'ancre (box déjà associées)

**Files :**
- Create : `packages/secubox-p2p/scripts/sbx-mesh-ancre` (root ; installé par `debian/rules` comme `sbx-mesh-join`)
- Modify : `packages/secubox-p2p/scripts/sbx-mesh-up` (appel en fin de succès), `packages/secubox-p2p/debian/postinst` (appel unique)
- Test : `packages/secubox-p2p/tests/test_rattrapage_ancre_3100.py`

**Interfaces :**
- Consumes : `ancre.ecrire`, `ancre.audit`.
- Produces : `sbx-mesh-ancre rattraper [--dump FICHIER]` — lit `wg show wg-mesh dump` (ou `--dump` en test) ; si
  l'état local est `role = satellite` et qu'**un seul** pair couvre tout le réseau maillé (`10.10.0.0/24`), écrit l'ancre
  avec sa clé, son endpoint et `master_mesh_ip` de l'état ; sinon n'écrit rien. Jamais d'écrasement. Audit `ancre_rattrapee`.

- [ ] **Step 1 : tests qui échouent** — `test_un_seul_pair_maitre_ancre_ecrite`, `test_deux_pairs_reseau_rien_ecrit`,
  `test_role_maitre_rien_ecrit`, `test_ancre_existante_jamais_ecrasee`, `test_sans_tunnel_rien_ecrit`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** implémenter (Python, `#!/usr/bin/python3`, `sys.path` comme `secubox-automesh`).
- [ ] **Step 4 :** relancer → PASS ; monter `secubox-p2p` (changelog, ref #3100) ; suite p2p verte.
- [ ] **Step 5 :** commit `feat: p2p, rattrapage de l'ancre par le tunnel (ref #3100)`.

### Task 5 : le maître sert un lot de flash signé (secubox-netboot)

**Files :**
- Create : `packages/secubox-netboot/sbin/secubox-netboot-lot` (root)
- Create : `packages/secubox-netboot/debian/secubox-netboot.sudoers` (le service netboot n'appelle que ce ctl)
- Modify : `packages/secubox-netboot/api/main.py` (routes), `packages/secubox-netboot/nginx/*.conf` du port 8099 (location `/lot-flash`)
- Test : `packages/secubox-netboot/tests/test_lot_flash_3100.py`

**Interfaces :**
- Consumes : `sbx-mesh-invite --code --nom NOM --flash --ttl 172800 --json` (Task 3) ; clé `/etc/secubox/netboot/keys/secubox-netboot.key`.
- Produces :
  - `domaine_pour(nom: str, domaine_maitre: str) -> str` (dans `api/main.py` ou un module `api/lot.py`) — `("gk1", "gk2.secubox.in") → "gk1.secubox.in"` ; `ValueError` si `nom` n'est pas `^[a-z][a-z0-9-]{0,30}$`.
  - `secubox-netboot-lot NOM` → stdout `{"lot": <JSON texte>, "signature": <base64>}` ; `lot` =
    `{"version": 1, "nom", "domaine", "code", "ancre": {"cle_publique", "adresse", "nom", "empreinte"}, "emis", "admin_empreinte"?}`.
  - `POST /api/v1/netboot/flash/prepare` (`require_jwt`) `{nom, mot_de_passe}` → enregistre `{nom, admin_empreinte argon2}` dans `/var/lib/secubox/netboot/flash-prepares/<nom>.json` (0600) ; le clair n'est jamais écrit.
  - `GET /lot-flash?nom=NOM` sur le port 8099 (LAN seulement, au plus 6 par heure et par adresse) → réponse du ctl ;
    inclut `admin_empreinte` si une préparation existe pour ce nom, puis la supprime. Audit `lot_flash_servi`.

- [ ] **Step 1 : tests qui échouent** — `test_domaine_pour`, `test_nom_invalide_refuse`,
  `test_lot_signe_verifie_avec_la_cle_publique` (clé RSA de test générée dans `tmp_path`),
  `test_preparation_consommee_une_fois`, `test_mot_de_passe_jamais_en_clair_sur_disque`, `test_route_lot_refuse_hors_lan`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** implémenter ctl, routes, sudoers, location nginx.
- [ ] **Step 4 :** relancer → PASS ; suite netboot verte.
- [ ] **Step 5 :** commit `feat: netboot, lot de flash signé servi au live (ref #3100)`.

### Task 6 : `sbx-netflash --nom` dépose ancre, code et profil

**Files :**
- Create : `packages/secubox-netboot/installer/sbx-netflash-profil` (Python, génère le `profil.toml`)
- Modify : `packages/secubox-netboot/installer/sbx-netflash`
- Test : `packages/secubox-netboot/tests/test_netflash_depot_3100.py`

**Interfaces :**
- Consumes : `GET http://<srv>/lot-flash?nom=NOM` (Task 5), clé publique `/etc/secubox/netboot-image.pub`.
- Produces :
  - `sbx-netflash-profil --nom NOM --domaine DOM --empreinte ARGON2` → `profil.toml` sur stdout : `[box]` nom, langue
    `fr`, clavier `fr`, fuseau `Europe/Paris`, ntp `true` ; `[admin]` mot_de_passe = empreinte, totp `enroler` ;
    `[reseau]` mode `routeur`, domaine ; `[services]` profil `actuel` ; `[maillage]` mode `automesh` ; `[apt]` auto `true`, heure `03:00`.
  - `sbx-netflash --image NOM.img.gz --nom NOM` : avant d'écrire, récupère et **vérifie** le lot (refus = rien écrit) ;
    sans `admin_empreinte` dans le lot, demande le mot de passe deux fois à la console et le hache (argon2) ; flash avec
    `--no-reboot` ; monte p2 puis p1 ; écrit `automesh.code` (0600), l'ancre (0644), `secubox/profil.toml` ; démonte ;
    redémarre sauf `--no-reboot`. Sans `--nom` : comportement actuel inchangé.

- [ ] **Step 1 : tests qui échouent** — `test_profil_genere_valide_par_premier_pas` (passe le `profil.toml` produit à
  la validation de `secubox-premier-pas` : `examiner` → complet), `test_lot_signature_invalide_rien_ecrit`
  (fonction de dépôt appelée sur une racine `tmp_path`, `dd` simulé), `test_depot_ecrit_code_ancre_profil_avec_droits`,
  `test_sans_nom_comportement_inchange`, `test_echec_montage_ne_detruit_rien`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** implémenter (le dépôt est une fonction bash `depose_dans RACINE BOOT` pour être testable sans eMMC).
- [ ] **Step 4 :** relancer → PASS ; monter `secubox-netboot` ; suite netboot verte.
- [ ] **Step 5 :** commit `feat: netboot, sbx-netflash --nom dépose ancre, code et profil (ref #3100)`.

### Task 7 : le panneau premier-pas du maître pousse l'ancre (box non flashée)

**Files :**
- Modify : `packages/secubox-premier-pas/premier_pas/maitre.py` (poussée de l'étape `maillage`), `premier_pas/profil.py` (clés `ancre_cle`, `ancre_adresse`, `ancre_nom`, `ancre_empreinte` acceptées dans `[maillage]`), `premier_pas/moteur.py` (application : écrit l'ancre avant `sbx-mesh-join`)
- Test : `packages/secubox-premier-pas/tests/test_poussee_ancre_3100.py`

**Interfaces :**
- Consumes : `ancre.ecrire` (Task 1, via `/usr/lib/secubox/p2p`), `sbx-mesh-invite --code` (Task 3) pour le code poussé.
- Produces : le profil poussé porte l'ancre ; à l'application, l'ancre est écrite (`ecraser=False`) puis la jonction lancée.

- [ ] **Step 1 : tests qui échouent** — `test_profil_pousse_contient_l_ancre_du_maitre`,
  `test_application_ecrit_l_ancre_avant_la_jonction`, `test_cles_d_ancre_inconnues_toujours_refusees_ailleurs`.
- [ ] **Step 2 :** lancer → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer → PASS ; monter `secubox-premier-pas` ; suite verte.
- [ ] **Step 5 :** commit `feat: premier-pas, l'ancre du maître poussée avec le maillage (ref #3100)`.

### Task 8 : intégration au banc

**Files :** aucun nouveau ; `.claude/HISTORY.md`, `.claude/WIP.md`.

- [ ] **Step 1 :** construire et déployer `secubox-p2p`, `secubox-netboot`, `secubox-premier-pas` sur gk2 ; publier sur apt ; reconstruire le squashfs du live (`taskset` un cœur, `nice 19`) pour y porter le nouveau `sbx-netflash`.
- [ ] **Step 2 :** rattrapage : sur gk1 et gk3, `sbx-mesh-ancre rattraper` → ancre écrite avec la clé de gk2 (`wg show wg-mesh` : même clé).
- [ ] **Step 3 :** reflash de gk1 depuis le live : `sbx-netflash --image secubox-isp-mochabin-trixie.img.gz --nom gk1` → premier démarrage sans action ; attendu : nom `gk1`, domaine `gk1.secubox.in`, `wg-mesh` à la même adresse maillée qu'avant, `admin.gk1.secubox.in` 200 après la synchronisation du relais.
- [ ] **Step 4 :** faux maître : sur gk1, `sbx-mesh-join` vers une adresse qui répond une autre clé → sortie 3, ligne `maitre_refuse` dans l'audit.
- [ ] **Step 5 :** suivi (HISTORY, WIP), `closes #3100` une fois déployé et constaté.
