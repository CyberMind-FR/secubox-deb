<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# gk2 passerelle du LAN — plan de construction

> **Pour les agents :** SOUS-COMPÉTENCE REQUISE : `superpowers:subagent-driven-development` (recommandé) ou
> `superpowers:executing-plans` pour exécuter ce plan tâche par tâche. Les étapes utilisent la syntaxe case à
> cocher (`- [ ]`).

**But :** faire de gk2 la passerelle DHCP du LAN plat de la Freebox, avec blocage effectif par zone, et une sonde
de secours qui rend la main à la Freebox si gk2 cesse de répondre.

**Architecture :** un nouveau paquet `secubox-pseudo-routeur` orchestre trois pièces existantes : le connecteur
`secubox-freebox` (bascule du DHCP), la chaîne `forward` nftables déjà posée par `secubox-nac`, et l'API du NAC
(classement des appareils). La sonde de secours est son propre service système, indépendant de l'API du module,
pour continuer à surveiller même si le reste du module est à l'arrêt.

**Stack :** Python (FastAPI, comme les autres modules), bash pour le script de sonde (pas de dépendance Python
dans le chemin critique du retour arrière), nftables, systemd (service + timer, minuteur transitoire).

**Spec :** `docs/superpowers/specs/2026-10-19-gk2-passerelle-lan-design.md`

## Contraintes globales

- Réseau LAN plat : `192.168.1.0/24`, Freebox en `.254`, gk2 en `.200`. Aucune hypothèse de sous-réseau séparé.
- La sonde de secours (Tâche 1) doit être livrée, testée et **active** avant que la Tâche 3 (bascule réelle du
  DHCP) puisse s'exécuter sur une vraie box — jamais l'inverse.
- Délai de retour automatique : **3 minutes** (3 échecs consécutifs de sonde, une sonde toutes les 60 s).
- Appareil hors de toute zone NAC connue : **bloqué** (politique `DEFAULT DROP` de la chaîne `forward`, pas d'ajout
  automatique à `quarantine_zone` — voir Tâche 2).
- Aucune règle `ct state established` sur ce trafic (le retour ne passe pas par gk2).
- Utilisateur dédié `secubox-pseudo-routeur`, jamais root dans l'API ; les écritures privilégiées (sysctl,
  nftables, DHCP Freebox) passent par un ctl root à portée étroite (`pseudo-routeurctl`), sudoers exact.
- Toute bascule (activation, retour manuel, retour automatique) écrit une ligne dans `/var/log/secubox/audit.log`.
- Portée de l'essai réel : bascule générale dès le premier essai (décision du propriétaire) — aucune tâche de ce
  plan n'introduit de mode « un seul appareil de test ».

## Review Focus

- Un appareil déjà classé (`lan_allowed`, `guest_zone`, `iot_zone`) par le NAC avant ce changement garde son accès
  après la bascule de la chaîne en `DEFAULT DROP` — sinon toute la maison perd Internet au premier déploiement.
- La sonde de secours doit se déclencher même si le SERVICE qui l'écrit plante (pas seulement s'il répond mal) :
  le minuteur de retour est une unité **indépendante**, pas un `except` dans le code de la sonde.
- Écrire la passerelle Freebox avant que la sonde ne soit confirmée active doit être refusé par le ctl, pas
  seulement déconseillé dans la documentation.
- Une adresse MAC invalide ou absente envoyée à l'API d'import des appareils Freebox ne doit pas planter la liste
  ni être proposée comme suggestion de classement.
- Le compteur `nft` de la nouvelle règle `DEFAULT DROP` doit être lisible sans `sudo` interactif (le module tourne
  en utilisateur non privilégié) : prévoir la lecture par le ctl comme les autres compteurs SecuBox.

---

## Fichiers

- Créer `packages/secubox-pseudo-routeur/sbin/pseudo-routeurctl` : ctl root (transfert IP, génération de la chaîne
  `forward`, bascule DHCP Freebox via le connecteur, lecture d'état).
- Créer `packages/secubox-pseudo-routeur/sbin/sonde-secours` : script bash de la sonde (vérification + réarmement
  du minuteur), aucune dépendance Python.
- Créer `packages/secubox-pseudo-routeur/systemd/pseudo-routeur-sonde.service` et `.timer` (toutes les 60 s).
- Créer `packages/secubox-pseudo-routeur/api/main.py` : API FastAPI (état, bascule, journal, suggestions
  d'appareils), appelle `pseudo-routeurctl` par `sudo -n`.
- Créer `packages/secubox-pseudo-routeur/nft/secubox-pseudo-routeur.nft` : chaîne `forward` additive (lue par
  `nft -f`, table dédiée, comme les autres modules).
- Créer `packages/secubox-pseudo-routeur/www/pseudo-routeur/index.html` : panneau (état, bascule, journal, liste de
  suggestion Freebox).
- Modifier `packages/secubox-freebox/api/service.py` : nouvelle méthode `regler_passerelle_dhcp(ip)` et
  `appareils_non_classes()` (liste Freebox filtrée par ce que le NAC connaît déjà).
- Créer `packages/secubox-pseudo-routeur/debian/*` (control, rules, postinst, prerm, changelog, compat).
- Créer `packages/secubox-pseudo-routeur/menu.d/*.json`.

## Interfaces

- `secubox-freebox` (existant) : `Freebox.client.lire(chemin)`, `Freebox.client.ecrire(methode, chemin, corps)`,
  motif `_regler(chemin, cle, actif, action)` → `(etat, change)` — voir `packages/secubox-freebox/api/service.py`.
- `secubox-nac` (existant) : route `GET /api/v1/nac/devices` (liste avec zone résolue), route
  `POST /api/v1/nac/zones/{zone}/add` ou équivalent (voir `ZONES` dict, `_nft_add_element`,
  `packages/secubox-nac/api/main.py:521-563` pour la résolution de zone).

---

### Task 1: sonde de secours (dead-man switch)

**Fichiers :**
- Créer : `packages/secubox-pseudo-routeur/sbin/sonde-secours`
- Créer : `packages/secubox-pseudo-routeur/systemd/pseudo-routeur-sonde.service`
- Créer : `packages/secubox-pseudo-routeur/systemd/pseudo-routeur-sonde.timer`
- Test : `packages/secubox-pseudo-routeur/tests/test_sonde_secours.py`

**Interfaces :**
- Produit : `sonde-secours verifier` (code 0 = sonde OK, code 1 = échec), `sonde-secours etat` (JSON
  `{"echecs_consecutifs": int, "actif": bool}` lu depuis `/var/lib/secubox/pseudo-routeur/sonde.json`).
- Consommé par : Tâche 3 (le ctl refuse la bascule DHCP si `sonde-secours etat` ne rend pas `actif: true`).

- [ ] **Étape 1 : écrire le test qui échoue, pour la logique pure de décision**

```python
# packages/secubox-pseudo-routeur/tests/test_sonde_secours.py
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "sonde-secours"


def _etat(tmp_path, env=None):
    e = dict(env or {}, SECUBOX_SONDE_ETAT=str(tmp_path / "sonde.json"))
    subprocess.run(["bash", str(SCRIPT), "verifier"], env=e, capture_output=True, text=True)
    return json.loads((tmp_path / "sonde.json").read_text())


def test_trois_echecs_consecutifs_marquent_inactif(tmp_path, monkeypatch):
    faux_sonde = tmp_path / "bin" / "ping"
    faux_sonde.parent.mkdir()
    faux_sonde.write_text("#!/bin/sh\nexit 1\n")
    faux_sonde.chmod(0o755)
    env = {"PATH": f"{faux_sonde.parent}:/usr/bin:/bin"}
    for _ in range(3):
        etat = _etat(tmp_path, env)
    assert etat["echecs_consecutifs"] == 3
    assert etat["actif"] is False


def test_un_succes_reinitialise_le_compteur(tmp_path):
    faux_bin = tmp_path / "bin"
    faux_bin.mkdir()
    (faux_bin / "ping").write_text("#!/bin/sh\nexit 1\n")
    (faux_bin / "ping").chmod(0o755)
    env = {"PATH": f"{faux_bin}:/usr/bin:/bin"}
    _etat(tmp_path, env)
    _etat(tmp_path, env)
    (faux_bin / "ping").write_text("#!/bin/sh\nexit 0\n")
    etat = _etat(tmp_path, env)
    assert etat["echecs_consecutifs"] == 0
    assert etat["actif"] is True
```

- [ ] **Étape 2 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_sonde_secours.py -v`
Attendu : ÉCHEC, `sbin/sonde-secours` n'existe pas encore.

- [ ] **Étape 3 : écrire `sbin/sonde-secours`**

Deux verbes : `verifier` et `etat`. `verifier` teste dans l'ordre `sysctl net.ipv4.ip_forward` = 1, une règle
`forward` présente dans la table dédiée (`nft list table inet secubox_pseudo_routeur` non vide), puis
`ping -c1 -W2 1.1.1.1` à travers l'interface de sortie. Sur échec, incrémente `echecs_consecutifs` dans le fichier
d'état (créé avec `umask 077`, `0 644` autrement non lisible par l'API en utilisateur non privilégié — trancher à
l'implémentation en fonction de qui doit le lire) ; sur succès, le remet à 0. Écrit `actif: echecs_consecutifs < 3`
(seuil en dur, cohérent avec la contrainte globale de 3 minutes à une sonde par minute). `etat` affiche le contenu
du fichier (JSON), ou `{"echecs_consecutifs": 0, "actif": null}` si le fichier n'existe pas encore (jamais lancé).

- [ ] **Étape 4 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_sonde_secours.py -v`
Attendu : RÉUSSITE, 2 tests.

- [ ] **Étape 5 : écrire le test du réarmement du minuteur de retour**

```python
def test_echec_arme_le_minuteur_de_retour_independamment(tmp_path):
    """Le minuteur qui REND la main à la Freebox doit etre arme par un service SEPARE
    de celui qui echoue, pour se declencher meme si le service de sonde plante net."""
    unite = Path("/usr/lib/secubox/pseudo-routeur/systemd/pseudo-routeur-sonde.service")
    assert unite.exists()
    texte = unite.read_text()
    assert "pseudo-routeur-retour.timer" not in texte, (
        "le retour ne doit pas etre arme DANS le service de sonde (sinon un crash du "
        "service de sonde empeche aussi le retour) : il vit dans sa propre unite, "
        "reveillee par OnFailure= du service de sonde ET par le timer regulier"
    )
```

Ce test documente la contrainte d'architecture (Review Focus, point 2) plutôt que de l'exécuter : il échoue tant
que l'unité n'existe pas, ce qui force l'étape 6 à poser `OnFailure=` plutôt qu'un appel direct dans le script.

- [ ] **Étape 6 : écrire les unités systemd**

`pseudo-routeur-sonde.service` (`Type=oneshot`, `ExecStart=/usr/sbin/sonde-secours verifier`,
`OnFailure=pseudo-routeur-retour.service` — se déclenche si le script **sort en erreur**, pas seulement s'il
rapporte un échec applicatif ; le script doit donc sortir en code non nul après le 3ᵉ échec consécutif, pas avant).
`pseudo-routeur-sonde.timer` (`OnActiveSec=60s`, `OnUnitActiveSec=60s` — motif #2919/#2925, les deux sinon la
minuterie ne redémarre pas seule après une réactivation). `pseudo-routeur-retour.service` (appelle
`pseudo-routeurctl retour-freebox`, Tâche 3).

- [ ] **Étape 7 : lancer la suite complète du paquet, vérifier qu'elle passe**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/ -v`
Attendu : RÉUSSITE, tous les tests de la tâche.

- [ ] **Étape 8 : valider**

```bash
cd packages/secubox-pseudo-routeur && bash -n sbin/sonde-secours && echo ok
git add packages/secubox-pseudo-routeur/sbin/sonde-secours packages/secubox-pseudo-routeur/systemd packages/secubox-pseudo-routeur/tests/test_sonde_secours.py
git commit -m "feat: pseudo-routeur, sonde de secours independante (ref #2940)"
```

---

### Task 2: chaîne `forward` — transfert IP et zones

**Fichiers :**
- Créer : `packages/secubox-pseudo-routeur/nft/secubox-pseudo-routeur.nft`
- Modifier : `packages/secubox-pseudo-routeur/sbin/pseudo-routeurctl` (ajoute les verbes `activer-transfert`,
  `generer-chaine`, `etat-transfert`)
- Test : `packages/secubox-pseudo-routeur/tests/test_chaine_forward.py`

**Interfaces :**
- Consomme : les ensembles nftables existants `inet secubox_nac { lan_allowed, guest_zone, iot_zone,
  quarantine_zone, blocked }` (déjà peuplés par `secubox-nac`, jamais recréés ici).
- Produit : `pseudo-routeurctl generer-chaine` (écrit le fichier `.nft`, ne l'applique pas), `pseudo-routeurctl
  activer-transfert` (`nft -f` + `sysctl net.ipv4.ip_forward=1`), `pseudo-routeurctl etat-transfert` (JSON
  `{"transfert_actif": bool, "paquets_rejetes": int}` lu depuis le compteur nommé de la chaîne).

- [ ] **Étape 1 : écrire le test qui échoue**

```python
# packages/secubox-pseudo-routeur/tests/test_chaine_forward.py
import re
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _generer(tmp_path):
    r = subprocess.run(["bash", str(CTL), "generer-chaine"],
                       env={"PATH": "/usr/bin:/bin", "SECUBOX_PR_NFT_OUT": str(tmp_path / "chaine.nft")},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return (tmp_path / "chaine.nft").read_text()


def test_politique_default_drop(tmp_path):
    txt = _generer(tmp_path)
    assert re.search(r"chain forward \{[^}]*policy drop;", txt, re.S)


def test_lan_allowed_et_zones_connues_acceptees_avant_le_drop(tmp_path):
    txt = _generer(tmp_path)
    assert "@lan_allowed" in txt and "accept" in txt
    assert "@guest_zone" in txt and "@iot_zone" in txt
    # blocked/quarantine restent un drop explicite, avant toute regle d'acceptation
    assert txt.index("@blocked") < txt.index("accept")


def test_nftables_valide_la_syntaxe(tmp_path):
    if not __import__("shutil").which("nft"):
        pytest.skip("nft absent")
    txt = _generer(tmp_path)
    base = tmp_path / "base.nft"
    base.write_text("table inet secubox_nac { set lan_allowed { type ether_addr; } "
                    "set guest_zone { type ether_addr; } set iot_zone { type ether_addr; } "
                    "set quarantine_zone { type ether_addr; } set blocked { type ether_addr; } }\n" + txt)
    r = subprocess.run(["nft", "-c", "-f", str(base)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
```

- [ ] **Étape 2 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_chaine_forward.py -v`
Attendu : ÉCHEC, verbe `generer-chaine` absent.

- [ ] **Étape 3 : écrire `generer-chaine` dans `pseudo-routeurctl`**

Produit une table `inet secubox_pseudo_routeur` avec une seule chaîne `forward`
(`type filter hook forward priority filter - 1; policy drop;` — juste après la chaîne `forward` existante de
`secubox-nac`, priorité `-5`, pour que ses `drop` de `blocked`/`quarantine_zone` restent évalués en premier) :
`ether saddr @blocked drop`, `ether saddr @quarantine_zone drop` (recopiés, cohérence avec #2940 Review Focus
point 1 — un appareil déjà bloqué par le NAC le reste), puis `ether saddr @lan_allowed accept`,
`ether saddr @guest_zone accept`, `ether saddr @iot_zone accept`, un compteur nommé
`sbx_pr_forward_rejete` avant la fin de chaîne (la politique `drop` ferme déjà tout le reste, le compteur sert à
`etat-transfert`).

- [ ] **Étape 4 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_chaine_forward.py -v`
Attendu : RÉUSSITE, 3 tests (le 3ᵉ ignoré si `nft` absent).

- [ ] **Étape 5 : écrire `activer-transfert` et `etat-transfert`**

`activer-transfert` : `generer-chaine` vers le fichier réel (`/etc/nftables.d/zz-secubox-pseudo-routeur.nft`,
préfixe `zz-` pour passer après la base — motif documenté dans `.claude/PATTERNS.md`), `nft -f`, puis
`sysctl -w net.ipv4.ip_forward=1`. `etat-transfert` lit `sysctl net.ipv4.ip_forward` et le compteur nommé via
`nft -j list counter inet secubox_pseudo_routeur sbx_pr_forward_rejete`.

- [ ] **Étape 6 : lancer la suite, vérifier qu'elle passe**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/ -v`
Attendu : RÉUSSITE.

- [ ] **Étape 7 : valider**

```bash
git add packages/secubox-pseudo-routeur/nft packages/secubox-pseudo-routeur/sbin/pseudo-routeurctl packages/secubox-pseudo-routeur/tests/test_chaine_forward.py
git commit -m "feat: pseudo-routeur, chaine forward DEFAULT DROP par zone (ref #2940)"
```

---

### Task 3: bascule du DHCP Freebox, gardée par la sonde

**Fichiers :**
- Modifier : `packages/secubox-freebox/api/service.py` (ajoute `regler_passerelle_dhcp`)
- Modifier : `packages/secubox-pseudo-routeur/sbin/pseudo-routeurctl` (ajoute `activer`, `retour-freebox`, `etat`)
- Test : `packages/secubox-freebox/tests/test_passerelle_dhcp.py`
- Test : `packages/secubox-pseudo-routeur/tests/test_bascule_gardee.py`

**Interfaces :**
- Consomme : `Freebox.client.lire`/`ecrire` (Tâche 1 de `secubox-freebox`, déjà en place), `sonde-secours etat`
  (Tâche 1 de ce plan).
- Produit : `Freebox.regler_passerelle_dhcp(ip: str) -> dict` (motif de `_regler`, relu avant/après, journalisé,
  lève `C.ErreurFreebox` si la Freebox ne confirme pas). `pseudo-routeurctl activer` (refuse si la sonde n'est pas
  active), `pseudo-routeurctl retour-freebox` (toujours exécutable, y compris sonde inactive — c'est le chemin de
  secours), `pseudo-routeurctl etat` (JSON `{"mode": "gk2"|"freebox", "sonde_active": bool}`).

- [ ] **Étape 1 : écrire le test qui échoue, côté Freebox**

```python
# packages/secubox-freebox/tests/test_passerelle_dhcp.py
from tests.test_pare_feu_ecriture import _pret, ok


def test_passerelle_ecrit_puis_relit_et_journalise(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"gateway": "192.168.1.254"}),
                                       ok({"gateway": "192.168.1.200"}), ok({"gateway": "192.168.1.200"})])
    r = svc.regler_passerelle_dhcp("192.168.1.200")
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("dhcp/config/")
    assert r["passerelle"] == "192.168.1.200" and r["change"] is True
    assert journal[0]["action"] == "passerelle_dhcp" and journal[0]["apres"] == "192.168.1.200"


def test_deja_dans_l_etat_voulu_n_ecrit_rien(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"gateway": "192.168.1.200"})])
    r = svc.regler_passerelle_dhcp("192.168.1.200")
    assert r["change"] is False and not [a for a in f.appels if a[0] == "PUT"]
```

- [ ] **Étape 2 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-freebox/tests/test_passerelle_dhcp.py -v`
Attendu : ÉCHEC, `regler_passerelle_dhcp` n'existe pas.

- [ ] **Étape 3 : implémenter `Freebox.regler_passerelle_dhcp(self, ip: str) -> dict` dans `service.py`**

Même charpente que `regler_pare_feu_ipv6` (droit `settings`, lecture avant, `PUT dhcp/config/` avec seulement la
clé `gateway` — ne jamais réécrire les autres clés de `dhcp/config/` lues au passage, `lire()` peut rendre `dns`,
`ip_range_start/end` etc. qu'il ne faut pas retoucher), relecture, journal `{"action": "passerelle_dhcp", "avant":
..., "apres": ...}`, lève si la relecture ne confirme pas.

- [ ] **Étape 4 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-freebox/tests/test_passerelle_dhcp.py -v`
Attendu : RÉUSSITE, 2 tests.

- [ ] **Étape 5 : écrire le test qui échoue, côté garde dans `pseudo-routeurctl`**

```python
# packages/secubox-pseudo-routeur/tests/test_bascule_gardee.py
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _ctl(tmp_path, *args, sonde_active):
    etat = tmp_path / "sonde.json"
    etat.write_text(json.dumps({"echecs_consecutifs": 0 if sonde_active else 3, "actif": sonde_active}))
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_SONDE_ETAT": str(etat)}
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=20)


def test_activer_refuse_sans_sonde_active(tmp_path):
    r = _ctl(tmp_path, "activer", sonde_active=False)
    assert r.returncode == 2
    assert "sonde" in r.stdout.lower() or "sonde" in r.stderr.lower()


def test_retour_freebox_fonctionne_meme_sonde_inactive(tmp_path):
    r = _ctl(tmp_path, "retour-freebox", sonde_active=False)
    assert r.returncode in (0, 1)  # peut echouer sur l'appel reseau en test, jamais sur la garde elle-meme
    assert "sonde" not in (r.stderr or "").lower()
```

- [ ] **Étape 6 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_bascule_gardee.py -v`
Attendu : ÉCHEC, verbes `activer`/`retour-freebox` absents.

- [ ] **Étape 7 : implémenter `activer`, `retour-freebox`, `etat` dans `pseudo-routeurctl`**

`activer` : lit `sonde-secours etat`, refuse (code 2, message explicite) si `actif` n'est pas `true` ; sinon appelle
`activer-transfert` (Tâche 2) puis `sudo -u secubox-freebox` la nouvelle route du module freebox (ou directement
le connecteur en Python, à trancher à l'implémentation selon ce qui est déjà exposé en CLI côté `secubox-freebox`
— sinon ajouter un point d'entrée CLI minimal à ce module dans cette même étape). `retour-freebox` : même appel
avec `192.168.1.254`, sans lire l'état de la sonde. `etat` : agrège `etat-transfert` (Tâche 2) et la passerelle
actuellement réglée (lue côté Freebox).

- [ ] **Étape 8 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_bascule_gardee.py -v`
Attendu : RÉUSSITE, 2 tests.

- [ ] **Étape 9 : lancer toute la suite des deux paquets touchés**

Exécuter : `pytest packages/secubox-freebox/tests/ packages/secubox-pseudo-routeur/tests/ -v`
Attendu : RÉUSSITE.

- [ ] **Étape 10 : valider**

```bash
git add packages/secubox-freebox/api/service.py packages/secubox-freebox/tests/test_passerelle_dhcp.py packages/secubox-pseudo-routeur/sbin/pseudo-routeurctl packages/secubox-pseudo-routeur/tests/test_bascule_gardee.py
git commit -m "feat: pseudo-routeur, bascule DHCP gardee par la sonde de secours (ref #2940)"
```

---

### Task 4: import des appareils Freebox (suggestions de classement)

**Fichiers :**
- Modifier : `packages/secubox-freebox/api/service.py` (ajoute `appareils_non_classes`)
- Créer : `packages/secubox-pseudo-routeur/api/classement.py` (table de correspondance `host_type` → zone)
- Test : `packages/secubox-freebox/tests/test_appareils_non_classes.py`
- Test : `packages/secubox-pseudo-routeur/tests/test_classement.py`

**Interfaces :**
- Produit : `Freebox.appareils_non_classes(macs_connues: set[str]) -> list[dict]` (chaque élément :
  `{"mac": str, "nom": str, "host_type": str}`, lus depuis `lan/browser/pub/`, uniquement ceux dont la MAC n'est
  pas dans `macs_connues`). `classement.zone_suggeree(host_type: str) -> str | None` (table figée de la Tâche 4 de
  la spec, rend `None` pour `workstation`/`laptop`/`smartphone` — pas de suggestion).

- [ ] **Étape 1 : écrire le test qui échoue, table de correspondance**

```python
# packages/secubox-pseudo-routeur/tests/test_classement.py
from api.classement import zone_suggeree


def test_table_de_correspondance_exacte_de_la_spec():
    assert zone_suggeree("freebox_pop") == "lan_allowed"
    assert zone_suggeree("freebox_wifi") == "lan_allowed"
    assert zone_suggeree("printer") == "lan_allowed"
    assert zone_suggeree("networking_device") == "lan_allowed"
    assert zone_suggeree("television") == "guest"
    assert zone_suggeree("multimedia_device") == "guest"
    assert zone_suggeree("workstation") is None
    assert zone_suggeree("laptop") is None
    assert zone_suggeree("smartphone") is None
    assert zone_suggeree("type_jamais_vu") is None
```

- [ ] **Étape 2 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_classement.py -v`
Attendu : ÉCHEC, module absent.

- [ ] **Étape 3 : implémenter `zone_suggeree(host_type: str) -> str | None` dans `api/classement.py`**

Dictionnaire figé d'après la table de la section 4 de la spec ; `.get(host_type)` (rend `None` pour une clé
absente, pas de valeur par défaut).

- [ ] **Étape 4 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_classement.py -v`
Attendu : RÉUSSITE.

- [ ] **Étape 5 : écrire le test qui échoue, côté Freebox**

```python
# packages/secubox-freebox/tests/test_appareils_non_classes.py
from tests.test_pare_feu_ecriture import _pret


def _lecture_hotes(hotes):
    return [{"success": True, "result": hotes}]


def test_filtre_les_macs_deja_connues(tmp_path):
    hotes = [{"l2ident": {"id": "AA:BB:CC:00:00:01"}, "names": [{"name": "tv"}], "host_type": "television"},
             {"l2ident": {"id": "AA:BB:CC:00:00:02"}, "names": [{"name": "pc"}], "host_type": "workstation"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    r = svc.appareils_non_classes(macs_connues={"aa:bb:cc:00:00:01"})
    assert len(r) == 1 and r[0]["mac"] == "aa:bb:cc:00:00:02" and r[0]["host_type"] == "workstation"


def test_macs_connues_vide_rend_tout(tmp_path):
    hotes = [{"l2ident": {"id": "AA:BB:CC:00:00:01"}, "names": [{"name": "tv"}], "host_type": "television"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    assert len(svc.appareils_non_classes(macs_connues=set())) == 1


def test_hote_sans_adresse_mac_ignore(tmp_path):
    hotes = [{"l2ident": {}, "names": [{"name": "?"}], "host_type": "workstation"}]
    svc, f, _ = _pret(tmp_path, _lecture_hotes(hotes))
    assert svc.appareils_non_classes(macs_connues=set()) == []
```

- [ ] **Étape 6 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-freebox/tests/test_appareils_non_classes.py -v`
Attendu : ÉCHEC.

- [ ] **Étape 7 : implémenter `Freebox.appareils_non_classes(self, macs_connues: set[str]) -> list[dict]`**

Lit `lan/browser/pub/` (déjà utilisé par la sonde IPv6 du 2026-10-19, même motif de lecture que
`fb.client.lire(...)`), extrait `(h.get("l2ident") or {}).get("id")`, ignore un hôte sans MAC, normalise la MAC en
minuscules, filtre ceux déjà dans `macs_connues`, rend `{"mac", "nom": premier name.name ou "", "host_type"}`.

- [ ] **Étape 8 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-freebox/tests/test_appareils_non_classes.py -v`
Attendu : RÉUSSITE.

- [ ] **Étape 9 : lancer toute la suite des deux paquets**

Exécuter : `pytest packages/secubox-freebox/tests/ packages/secubox-pseudo-routeur/tests/ -v`
Attendu : RÉUSSITE.

- [ ] **Étape 10 : valider**

```bash
git add packages/secubox-freebox/api/service.py packages/secubox-freebox/tests/test_appareils_non_classes.py packages/secubox-pseudo-routeur/api/classement.py packages/secubox-pseudo-routeur/tests/test_classement.py
git commit -m "feat: pseudo-routeur, import et suggestion de classement des appareils Freebox (ref #2940)"
```

---

### Task 5: API, panneau et empaquetage

**Fichiers :**
- Créer : `packages/secubox-pseudo-routeur/api/main.py`
- Créer : `packages/secubox-pseudo-routeur/www/pseudo-routeur/index.html`
- Créer : `packages/secubox-pseudo-routeur/menu.d/*.json`
- Créer : `packages/secubox-pseudo-routeur/debian/{control,rules,postinst,prerm,changelog,compat}`
- Créer : `packages/secubox-pseudo-routeur/sudoers/secubox-pseudo-routeur`
- Test : `packages/secubox-pseudo-routeur/tests/test_api.py`

**Interfaces :**
- Consomme : toutes les interfaces produites aux tâches 1 à 4.
- Produit : `GET /api/v1/pseudo-routeur/etat` (lecture, `require_lecture`), `POST .../activer`,
  `POST .../retour-freebox` (écriture, `require_jwt`), `GET .../suggestions` (lecture), `GET .../journal`
  (lecture, pagination simple comme les autres journaux SecuBox).

- [ ] **Étape 1 : écrire le test qui échoue, garde des routes**

```python
# packages/secubox-pseudo-routeur/tests/test_api.py
from fastapi.testclient import TestClient
from api import main


def test_etat_accessible_en_lecture_sans_jwt_mais_pas_sans_rien():
    c = TestClient(main.app)
    r = c.get("/etat")
    assert r.status_code in (200, 401, 403)  # jamais 404/500 : la route existe et sa garde repond


def test_activer_exige_jwt():
    c = TestClient(main.app)
    r = c.post("/activer")
    assert r.status_code in (401, 403)
```

- [ ] **Étape 2 : lancer, vérifier l'échec**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_api.py -v`
Attendu : ÉCHEC, `api/main.py` absent.

- [ ] **Étape 3 : écrire `api/main.py`**

FastAPI standard du dépôt (voir `packages/secubox-freebox/api/main.py` pour le gabarit : `_repondre`, découpage
des erreurs). Chaque route appelle `pseudo-routeurctl` par `sudo -n` en thread (motif déjà utilisé par
`secubox-certs`, Tâche async `asyncio.to_thread`). `GET /suggestions` appelle la méthode de la Tâche 4 côté
`secubox-freebox` par son propre socket (`require_jwt` du module courant suffit, pas besoin d'un second jeton).

- [ ] **Étape 4 : lancer, vérifier le succès**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/test_api.py -v`
Attendu : RÉUSSITE.

- [ ] **Étape 5 : écrire le panneau `www/pseudo-routeur/index.html`**

Profil Aurora (`.claude/WEBUI-PANEL-GUIDELINES.md`) : état en tuile (gk2/Freebox passerelle, sonde active ou non),
bouton « Devenir la passerelle » avec confirmation intégrée à la page (jamais de `confirm()`), liste des
suggestions (Tâche 4) avec bouton « Classer » par ligne qui appelle l'API du NAC existante, journal en tableau.
Mode `?demo=1` sans écriture, comme les autres pages.

- [ ] **Étape 6 : empaqueter**

`debian/control` (`Depends: secubox-core, secubox-aggregator, secubox-freebox (>= 0.5.1), secubox-nac,
secubox-hardening`), `debian/rules` (installe `sbin/`, `systemd/`, `nft/`, `www/`, `menu.d/`), `debian/postinst`
(utilisateur dédié `secubox-pseudo-routeur`, sudoers exact pour `pseudo-routeurctl`, **n'active ni ne démarre
`pseudo-routeur-sonde.timer` à l'installation** — seule l'activation explicite via `POST /activer` doit l'armer, un
module installé ne doit jamais commencer à transférer de paquets tout seul), `debian/changelog`
(`0.1.0-1~bookworm1`).

- [ ] **Étape 7 : lancer toute la suite du nouveau paquet**

Exécuter : `pytest packages/secubox-pseudo-routeur/tests/ -v`
Attendu : RÉUSSITE, tous les tests du plan.

- [ ] **Étape 8 : valider**

```bash
git add packages/secubox-pseudo-routeur
git commit -m "feat: pseudo-routeur, API, panneau et empaquetage (ref #2940)"
```

---

## Essai réel (hors des tâches de code, après fusion)

Hors heures d'usage du foyer, suivre l'ordre de la spec : installer le paquet (la sonde ne démarre pas seule),
appeler `POST /activer` depuis une session administrateur (confirme la sonde avant toute bascule du DHCP),
vérifier `GET /etat`, puis observer 10-15 minutes avant de considérer l'essai concluant. Couper manuellement
`pseudo-routeur-sonde.service` à un moment donné pour vérifier que le retour automatique se déclenche bien sous
3 minutes, sans action humaine.
