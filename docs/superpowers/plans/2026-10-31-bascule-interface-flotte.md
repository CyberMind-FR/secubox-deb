<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Bascule d'interface locale ⇄ distante depuis la Flotte (#3302)

**But :** basculer une box entre interface **locale** (webui sur la box, relayée par le WAF du maître) et **distante**
(profil léger `distante`, webui servie par le maître sur `admin.<box>`) depuis la Flotte, sans SSH.

**Architecture :** le maître envoie un Operate ; l'agent le traduit en verbe du ctl root ; le ctl décide (ancre, mains
liées, accord du détenteur sur une box cliente), mémorise le profil de retour et lance une unité transitoire qui applique
le profil (`secubox-profilectl apply --profile … --yes`). Une bascule vers `distante` n'est acquise qu'à la
**confirmation du maître** (preuve que le canal maître ⇄ box survit) ; sans elle, une minuterie « homme mort » rend
l'interface locale.

## Contrat

| Couche | Ajout |
|---|---|
| ctl (`secubox-pilotagectl`) | `interface <locale\|distante\|confirmer>` ; internes `_interface <job>`, `_interface-garde <job>` (local seulement) ; état root `interface.json` ; actions de politique `interface-locale`, `interface-distante` (accord du détenteur sur box cliente), `interface-confirmer` ; `interface` est une opération exclusive |
| agent (Go) | `Device.X_SECUBOX_Pilotage.Interface.Basculer()` `{sens}` → `interface <sens>` ; `…Interface.Confirmer()` → `interface confirmer` |
| maître (`secubox-pilotage`) | catalogue `interface-distante`, `interface-locale` (confirmation forte) ; `Suivi` : fin réussie d'`interface-distante` ⇒ Operate `Confirmer()` automatique, audité |
| Flotte (`secubox-annuaire/www/fleet`) | ligne d'action « Passer en interface distante / locale » selon `b.interface`, confirmation forte, suivi par le journal des opérations ; « Ouvrir » suit déjà l'interface déclarée |

## Règles

- Profil de retour : `/etc/secubox/profiles/active` s'il est sûr et ≠ `distante`, sinon `profil_retour` de
  `/etc/secubox-pilotage/interface.toml` (root, non inscriptible par d'autres) ; aucun ⇒ refus « profil de retour inconnu »
  (jamais d'apply sans profil : il éteindrait tout sauf le socle).
- Homme mort : `delai_garde_s` (défaut 600, borné 120..3600) ; minuterie transitoire `secubox-pilotage-garde-<job>` ;
  confirmation ou retour en locale l'arrêtent.
- `active` est réécrit (par descripteur) avec le profil réellement appliqué, pour que `coupe` (postinst) et le hub
  voient le bon profil.
- Audit de chaque étape : `interface_demandee` (via `pilotage_demande`), `interface_basculee`, `interface_confirmee`,
  `interface_retour` (`cause` : apply|homme-mort|demande), `interface_echec`.
- Idempotent : apply d'un profil déjà en place ne change rien ; « confirmer » sans bascule en attente est refusé
  proprement.

## Tâches (TDD)

1. ctl : analyse, politique, état, unités `_interface`/`_interface-garde` — tests `test_pilotagectl.py` (faux
   systemd-run/systemctl, faux `secubox-profilectl`).
2. agent Go : traduction des deux commandes — `operations_test.go`.
3. maître : catalogue + suite `Confirmer()` — `test_operations_api.py` / nouveau test.
4. Flotte : ligne d'action ; test statique du HTML si un modèle existe.
5. Versions, changelogs `~trixie1`, README des trois paquets.
