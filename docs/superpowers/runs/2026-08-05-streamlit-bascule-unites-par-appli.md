<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Bascule du parc Streamlit vers les unités par appli — run du 2026-08-05

Issue [#982](https://github.com/CyberMind-FR/secubox-deb/issues/982) · suite de #963 · cause de fond de #946.

Le code des unités par appli était fusionné dans master depuis #963 ; la bascule
sur le conteneur vivant n'avait jamais été jouée. Ce document est le compte rendu
de son exécution.

## État de départ relevé

| | |
|---|---|
| paquet installé | `1.2.4-1~bookworm2` — mais `streamlitctl` et `api/main.py` **identiques au master** (md5), donc copiés à la main |
| `/usr/lib/secubox/streamlit/lxc/` | absent |
| `streamlit-app@.service` / `streamlit-launch` dans le conteneur | absents |
| `streamlit-all.service` | `active`, `enabled`, `ExecStop=/usr/bin/pkill -f streamlit`, `Restart=on-failure` |
| `secubox-streamlit-idle.timer` | `inactive` (arrêt manuel) mais `enabled` |
| charge / parc | 22.57 · 23 applis en cours sur 63 déclarées |

Rien de la migration n'était commencé : état de départ propre, aucun demi-état à
réconcilier.

## Le point bloquant, découvert au relevé

**Aucune des 23 applis en cours n'était redémarrable par les nouvelles unités :**

- 15 n'avaient **aucun** `.streamlit.toml` persisté → `streamlit-launch` serait
  sorti en code 5 (« refusing to guess »)
- les 8 autres portaient toutes `port = 8501` — le défaut corrigé en #963 — et
  **aucune ligne `entrypoint`** → sortie en code 4

Tuer le parc avant d'avoir capturé la vérité vivante aurait rendu les 23 applis
irréveillables. C'est ce constat, et non une préférence de méthode, qui ordonne
toute la séquence : la capture d'abord, la vidange ensuite.

`streamlitctl app repair` couvrait déjà exactement ces deux cas (cas 3 « port
périmé », cas 4 « toml absent ou sans entrypoint ») — aucun code nouveau n'a été
nécessaire.

## Séquence exécutée

### 1. Empaqueter les assets — `secubox-streamlit 1.4.0-1~bookworm1`

`lxc/streamlit-app@.service` + `lxc/streamlit-launch` étaient dans master et
`debian/rules` savait les installer, mais aucun paquet portant ce contenu n'avait
jamais été construit. Bump `1.3.0 → 1.4.0` plutôt que reconstruction de 1.3.0 :
une même version au contenu différent laisserait apt.secubox.in servir des octets
périmés.

Installé sur gk2, puis **minuterie re-stoppée immédiatement** — le `postinst` fait
`enable --now secubox-streamlit-idle.timer`.

### 2. Déposer le gabarit d'unité dans le conteneur

Même chemin que `cmd_install` (tar | `lxc-attach`), sur un conteneur déjà
provisionné. Vérifié : 0 unité activée, 0 unité démarrée, `ss` présent dans le
conteneur (le garde-fou anti-collision de port de `streamlit-launch` en dépend).

### 3. `app repair` — capture de la vérité vivante

Dry-run relu avant application : 23 `missing-entrypoint-record` + 5 `stale-port`.
Appliqué : **28/28**, sauvegardes `.bak.<horodatage>` pour tout fichier préexistant.

Vérification indépendante après coup : les 23 applis en cours ont un port et un
entrypoint persistés **concordants avec la table des processus réelle**.

Aucun processus touché à cette étape.

### 4. Neutraliser `streamlit-all.service`

Drop-in `zz-secubox-neutralize.conf` dans le conteneur :

```ini
[Service]
ExecStop=
Restart=no
```

puis `systemctl disable`. **Jamais de `stop` à ce stade** : l'ancien
`ExecStop=pkill -f streamlit` est global au parc et aurait tué aussi les processus
des unités par appli, qui vivent hors de son cgroup. C'est le piège principal de
cette bascule.

Vérifié : `ExecStop=` vide, `Restart=no`, `disabled`, toujours `active`, 24
processus intacts.

### 5. Bascule

**Témoin d'abord** (`tamagochi_gol`, port 8514) : ancien processus tué → `app
start` → unité `active` avec un **vrai `MainPID`** (37160, là où l'ancien service
avait perdu le sien à 0) → **HTTP 200 en moins de 10 s**.

Contrôle de cgroup avant la vidange : 23 processus dans le cgroup de
`streamlit-all`, et le témoin **hors** de ce cgroup
(`system-streamlit\x2dapp.slice/streamlit-app@tamagochi_gol.service`).

**Vidange** : `systemctl stop streamlit-all.service`. Avec `ExecStop` vidé, systemd
retombe sur `KillMode=control-group` — la portée est le cgroup, donc les 22
processus restants et rien d'autre.

Résultat : `inactive`/`disabled`, 22 processus partis, **le témoin toujours servi
en HTTP 200**. C'est la preuve directe que le piège est désamorcé.

**Réveil à la demande** vérifié sur les deux formes de point d'entrée :

| appli | forme | réveil |
|---|---|---|
| `prompt_forge` | script à plat | à l'écoute après **6 s** |
| `cc_osint` | appli-répertoire | à l'écoute après **4 s** |

Les deux en HTTP 200. (Mesuré board déchargée ; la fourchette 26–78 s de #963 avait
été relevée avec 23 applis résidentes.)

### 6. Réarmer la veille

`idle-check --dry-run` → `active=0 idle=0 would-stop=0`, puis
`secubox-streamlit-idle.timer` démarrée. Elle est désormais **`active` et
`enabled`** : plus d'arrêt manuel à retenir, et le réarmement est sûr puisque
`streamlit-all` est désactivé et ne peut plus ressusciter le parc.

## Résultat

| | avant | après |
|---|---|---|
| processus Streamlit résidents | 23 | **0** |
| charge (1 min) | 22.6 → 31.7 | **15.9** et en baisse |
| applis redémarrables par les unités | 0 / 23 | **23 / 23** |
| `streamlit-all.service` | active, enabled | inactive, disabled, `ExecStop` vidé |
| minuterie de veille | inactive, arrêt manuel non persistant | active + enabled |
| vignettes du mur | 18 valides | **18 valides** (conservées) |

Le mur mosaïque reste peuplé : les vignettes survivent à l'extinction des applis,
ce qui était l'objet de #958.

## Deux constats à traiter séparément

**`autostart = true` est déjà désaccordé du réel.** Trois applis le déclarent au
niveau `[apps.*]` — `diapvid` (8519), `files_51` (8530), `enhance_app` (8531) — et
**aucune des trois ne tournait avant la bascule**. La déclaration était donc déjà
inerte. Rien n'a été démarré de ce chef : ce serait ajouter des processus que la
board n'avait pas. `streamlitctl autostart` les démarrerait et les `enable`rait
d'un coup si l'intention est de rétablir le toujours-actif. À décider, pas à
supposer.

Les 23 autres `autostart = true` sont sur des sections `[instances.*]`, que
`cmd_autostart` ne lit pas (il n'itère que `^\[apps\.`).

**L'accès direct à l'URL ne réveille pas.** #746 est toujours ouverte : le réveil
passe par le lien explicite des tuiles endormies du mur. Une appli endormie
sollicitée par son vhost public répond en erreur tant qu'elle n'a pas été réveillée.
C'est le contrat de #946 assumé, mais il change ce que voit un visiteur.

**Le drop-in de neutralisation vit dans le conteneur**, pas dans le paquet. Un
conteneur reconstruit repartirait de `cmd_install`, qui ne crée pas
`streamlit-all.service` — le drop-in serait alors sans objet. Aucune action requise,
mais c'est à savoir avant toute reconstruction.
