# Système de profils & activation de modules — Conception

**Date** : 2026-07-17
**Statut** : conception validée, prête pour le plan d'implémentation
**Auteur** : Gérald Kerma <devel@cybermind.fr>

---

## Objectif

Basculer la box entre des **contextes d'usage** (« média » le soir, « sécurité » en journée, « démo » en
vitrine) en activant/désactivant des ensembles de modules et leurs services — plus un **toggle individuel
par module**, persistant au reboot.

But retenu : **bascule de contexte au quotidien**. Pas une édition produit, pas une posture CSPN attestée
(même si le design respecte les contraintes CSPN existantes du projet).

## Le réel mesuré sur gk2 (2026-07-17)

Ces chiffres justifient les choix de conception ; ils ne sont pas décoratifs.

| Mesure | Valeur | Conséquence |
|---|---|---|
| units `secubox-*` | 187 (118 actives, 141 enabled) | rayon de souffle d'une bascule = des dizaines d'units |
| load | 5.4 sur **4 cœurs** | box déjà sursouscrite |
| RAM libre | ~2 Go / 8 Go | on éteint **avant** d'allumer, sinon le pic tue la box |
| conteneurs LXC | 24 | un actionneur non-systemd |
| `menu.d/*.json` existants | 134 | la fondation déclarative existe déjà |
| paquets avec `nginx/` | 112 | un portail web à retirer/remettre |
| units `Requires=secubox-core.service` | **80** | cascade dure sur un `Type=oneshot` qui fait `mkdir` |
| units avec `CPUWeight` défini | 59/60 échantillonnées | l'infra de priorité existe déjà |
| service + socket propres par module | oui (vérifié : peertube, lyrion, photoprism, nextcloud, dpi, waf, billets, podcaster) | `systemctl disable --now` est un vrai « off » unitaire |

Trois contraintes de la box, déjà éprouvées en production, contraignent le moteur :

1. **Pas de restart de masse** — 111 daemons sur ~2 Go libres : un `systemctl` parallèle en masse
   provoque un effondrement (thundering herd). L'application doit être **séquentielle, avec attente de
   socket**.
2. **`RuntimeDirectory=secubox` partagé** — redémarrer une unit peut effacer `/run/secubox` et tuer les
   sockets des voisines (corrigé sur la board par `RuntimeDirectoryPreserve=yes` ; le backport source
   reste dû). Le moteur doit en tenir compte.
3. **`Requires=secubox-core`** sur 80 units — cascade d'arrêt sur un oneshot de préparation de
   répertoires.

Aucune de ces trois n'est exprimable dans une `.target` systemd — d'où l'architecture retenue.

## Architecture retenue

**Manifestes déclaratifs en fichiers plats + moteur de réconciliation.**

Alternatives écartées :

- **Tout systemd natif** (profil = `.target` + presets). Rédhibitoire : LXC, routes WAF et menus ne sont
  pas des units ; une target exprime « ce qui doit tourner », pas « ce qui doit être éteint » ;
  l'épinglage n'a pas d'équivalent propre.
- **Manifestes → génération de targets**. On paie la complexité de génération *et* il faut quand même
  gérer LXC/portail à côté.

Le modèle retenu traite uniformément les **trois actionneurs hétérogènes** (systemd / LXC / portail) et
fournit un **diff avant application** — indispensable vu le rayon de souffle. Les fichiers plats sont
réutilisables et partageables (via le mesh, hors périmètre ici).

---

## ① Manifeste module

Un fichier plat par module, livré par son paquet, installé en `/etc/secubox/modules.d/<id>.toml`.
Source : `packages/secubox-<id>/modules.d/<id>.toml`.

```toml
id        = "peertube"
category  = "media"        # media | security | network | infra | dev | mesh
runtime   = "lxc"          # native | lxc
exposure  = "public"       # public | lan | internal
units     = ["secubox-peertube.service"]
lxc       = "peertube"     # présent seulement si runtime = "lxc"
portal    = { domain = "peertube.gk2.secubox.in" }   # absent si pas de portail
priority  = 40             # 0-100 — pilote CPUWeight ET l'ordre d'application
protected = false          # true = jamais éteignable
needs     = ["auth"]       # deps souples, au niveau module (ids, pas units systemd)
```

**Taxonomie** (les catégories demandées, formalisées) :

- `runtime` : `native` | `lxc` — « avec LXC ou pas ».
- `exposure` : `public` (portail externe via HAProxy/WAF) | `lan` (LAN-only, ex. lyrion) | `internal`
  (pas d'accès utilisateur direct).
- `category` : regroupement métier, pour les stats.

`menu.d/*.json` **reste inchangé** : c'est une préoccupation UI (path, ordre, icône), avec son propre
cycle de vie. Le manifeste ne porte que le cycle de vie du module. Aucun champ n'est dupliqué : le nom et
l'icône restent lus depuis `menu.d`.

### Le profiler de configuration — `secubox-profilectl scan`

On ne rédige pas 134 manifestes à la main. `scan` les **dérive du réel** :

- parcourt les units `secubox-*`, les conteneurs LXC, `/etc/secubox/waf/haproxy-routes.json`, `menu.d/`
- **mesure le coût réel** par module : RSS et temps CPU (via `systemctl show -p MainPID` → `/proc`)
- émet des manifestes *draft* dans `/etc/secubox/modules.d/` (jamais d'écrasement d'un manifeste
  existant sans `--force` : un manifeste corrigé à la main fait autorité sur une dérivation)
- signale ce qu'il n'a pas su classer, au lieu de deviner

Le coût mesuré est **la donnée qui rend le panneau utile** : sans lui, l'utilisateur ne sait pas ce que
coûte réellement un module.

---

## ② Modèle d'état — profils + pins

Profils : `/etc/secubox/profiles/<name>.toml` — fichiers plats, réutilisables.

```toml
name  = "media"
label = "🎬 Média"
description = "Serveurs médias allumés, analyse lourde éteinte."
on = ["lyrion", "peertube", "photoprism", "podcaster"]
# tout ce qui n'est pas listé → OFF (sauf protected)
```

Pins : `/etc/secubox/profiles/pins.toml` — le toggle individuel persistant.

```toml
gitea = "on"    # 📌 survit aux bascules de profil
dpi   = "off"
```

Profil actif : `/etc/secubox/profiles/active` (contient un nom).

### Résolution de l'état désiré

Ordre strict, sans exception :

```
protected        → ON   (toujours, non négociable)
épinglé          → valeur du pin      📌
listé dans on    → ON                 ⟳
sinon            → OFF                ⟳
```

Les profils sont **exhaustifs** (état désiré complet) : basculer donne toujours le même résultat quel que
soit l'état de départ — pas de dérive accumulée. Les **pins** réconcilient ce déterminisme avec la
liberté de forcer un module ; ils sont explicites et visibles (📌 épinglé vs ⟳ suit le profil).

### Noyau protégé

`protected = true` sur : `nginx`, `secubox-auth`, `secubox-aggregator`, le firewall, et le moteur de
profils lui-même. Sinon un profil peut éteindre ce qui permet de le rallumer : la box se verrouille,
sans webui ni Companion pour revenir — et le rollback 4R ne sert à rien si l'API qui l'exécute est
éteinte.

Le moteur **refuse** tout diff touchant un module protégé — y compris via un pin. Ce n'est pas un
avertissement : c'est un refus.

---

## ③ Moteur — `secubox-profilectl`

Commandes : `scan` · `status` · `diff` · `apply` · `pin <id> on|off` · `unpin <id>` · `rollback`

`diff` est le **défaut** ; `apply` exige `--yes`. Une bascule ne doit jamais être un accident.

### Algorithme d'application

1. Calculer l'état désiré de tous les modules (§②).
2. **Diff vs le réel** : `systemctl is-enabled`/`is-active`, état LXC (`lxc-ls -f`), présence de la route
   portail. Le réel est *observé*, jamais supposé depuis un état stocké.
3. **Refus** si le diff touche un module `protected`.
4. **Snapshot 4R** (double-buffer : `shadow` → validation → swap atomique), conforme au module
   PARAMETERS du projet.
5. **Éteindre AVANT d'allumer.** Avec ~2 Go libres, allumer d'abord ferait un pic qui tue la box.
6. **Séquentiel, un module à la fois, avec attente de socket** entre chaque. Jamais en parallèle.
   Dans chaque phase, ordre par `priority` (les plus prioritaires allumés en premier, éteints en
   dernier).
7. **Audit append-only** de chaque décision dans `/var/log/secubox/audit.log`.
8. Échec d'un module → arrêt, rollback, rapport de ce qui a été appliqué.

### Actionneurs

| Type | ON | OFF |
|---|---|---|
| systemd | `systemctl enable --now <unit>` | `systemctl disable --now <unit>` |
| LXC | `lxc-start` + `lxc.start.auto=1` | `lxc-stop` + `lxc.start.auto=0` |
| portail | route ajoutée dans `haproxy-routes.json` (hot-reload) | route retirée |

`disable` et `lxc.start.auto=0` sont **déjà persistants au reboot** — c'est la persistance de base.

### Réconciliation au boot

`secubox-profile-apply.service` (oneshot, après `network.target`) rejoue la réconciliation au démarrage.
La persistance ne repose donc pas seulement sur `disable`/`start.auto` : la dérive (paquet réinstallé qui
ré-`enable` son unit dans son postinst — un comportement réel de ce projet) est **corrigée au boot**.

---

## ④ Dépendances minimisées — prérequis

Convertir les **80 `Requires=secubox-core.service` → `Wants=`**.

`secubox-core.service` est un `Type=oneshot` / `RemainAfterExit=yes` dont l'`ExecStart` fait
`mkdir -p /var/log/suricata` + `chown`. Un `Requires=` dur y accroche 80 services : si core échoue ou est
arrêté, les 80 tombent en cascade. `After=` garde l'ordre ; `Wants=` retire la cascade. C'est un
`Wants=` déguisé en `Requires=`.

Ce travail **précède** le moteur : sinon celui-ci hérite des cascades et un `disable` isolé peut en
entraîner d'autres.

`needs` dans le manifeste porte les dépendances **au niveau module** (ids), utilisées pour :
- ordonner l'application,
- **avertir** avant une bascule (« éteindre `auth` casse 6 modules »).

On n'invente pas de nouvelles dépendances systemd. Le graphe reste minimal et lisible.

---

## ⑤ Priorités présentées

`priority` (0-100) du manifeste :

- pilote un drop-in `CPUWeight` par unit (l'infra existe : 59/60 units en ont déjà un) ;
- pilote l'**ordre d'application** ;
- **est affichée** dans le panneau : tri et regroupement par priorité, pour que « ce qui compte » soit
  visible d'un coup d'œil.

Le panneau montre par module : état (ON/OFF, 📌/⟳), catégorie, `runtime`, `exposure`, `priority`, et le
**coût mesuré** (RSS).

---

## ⑥ Stats par catégorie

`GET /api/v1/profiles/stats` → agrégat par `category`, `runtime` et `exposure` :
modules ON/OFF, RSS total, CPU. Alimente le panneau webui et le Companion.

Exemple : `media: 4 ON / 2 OFF, 1.2 Go RSS` · `public: 11 exposés` · `lxc: 9 ON / 15 OFF`.

La **centralisation mesh des métriques clients fait l'objet d'un spec séparé** : c'est un système
distribué (3 nœuds, annuaire, DHT) avec ses propres problèmes de transport, d'authentification et de
cohérence. Le fusionner ici produirait deux systèmes conçus à moitié. Ce spec se contente d'exposer des
stats **locales** propres — que le mesh pourra consommer.

---

## ⑦ Surfaces

- **CLI** : `secubox-profilectl` — helper root, exposé aux daemons via sudoers *scopé* (les modules
  tournent en `secubox` avec `NoNewPrivileges`, motif établi du projet).
- **API** : `/api/v1/profiles/*`, sur **son propre service et son propre socket** —
  **jamais servie par l'aggregator**. Le moteur ne doit pas dépendre de ce qu'il est susceptible de
  redémarrer ; servi in-process, une bascule pourrait le tuer en plein milieu.
- **Panneau webui** `/profiles/` — cyan hybrid-skin, conforme à `WEBUI-PANEL-GUIDELINES.md`.
- **Module Companion** `profiles` — bascule et état depuis le téléphone.

Toutes les surfaces exigent JWT (`Depends(require_jwt)`).

---

## Hors périmètre (YAGNI)

Écarté tant que la bascule manuelle n'a pas tourné en conditions réelles :

- planification horaire / profils auto-déclenchés ;
- synchronisation des profils via le mesh ;
- profils par utilisateur ;
- métriques mesh centralisées (spec séparé).

---

## Tests

- **Unitaires** : résolution d'état (protected > pin > profil > défaut) ; calcul du diff ; ordre
  d'application (OFF avant ON, priorité respectée) ; refus sur module protégé.
- **Intégration** : `scan` sur une arborescence factice ; `apply` en dry-run produit le bon plan.
- **Sécurité** : un profil qui tente d'éteindre `auth` est refusé ; un pin sur un module protégé est
  refusé.
- L'`apply` réel est validé sur la board, module par module, en partant d'un module sans dépendant
  (`lyrion`), jamais sur un lot.

Cible ≥ 80 % (contrainte CSPN du projet).

---

## Découpage d'implémentation

| Phase | Contenu | Risque |
|---|---|---|
| 1 | manifestes + `scan`/profiler + `status` + `diff` — **lecture seule** | nul |
| 2 | `Requires=` → `Wants=` sur les 80 units | faible, isolé |
| 3 | `apply` + pins + réconciliation au boot | **élevé** — le vrai morceau |
| 4 | profils (ensembles) + panneau webui + Companion | moyen |
| 5 | stats par catégorie | faible |

La phase 1 a une valeur propre : elle livre l'inventaire, la taxonomie et le **coût par module** sans
rien éteindre. Elle doit tourner sur la vraie box avant que la phase 3 n'écrive quoi que ce soit.
