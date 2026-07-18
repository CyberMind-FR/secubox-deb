# Profils fonctionnels + export installateur — Conception

**Date** : 2026-07-18
**Statut** : conception validée (design approuvé « go ok all »), prête pour le plan
**Auteur** : Gérald Kerma <devel@cybermind.fr>
**Module** : `secubox-profiles` (Phase 1 déjà livrée : manifests, `scan`, `status`, `diff` — lecture seule)

---

## Objectif

Deux livrables sur le moteur de profils Phase 1 existant :

1. **Profils fonctionnels et optimisés** ancrés dans l'inventaire réel de gk2, pour
   **exercer le switch** — aujourd'hui via `diff` (le seul actuateur de Phase 1),
   `apply` restant la Phase 3.
2. **Export installateur** : une sous-commande **lecture seule** qui produit la liste
   des paquets Debian correspondant aux **seuls modules actifs** d'un profil, pour
   builder un installateur/image ne posant que ces modules.

Aucune Phase 3 (`apply`) ici : les deux livrables sont read-only et compatibles Phase 1.

## Données de terrain (gk2, scan 2026-07-17)

187 modules, **119 ON = 3182 Mo RSS**, 3 protégés (`aggregator`, `auth`, `core`).
142 paquets `secubox-*` pour 187 modules ⟹ mapping module→paquet **pas 1:1** (un paquet
peut porter plusieurs modules/units : `secubox-core` porte core+runtime+leds+…).

---

## ① Profils (livrable 1)

### Schéma (déjà défini par `state.load_profile`)

TOML plat : `name` (DOIT == nom de fichier sans extension), `label` optionnel, `on = [ids]`
**exhaustif** (ce qui n'est pas listé est éteint). La résolution `state.resolve` est stricte
et inchangée : `protected → ON` · `pin → valeur du pin` · `dans on → ON` · `sinon → OFF`.

### Les quatre tiers (membres = IDs réels validés contre les 187 manifests)

| Profil | Modules | ~RSS | Rôle |
|---|---|---|---|
| `full` | 119 | 3182 Mo | snapshot du loadout courant — baseline |
| `lite` | 38 | 1066 Mo | daily-driver : sécu complète + infra cœur + 1 dashboard, sans LXC lourds/media/AI |
| `secure-gateway` | 17 | 625 Mo | appliance durcie : firewall/waf/haproxy/crowdsec/auth/certs/dns/exposure/users — gros `diff`, test de switch fort |
| `media-lab` | 108 | 2541 Mo | box maison-média : `full` moins la lourde analytique sécu |

Les listes exactes sont figées dans le plan (générées depuis `status --json`, chaque ID
vérifié présent dans `modules.d/`).

**Précédence des pins (à documenter, comportement correct)** : `pins.toml` (12 modules
épinglés `off` sur gk2) l'emporte sur `on`. `diff full` peut donc afficher des `stop` pour
des modules épinglés-off encore en cours d'exécution — c'est le mécanisme de pin qui survit
aux bascules, pas un bug. Les vrais tests de bascule sont `lite`/`secure-gateway`.

### Livraison

Référence **read-only** dans le paquet : `profiles/*.toml` → `/usr/share/secubox/profiles/`.
`postinst` **sème** chaque profil manquant dans `/etc/secubox/profiles/` (jamais d'écrasement
— les éditions opérateur persistent). Versionné dans le repo (`packages/secubox-profiles/profiles/`).

## ② Export installateur (livrable 2)

### Cœur testable — `api/export.py`

```
resolve_packages(manifests, profile, pins, *, run=_run) -> ExportResult
```

- Ensemble désiré ON = `{ id | resolve(m, profile, pins) == ON }` (réutilise `state.resolve`, pur).
- Pour chaque module ON → paquet propriétaire via ses `units` : `dpkg -S <unit>` → paquet.
  - **Repli** si aucune unit ou `dpkg -S` échoue : candidat `secubox-<id>`, vérifié présent
    (`dpkg -l`) ; sinon le module part dans **`unresolved`** (jamais abandonné en silence).
- `run` injecté (mêmes conventions que `cli._run` : `rc=None` = n'a pas pu s'exécuter) →
  testable sans board.
- `ExportResult` : `profile`, `on_ids: list[str]`, `packages: list[str]` (dédupliqués, triés),
  `unresolved: list[str]`, `rss_estimate_mo: int`.

**Sûreté** : un installateur qui omet un module en silence produit une image cassée. Les
`unresolved` sont donc toujours **remontés** (stderr + champ JSON), jamais masqués.

### Surface CLI — `secubox-profilectl export <profil> [--format pkglist|apt|json]`

- `pkglist` (défaut) : un paquet par ligne sur **stdout** ; `unresolved` en warning sur **stderr**.
- `apt` : une ligne `apt-get install -y <paquets>` prête à consommer.
- `json` : `ExportResult` sérialisé.
- Exit 0 même avec `unresolved` (warning), pour rester scriptable. (`--strict` → exit non-nul
  si `unresolved` non vide : YAGNI pour l'instant, non implémenté.)

Read-only, JWT non requis en CLI (root local) ; pas de route web dans ce lot (le panel
d'export viendra si besoin, hors périmètre ici).

---

## Tests

- **Profils** : chaque `profiles/*.toml` charge via `load_profile` sans erreur (`name`==stem) ;
  un test de cohérence vérifie que **tout ID listé existe** parmi un ensemble de manifests de
  référence (garde-fou anti-typo — sinon un ID mort serait silencieusement OFF).
- **resolve** (déjà couvert Phase 1) : re-vérifier qu'un profil donné produit le bon désiré-état
  pour protected / pin / listé / absent.
- **export** (pur, `run` injecté) : units→paquet dédupliqué+trié ; repli `secubox-<id>` quand
  pas d'unit ; module réellement introuvable → `unresolved` (pas dans `packages`) ; `dpkg -S`
  qui échoue (rc=None) → repli puis `unresolved`, jamais un paquet fabriqué ; les 3 formats ;
  `rss_estimate_mo` sommé. Chaque test doit pouvoir échouer (mutation).

Couverture ≥ 80 % (CSPN).

## Hors périmètre (YAGNI)

- `apply` (Phase 3 : snapshot 4R, séquencement, réconciliation boot).
- Axe d'activation riche (alwayson/ondemand/sleeper/disabled/uninstalled/broken) — modèle
  distinct, nécessiterait sa propre conception.
- Sync de profils via le mesh ; panel web d'export ; build automatique de l'image.
- `--strict` sur l'export.
