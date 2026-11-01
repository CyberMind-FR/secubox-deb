<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBX TV PRIVACY — lot 1 « socle appareil » (#3374)

Analyse réseau et protection de la vie privée des TV et box multimédia par filtrage DNS par
appareil. Ni injection de publicité, ni contournement des DRM. Le moteur reste `dnstv`
(`packages/secubox-ad-guard/api/dnstv*.py`) ; la table `devices` de `main.py` (morte) n'est pas reprise.

## Constat

`etat.json` (gk2) : `clients` = 13 entrées pour 3 appareils. Ce ne sont pas des erreurs : une entrée
= une adresse (IPv4, IPv6 en rotation #2981), le même `nom` les relie, et la vue Unbound est
`_slug(nom)`. Le contrôleur root rend Unbound **par adresse** (`access-control-view`). On garde donc
`clients` tel quel (forme opérationnelle lue par root) et on **ajoute** le pivot MAC à côté.

## Fichiers

| Fichier | Rôle |
|---|---|
| `api/dnstv.py` | `SCHEMA_ETAT = 2`, `PROFILS`, `SOURCES_PROFIL`, `_valider_appareils()` ; `valider_etat` accepte et conserve `schema` et `appareils` (le contrôleur root, qui n'importe que `dnstv`, accepte donc v1 et v2) |
| `api/dnstv_appareils.py` (nouveau) | migration, lecture NAC, profils, vue par MAC, correction manuelle |
| `api/dnstv_routes.py` | migration au chargement ; `/status` et `/auto/detection` enrichis ; `GET /appareils` ; `POST /appareils/{mac}/profil` |
| `sbin/secubox-adguard-auto` | migration sous le verrou des règles (gk2 migre dans la minute, sans visite de la page) |

## Signatures (`dnstv_appareils`)

```python
migrer(brut: dict, maintenant: int) -> tuple[dict, dict]          # pur ; (état v2, rapport)
migrer_fichier(dossier: Path | None = None) -> dict | None          # idempotent ; None si déjà v2 ou absent
lire_inventaire_nac(chemin: Path | None = None) -> dict[str, dict]  # mac -> ligne NAC ; {} si absent/refusé
profil_depuis_nac(ligne: dict) -> dict                              # {type, source:"nac", confiance, preuves}
profil_par_observation(domaines: Iterable[str]) -> dict | None      # {type, source:"observation", confiance, preuves}
vue_appareils(etat, nac, voisins, domaines_par_ip=None) -> list[dict]
corriger_profil(etat: dict, mac: str, type_: str | None, maintenant: int) -> dict
```

## Schéma v2 de `etat.json`

```json
{"schema": 2, "actif": true, "mode_defaut": "auto", "ajout_auto": true, "auto_essai": false,
 "ignores": [], "autorisations": {},
 "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": "aa:bb:cc:dd:ee:ff"}],
 "appareils": {"aa:bb:cc:dd:ee:ff": {"nom": "TV banc",
               "profil": {"type": "ANDROID_TV", "source": "manuel", "confiance": 100, "maj": 1793548800}}}}
```

- `clients` inchangé (v1). `appareils` : clé = MAC (minuscules, `a:b:c:d:e:f`), 64 au plus ;
  `nom` (NOM_RE) ; `profil` présent **seulement** pour une correction manuelle. Le profil NAC ou
  d'observation se recalcule à la lecture (il suit l'inventaire), il n'est jamais figé dans l'état.
- Profils : `FREEBOX_PLAYER`, `ANDROID_TV`, `GOOGLE_TV`, `SAMSUNG_TIZEN`, `LG_WEBOS`, `APPLE_TV`,
  `GENERIC_SMART_TV`, `INCONNU`. Sources : `nac`, `manuel`, `observation`. Confiance : entier 0–100.
- Un état sans `schema` est v1 ; `valider_etat` n'écrit `schema`/`appareils` que s'ils sont présents.

## Migration (non destructive)

1. Rien si `schema == 2` (idempotent) ou fichier absent.
2. Copie octet pour octet en `etat.json.avant-3374` (`O_EXCL|O_NOFOLLOW`, 0640), **une seule fois**.
3. Regroupement des `clients` par MAC. Les clients sans MAC restent tels quels, sans entrée `appareils`.
4. **Aucun mode n'est modifié** (décision du contrôleur, revue du lot 1) : la migration n'ajoute que
   `schema` et `appareils`, elle n'a donc aucun effet DNS. Les modes divergents d'une même MAC sont
   signalés (`modes_divergents` dans le rapport et dans la vue, qui affiche le mode le plus strict :
   block > auto > observe > off).
5. Le nom affiché vient de `clients` (entrée la plus récente) : un renommage s'y voit aussitôt.
6. Routes de lecture : aucun verrou si l'état est déjà v2 ; sinon verrou commun pris sans attendre,
   migration différée s'il est occupé. `POST …/profil` répond 409 tant que l'état est v1.
7. Sauvegarde : brouillon `O_EXCL`, écriture complète, `fsync`, puis `link` (jamais d'écrasement).

## Source NAC choisie

Le NAC tient `/var/lib/secubox/nac/devices.db` (SQLite WAL, compte `secubox`, table `devices`,
clé MAC). Lecture par ad-guard (même compte `secubox`) :

- `os.lstat` : fichier ordinaire, pas un lien, propriétaire = notre uid ou root, pas inscriptible
  par « autres », taille ≤ 64 Mio ; sinon refus (inventaire vide, journalisé) ;
- `sqlite3.connect("file:…?mode=ro", uri=True, timeout=2)` (même procédé que
  `secubox-nac/api/dnsevidence.py` en sens inverse), `SELECT` à colonnes nommées, `LIMIT 4096` ;
- aucun écrit chez le NAC ; toute erreur ⇒ `{}` (journalisée).
- **Repli** : NAC absent ⇒ `ip neigh` (`dnstv.lire_voisins`, déjà utilisé) pour rattacher les IP,
  et profil par observation DNS d'ad-guard, sinon `INCONNU`.
- IPv6 : le NAC ne garde qu'une adresse par MAC ; les autres viennent de `ip neigh` et des `clients`.

## Profils (preuves NAC : `os`/`os_source` d'osdetect, `device_subtype`, `oui_vendor`, `hostname`, `device_type`)

Jamais du nom donné dans ad-guard (« TV banc »). Confiance selon la preuve d'`os_source` :
classe vendeur DHCP 90, User-Agent 85, DNS 80, nom DHCP 60, empreinte 50.

1. `os` Tizen ⇒ SAMSUNG_TIZEN ; `os` webOS ⇒ LG_WEBOS.
2. nom DHCP `freebox-player`/`player-` ⇒ FREEBOX_PLAYER (60, 70 si OUI Freebox) ; OUI Freebox seul
   (MAC non aléatoire) ⇒ FREEBOX_PLAYER 50.
3. nom DHCP `apple-tv` ⇒ APPLE_TV 60 ; OUI Apple + sous-type streaming/récepteur ⇒ APPLE_TV 55.
4. `os` Google Cast ou nom DHCP `google-tv`/`chromecast` ⇒ GOOGLE_TV.
5. `os` Android + sous-type TV/décodeur/streaming ou `device_type=smart_tv` ⇒ ANDROID_TV (≤ 70).
6. sous-type télévision ou `device_type=smart_tv` ⇒ GENERIC_SMART_TV 40.
7. sinon INCONNU 0. Une MAC aléatoire n'est jamais typée par son OUI.

Observation (sans NAC) : domaines Samsung/LG de connectivité vus par ad-guard ⇒ SAMSUNG_TIZEN /
LG_WEBOS, confiance 70. **Une correction manuelle prime toujours.**

## API

- `GET /adblock-tv/appareils` (`require_lecture`) : liste par MAC
  `{mac, nom, ips, mode, profil, profil_source, profil_confiance, preuves, nac}`.
- `POST /adblock-tv/appareils/{mac}/profil` (`require_jwt`), corps `{"type": "<PROFIL>" | null}` :
  `null` efface la correction. Sous le verrou commun. Pas d'appel au contrôleur : le profil n'a
  aucun effet DNS au lot 1.
- `/status` : `clients[*]` gagnent `profil`, `profil_source`, `profil_confiance`, `ips` (si MAC),
  et une clé `appareils` ; `/auto/detection` : `appareils[*]` gagnent les mêmes champs. Aucun retiré.
