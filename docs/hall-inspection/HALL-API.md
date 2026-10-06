<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HALL-API — endpoints réellement appelés pendant le parcours invité

Relevé par Chromium headless 145 (Playwright) sur https://hall.gk2.secubox.in/ le 2026-10-02 : chaque requête `fetch`/XHR émise par le Hall et par les écrans qu'il embarque, avec le statut reçu. *La comparaison entre un client du réseau local et un visiteur externe n'est pas publiée ici.* Aucune URL n'a été devinée : tout ce qui suit a été appelé par l'interface elle-même. Les **écritures** (POST/PUT/DELETE) ont été bloquées par le navigateur avant d'atteindre le serveur.

## Lecture des colonnes
- **Statuts** : ce qu'ont reçu tous les écrans visités (accueil, 31 services, pages annexes).
- Les formes JSON (clés) viennent des réponses reçues ; les valeurs ne sont pas recopiées.

## 1. Tous les endpoints vus pendant l'ensemble du parcours


### `acces.gk2.secubox.in` — 3 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/acces/file` | 1 | 401×1 | detail |
| GET | `/api/v1/acces/invitation/url` | 2 | 200×2 | url, qr, sbxos |
| GET | `/api/v1/acces/profils` | 1 | 401×1 | detail |

### `actor.gk2.secubox.in` — 3 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/actor/actors` | 1 | 401×1 | detail |
| GET | `/api/v1/actor/campaigns` | 1 | 401×1 | detail |
| GET | `/api/v1/actor/stats` | 1 | 401×1 | detail |

### `admin.gk2.secubox.in` — 19 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/cookie-audit/summary` | 10 | 200×5, 401×5 | enabled, generated_at, summary |
| GET | `/api/v1/devwatch/issues` | 1 | 200×1 | ok, compte, delai_median_jours, delai_median_heures, echantillon_fermees, plus_ancienne_jo |
| GET | `/api/v1/devwatch/summary` | 24 | 200×17, FAILED×5, 401×2 | ok, repo, totals, cadence, emancipation, fund, latest_commits, latest_release, evolutions, |
| GET | `/api/v1/hub/auth_mode` | 2 | 401×2 | detail |
| GET | `/api/v1/hub/boot_mode` | 2 | 401×2 | detail |
| GET | `/api/v1/hub/dashboard` | 6 | 401×6 | detail |
| GET | `/api/v1/hub/health` | 2 | 200×2 | status, module |
| GET | `/api/v1/hub/public/health-batch` | 2 | 200×2 | modules, count |
| GET | `/api/v1/hub/public/led_status` | 2 | 200×2 | led1, led2, led3, raw |
| GET | `/api/v1/hub/public/menu` | 2 | 200×2 | categories, total_installed, total_active, cached_at |
| GET | `/api/v1/metablogizer/sites` | 3 | 401×2, FAILED×1 | detail |
| GET | `/api/v1/metablogizer/status` | 1 | 200×1 | module, version, enabled, components, site_count, published_count, sites_root, sites_cache |
| GET | `/api/v1/metrics/cert-status` | 10 | 200×5, 401×5 | enabled, generated_at, summary, next_renewal, warnings |
| GET | `/api/v1/metrics/health/summary` | 10 | 200×5, 401×5 | score, modules, waf, system, services, counts, _cache, timestamp, ssl |
| GET | `/api/v1/metrics/live-hosts` | 10 | 200×5, 401×5 | enabled, window_minutes, generated_at, entries, total_requests |
| GET | `/api/v1/metrics/visitor-origin` | 10 | 200×5, 401×5 | enabled, window_minutes, generated_at, entries |
| GET | `/api/v1/portal/theme` | 1 | 200×1 | board_type, board_model, profile, theme, css_vars |
| GET | `/api/v1/vault/etat` | 1 | 401×1 | detail |
| GET | `/api/v1/waf/stats` | 4 | 200×2, 401×2 | total_threats, threats_today, observed_threats, observed_today, by_category, by_severity,  |

### `billets.gk2.secubox.in` — 2 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/feed/activity` | 3 | 200×3 | comments, reactions |
| GET | `/jeton` | 3 | 200×3 | csrf, ts_token |

### `depot.gk2.secubox.in` — 1 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/droplet/depot/reglages` | 1 | 200×1 | actif, taille_max, fichiers_max |

### `hall.gk2.secubox.in` — 96 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/adm/api/v1/droplet/status` | 21 | 200×19, 401×2 | upload_dir, default_domain, sites_count, apps_count |
| GET | `/adm/api/v1/torrent/status` | 5 | 200×5 | module, version, enabled, installed, running, asleep, sources, components |
| GET | `/adm/api/v1/ytsas/status` | 16 | 200×16 | status, active, disk_free, jobs, cookies, total, conserved, downloading, to_peertube |
| GET | `/api/v1/acces/file` | 25 | 401×21, 403×4 | detail |
| GET | `/api/v1/acces/invitation/url` | 26 | 200×26 | url, qr, sbxos |
| GET | `/api/v1/acces/profils` | 5 | 404×5 | detail |
| GET | `/api/v1/acces/session/etat` | 43 | 200×43 | session |
| GET | `/api/v1/actor/stats` | 33 | 200×33 | actors, attempts_24h, blocked_24h, by_sensor, campaigns, dropped, events_24h, global, hone |
| GET | `/api/v1/dpi/clients` | 25 | 200×22, 401×3 | list[4] |
| GET | `/api/v1/dpi/countries` | 24 | 200×21, 401×3 | list[13] |
| GET | `/api/v1/dpi/stats` | 31 | 200×28, 401×3 | connected, total_flows, total_bytes, updated_at, protocols, apps, categories, talkers, ris |
| GET | `/api/v1/dpi/suggestions` | 23 | 200×20, 401×3 | list[16] |
| GET | `/api/v1/dpi/usage` | 25 | 200×22, 401×3 | usages, providers, applications, unknown |
| GET | `/api/v1/freeboxtv/channels` | 20 | 200×17, 403×3 | channels |
| GET | `/api/v1/lyrion/now-playing` | 61 | 200×60, FAILED×1 | title, artist, album, player, mode |
| POST | `/api/v1/lyrion/player/00%3A04%3A20%3A2b%3Aac%3Aea/action/pause` | 1 | FAILED×1 |  |
| GET | `/api/v1/lyrion/players` | 21 | 200×21 | players, count |
| GET | `/api/v1/messagerie/annuaire` | 26 | 200×19, FAILED×7 | personnes |
| GET | `/api/v1/messagerie/fil` | 52 | 200×45, FAILED×7 | messages, moi |
| GET | `/api/v1/messagerie/prives` | 52 | 200×45, FAILED×7 | messages |
| GET | `/api/v1/metablogizer/public/mosaique` | 19 | 200×16, 401×3 | sites, total, vignettes_manquantes |
| GET | `/api/v1/openpgp/moi` | 19 | 401×19 | detail |
| GET | `/api/v1/profiles/lifecycles` | 21 | 200×18, 401×3 | lifecycles |
| GET | `/api/v1/radio/current` | 8 | 200×8 | horloge_ms, offset_ms, piste, silence |
| GET | `/api/v1/sbxid/activite` | 19 | 200×19 | activites |
| GET | `/api/v1/sbxid/moi` | 22 | 401×22 | detail |
| GET | `/api/v1/vault/etat` | 19 | 401×19 | detail |
| GET | `/api/v1/vault/moi` | 20 | 401×20 | detail |
| GET | `/api/v1/webos/depot/reglages` | 21 | 200×18, FAILED×1, 401×2 | ok, donnees |
| GET | `/api/v1/webos/public/actions/droplet/liste` | 21 | 200×21 | ok, donnees |
| GET | `/api/v1/webos/public/actions/droplet/stockage` | 21 | 200×20, FAILED×1 | ok, detail |
| GET | `/api/v1/webos/public/actions/torrent/liste` | 5 | 200×5 | ok, detail |
| GET | `/api/v1/webos/public/actions/ytsas/liste` | 15 | 200×15 | ok, donnees |
| GET | `/api/v1/webos/public/aide/cartes` | 32 | 200×32 | cartes |
| GET | `/api/v1/webos/public/aide/cartes/acteurs` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/activite` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/coffre` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/contenu` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/dpi` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/forums` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/freeboxtv` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/lyrion` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/metablogizer` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/metanews` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/mon-coffre` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/peertube` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/podcaster` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/radio` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/securite` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/surfviewer` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/aide/cartes/zigbee` | 1 | 200×1 | id, ic, nom, role, usage, acces, service, metriques, etat, phrase |
| GET | `/api/v1/webos/public/broadcast` | 89 | 200×89 | actif, url, titre, par, pos, ts |
| GET | `/api/v1/webos/public/cardlets` | 17 | 200×17 | cardlets, count |
| GET | `/api/v1/webos/public/cardlets/podcaster` | 32 | 200×32 | id, kind, status, content, metrics, worker, silence |
| GET | `/api/v1/webos/public/cardlets/radio` | 32 | 200×32 | id, kind, status, content, metrics, silence |
| GET | `/api/v1/webos/public/cardlets/waf` | 20 | 200×20 | recent, trend_jour, id, kind, status, content, metrics, categorie, silence |
| GET | `/api/v1/webos/public/menu/acces` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/acteurs` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/activite` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/bbs` | 1 | 200×1 | id, items |
| GET | `/api/v1/webos/public/menu/billets` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/coffre` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/comptes` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/depot` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/devwatch` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/dpi` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/freeboxtv` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/lyrion` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/mail` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/messagerie` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/metablogizer` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/metanews` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/mon-coffre` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/mood` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/nextcloud` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/peertube` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/photoprism` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/podcaster` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/radio` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/sbxos` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/securite` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/socialrelay` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/surfviewer` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/torrent` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/ytsas` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/zia` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/menu/zigbee` | 1 | 404×1 | detail |
| GET | `/api/v1/webos/public/services` | 26 | 200×26 | services, computed_at |
| GET | `/api/v1/webos/public/waf/qui-frappe` | 19 | 200×19 | ok, attaquants, campagnes_total, haute_valeur, campagnes |
| GET | `/api/v1/webos/session` | 20 | 401×20 | detail |
| GET | `/api/v1/ytsas/list` | 26 | 200×26 | list[180] |
| GET | `/api/v1/zia/capabilities` | 16 | 200×14, 401×2 | capabilities |
| GET | `/api/v1/zia/health` | 19 | 200×19 | ok, engine, model, uptime_s |
| GET | `/api/v1/zigbee/devices` | 41 | 200×37, FAILED×1, 403×3 | pont, appareils |
| GET | `/pt/api/v1/videos` | 16 | 200×16 | total, data |
| GET | `/sbxos/mine/curation.json` | 10 | 200×10 | _pourquoi, _source, lieux |

### `lyrion.gk2.secubox.in` — 8 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| POST | `/cometd/handshake` | 4 | FAILED×4 |  |
| GET | `/html/lang/fr.json` | 1 | 200×1 |  |
| GET | `/html/misc/emblems.json` | 1 | 200×1 |  |
| GET | `/html/misc/icon-map.json` | 1 | 200×1 |  |
| GET | `/html/misc/player-icons.json` | 1 | 200×1 |  |
| GET | `/html/misc/track-sources.json` | 1 | 200×1 |  |
| POST | `/jsonrpc.js` | 11 | FAILED×11 |  |
| GET | `/material/customactions.json` | 1 | 200×1 |  |

### `metanews.gk2.secubox.in` — 3 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/metanews/categories` | 17 | 200×16, FAILED×1 | categories, ok |
| GET | `/api/v1/metanews/sources` | 1 | 200×1 | ok, sources |
| GET | `/api/v1/metanews/topics` | 23 | 200×22, FAILED×1 | ok, topics |

### `mood.gk2.secubox.in` — 1 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/mood/commun` | 1 | 200×1 | participants, suffisant, seuil, base_commune, base_active, detail, reserve |

### `peertube.gk2.secubox.in` — 20 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/config/` | 3 | 200×3 | client, defaults, webadmin, instance, search, plugin, theme, email, contactForm, serverVer |
| GET | `/api/v1/config/about` | 1 | 200×1 | instance |
| GET | `/api/v1/oauth-clients/local` | 3 | 200×3 | client_id, client_secret |
| GET | `/api/v1/player-settings/videos/3X6u1Sz5ZUxM9Pzdj3okGs` | 3 | 200×3 | theme |
| GET | `/api/v1/plugins/peertube-plugin-livechat/public-settings` | 6 | 200×6 | publicSettings |
| GET | `/api/v1/server/following` | 2 | 200×2 | total, data |
| GET | `/api/v1/videos` | 4 | 200×4 | data |
| POST | `/api/v1/videos/17e3904e-a07c-48d3-aa8e-79ce9ddbd226/views` | 1 | FAILED×1 |  |
| GET | `/api/v1/videos/3X6u1Sz5ZUxM9Pzdj3okGs` | 3 | 200×3 | id, uuid, shortUUID, url, name, category, licence, language, privacy, nsfw, nsfwFlags, nsf |
| GET | `/api/v1/videos/3X6u1Sz5ZUxM9Pzdj3okGs/captions` | 3 | 200×3 | total, data |
| GET | `/api/v1/videos/3X6u1Sz5ZUxM9Pzdj3okGs/chapters` | 3 | 200×3 | chapters |
| GET | `/api/v1/videos/3X6u1Sz5ZUxM9Pzdj3okGs/storyboards` | 3 | 200×3 | storyboards |
| GET | `/api/v1/videos/categories` | 2 | 200×2 | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 |
| GET | `/api/v1/videos/languages` | 2 | 200×2 | aa, ab, af, ak, am, ar, an, ase, as, asq, av, avk |
| GET | `/client/locales/fr-FR/player.json` | 3 | 200×3 | Quality, Auto, Speed, Subtitles/CC, Peers, peers, peer, no peers, Go to the video page, Se |
| GET | `/client/locales/fr-FR/server.json` | 5 | 200×5 | Music, Films, Vehicles, Art, Sports, Travels, Gaming, People, Comedy, Entertainment, News  |
| GET | `/plugins/translations/fr-FR.json` | 3 | 200×3 | peertube-plugin-livechat |
| GET | `/static/streaming-playlists/hls/17e3904e-a07c-48d3-aa8e-79ce9ddbd226/44b3aad2-b9fb-4fe9-be06-39aefe6830dc-master.m3u8` | 3 | 200×3 |  |
| GET | `/static/streaming-playlists/hls/17e3904e-a07c-48d3-aa8e-79ce9ddbd226/8f9ea6b0-b66d-49cc-ac2f-29594415d3ed-480-fragmented.mp4` | 47 | 206×46, FAILED×1 |  |
| GET | `/static/streaming-playlists/hls/17e3904e-a07c-48d3-aa8e-79ce9ddbd226/8f9ea6b0-b66d-49cc-ac2f-29594415d3ed-480.m3u8` | 1 | 200×1 |  |

### `podcaster.gk2.secubox.in` — 1 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/podcaster/public/library` | 20 | 200×16, FAILED×1, 401×3 | title, episodes, feeds, share |

### `radio.gk2.secubox.in` — 5 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/radio/current` | 74 | 200×71, FAILED×3 | chat, horloge_ms, offset_ms, piste, silence |
| POST | `/api/v1/radio/pistes/{n}/duree` | 23 | FAILED×23 |  |
| GET | `/api/v1/radio/playlist` | 31 | 200×31 | avenir, passe, pistes |
| GET | `/api/v1/radio/propositions` | 31 | 200×31 | propositions |
| GET | `/api/v1/radio/stats` | 28 | 200×28 | auditeurs, pistes, propositions, visites |

### `socialrelay.gk2.secubox.in` — 2 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/socialrelay/feed` | 1 | 200×1 | ok, posts |
| GET | `/api/v1/socialrelay/sources` | 2 | 200×2 | ok, sources |

### `waf.gk2.secubox.in` — 5 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/waf/bans` | 1 | 200×1 | bans, total, application |
| GET | `/api/v1/waf/campaigns` | 1 | 200×1 | available, attaquants, campagnes |
| GET | `/api/v1/waf/detections` | 1 | 200×1 | detections, count |
| GET | `/api/v1/waf/history` | 1 | FAILED×1 |  |
| GET | `/api/v1/waf/stats` | 1 | 200×1 | total_threats, threats_today, observed_threats, observed_today, by_category, by_severity,  |

### `ytsas.gk2.secubox.in` — 1 endpoint(s)

| Méthode | Chemin | Appels | Statuts | Forme (clés JSON) |
|---|---|---|---|---|
| GET | `/api/v1/ytsas/list` | 1 | 200×1 | list[180] |

Total : **170 endpoints distincts** (les identifiants numériques et hexadécimaux sont regroupés en `{n}` et `{id}`).


## 2. Écritures tentées par l'interface (bloquées, aucune n'a atteint le serveur)
| Méthode | Endpoint | Tentatives | Ce que fait l'interface |
|---|---|---|---|
| POST | `radio.gk2.secubox.in/api/v1/radio/pistes/{n}/duree` | 23 | le lecteur radio rapporte la durée d'une piste dès qu'il la charge |
| POST | `lyrion.gk2.secubox.in/jsonrpc.js` | 11 | la télécommande Lyrion interroge le serveur de musique |
| POST | `lyrion.gk2.secubox.in/cometd/handshake` | 4 | Lyrion ouvre son canal temps réel |
| POST | `peertube.gk2.secubox.in/api/v1/videos/{id}/views` | 1 | PeerTube compte une vue de vidéo |
| POST | `hall.gk2.secubox.in/api/v1/lyrion/player/{mac}/action/pause` | 1 | le Hall tente de mettre un lecteur Lyrion en pause |

**Constat** : un simple chargement de l'accueil par un invité provoque des écritures automatiques (durée radio, comptage de vue, handshake Lyrion). Je les ai bloquées pour ne rien modifier ; un visiteur normal les laisse passer.

## 3. Ressources tierces appelées par le navigateur
| Hôte | Requêtes | Origine observée |
|---|---|---|
| `fonts.googleapis.com` / `fonts.gstatic.com` | 33 / 45 | l'accueil du Hall (police Courier Prime) et la page Billets : appel direct à Google depuis le navigateur du visiteur |
| `www.franceinfo.fr`, `img.lemde.fr`, `www.radiofrance.fr`, `www.humanite.fr`, `io-fsly-bfmtv.cdn.nextradiotv.com` | 19 / 7 / 2 / 1 / 3 | vignettes des sujets MetaNews, chargées depuis les sites des médias |
| `www.zigbee2mqtt.io` | 10 | images de la carte Zigbee (documentation des appareils) |

## 4. Types de réponses
Pages HTML des cartes (`/cardlets/*.html`, `/messagerie/`, `/zia/micro.html`, `/sbxos/`, `/i/acces/micro.html`), scripts partagés (`domaine.js`, `lexie.js`, `/api/v1/webos/public/hotes.js`), médaillons `.webp`, flux média radio (`/media/{n}` en 206), flux vidéo YouTube souverain (`/api/v1/ytsas/stream/{id}`), HLS PeerTube (`/static/streaming-playlists/hls/…`).

