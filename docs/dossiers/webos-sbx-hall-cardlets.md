<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Brief de conception fourni par l'utilisateur (Gérald Kerma / AletheiaVox),
  transcrit ici comme document de référence. NE PAS IMPLÉMENTER sans brainstorm
  + spec dédiés (Phase 0 = Discovery only). Issue de suivi : voir MEMORY / gh.
-->

# SecuBox-Deb — WebOS SBX / Hall Cardlets — brief de conception

**Repo cible** : `CyberMind-FR/secubox-deb` · **Surface** : `all.gk2.net` → futur `hall.gk2.net`
**Scope V1** : services SecuBox/GK2 natifs uniquement. **Hors V1** : replay cookie tiers (Facebook/YouTube/SAS), embedding arbitraire.

## 1. Mission
Transformer le portail GK2 en **bureau WebOS vivant** sans perdre la vérité opérationnelle d'`all.gk2.net` (catalogue, LAN/WAN, santé online/degraded/offline, latence, URL canonique, description). Ajoute contexte + interactions via **cardlets**, sans remplacer les données réelles par des mockups.

**UX cœur** : `Carte service → Cardlet active → Application complète`. La carte compacte est l'état par défaut ; elle peut révéler un fragment fonctionnel sûr de l'app ; l'app reste indépendante et s'ouvre normalement.

## 2. Conventions à préserver (lire le code AVANT de créer)
`.claude/WEBUI-PANEL-GUIDELINES.md`, `.claude/MODULE-COMPLIANCE.md`, `packages/secubox-hub/www/shared/sidebar.js`, `packages/secubox-bbs/internal/web/templates/layout.html`, `packages/secubox-radio/`, `packages/secubox-toolbox/`, `docs/AI-HANDOVER-cabine-evolution.md`.
- Navigation santé-aware partagée ; menu Hub + APIs santé AVANT toute nouvelle logique de registre.
- `sbx_token` = clé localStorage canonique des mutations authentifiées.
- Rendu cache-first + revalidation en arrière-plan ; dégradation gracieuse à l'échec API.
- Opérations privilégiées scopées via les `ctl` de module. Pas de registre dupliqué. Pas de migration framework.
- **Le WebOS public n'est PAS le skin admin hybrid-dark** : Hall/WebOS a sa propre surface blanche haute-lisibilité AletheiaVox (les panels admin gardent la charte hybrid-dark).

## 3. Split produit
- **`all.gk2.net`** : catalogue de services autoritatif (quoi existe, où, LAN/WAN, santé, latence, description).
- **`hall.gk2.net`** : bureau WebOS consommant le MÊME registre + enrichissant certains services de cardlets.
- **Jamais** forker les définitions de service entre All et Hall (registre/santé partagés).

## 4. Shell WebOS SBX
Fournit : launcher/menu, statut nœud, identité/avatar local, notifications, cycle de vie cardlet, invitation de session optionnelle, hooks observabilité Cabine R5.
NE DOIT PAS : posséder la session de chaque app, scraper des mots de passe, copier des cookies entre domaines, iframer chaque app, devenir obligatoire pour l'accès direct. **Si le WebOS tombe, chaque app reste utilisable.**

## 5. Modèle cardlet (3 états)
- **Carte compacte** : icon, nom, hostname, description, état online/degraded/offline/unknown, LAN/WAN, latence.
- **Cardlet active** : petite surface applicative vivante et sûre.
- **Application complète** : l'app existante.
> Axiome : *une cardlet n'est PAS une capture d'écran — c'est une capacité sûre, vivante, exposée par l'app.*

## 6. Radio = cardlet active de référence
Structure : barre (refresh|play|favorite|audio|volume) + cover/métadonnées/compteurs + input message compact + chat/réactions récentes. Densité fonctionnelle à préserver pour les autres modules.

Payload normalisé (l'adaptateur traduit l'API Radio réelle, jamais le screenshot en dur) :
```json
{"id":"radio","kind":"radio-now-playing","status":"online","updated_at":"ISO-8601",
 "content":{"title":"...","subtitle":"...","artwork":"/api/v1/webos/cardlets/radio/artwork","station":"..."},
 "metrics":[{"id":"listeners","value":0},{"id":"participants","value":0},{"id":"views","value":0}],
 "actions":[{"id":"refresh","safe":true},{"id":"play_pause","safe":true},{"id":"favorite","safe":true},{"id":"volume","safe":true},{"id":"open","safe":true}],
 "social":{"can_post":false,"recent":[]}}
```

## 7. Candidats cardlets (aperçu sûr / actions sûres)
Billets (posts récents / open,new-post), BBS (sujets+non-lus / open-topic), gk2.net, Podcaster (épisode / play), YT-SAS (item caché), Torrent (nb actifs), PeerTube (live/dernière vidéo / play), Nextcloud (**quota avant noms**), Gitea (santé/compteurs), Jellyfin/Lyrion (now-playing / play,pause), **Webmail (nb non-lus seulement par défaut)**, Zigbee2MQTT (nb devices), Dépôt (état publish), Mastodon (posts locaux / compose si autorisé), Radio (cardlet riche), Kbin (threads), MetaNews (topics clusterisés + nb sources).
**Défauts privacy** : Mail=count avant contenu ; Nextcloud=quota avant fichiers ; contenu privé/social seulement si l'auth courante l'autorise.

## 8. Contrat registre (étendre le Hub existant, pas de parallèle)
Objet service normalisé : `id, name, description, category, icon, urls{lan,wan}, routing{mode,available}, health{state,latency_ms}, cardlet{enabled,kind,endpoint,size}, auth{mode}, capabilities[]`.
Endpoints à réutiliser d'abord : `/api/v1/hub/public/menu`, `/api/v1/hub/public/health-batch`, `/api/v1/hub/dashboard`.

## 9. APIs WebOS (`/api/v1/webos/...`)
`GET services|status|cardlets|cardlets/{id}|notifications` · `POST cardlets/{id}/actions/{action}`. Session Bridge feature-flaggé : `POST session/invite|exchange`. Pas de polling dupliqué si Hub le fournit déjà.

## 10. Cache / refresh
Cache-first → paint instant → revalidate → patch seulement l'UI changée. Valeurs de départ : registre 1h+revalidate, santé 15s, cardlet live 5–15s ou event-driven, contenu lent 30–60s, notifs 15–30s. Timeout par-cardlet, retry indépendant, last-known-good + timestamp stale visible, cache adaptateur côté serveur, ETag/If-None-Match. **Une cardlet morte ne bloque jamais tout le Hall.**

## 11. Responsive
Desktop : barre système + sidebar (catégories/favoris/système) + grille `repeat(auto-fit,minmax(280px,1fr))`, tailles sémantiques small|medium|wide (pas de coords pixel en V1). Tablet : 2 colonnes, sidebar repliable, cardlet focus inline/bottom-sheet. Mobile : 1 colonne, bouton SBX = drawer, cibles 44px, pas de scroll horizontal.

## 12. Design visuel (WebOS public)
Base blanc/off-white, contraste élevé, navy/cyan sobre, états sémantiques vert/orange/rouge, bordures fines, ombres légères, chaleur AletheiaVox, Zanimalos en accents rares, demi-bulles savon seulement pour états/événements importants. Éviter : mascotte sur chaque carte, gradients lourds sous le texte, glass excessif, faux néon, data décorative, santé/latence cachées sous l'illustration.

## 13. Barre WebOS injectée (V1 : apps SecuBox/GK2 natives seulement)
Allowlist vhost, marqueur idempotent, HTML-only, CSP-aware, assets locaux, fail-open, opt-out par-vhost, pas de réécriture cookie. Bootstrap `<div id="sbx-webos-root" data-sbx-webos="1"></div><script src="/shared/webos/webos-runtime.js" defer>`. Jamais de secret en attribut DOM/inline.

## 14. Identité locale + Session Bridge (V1 ≠ copier des cookies)
Flux : identité locale SBX → invitation spécifique-cible → code opaque one-time TTL court → la cible valide audience+usage-unique → la cible crée SA PROPRE session locale. Sécurité : TTL court, one-time, audience explicite, CSRF, pas de cookie source dans le ticket, pas de mot de passe, pas de bearer en query, audit métadonnées seulement, rate-limit, détection replay. Services externes = threat model futur séparé.

## 15. Cabine R5 (observabilité)
Événements sûrs : `webos.module.open`, `webos.cardlet.refresh`, `webos.invite.requested|issued|accepted|rejected`, `webos.session.created|replay_detected`. Jamais de cookie/mot de passe/bearer complet/corps de MP brut.

## 16. Machine à états cardlet
`loading|ready|stale|offline|restricted|error`. Stale reste visible+timestamp ; offline isolé au service ; restricted dit explicitement « auth requise » ; erreurs fatales visibles ; staleness ordinaire ≠ panique rouge ; LED santé opérationnelle autoritative.

## 17. Accessibilité
Boutons/landmarks sémantiques, focus visible, clavier, état pas encodé par couleur seule, reduced-motion, alt utile, WCAG AA, pas d'interaction drag-only.

## 18. Structure d'implémentation proposée (découvrir les chemins d'abord)
`packages/secubox-hub/api/webos/{registry,cardlets,session_bridge}` + `www/shared/webos/{webos-runtime.js,webos-bar.js,webos-cardlets.js,webos.css}` + `www/hall/index.html` + `adapters/cardlets/{radio,bbs,metanews}`. Proposition, pas permission de dupliquer.

## 19. Feature flags
`webos.{enabled,hall_enabled,injected_bar_enabled:false,cardlets_enabled,session_bridge_enabled:false,cabine_events_enabled:false}` + par-service `services.<id>.cardlet` / `private_preview`.

## 20. Phases de livraison
- **Phase 0 — Discovery ONLY (pas de code)** : rendre source servant all.gk2.net, source registre, source santé/latence, source failover LAN/WAN, hooks auth, API/data cardlet Radio actuelle, code sidebar/cache/WebOS réutilisable, fichiers Phase 1 exacts proposés, risques.
- **P1** Registre normalisé partagé (mêmes services réels, santé+latence, service offline rend seul, pas de liste statique dupliquée).
- **P2** Shell Hall + cartes compactes (parité opérationnelle all.gk2.net, responsive, first-paint caché).
- **P3** Cardlet Radio réelle (contenu/artwork/metrics/contrôles sûrs/chat si auth ; échec Radio isolé).
- **P4** BBS + MetaNews (adaptateurs réels).
- **P5** Cardlets restantes (PeerTube→Nextcloud→Mastodon→Webmail→Jellyfin/Lyrion→Billets→Podcaster→Kbin→Torrent→Zigbee→Dépôt→Gitea→YT-SAS→gk2.net).
- **P6** Barre WebOS injectée (pilote Hall→BBS→Radio, flag+allowlist).
- **P7** Session Bridge (pilote 1 app native).
- **P8** Événements Cabine R5.

## 21. Definition of Done V1
Registre réel pilote l'UI ; santé/latence/reachability visibles ; Hall survit aux échecs de cardlet individuels ; Radio en cardlet active réelle ; BBS+MetaNews adaptateurs réels ; responsive+clavier ; `sbx_token` respecté ; cache-first ; erreurs scopées+visibles ; pas de replay cookie tiers ; pas de secret brut au navigateur/logs ; tests registre/cardlets/sécurité ; E2E board documenté ; rollback par feature flags.

## 22. Tests
Unit (normalisation registre, mapping santé, latence, schéma cardlet, cache stale, filtrage permissions, invite expiry/audience/replay). Frontend (registre vide/réel/1-offline, adaptateur Radio lent, payload stale, cardlet restricted, mobile, clavier-seul). Sécurité (échappement HTML, pas d'onclick inline non-fiable, CSP, CSRF, audience invalide, invite rejouée/expirée, fuite referrer/query, pas de secret en logs). E2E board (parité, LAN/WAN, refresh santé, ouvrir Radio, action playback sûre, panne isolée d'un service test, restore, responsive, audit logs secrets).

## 23. Axiome de conception
> *Une cardlet n'est pas une capture d'app. C'est une petite capacité sûre et vivante exposée par l'app.*
> *Hall n'absorbe pas les services — il les laisse respirer ensemble.* (Modèle poupée-russe inverse.)

---

## Rapport avec les TODO widgets déjà ouverts
Ce brief chapeaute : #1170 (cardlets vidéo média-en-fond), #1171 (widget ytsas micro/mini/full), #1172 (radio slide messages↔playlist). Ils sont des instances du modèle cardlet ci-dessus — à réconcilier dans le système commun (tailles small|medium|wide, contrat cardlet, adaptateur par module) plutôt qu'isolément.
