# Design — `sbxwaf` : moteur WAF Go host-native (remplacement mitmproxy)

- **Issue** : #744
- **Date** : 2026-06-26
- **Prior art** : #662 (port toolbox R3 `sbxmitm`), `docs/superpowers/specs/2026-06-18-mitm-engine-migration-analysis.md`
- **Statut** : design validé (brainstorming) — en attente de revue avant plan d'implémentation

## 1. Contexte & problème

Le WAF de SecuBox inspecte tout le trafic externe entrant (HAProxy TLS 1.3 → backend
`mitmproxy_waf` → mitmdump `--mode regular` → backends LXC). L'inspection tourne dans
`mitmproxy` 11.0.2 (LXC `10.100.0.60:8080`) avec trois addons Python :

- `secubox_waf.py` (930 lignes) — routing vhost→backend (`haproxy-routes.json`,
  reload mtime 10s), moteur de règles regex (SQLi/XSS/LFI/RCE…), ban gradué
  (fenêtre glissante 300s, seuil 3 → 403 WARNING puis 403 BAN), bridge CrowdSec
  LAPI (`/v1/alerts` → firewall-bouncer → nft drop), pages d'erreur synthétiques,
  `Connection: close` (#496), whitelist CIDR RFC1918, skip statiques, bypass token NC.
- `cookie_audit.py` — ledger RGPD des `Set-Cookie` (JSONL, valeurs hashées SHA256).
- `media_cache.py` — cache de réponses média (16 MB/objet, 2 GB total).

### Problèmes du moteur actuel
1. **Perf** : Python GIL-bound. Phase 9 (#501) a dû lancer **4 workers + fanout
   numgen** pour saturer les cœurs. Regex Python + dispatch asyncio par requête.
2. **Fragilité** : dépendance à la version mitmproxy (#605 timing `requestheaders`
   en v11), au drop-in confdir (#603), au drift `/data` vs `/srv` des routes — trois
   modes de panne mémorisés qui downent tous les vhosts inspectés.
3. **RAM** : ~150-200 MB × 4 workers dans le LXC.

## 2. Objectif & décisions

| Axe | Décision |
|-----|----------|
| Driver principal | **Performance/charge** (throughput, p99 latence, RAM) |
| Périmètre | **Remplacement COMPLET** — aucun mitmproxy résiduel dans le WAF |
| Placement | **Host-native** (workers `secubox-waf-ng-worker@`), durci |
| Approche | **A** — binaire dédié `sbxwaf`, cœur partagé extrait de `sbxmitm`, shadow→cutover |

### Gains estimés (à valider par bench, = critères go/no-go BLOQUANTS)
- Throughput : **>5×/cœur** (suppression GIL + fanout) ; cible bench `>5× req/s·cœur`.
- Latence p99 : **<⅓** (regexp compilé + GC concurrent, pas de thrash refcount).
- RAM : **<¼** (1 binaire statique ~30-80 MB vs 600-800 MB).
- Robustesse : suppression des 3 modes de panne (binaire statique, zéro runtime).

Ces seuils sont **bloquants** : pas de cutover tant qu'ils ne sont pas atteints sur
le bench de charge (§7.3). Si un cas live-dashboard incompressible empêche un seuil,
il est documenté et arbitré explicitement avant cutover.

### Non-objectifs (YAGNI)
- Pas d'unification immédiate des moteurs (`sbxmitm` reste séparé — approche B écartée
  pour ne pas coupler les cycles de release WAF et toolbox R3).
- Pas de JA4/splice TLS dans le WAF (besoins toolbox R3, hors périmètre WAF).

## 3. Architecture cible

```
Internet ──TLS1.3──> HAProxy :443
                        │  use_backend mitmproxy_waf  (ACL vhost)
                        ▼
                 backend mitmproxy_waf
                   server waf <HOST_IP>:8080   ◄── flip cutover (host au lieu du LXC)
                        ▼
        ┌─────────────────────────────────────────┐
        │  sbxwaf  (host-native, user secubox-waf) │
        │  workers ng-worker@1..2 (rolling restart)│
        │  ├─ forge CA per-host (mode regular)     │
        │  ├─ routes-loader (haproxy-routes.json)  │
        │  ├─ moteur règles WAF (waf-rules.json)   │
        │  ├─ ban gradué (fenêtre glissante)       │
        │  ├─ bridge CrowdSec LAPI                 │
        │  ├─ cookie-audit JSONL                   │
        │  ├─ media-cache                          │
        │  └─ pages d'erreur 502/503/504           │
        └─────────────────────────────────────────┘
                        ▼
            backends LXC 10.100.0.0/24
```

- **Position réseau identique** à mitmdump : écoute `:8080`, **même confdir CA**
  (migrée `/data/mitmproxy` → `/etc/secubox/waf/ca`), **même `haproxy-routes.json`**
  (reload mtime), **backend HAProxy inchangé** (on flip l'IP `server waf` du LXC vers
  l'host). La frontière TLS exacte (forge `--mode regular`) est miroitée par `sbxwaf`.
- **Concurrence** : 1 process tous-cœurs. On garde **2 workers** pour le
  rolling-restart sans coupure (pas pour scaler) — le fanout numgen 4-workers
  disparaît.

## 4. Composants (unités isolées, testables)

| Package / cmd | Rôle | Dépend de |
|---|---|---|
| `internal/forge` | CA + forge leaf per-host (extrait de `sbxmitm`) | crypto/tls, x509 |
| `internal/relay` | POST async unix-socket fire-and-forget | net |
| `internal/httpcodec` | gzip/br/zstd decode+reencode (extrait) | compress, brotli, zstd |
| `internal/util` | helpers HTTP communs | — |
| `cmd/sbxwaf/routes.go` | charge `haproxy-routes.json`, reload mtime, rewrite `req.Host/URL` | internal |
| `cmd/sbxwaf/rules.go` | regex compilées depuis `waf-rules.json`, match path/query/body/UA | regexp |
| `cmd/sbxwaf/ban.go` | fenêtre glissante 300s, seuil → WARNING/BAN, map lock-guarded TTL | sync |
| `cmd/sbxwaf/crowdsec.go` | POST LAPI `/v1/alerts` (JWT) | net/http |
| `cmd/sbxwaf/cookieaudit.go` | parse Set-Cookie, hash SHA256, append JSONL | crypto/sha256 |
| `cmd/sbxwaf/mediacache.go` | cache réponses média (16MB/2GB) — réutilise `mediacatch.go` | — |
| `cmd/sbxwaf/errpages.go` | templates 502/503/504 embarqués | embed |
| `cmd/sbxwaf/main.go` | reverse-proxy HTTP, pipeline d'inspection, listen :8080 | net/http |

Chaque unité a un contrat clair (entrée→verdict) et est testable isolément contre
des fixtures. Le cœur partagé `internal/*` est consommé par `cmd/sbxmitm` ET
`cmd/sbxwaf` sans coupler leurs binaires.

## 5. Portage des fonctions (remplacement complet)

Parité **exacte** requise avec `secubox_waf.py` (sécurité-critique, no-regress) :

- **Routing** : `requestheaders` → lookup host dans routes, rewrite cible ; host non
  mappé → **421**.
- **Règles** : catégories regex (SQLi/XSS/LFI/RCE…) depuis `waf-rules.json`
  (enabled/severity), match sur path+query+body+UA. Skip statiques (.js/.css/.png/
  health/status), bypass tokens NC (`/index.php/login/v2/`, `/ocs/v2.php/core/login`).
- **Ban gradué** : fenêtre glissante 300s, seuil 3 → 1ʳᵉ détection **403 WARNING**,
  count≥3 **403 BAN** ; whitelist CIDR RFC1918+loopback (opérateurs LAN jamais bannis).
- **CrowdSec** : alerte JWT → LAPI `/v1/alerts` → bouncer nft drop (4h défaut).
- **Pages d'erreur** : interception 502/503/504 → pages thémées.
- **Cookie-audit** : `response` → Set-Cookie → JSONL hashé.
- **Media-cache** : Content-Type/size/TTL → store/serve.
- **`Connection: close`** (#496) conservé.

## 6. Durcissement (compense la perte d'isolation LXC)

Le host-native expose le WAF (trafic attaquant) sur l'hôte → contrôles compensatoires
(exigence CSPN — séparation de privilèges, AppArmor enforce) :

- `User=secubox-waf` / `Group=secubox-waf` non-privilégié (créé en postinst).
- `NoNewPrivileges=yes`, `ProtectSystem=strict` + `ReadWritePaths` minimal
  (`/var/log/secubox`, `/var/cache/secubox/waf`, `/run/secubox`), `ProtectHome=yes`.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, drop de toutes capabilities,
  `SystemCallFilter` (seccomp).
- **Profil AppArmor enforce** livré dans `debian/`, activé en postinst.
- Journalisation audit **append-only** `/var/log/secubox/audit.log` (ban/unban/règle).
- Secrets (JWT CrowdSec, clé CA) hors code, `/etc/secubox/secrets/` chmod 600 owner
  `secubox-waf`.

## 7. Migration : shadow → parité → cutover → rollback

1. **Shadow-run** : `sbxwaf` déployé sur un **port parallèle** (`:8081`), trafic
   miroité (HAProxy `mode tcp` mirror / tee). Aucun impact prod.
2. **Harness de parité** : corpus de requêtes (malveillantes + légitimes) rejoué
   contre Python ET Go ; compare **verdict** (allow/204/403/421/ban) + **cible de
   routing**. Réutilise le pattern `parity-fixtures.json` (#662). No-regress détection
   = **bloquant**.
3. **Bench perf** (go/no-go) : throughput req/s·cœur, p99 latence, RSS — cibles §2.
4. **Cutover** : flip du `server waf` HAProxy (IP LXC → host:8080). **Rollback** =
   re-flip vers le LXC (mitmproxy reste déployé jusqu'à validation).

## 8. Tests

- **Unitaires** : chaque package `internal/*` + `cmd/sbxwaf/*` (rules, ban, routes,
  cookieaudit) avec fixtures.
- **Parité** : harness §7.2 (vs mitmproxy live).
- **Charge** : bench §7.3 (critères cutover).
- **Sécurité** : non-régression de la détection (corpus d'attaques connu) + tests CSPN
  (séparation privilèges, AppArmor enforce, audit append-only).

## 9. Risques & mitigations

| Risque | Mitigation |
|---|---|
| Régression de détection WAF | Harness parité bloquant + corpus d'attaques avant cutover |
| Perte d'isolation (host-native) | Durcissement §6 (user dédié, AppArmor, seccomp, caps) |
| Frontière TLS forge mal miroitée | Shadow-run + comparaison réponses ; mitmproxy en rollback |
| Couplage cœur partagé ↔ toolbox | `internal/*` versionné, binaires séparés, tests des deux cmd |
| Drift CrowdSec LAPI (auth/format) | Test d'intégration LAPI + fallback log si POST échoue |
