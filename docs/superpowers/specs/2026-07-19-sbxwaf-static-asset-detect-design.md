# sbxwaf — fingerprinting sur chemins d'assets statiques — Conception

**Date** : 2026-07-19
**Statut** : conception validée (root cause confirmé + Option B approuvée)
**Auteur** : Gérald Kerma <devel@cybermind.fr>
**Composant** : `packages/secubox-toolbox-ng/cmd/sbxwaf` (moteur WAF Go, interim)

---

## Cause racine (systematic-debugging, Phase 1 — CONFIRMÉE)

`main.go:334` : `skip := privateCIDR(ip) || staticAsset(rawPath) || ncBypass(rawPath)`.
`staticAsset()` (`inspect.go:89`) renvoie `true` pour tout chemin finissant en
`.js/.css/.png/…`. Quand `skip` est vrai, **tout le bloc d'inspection est court-circuité**,
dont `s.rules.Match()` (`main.go:389`). Donc une sonde de scanner sur un chemin d'asset
statique (ex. `/global-protect/portal/css/bootstrap.min.css` sur une box sans PAN-OS)
**échappe entièrement à la détection** — aucune règle detect/honeypot ne s'évalue, aucun
log. Le fast-path est porté du WAF Python (`check_request`), motivé par la **perf** (ne pas
passer ~150 regex sur chaque asset — la majorité du trafic) et l'**anti-FP** (le contenu
d'un asset légitime ne doit pas déclencher les règles SQLi/XSS).

**Fausse piste écartée** : le media-cache (`main.go:509`) est une étape séparée et
postérieure ; il n'est pas en cause.

## Principe du fix — Option B : le skip ne s'applique qu'aux règles *block*

Sur un chemin statique (et pour un client **non** privé/trusted), faire tourner **seulement
les catégories `detect`/`escalate`** contre `path + query + ua` (sans lire le body), et
**continuer à sauter les catégories `block`** + l'inspection du body.

Rationale : `detect` est zéro-FP par construction (ne bannit jamais) et `escalate` ne
bannit qu'un scanner récidiviste — aucune des deux ne porte le risque de FP qui motivait le
skip. Le fingerprinting par chemin (product_absent_probes) se déclenche donc, sans jamais
introduire de nouveau *block* sur un asset légitime. Coût perf borné (seules les catégories
non-block, peu nombreuses).

**Propriété prouvée** : le test existant `TestInspectStaticAssetSkip` (une règle SQLi
*block* sur `/app.js?q=…union select…` doit passer sans 403) **reste vert** — Option B
garde le skip des règles block sur les statiques. Aucun comportement block existant ne change.

## Périmètre du changement (deux fichiers)

1. **`rules.go`** — nouvelle méthode filtrée :
   ```go
   func (r *Rules) MatchModes(method, rawPath, rawQuery, body, ua string,
                              includeBlock bool) (cat, sev, mode string, hit bool)
   ```
   Identique à `Match`, mais quand `includeBlock == false` les catégories en `modeBlock`
   sont sautées. `Match` devient un délégué `MatchModes(..., true)` — signature et
   comportement publics inchangés (tous les tests `Match` existants passent).

2. **`main.go` handler** — retirer `staticAsset` du calcul de `skip` ; calculer
   `isStatic := staticAsset(rawPath)` ; dans `if !skip` : pour un statique, ne pas lire le
   body et appeler `MatchModes(..., includeBlock=false)` ; sinon, chemin existant
   (`includeBlock=true`, body lu). Les trois branches detect/escalate/block downstream sont
   **inchangées** : sur un statique, `MatchModes` ne renvoie jamais `block`, donc la branche
   block ne se déclenche pas naturellement.

`privateCIDR`, `ncBypass`, trusted-host restent des skips **complets** (le LAN et les tokens
mobiles NC ne sont jamais fingerprintés — inchangé).

## Tests

- **rules_test** : `MatchModes(includeBlock=false)` saute une catégorie block, mais renvoie
  un hit pour une catégorie detect/escalate ; `MatchModes(includeBlock=true)` ≡ `Match`.
- **inspect_test / main_test** :
  - un chemin `.css`/`.js` matchant une catégorie **detect** est désormais inspecté et
    journalisé `action=detect`, et **passe** (non bloqué) — le cœur du fix ;
  - un chemin `.js` matchant une catégorie **block** (SQLi) **passe toujours** sans 403
    (`TestInspectStaticAssetSkip` inchangé, re-vérifié) ;
  - un chemin statique matchant une catégorie **escalate** observe/escalade comme sur un
    chemin normal ;
  - un asset statique légitime (ne matchant rien) passe sans log ni block ;
  - un client privé (RFC1918) sur un chemin statique reste entièrement bypassé.
- Chaque test comportemental doit pouvoir échouer (mutation).

## Déploiement

`sbxwaf` est le binaire **interim** (pas construit par le `.deb`, qui build sbxmitm +
sbx-sentinel). Build cross-arm64 offline vendored :
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off go build -trimpath -o sbxwaf ./cmd/sbxwaf`,
swap `/usr/sbin/sbxwaf` par **`mv`** (jamais `cp` — *text file busy*), puis
`systemctl restart secubox-waf-ng` (**jamais** `kill -HUP`). Un bump du changelog
toolbox-ng documente le changement pour la traçabilité même si le binaire est déployé à la main.

## Hors périmètre (YAGNI)

- Faire tourner **toute** la ruleset (block compris) sur les statiques (Option A, rejetée :
  perf + FP).
- Le contournement du **media-cache** (n'est pas la cause).
- Ajouter le build de sbxwaf au `.deb` (tâche de packaging distincte).
- La correction Python parity (le WAF Python est en voie de retrait).
