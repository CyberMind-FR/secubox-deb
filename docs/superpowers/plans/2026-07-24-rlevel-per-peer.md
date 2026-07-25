# R-level MITM par peer wg-toolbox — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Régler le niveau d'inspection MITM (off/passive/active/reel) par peer wg-toolbox, avec self-service borné, override admin, statut webui temps réel.

**Architecture:** Un clamp par-peer sur la décision existante `Policy.Decide` de sbxmitm (Go). Une nouvelle unité `rlevel.go` charge `peer-rlevel.json` (+ réutilise le mapping IP→pubkey de `machash.go`/`wg-peers.json`) via le même `reload.Watcher` que le reste, et modifie le verdict par flux. `off` se fait en amont au niveau nft (exclusion du DNAT→mitm). Surface : ctl root scopé + API toolbox + panneau.

**Tech Stack:** Go stdlib pur (sbxmitm, `-mod=vendor`, cross arm64 offline), bash ctl, nftables dropin, FastAPI (toolbox), webui hybrid-dark.

## Global Constraints

- **Modes** : `off(0) < passive(1) < active(2) < reel(3)`. Effectif = `forced ?? clamp(chosen, floor, reel)`.
- **Clamp du verdict** (sur `Decide → {allow,block,splice,mitm}`) :
  - `passive` → **toujours `splice`** (passthrough + log méta, zéro déchiffrement).
  - `active` → déchiffre mais **n'enforce PAS le block** : `block → mitm` ; `splice`/`allow`/`mitm` inchangés (pinné reste splice).
  - `reel` → `Decide` **tel quel** (block honoré) + enforcement (le block 204 existant EST l'enforcement v1 ; ban/rewrite réutilisent l'existant).
  - `off` → jamais atteint dans le worker (exclu par nft en amont).
- **splice-learned/bypass prime toujours** : un hôte pinné (Signal/banques) que `Decide` renvoie `splice` reste splice même en active/reel — on ne le déchiffre jamais (évite 502). Le clamp ne peut que **baisser** l'inspection (passive) ou **retenir** l'enforcement (active), jamais forcer le déchiffrement d'un pinné.
- **Fail-safe passive** : peer inconnu → `passive` ; `peer-rlevel.json` illisible/corrompu → `passive` pour tous ; jamais `off` silencieux, jamais déchiffrement d'office.
- **⚠ default_mode configurable** : le comportement ACTUEL (tout peer MITM'd+block ≈ reel) change si le défaut est passive. `peer-rlevel.json defaults.mode` est **configurable** ; le déploiement le fixe explicitement (recette : seed à `active` ou `reel` pour préserver, ou `passive` pour privacy-forward — décision opérateur, loggée).
- **Auth self-service = identité tunnel** : l'API `/rlevel/me` résout la pubkey depuis l'IP source `10.99.x` (wg garantit IP↔pubkey) ; une IP hors wg-toolbox → 403. Un peer ne descend jamais sous son `floor` ni ne lève un `forced`.
- **Délégation root** : écriture JSON + regen nft + signal workers via `sbxmitm-policyctl` (sudo scopé, commandes exactes). Jamais d'action root in-process ([[feedback_webui_delegates_to_confined_ctl]]).
- **Hot-reload** : nouveaux flux seulement ; flux établis intacts. Réutilise `reload.Watcher`.
- **nft** : dropin `table inet secubox-toolbox-rlevel` trié AVANT le fanout DNAT toolbox ([[feedback_nft_layered_dropins_persistence]]) ; DEFAULT DROP inchangé.
- **Déploiement = rolling** : redémarrer `secubox-toolbox-ng-worker@1..4` **un par un** (jamais les 4 d'un coup — interruption du MITM) ([[feedback_no_mass_daemon_restart]]).
- **Go** : stdlib pur, `-mod=vendor`, cross `GOARCH=arm64` offline. Audit CSPN append-only sur toute écriture de politique.
- **Pas de SocksPolicy/chown parents/`#DEBHELPER#` en commentaire/.bak en sites-enabled.** Commits `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, aucune réf IA.

## File Structure

**secubox-toolbox-ng (Go)**
- `cmd/sbxmitm/rlevel.go` — RLevel enum, `effective()`, `clampVerdict()`, `PeerPolicy` (load `peer-rlevel.json` + ip→pubkey + hot-reload), `ModeForIP()`
- `cmd/sbxmitm/rlevel_test.go` — tests purs
- `cmd/sbxmitm/machash.go` — étendre : exposer `ip→pubkey` (déjà lit wg-peers.json)
- `cmd/sbxmitm/main.go` — insérer le clamp au call-site `Decide` (+ init PeerPolicy)

**secubox-toolbox (paquet : ctl + nft + API + panel)**
- `sbin/sbxmitm-policyctl` — écrit `peer-rlevel.json`, regen nft off, signal workers ; audit
- `nft.d/` génération dropin off-bypass (par le ctl)
- `api/…/rlevel.py` (ou routes dans l'API toolbox) — `/rlevel/peers`, `/rlevel/peer/<pk>`, `/rlevel/me`
- `www/…/rlevel/index.html` — panneau ; `menu.d/` entrée
- `debian/…` — install, sudoers, changelog

---

### Task 1: Go — RLevel + effective() + clampVerdict() (pur)

**Files:** Create `cmd/sbxmitm/rlevel.go`, `cmd/sbxmitm/rlevel_test.go`

**Interfaces:**
- Produces: `type RLevel int` (Off=0,Passive=1,Active=2,Reel=3) ; `parseRLevel(string) (RLevel,bool)` ; `effective(chosen, forced, floor RLevel, hasForced bool) RLevel` = `hasForced ? forced : clamp(chosen, floor, Reel)` ; `clampVerdict(mode RLevel, verdict string) string`.

- [ ] **Step 1: failing tests**
```go
// rlevel_test.go
package main
import "testing"
func TestEffective(t *testing.T) {
    cases := []struct{ chosen, forced, floor RLevel; hasF bool; want RLevel }{
        {Active, 0, Passive, true, 0},      // forced wins (off)
        {Off, 0, Passive, false, Passive},  // clamped up to floor
        {Reel, 0, Passive, false, Reel},
        {Active, 0, Active, false, Active},
    }
    for i, c := range cases {
        if got := effective(c.chosen, c.forced, c.floor, c.hasF); got != c.want {
            t.Fatalf("case %d: got %v want %v", i, got, c.want)
        }
    }
}
func TestClampVerdict(t *testing.T) {
    // passive → always splice
    for _, v := range []string{"allow","block","mitm","splice"} {
        if got := clampVerdict(Passive, v); got != "splice" { t.Fatalf("passive %s→%s", v, got) }
    }
    // active → block downgraded to mitm, splice stays splice (pinned safe)
    if clampVerdict(Active,"block") != "mitm" { t.Fatal("active block") }
    if clampVerdict(Active,"splice") != "splice" { t.Fatal("active splice must stay") }
    if clampVerdict(Active,"mitm") != "mitm" { t.Fatal("active mitm") }
    // reel → verdict unchanged
    for _, v := range []string{"allow","block","mitm","splice"} {
        if clampVerdict(Reel, v) != v { t.Fatalf("reel %s changed", v) }
    }
}
```
- [ ] **Step 2:** `cd packages/secubox-toolbox-ng && go test ./cmd/sbxmitm/ -run 'TestEffective|TestClampVerdict'` → FAIL (undefined).
- [ ] **Step 3: implement rlevel.go** (enum + parseRLevel + effective + clampVerdict per the Global Constraints clamp table). `clampVerdict`: `Off`→verdict unchanged (never called; nft handles); `Passive`→`"splice"`; `Active`→ if verdict=="block" return "mitm" else verdict; `Reel`→verdict. SPDX header.
- [ ] **Step 4:** `go test ... -run 'TestEffective|TestClampVerdict'` → PASS.
- [ ] **Step 5: commit** `feat(toolbox-ng): rlevel effective() + clampVerdict() (off/passive/active/reel)`.

---

### Task 2: Go — PeerPolicy loader (peer-rlevel.json + ip→pubkey + hot-reload + fail-safe)

**Files:** Create PeerPolicy in `cmd/sbxmitm/rlevel.go` (extend), `cmd/sbxmitm/machash.go` (expose ip→pubkey), tests in `rlevel_test.go`.

**Interfaces:**
- Consumes: `wg-peers.json` (déjà lu par machash : `{"peers":{"<pk>":{"ip":"10.99.1.X"}}}`).
- Produces: `type PeerPolicy struct{...}` ; `LoadPeerPolicy(rlevelPath, wgPeersPath string) (*PeerPolicy, error)` (best-effort, jamais fatal) ; `(*PeerPolicy).ModeForIP(ip string) RLevel` (résout ip→pubkey→effective, fail-safe `Passive` si ip inconnue/json illisible) ; hot-reload via `reload.Watcher` (targets: rlevel + wg-peers).

- [ ] **Step 1: failing test** — fixtures: a `peer-rlevel.json` `{"defaults":{"mode":"passive","floor":"passive"},"peers":{"PK1":{"chosen":"active","forced":null,"floor":"passive"},"PK2":{"forced":"off"}}}` + a `wg-peers.json` `{"peers":{"PK1":{"ip":"10.99.1.5"},"PK2":{"ip":"10.99.1.6"}}}` written to `t.TempDir()`. Assert: `ModeForIP("10.99.1.5")==Active`, `ModeForIP("10.99.1.6")==Off` (forced), `ModeForIP("10.99.1.99")==Passive` (unknown→default), corrupt json → all `Passive`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: implement** — parse JSON (stdlib `encoding/json`), build `ip→PeerEntry` by joining wg-peers (pubkey→ip) with rlevel peers (pubkey→{chosen,forced,floor}); `ModeForIP` = lookup entry (or defaults) → `effective(...)`; register two `reload.Target` (rlevel + wg-peers) rebuilding the joined map under a mutex on mtime change (mirror the policy.go Watcher pattern). Fail-safe: unreadable/parse-error → keep a map that yields `Passive` for every IP (i.e., empty peers + defaults=passive).
- [ ] **Step 4:** run → PASS. Also `go vet ./cmd/sbxmitm/`.
- [ ] **Step 5: commit** `feat(toolbox-ng): PeerPolicy loader (peer-rlevel.json + ip→pubkey join, hot-reload, fail-safe passive)`.

---

### Task 3: Go — brancher le clamp au call-site Decide

**Files:** Modify `cmd/sbxmitm/main.go` (init PeerPolicy on the Proxy; clamp after `Decide`), test `cmd/sbxmitm/rlevel_wire_test.go`.

**Interfaces:**
- Consumes: `peerIP(conn)` (existant, main.go:251), `px.pol.Decide` (main.go:297), `PeerPolicy.ModeForIP` (Task 2).
- Produces: after `verdict := px.pol.Decide(host, host)`, insert `if px.rlevel != nil { verdict = clampVerdict(px.rlevel.ModeForIP(peerIP(client)), verdict) }`. Add `rlevel *PeerPolicy` field to `Proxy`, init in the constructor from default paths (env-overridable `SECUBOX_PEER_RLEVEL`, `SECUBOX_WG_PEERS`). `nil` rlevel = no-op (current behavior) for tests that don't set it.

- [ ] **Step 1: failing test** — a table-driven test constructing a `Proxy` with a stub `PeerPolicy` forcing a mode for a fixed IP, calling the exported clamp path (or a small helper `px.decideForPeer(clientIP, host)`), asserting: passive IP → "splice" even for a would-be-mitm host; active IP → "mitm" for a would-be-block host; reel IP → block preserved. (If the call-site isn't unit-testable directly, add `func (px *Proxy) decideForPeer(clientIP, host, sni string) string` that wraps Decide+clamp and call it from BOTH accept paths; test that.)
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: implement** `decideForPeer` wrapper + use it at both call-sites (transparent accept + wg accept) so they never drift; init `px.rlevel`.
- [ ] **Step 4:** `go test ./cmd/sbxmitm/ -run RLevel` PASS + **full suite** `go test ./...` PASS (no regression to parity harness). `go vet`.
- [ ] **Step 5: commit** `feat(toolbox-ng): per-peer clamp wired into Decide (decideForPeer, both accept paths)`.

---

### Task 4: ctl — sbxmitm-policyctl (write JSON + regen nft off + signal workers + audit)

**Files:** Create `packages/secubox-toolbox/sbin/sbxmitm-policyctl`, test `packages/secubox-toolbox/tests/test_policyctl.py` (or bash test).

**Interfaces:**
- Produces: `sbxmitm-policyctl set-floor <pubkey> <mode>` / `force <pubkey> <mode|none>` / `set-chosen <pubkey> <mode>` / `set-default <mode> <floor>` — atomically rewrite `/var/lib/secubox/toolbox/peer-rlevel.json` (shadow+rename), regen the nft off-dropin from peers whose effective==off, `nft -f` it, and touch/signal so workers hot-reload (the file mtime change suffices — workers watch it). `list` prints the JSON. Every mutation appends to `/var/log/secubox/audit.log`. Env-overridable paths for tests (`RLEVEL_FILE`, `WG_PEERS`, `NFT_D`, `DRYRUN`).
- Validation: mode ∈ {off,passive,active,reel} ; pubkey present in wg-peers.json else error ; `set-chosen` clamps to floor (server-side guard mirrors the peer API).

- [ ] **Step 1: failing tests** — set-floor/force/set-chosen mutate the JSON correctly (idempotent, atomic); `force off` puts the peer's IP in the regenerated nft off-dropin; `force none` removes it; invalid mode → non-zero rc, JSON untouched; audit line appended.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: implement** (bash + `jq` for JSON; `set -euo pipefail`; shadow-write+`mv` atomic; nft dropin `table inet secubox-toolbox-rlevel { chain prerouting { type nat hook prerouting priority dstnat -1; ip saddr { <off-ips> } return } }` — priority ONE LESS than the toolbox DNAT fanout so it runs first; empty set → empty table; DRYRUN skips nft/signal).
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5: commit** `feat(toolbox): sbxmitm-policyctl (atomic peer-rlevel.json + nft off-bypass regen + audit)`.

---

### Task 5: nft — off-bypass dropin correctness

**Files:** the dropin template + a focused test `packages/secubox-toolbox/tests/test_nft_rlevel.py`.

**Interfaces:** consumes ctl output.

- [ ] **Step 1: failing test** — given peers PK-off (effective off) at 10.99.1.6 and PK-active at 10.99.1.5, the ctl-generated nft dropin contains `ip saddr` including `10.99.1.6` with a `return`/accept-before-DNAT semantics and NOT `10.99.1.5`; table name `secubox-toolbox-rlevel`; priority strictly before the toolbox DNAT fanout.
- [ ] **Step 2:** FAIL. **Step 3:** ensure ctl emits exactly that. **Step 4:** PASS.
- [ ] **Step 5: commit** `test(toolbox): nft off-bypass scope (only effective-off peers, before DNAT fanout)`.

---

### Task 6: API — /rlevel admin + peer self-service (tunnel-auth)

**Files:** add rlevel routes to the toolbox API (`packages/secubox-toolbox/…/api` — locate the existing toolbox FastAPI), test `test_rlevel_api.py`.

**Interfaces:**
- `GET /rlevel/peers` (admin, jwt) → list peers with {pubkey, label, chosen, forced, floor, effective, live(handshake)}. `POST /rlevel/peer/<pubkey>` (admin) → set floor/force (delegates `sudo -n sbxmitm-policyctl`). `GET /rlevel/me` / `POST /rlevel/me` (peer) → resolve pubkey from **request source IP** (10.99.x → wg-peers), get/set own `chosen` bounded by floor (403 if source IP not a wg-toolbox peer; 409 if below floor or forced). No in-process root — all writes via ctl.

- [ ] **Step 1: failing tests** (TestClient) — admin set-floor delegates to `_ctl` with `sbxmitm-policyctl`; `/rlevel/me` with a stubbed source IP resolving to a peer returns that peer's mode; `POST /rlevel/me` below floor → 409; source IP not in wg-peers → 403; peer cannot lift a `forced`.
- [ ] **Step 2:** FAIL. **Step 3:** implement (mirror proxypac API `_ctl` sudo pattern; source IP from `request.client.host` or `X-Real-IP`; jwt on admin routes, tunnel-identity on `/me`). **Step 4:** PASS.
- [ ] **Step 5: commit** `feat(toolbox): API /rlevel admin + peer self-service (tunnel-auth, ctl delegation)`.

---

### Task 7: Panel — /rlevel webui (table + badges + self-service) + navbar

**Files:** Create `packages/secubox-toolbox/…/www/rlevel/index.html`, `menu.d` entry, test `test_rlevel_panel.py`.

- [ ] **Step 1: failing test** — panel has sidebar (`class="sidebar"` + `/shared/sidebar.js`), reads `sbx_token`, calls `/api/v1/toolbox/rlevel/peers` (adapt to the real mount prefix), has mode badges (off/passive/active/reel), admin force/floor controls AND a self-service control, uses event delegation (no inline handler interpolating peer data — XSS guard, per the proxypac lesson), esc() on labels/pubkeys; `menu.d` JSON valid.
- [ ] **Step 2:** FAIL. **Step 3:** implement (hybrid-dark, model on the proxypac panel; delegation not inline onclick). **Step 4:** PASS.
- [ ] **Step 5: commit** `feat(toolbox): panneau /rlevel (statut par peer, badges, self-service, délégation événements)`.

---

### Task 8: Packaging + cross-build + rolling-deploy recipe

**Files:** `packages/secubox-toolbox/debian/{rules,postinst,control,changelog}`, `debian/secubox-toolbox.sudoers` (add the policyctl lines), and the Go build.

- [ ] **Step 1:** debian/rules installs `sbxmitm-policyctl` (0755), the rlevel API/panel/menu.d, and ships a **default** `/var/lib/secubox/toolbox/peer-rlevel.json` seed with `defaults.mode` set to **preserve current behavior** (see Global Constraints ⚠) — decision recorded in changelog; sudoers adds exact `sbxmitm-policyctl set-floor|force|set-chosen|set-default|list`. `#DEBHELPER#` alone on its line.
- [ ] **Step 2:** cross-compile the Go binary: `cd packages/secubox-toolbox-ng && GOARCH=arm64 GOOS=linux go build -mod=vendor -o /tmp/sbxmitm ./cmd/sbxmitm` → success; `file /tmp/sbxmitm` = ARM aarch64.
- [ ] **Step 3:** `go test ./...` (full toolbox-ng suite) PASS; both toolbox python suites PASS.
- [ ] **Step 4:** changelog bumps (toolbox + toolbox-ng), Depends sane. Build the `.deb`(s); `dpkg-deb -c` shows policyctl/sudoers/panel/menu.d; `bash -n` postinst.
- [ ] **Step 5: commit** `build(toolbox): package rlevel (policyctl, sudoers, panel, seed default_mode) + changelog`.

---

## Recette de déploiement (board — PRUDENT)

```bash
# 1. Décider default_mode AVANT (préserver comportement actuel ≈ reel, ou passive privacy-forward).
#    Seed /var/lib/secubox/toolbox/peer-rlevel.json defaults en conséquence.
# 2. Déployer le binaire sbxmitm cross-arm64 + policyctl + sudoers + panel.
# 3. ROLLING restart des workers (JAMAIS les 4 d'un coup) :
for i in 1 2 3 4; do
  systemctl restart secubox-toolbox-ng-worker@$i
  sleep 3; systemctl is-active secubox-toolbox-ng-worker@$i || break   # stop si un worker échoue
done
# 4. Restart aggregator si l'API toolbox y est montée (nouvelles routes /rlevel).
# 5. Vérifs : un peer en passive (splice, pas de déchiffrement observé), passe active (déchiffré),
#    passe reel (block honoré), forcé off par admin (bypass nft vérifié : trafic PAS DNAT'd),
#    un hôte pinné (Signal) reste splice en active/reel (pas de 502). Statut live dans le panneau.
```

## Hors périmètre (YAGNI v1)
Politique par utilisateur (login) ; `reel` forçant le déchiffrement des pinnés ; quotas/horaires ; per-flow ; ban/rewrite au-delà du block existant (hooks seulement). Cf. spec.
