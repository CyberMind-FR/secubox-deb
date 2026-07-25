# Support / Assistance Request — Design

**Date :** 2026-07-25
**Statut :** validé (design), prêt pour le plan d'implémentation
**Modules :** `secubox-annuaire` (control-plane) + `secubox-assist` (data-plane, neuf) + surface webui/CLI
**Sous-projet 2/3** de l'ensemble « auto-centre et multiple centres ». Réutilise le socle **Centres & Grants** livré au sous-projet 1 ([[project_gondwana_directory_live]], spec `2026-07-25-centers-grants-remote-config-design.md`). Le suivant (3/3) : *métriques centralisées+meshed*.

---

## Objectif

Permettre à une box de **demander de l'assistance à un centre** et d'ouvrir une **session d'aide temps réel** — le centre agit sur la box **le temps de l'incident**, sous consentement explicite, entièrement audité et révocable à l'instant. La box reste **souveraine** : aucune autorité permanente n'ouvre seule une session ; le centre ne peut jamais dépasser un **catalogue d'actions borné** sans un **second consentement** de l'opérateur.

## Décisions actées

1. **Niveau d'accès = session assistée temps réel.** Le centre agit en direct pendant une session time-boxée, révocable à tout instant, tout audité.
2. **Surface d'action = catalogue borné + escalade console sur double-consentement.** Par défaut, le centre n'invoque qu'un catalogue fixe d'actions « assist » (chaque action = un ctl scopé existant + audit). Un cas exceptionnel peut débloquer une console interactive par un **second** consentement opérateur, séparément time-boxé et révocable.
3. **Initiation bi-mode, configurable par centre.**
   - **Per-incident (pull)** : l'opérateur ouvre une demande ponctuelle ; l'`ASSIST_REQUEST` **est** l'autorité éphémère (zéro grant standing). Le centre ne peut jamais démarrer seul.
   - **Standing** : la box accorde une fois un grant `capability="assist"` (révocable) ; le centre peut alors demander une session, mais **chaque** session exige un consentement live de l'opérateur.
4. **Architecture à deux plans.** *Control-plane* (autorisation) = ops signées du journal `secubox-annuaire`, mesh-syncées, auditées. *Data-plane* (temps réel) = daemon `secubox-assist` exposant un WebSocket **par-session éphémère**, **bind wg-mesh uniquement**.
5. **Réutilise le socle sous-projet 1.** Journal signé BLAKE2b, `mesh_sync`, modèle `Grant`, résolution/révocation de grants, `audit.log` append-only.

## Contexte (substrat existant, vérifié)

- `secubox-annuaire` : journal signé append-only, `model.py` (Identity, `Grant`, `Op.*`), `grants.py` (`active_grants`, `owner`, `validate_issue`), `mesh_sync.py`, `verbs.py` (ops signées genesis-style), `config_router.py` (vérification signature centre + grant). Le sous-projet 1 a ajouté `GRANT_ISSUE`/`GRANT_REVOKE` + le modèle `Grant{center_did, capability, scope, layer, issued_by, ts}` + `NON_DELEGATABLE`.
- Mesh WireGuard `wg-mesh` `10.10.0.0/24` (3 nœuds : gk2 `.1` master, c3box `.2`, amd64 `.9`) — [[project_mesh_gk2_c3box]], [[project_p2p_dht_cluster_live]]. C'est le transport du data-plane.
- Pattern **ctl confiné** : la webui (user `secubox`) délègue toute action root à un `secubox-<mod>ctl` scopé par sudoers ([[feedback_webui_delegates_to_confined_ctl]]). Le catalogue assist réutilise ces ctls existants.
- `audit.log` append-only `/var/log/secubox/audit.log` (exigence CSPN, parent `0755` — [[project_var_log_secubox_traversal]], ne jamais resserrer le parent partagé).

## Composants

| Fichier | Rôle |
|---|---|
| `secubox-annuaire/annuaire/model.py` (étendu) | ops `ASSIST_REQUEST`/`ASSIST_ACCEPT`/`ASSIST_SESSION_OPEN`/`ASSIST_SESSION_CLOSE`/`ASSIST_CONSOLE_GRANT`/`ASSIST_CONSOLE_REVOKE` ; modèles `AssistRequest`, `AssistSession` (extra=forbid, DID patterns) ; `capability="assist"` reconnu |
| `secubox-annuaire/annuaire/assist.py` (neuf) | résout l'état depuis le journal : demandes en attente, session active (une seule par box), console accordée ?, expiries ; `active_session(entries, self_did)` (souveraineté : filtré `issued_by==self_did`) |
| `secubox-annuaire/annuaire/verbs.py` (étendu) | `assist_request`/`assist_accept`/`assist_session_open`/`assist_session_close`/`assist_console_grant`/`assist_console_revoke` (valide→signe→append) |
| `secubox-assist/` (paquet neuf) | daemon data-plane : serveur WebSocket **bind wg-mesh only**, auth par token de session (hash au journal), dispatcher catalogue→ctl, gestionnaire pty (console double-consent), collecteur de bundle diag, writer audit |
| `secubox-assist/sbin/secubox-assistctl` (neuf) | CLI root scopé : `request`/`accept`/`open`/`close`/`console-grant`/`console-revoke`/`list` (écrit les ops journal + pilote le daemon ; jamais d'action root hors catalogue+audit) |
| `secubox-assist/api/main.py` (neuf) | endpoints `/assist/*` : lecture in-process, écriture JWT-gated **déléguée à `assistctl`** |
| `secubox-assist/www/assist/index.html` (neuf) | panneau : demande d'assistance, moniteur live (flux d'actions, bouton consentement-console, kill-switch), historique ; côté centre : file entrante + console d'action |
| `menu.d/…-assist.json`, `nginx/assist.conf` | navbar + vhost |

## Modèle de données (ops de journal)

```
GRANT_ISSUE  { capability="assist", center_did, scope?, issued_by=<box_did>, ts, sig=<box> }   # mode standing (réutilise s-p 1)
ASSIST_REQUEST       { req_id, center_did, mode="per-incident"|"standing", scope, duration_s, reason, issued_by=<box_did>, ts, sig=<box> }
ASSIST_ACCEPT        { req_id, center_did, ts, sig=<center> }
ASSIST_SESSION_OPEN  { session_id, req_id, center_did, token_hash, expires_ts, issued_by=<box_did>, ts, sig=<box> }
ASSIST_SESSION_CLOSE { session_id, reason, issued_by=<box_did>|"auto-expiry", ts, sig=<box> }
ASSIST_CONSOLE_GRANT { session_id, expires_ts, issued_by=<box_did>, ts, sig=<box> }
ASSIST_CONSOLE_REVOKE{ session_id, issued_by=<box_did>, ts, sig=<box> }
```

- `mode` ∈ `{"per-incident","standing"}`. En `standing`, un grant `capability="assist"` actif est **requis** pour que le centre puisse initier ; en `per-incident`, aucun grant standing n'est requis (la demande signée par la box est l'autorité).
- **Le secret du token de session n'est JAMAIS journalisé** — seul `token_hash` (BLAKE2b du token) va au journal. Le token en clair est livré au centre via le canal mesh à l'acceptation, single-use.
- **Invariant session unique** : au plus **une** `AssistSession` active par box (un `ASSIST_SESSION_OPEN` sans `ASSIST_SESSION_CLOSE` du même `session_id`). Ouvrir une session alors qu'une est active est **rejeté**.
- Une session est **active** ssi `SESSION_OPEN` non suivi de `SESSION_CLOSE` **ET** `now < expires_ts`. Au-delà d'`expires_ts`, elle est **auto-expirée** (fail-closed) même sans op de close.
- Console **active** ssi `CONSOLE_GRANT` non suivi de `CONSOLE_REVOKE` **ET** `now < expires_ts` **ET** la session parente est active.

## Flux de données

### Per-incident (pull)
1. Opérateur (panneau `/assist/`) : « demander assistance à centre A », choisit scope + durée + motif → box signe `ASSIST_REQUEST(mode="per-incident")`.
2. `mesh_sync` livre l'op à A. A accepte → `ASSIST_ACCEPT`.
3. Opérateur **consent** à ouvrir → box frappe un token de session, signe `ASSIST_SESSION_OPEN(token_hash, expires_ts)`, livre le token en clair à A via le canal mesh.
4. A connecte le **WebSocket** de `secubox-assist` sur `wg-mesh` avec le token → invoque le **catalogue** ; chaque action → ctl scopé → `audit.log`.
5. (Optionnel) A demande la console → opérateur **2e consentement** → box signe `ASSIST_CONSOLE_GRANT` → pty non-root time-boxé, keystrokes audités.
6. Opérateur **kill** (ou `expires_ts` atteint) → `ASSIST_SESSION_CLOSE` → teardown immédiat WS + pty.

### Standing
1. Opérateur : `GRANT_ISSUE(A, capability="assist")` une fois (op signée box).
2. Plus tard, A : `ASSIST_REQUEST(mode="standing")` (autorisé car grant actif) → l'opérateur reçoit une **invite de consentement live**.
3. Sur consentement → `ASSIST_SESSION_OPEN` → identique aux étapes 3-6 ci-dessus.
4. Révoquer l'autorité standing = `GRANT_REVOKE` (le centre ne peut plus initier ; une session en cours est fermée à la prochaine recomposition).

## Catalogue d'actions borné

Chaque entrée mappe **un** ctl scopé existant ; le daemon n'exécute **jamais** de shell arbitraire en mode catalogue.

| Action catalogue | Délégation |
|---|---|
| `status.all` | lecture in-process (agrégateur/status) |
| `diag.collect` | collecteur de bundle diag (voir §Bundle) |
| `logs.tail <unit>` | `journalctl -u <unit> -n N` (allow-list d'unités `secubox-*`) |
| `service.restart <module>` | `secubox-<module>ctl restart` (ou `systemctl restart secubox-<module>` scopé) |
| `service.toggle <module> on\|off` | ctl module correspondant |
| `config.reload <scope>` | `profilectl`/`config_apply` 4R ([[project_profiles_apply_phase3a]]) |
| `config.rollback <scope>` | `profilectl rollback` (4R) |

- Les modules/unités visés sont une **allow-list** `secubox-*` ; toute cible hors allow-list est rejetée.
- **Aucun** ctl touchant `auth`/`secrets` n'est dans le catalogue (scope secrets inatteignable — cohérent `NON_DELEGATABLE` du s-p 1).

## Bundle diag (au démarrage de session)

- Contenu : status modules/versions, **extraits** de logs récents avec **rédaction conservatrice** (strip tokens/clés/mots-de-passe/emails via motifs), config **effective non-secrète**.
- **Jamais** `/etc/secubox/secrets/`, jamais de fichier `*.key`, jamais le contenu de `users.json`.
- Réutilise/anticipe le collecteur du sous-projet 3 (métriques/diag) — ici en lecture seule bornée.

## Invariants souveraineté / CSPN

- **Consentement opérateur explicite à chaque `SESSION_OPEN`** (les deux modes). Un grant standing seul n'ouvre **jamais** une session live.
- **Double-consentement** pour la console : op distincte, time-box distinct, révocation distincte. Défaut = catalogue borné.
- **Data-plane `wg-mesh` uniquement** : le WebSocket bind l'IP `wg-mesh` (`10.10.0.0/24`), **jamais `0.0.0.0`** (leçon escalade R-level [[project_rlevel_per_peer]]). nft ouvre le port **uniquement** sur `iifname wg-mesh`, DEFAULT DROP ailleurs.
- **Token single-use, hashé au journal** — le secret ne transite que par le canal mesh chiffré, jamais dans le journal ni les logs.
- **User dédié `secubox-assist`, AppArmor enforce, jamais root.** L'unique chemin privilégié = les ctls scopés du catalogue (audités). La console pty tourne sous `secubox-assist` (pas root).
- **Audit append-only complet** `/var/log/secubox/audit.log` : request, accept, open, **chaque** action catalogue, console-grant, **keystrokes** console, close. Ne jamais resserrer le parent partagé `0755`.
- **Expiry hard-cap** session + console ; **fail-closed** : `now ≥ expires_ts` ⇒ inactif même sans op de close ; **perte du mesh = session morte** (le WS tombe, plus d'action possible).
- **Kill-switch** toujours disponible à l'opérateur (`SESSION_CLOSE` immédiat).
- **Zéro-centre = aucune assistance possible** ; ajouter un centre est purement additif ; révocation instantanée.
- **Session unique** : jamais deux sessions actives concurrentes sur une box.

## Surface (webui + CLI + API)

- **Panneau `/assist/`** (hybrid-dark, jeton `sbx_token`, délégation d'événements — pas d'inline handler interpolé) :
  - **Côté box (opérateur)** : formulaire de demande (centre enrôlé, mode, scope, durée, motif) ; **moniteur live** de la session (flux d'actions horodaté, badge console, **bouton consentement-console**, **kill-switch**) ; historique des sessions (lu depuis le journal).
  - **Côté centre** (si la box est un centre) : file des demandes entrantes → accepter ; console d'action (catalogue + terminal si escalade accordée).
- **CLI `secubox-assistctl`** : `request <center> --mode --scope --duration --reason`, `accept <req-id>`, `open <req-id>`, `close <session-id>`, `console-grant <session-id> --duration`, `console-revoke <session-id>`, `list`.
- **API** délègue **toute écriture** à `secubox-assistctl` (jamais d'action privilégiée in-process — [[feedback_webui_delegates_to_confined_ctl]]) ; lectures in-process depuis le journal. L'agrégateur doit être redémarré pour charger de nouvelles routes ([[project_aggregator_inprocess_serving]]) — mais `secubox-assist` a **son propre service+socket** (comme billets [[project_billets_live_deploy]]), pas servi par l'agrégateur (le WS et le pty exigent un daemon dédié, pas la loop partagée [[project_aggregator_wedge_and_auth_extraction]]).

## Tests

- **model/verbs** : validation + signature de chaque op ; `req_id`/`session_id` bien formés ; `mode="standing"` sans grant actif → rejeté ; `mode="per-incident"` sans grant → accepté.
- **assist.py** : session active/expirée ; **session unique** (2e open rejeté) ; console active seulement si session active + non-révoquée + non-expirée ; souveraineté (`issued_by==self_did`).
- **token** : le secret ne fuit jamais (journal ne contient que `token_hash`) ; token single-use ; hash BLAKE2b vérifié.
- **consentement** : `SESSION_OPEN` requiert consentement (les deux modes) ; console requiert un **2e** consentement (grant console distinct).
- **bind mesh-only** : le WS refuse une connexion hors `wg-mesh` ; le daemon ne bind jamais `0.0.0.0`.
- **catalogue** : chaque action → ctl scopé attendu ; cible hors allow-list rejetée ; **aucun** shell arbitraire ; scope secrets inatteignable.
- **expiry/revoke** : `now ≥ expires_ts` ⇒ session/console inactive (fail-closed) ; `SESSION_CLOSE` ⇒ teardown ; `CONSOLE_REVOKE` ⇒ pty fermé.
- **audit** : présence de chaque événement (request→…→close) dans `audit.log` ; keystrokes console tracés.
- **API/CLI** : écriture déléguée à `assistctl` (pas d'action root in-process) ; JWT-gated.
- **panneau** : moniteur + délégation d'événements (garde XSS) ; menu.d valide.
- **e2e (mock mesh)** : per-incident (request→accept→open→action catalogue→close) ; standing (grant→request→consent→open) ; escalade console (2e consent→pty→revoke) ; auto-expiry ferme la session.

## Risques connus

| Risque | Traitement |
|---|---|
| Un centre agit sans consentement | `SESSION_OPEN` exige un consentement opérateur explicite dans **les deux** modes |
| Escalade catalogue → shell | console = op distincte + **2e** consentement + time-box + user non-root ; catalogue = allow-list de ctls |
| Fuite du token de session | secret hors journal (seul le hash) ; single-use ; canal mesh chiffré |
| Bind public / contournement SSO (cf. R-level) | WS **bind wg-mesh only** + nft `iifname wg-mesh` uniquement, DEFAULT DROP |
| Session fantôme après compromission d'un centre | grant/authority box-émis + révocable ; expiry hard-cap ; fail-closed sur perte mesh |
| Deux sessions concurrentes | invariant **session unique** par box |
| Accès aux secrets via diag/catalogue | rédaction conservatrice du bundle ; aucun ctl secrets ; jamais `/etc/secubox/secrets` |
| Daemon privilégié | user dédié non-root + AppArmor enforce ; seul chemin privilégié = ctls scopés audités |
| Loop agrégateur bloquée par le WS/pty | `secubox-assist` = service+socket **dédié**, pas servi par l'agrégateur |

## Hors périmètre de ce sous-projet

**Livré au sous-projet 3 :**
- **Métriques centralisées+meshed** : grant `capability="metrics"` — réutilisera le collecteur diag d'ici.

**Roadmap « à prévoir » (extensions additives post-socle, non rejetées).** Chacune se greffe sur le socle assist sans le casser : nouvelles actions catalogue et/ou nouveau canal data-plane, mêmes invariants CSPN (consentement, mesh-only, audit, expiry, non-root).
- **Transfert de fichiers** (récupérer un bundle diag/log, pousser un correctif) — action catalogue `file.pull`/`file.push` bornée + rédaction.
- **Partage d'écran / co-browsing** de la webui admin — nouveau canal data-plane time-boxé, même modèle de consentement que la console.
- **Sessions multi-centres simultanées** — relâcher l'invariant « session unique » vers N sessions concurrentes scopées (nécessite arbitrage d'actions concurrentes).
- **UI de replay** — rejouer une session depuis l'`audit.log` (qui **est** déjà l'enregistrement) ; pur front, aucun nouveau privilège.
- **Enregistrement vidéo** de session — dérivé du partage d'écran.
