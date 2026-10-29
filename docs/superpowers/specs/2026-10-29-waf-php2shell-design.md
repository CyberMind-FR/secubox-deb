<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit — détection PHP2Shell dans sbxwaf (issue #3257, étape 1)

- Date : 2026-10-29. Dépôt `CyberMind-FR/secubox-deb`, branche `master` à `698d1f1c2`, arbre propre (vérifié avant et après).
- Périmètre : lecture seule. Aucun fichier du dépôt modifié, aucune branche créée, aucune box contactée.
- Racine des chemins cités : `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/`.
  - `SBX` = `packages/secubox-toolbox-ng/cmd/sbxwaf/`
  - `NG` = `packages/secubox-waf-ng/`
- « inconnu » signifie que le point n'est pas confirmable sans la box (drop-ins, `/etc`, version PHP des LXC).

---

## 0. Conclusions principales

1. **Aujourd'hui, sbxwaf ne lit jamais un corps `multipart/form-data`.** `corpsBinaire()` classe tout multipart comme binaire (`SBX/corpsbinaire.go:38-40`). Le handler saute alors la lecture du corps : seuls le chemin, la requête et l'UA sont jugés, règles bloquantes comprises (`SBX/main.go:561-568`). L'abandon est **silencieux** : aucune ligne `body-inspect-skipped` n'est écrite, contrairement au saut par hôte (`main.go:543-560`). Les indicateurs PHP2Shell, qui vivent dans le corps multipart, sont donc invisibles pour le WAF actuel.
2. Le mécanisme de lecture bornée existe et se réutilise tel quel :
   - `io.ReadAll(io.LimitReader(r.Body, cap))` lit le préfixe ;
   - `io.MultiReader(préfixe, reste)` rejoue le corps au backend sans le modifier (`main.go:575-582`) ;
   - la troncature est déjà journalisée (`main.go:584-599`).
   La bibliothèque standard `mime/multipart` suffit (Go 1.22, `NextRawPart`). **Aucun nouveau démon n'est nécessaire.**
3. Le mode `detect` existe déjà, mais seulement au niveau de la **catégorie** (`SBX/rules.go:72-89`, `main.go:652-673`). Il ne bloque pas et ne touche pas au compteur de ban. En revanche, il **n'est pas inerte en aval** :
   - ses lignes partent vers `sbx-actord`. Toute gravité ≥ 40 y compte comme « hostile », et l'unité de production active `--mesures auto` ;
   - le profileur de campagnes compte ces lignes comme des « sondes », et l'unité active `--campagne-ban auto`.
   Voir § 3.4.
4. Le moteur de règles ne connaît que des **regex** sur une seule chaîne concaténée, avec la règle « première correspondance gagne ». Deux conséquences :
   - une catégorie `detect` placée avant une catégorie `block` **masque** cette dernière (`rules.go:429-441`, `main.go:652-673`) ;
   - les indicateurs PHP2Shell sont structurels (nombre de parties, profondeur, présence d'un champ). Ils ne doivent donc pas passer par `MatchDetail`.
5. **CrowdSec : aucune dépendance active** dans le périmètre WAF :
   - ni code, ni `go.mod`/`vendor`, ni unité, ni sudoers, ni AppArmor ;
   - la seule relation de paquet est **anti-dépendance** : `Conflicts/Replaces: secubox-crowdsec` (`NG/debian/control:35,42-44`) ;
   - il reste un commentaire obsolète, `SBX/main.go:193`, ainsi que des documents historiques.
6. Tests Go réellement lancés (x86_64, voir § 5.3), tous verts :
   - `go test ./cmd/sbxwaf/` : **ok**, 335 tests de premier niveau et 124 sous-tests, 0 échec, 0 ignoré ;
   - `-race` : ok ; `go vet` : ok ;
   - `go test ./...` (module toolbox-ng, 25 paquets) : ok.
7. Constats annexes importants (§ 2.6 et § 6.4). Ils sont hors du sujet PHP2Shell, mais ils conditionnent la mesure des faux positifs et le coût :
   - le corpus de test de parité est figé en **1.3.0** alors que le corpus livré est en **1.5.2** ;
   - le champ `check` (`user-agent`, `body`) est **ignoré** par le moteur Go ;
   - `waf-fp-004` et `waf-fp-008` bloquent tout texte contenant `select`, `union` ou `script`. Mesuré : le chemin `/description` est bloqué ;
   - le balayage regex d'un corps texte de 1 Mio coûte **environ 1,6 s de CPU** sur un i9-13900H (mesure sur une copie dans le scratchpad).

---

## 1. Voie réelle d'une requête HTTP dans sbxwaf

### 1.1 Point d'entrée et ordre de traitement

| Étape | Code | Note |
|---|---|---|
| Écoute | `SBX/main.go:1552-1556` (`http.Server{Addr, Handler: srv.handler(), ReadHeaderTimeout: 10s}`) | Pas de `ReadTimeout` ni de `MaxHeaderBytes` explicites. Un corps envoyé lentement n'est borné que par HAProxy (configuration « inconnu »). |
| Unité | `NG/systemd/secubox-waf-ng.service:129-147` | `--listen 127.0.0.1:8085`, `--rules /etc/secubox/waf/waf-rules.json`, `--threat-log /var/log/secubox/waf/waf-threats.log`. **Pas de `--max-body-inspect`, donc 1 Mio.** Plus `--nft-ban --scan-sensor --actor-ban auto --campagne-ban auto --reevaluation auto --mesures auto`. |
| Rechargement à chaud | `main.go:318-333` (`routes.Maybe`, `rules.Maybe`, `onDemand.Maybe`) | Un stat par requête. |
| Échelle de réponse | `main.go:335-337` (`mesures.Intercepte`) | Avant toute inspection. |
| Routage | `main.go:340-407` (`routeLookup`, réveil, leurre, 421) | |
| Proxy en cache | `main.go:409-462` | |
| Début de l'inspection | `main.go:466` (`if s.rules != nil`) | `Connection: close` hors WebSocket : `main.go:471-473`. |
| IP cliente | `inspect.go:155-180` (`clientIP`, chaîne X-Forwarded-For lue depuis la droite) | |
| Anti-robots par vhost | `main.go:495-514` | |
| Contournements complets | `main.go:524-528` : `privateCIDR(ip) \|\| ncBypass(rawPath) \|\| isTrustedHost` | LAN ; `/index.php/login/v2/` ; `/ocs/v2.php/core/login` ; `git.gk2…`, `git.secubox.in`, `admin.gk2…` (`main.go:1216-1218`). |
| Actif statique | `main.go:530`, `inspect.go:91-101` | Suffixe `.js`/`.css`/…, ou chemin contenant **`/health`, `/status`, `system_health`**. |
| Choix du corps | `main.go:537-601` | Voir § 1.2. |
| Correspondance | `main.go:609-617` : `s.rules.MatchDetail(method, rawPath, rawQuery, string(bodyBytes), UA, includeBlock, nil)` | Puis la re-vérification de la phase G (`main.go:640-651`, second appel à `MatchDetail`). |
| Décision | `detect` : `main.go:652-673` ; `escalate` : `674-701` ; `block` : `702-769` | |
| Relais au backend | `main.go:907` (`proxy.ServeHTTP`) ou chemin du cache média `803-904` | |

### 1.2 Le corps : lecture, limite, troncature

```text
main.go:532-601
  binaire  := corpsBinaire(Content-Type)        // corpsbinaire.go:29-55
  sansCorps := isSkipBodyHost(Host)             // --waf-skip-body-hosts (unité : depot.gk2.secubox.in)
  if sansCorps        -> pas de lecture ; ligne « body-inspect-skipped » (audit)          :543-560
  else if isStatic || binaire -> pas de lecture ; includeBlock = binaire ; AUCUNE ligne   :561-568
  else                -> préfixe = ReadAll(LimitReader(Body, cap)) ;
                         Body = NopCloser(MultiReader(préfixe, Body))                      :575-582
                         si len(préfixe) == cap -> ligne « body-inspect-truncated » + log  :584-599
```

| Question | Réponse | Preuve |
|---|---|---|
| Valeur par défaut de `--max-body-inspect` | 1 Mio (`1 << 20`) | `inspect.go:182-188` ; drapeau `main.go:1207-1211` ; non surchargé par l'unité (`secubox-waf-ng.service:129-147`). Un drop-in sur la box reste possible (« inconnu »). |
| Au-delà de la limite | Le corps est **tronqué pour l'inspection seulement**. Le reste est relayé sans être inspecté. Une ligne `category=action="body-inspect-truncated"`, `severity="audit"` est écrite, et une ligne `log.Printf AUDIT` aussi. | `main.go:584-599` ; documenté dans `NG/docs/CUTOVER.md:196-229` |
| Marquage | Oui, mais **approximatif** : (a) un corps de **exactement** `cap` octets est déclaré tronqué ; (b) l'erreur de lecture est ignorée (`prefix, _ := …`) : un client qui coupe, ou une lecture en erreur, donne un préfixe partiel traité comme un corps complet ; (c) `r.ContentLength` n'est pas consulté. | `main.go:580`, `584` |
| Multipart | **Jamais lu.** Classé binaire, donc `includeBlock = true` sur chemin, requête et UA seulement ; corps vide pour `MatchDetail` ; aucune trace. | `corpsbinaire.go:38-40`, `main.go:561-568`. Origine : faux positif « rce » sur un envoi d'image Mastodon, le 2026-08-17 (`corpsbinaire.go:16-24`). Test qui fige ce choix : `corpsbinaire_test.go:5-17`. |
| Ce que voit `MatchDetail` | `unquotePlus(path) + " " + unquotePlus(query) + " " + body + " " + UA`, plus les variantes normalisées du chemin et de la requête, le tout passé en minuscules. **Le corps est brut** : il n'est ni décodé en URL ni analysé (fixture `sqli_boolean_or_1eq1_body_urlencoded_nobodydecode`). Les en-têtes autres que l'UA (Cookie, Content-Type, Content-Disposition) ne sont **pas** inspectés. | `rules.go:403-419` |
| Rejeu au backend | Lu une fois jusqu'à `cap`, puis rejoué en flux (`MultiReader`) ; `ContentLength` est inchangé. Le corps transmis n'est jamais modifié. | `main.go:582`, test `inspect_test.go:268` (`TestInspectLargeBodyForwardedIntact`) |
| Effet de bord temporel | Pour un corps texte, sbxwaf **attend** de lire jusqu'à 1 Mio avant de relayer. Il absorbe donc les pauses TCP du client : un corps de moins de 1 Mio part d'un bloc vers le backend. Pour le multipart, rien n'est tamponné : le flux et ses pauses passent tels quels. L'effet sur la course de CVE-2026-109619 (pause de plus de 1 s) reste à **vérifier**. | Déduit de `main.go:580-582` |

### 1.3 La correspondance (`MatchDetail` et sa famille)

- Les signatures `Match`, `MatchModes` et `MatchExcept` délèguent toutes à `MatchDetail` (`rules.go:353-380`). `MatchDetail` est définie en `rules.go:403-443`.
- Parcours : catégories dans l'ordre du fichier, motifs dans l'ordre. **La première correspondance gagne**, quel que soit le mode (`rules.go:429-441`).
- Un appel ou deux par requête : un second appel si la catégorie est supprimable par la phase G (`main.go:640-651`).
- **Masquage par `detect`** : si une catégorie `detect` touche en premier, la requête passe (`main.go:652-673`), sans réévaluer les catégories `block` plus loin. Aujourd'hui, `recon_crawler` (detect) et `product_absent_probes` (escalate) sont placées après les injections, donc l'ordre protège. Mais toute nouvelle catégorie `detect` sous forme de regex doit être ajoutée **en fin** de liste, sinon la protection baisse sans bruit.

---

## 2. Le corpus de règles

### 2.1 Fichiers et installation

| Fichier | Rôle | Version (`_meta.version`) |
|---|---|---|
| `NG/composants/waf/config/waf-rules.json` | Corpus livré, installé en `/usr/share/secubox/waf/waf-rules.json` (`NG/debian/rules:91-92`) | **1.5.2** (2026-09-20) : 18 catégories, 158 motifs, identifiants uniques |
| `/etc/secubox/waf/waf-rules.json` (box) | Fichier **lu par sbxwaf** (`--rules`). N'est pas un conffile. | Celui de la box (voir § 2.5) |
| `packages/secubox-toolbox-ng/testdata/waf-rules.json` | Corpus des tests de parité | **1.3.0** (2026-05-07) : 17 catégories, 149 motifs. **Désynchronisé** du livré. |

Écrivains de `/etc/secubox/waf/waf-rules.json` :

- `waf-rules-sync` (`NG/composants/waf/scripts/waf-rules-sync`), appelé par le postinst (`NG/composants/waf/debian/postinst:140-151`). Les catégories livrées remplacent celles de la box, les catégories `generated: true` de la box sont conservées. Il crée une sauvegarde `.avant-<version>` et redémarre `secubox-waf-ng` si le code retour vaut 10.
- **wafgen** (`packages/secubox-security-posture/composants/cve-triage/api/wafgen/emit.py:79-103`) réécrit `product_absent_probes` en préservant le reste, avec un remplacement atomique.

### 2.2 Schéma réel d'une règle (tel que le lit Go)

```text
{ "_meta": {...},                          # ignoré par Go (rules.go:157-170 ne lit que "categories")
  "categories": { "<cat_id>": {            # ordre du fichier conservé (json.Decoder, rules.go:191-216)
      "name": str, "severity": "low|medium|high|critical|info" (défaut "medium", rules.go:224-227),
      "enabled": bool (absent ⇒ true, rules.go:219-221),
      "mode": "block|detect|escalate" (absent/""/null ⇒ block ; inconnu ⇒ block + log, rules.go:229-244),
      "patterns": [ {"id": str, "pattern": regex RE2, "desc": str} ] } } }   # rules.go:176-187
```

- Champs présents dans le JSON mais **ignorés par Go** : `owasp`, `_note`, `generated`, `generated_at`, et au niveau du motif `cve`, `vendor`, `source`, **`check`**.
  - `check` : `scanners/scan-001` = `user-agent`, `router_botnet` = `user-agent`, `waf_fingerprint` = `user-agent`, `voip` = `body`, `recon_crawler` = `hash`.
  - Le motif est quand même appliqué au chemin, à la requête et au corps (§ 6.4).
- La gravité est **par catégorie** : chaque motif en hérite (`rules.go:96-97`, `276`).
- Le mode est **par catégorie** (`compiledCategory.mode`, `rules.go:101-106`). Il n'existe pas de mode par motif.
- Identifiant stable : `id` du motif, unique sur les 158 du corpus livré. Il est rendu par `MatchDetail` et écrit en `rule_id` (#1313).
- Les modes en service dans le corpus livré :
  - `recon_crawler` : `detect`, gravité `info` ;
  - `product_absent_probes` : `escalate` (générée) ;
  - les 16 autres : `block` (mode absent).

### 2.3 Chargement et rejet

- Chaque motif est compilé en `(?i)`. Un échec de compilation fait **sauter le motif**. L'identifiant `cat/id` est conservé dans `rejetes` et une ligne `ALERTE … DECLARES/CHARGES` est écrite (`rules.go:255-294`).
- Un fichier absent ou un JSON invalide donne un jeu **vide qui ne correspond jamais**, sans arrêt du service (`rules.go:148-164`). Cela ouvre le WAF en silence : seule une ligne de log le signale.
- `Rules.Integrite()` (`rules.go:454-465`) rend `déclarés/chargés/rejetés`. **Aucun appelant en dehors des tests** : l'écart n'est exposé ni par `/healthz` ni par le panneau, alors que c'était l'objet de #1317.
- Le corpus de test 1.3.0 a encore 5 motifs rejetés (`\u0000`). Ils ont été corrigés en 1.5.2 selon le changelog (vu dans la sortie de `go test`).

### 2.4 Tests existants des règles

| Fichier | Couvre |
|---|---|
| `SBX/parity_test.go` + `testdata/waf-parity-fixtures.json` | 53 fixtures (sqli 8, lfi 5, xss 5, rce 4, scanner, honeypot, cve, router, ban, 3 `known_gap`), rejouées par `runDecision` (Match, puis ban). **Corpus 1.3.0**, sans le chemin multipart du handler. |
| `SBX/rules_test.go` | Chargement, `enabled`, compilation, chemin/corps/UA, rechargement à chaud, modes (absent ⇒ block, inconnu ⇒ block, detect, escalate) |
| `SBX/matchdetail_test.go` | `rule_id`, exclusions |
| `SBX/integrite_test.go` | Déclarés/chargés/rejetés |
| `SBX/inspect_test.go` | IP privée, actif statique (detect seulement), contournement NC, corps de plus de 1 Mio relayé intact, attaque dans le premier Mio |
| `SBX/skipbody_test.go`, `corpsbinaire_test.go` | Saut du corps, classement binaire (multipart compris) |
| `SBX/main_test.go:515-789` | `detect` laisse passer et ne bannit pas ; `block` et mode absent bloquent ; `escalate` ; rechargement du mode à chaud |
| `SBX/vhostprofiles_integration_test.go:190` | **Seul test Go qui charge le corpus livré** (`fichierLivreWafNg`) |
| `NG/composants/waf/tests/test_waf_rules_sync.py`, `test_detect_exclusion.py` | Fusion de la synchronisation ; compteurs « observés » contre « bloqués ». Lancés : 10 réussis. |

### 2.5 Version du corpus sur la box

`waf-rules-sync` ne remplace que `categories`. Pour les autres clés de premier niveau, il **garde celles de la box** et n'ajoute que les clés absentes (`waf-rules-sync:37-38`). `_meta` (donc la version) n'est **jamais mis à jour** après la première pose : la version affichée sur la box n'est pas fiable. La version réelle sur gk1 et gk2 est « inconnu ». À corriger si le catalogue doit être versionné.

### 2.6 L'API Python du panneau

`NG/composants/waf/api/main.py` :

- elle lit `/usr/share/secubox/waf/waf-rules.json`, le corpus **livré** et non celui de la box (`:32`). Elle contient en repli un chemin de développement codé en dur, `/home/reepost/…/packages/secubox-waf/config/waf-rules.json` (`:194`) ;
- elle compile les motifs **sans tenir compte de `mode`** (`:187-215`) ;
- elle expose `POST /check` (`require_jwt`), qui peut bannir via `wafctl ban` si `_should_autoban` le décide (`:302-312`, `:1831-1857`).

Si les signatures PHP2Shell étaient écrites comme des motifs regex `detect`, ce chemin Python les traiterait comme bloquantes. L'utilisation réelle de `/check` est « inconnu » ; aucun appelant n'a été trouvé dans les paquets HAProxy et WAF.

---

## 3. Événements et décisions

### 3.1 Journal des menaces

- Chemin : `/var/log/secubox/waf/waf-threats.log` (`main.go:1163`, unité `:137`). Format NDJSON en ajout seul, mode 0640. Rotation quotidienne, 20 Mo maximum, 7 fichiers (`NG/composants/waf/logrotate.d/secubox-waf`).
- Champs (`SBX/threatlog.go:169-192`) :
  - `timestamp, client_ip, host, method, path, category, severity, rule_id, action, user_agent` ;
  - `tool, ja4, negative_space, http_fingerprint, behavior_traits, leurre, filigrane, marque_revenue` (omitempty).
- **Il n'y a pas de champ `mode` ni `decision` séparés.** `action` mélange les deux :
  - valeurs possibles : `detect | warning | banned | robot | body-inspect-skipped | body-inspect-truncated` ;
  - l'escalade en observation écrit `detect` (`main.go:1033-1050`).
- Particularités du journal :
  - `client_ip` privé est réécrit en `local` (`threatlog.go:226-229`) ;
  - l'auto-test (198.51.100.0/24 + UA `SecuBox-WAF-SelfTest/`) part dans `waf-selftest.log` (`:197-216`, `:251-256`) ;
  - le chemin est journalisé **sans la requête**, et jamais avec le corps (bon point pour la consigne « pas de corps ni de secrets »).

### 3.2 Corrélation SBX existante

- **Actor Intelligence** : `Record` envoie une enveloppe RFC-0013 vers `/run/secubox/actord.sock`, en mode « tire et oublie », pour toute IP non locale (`threatlog.go:268-276`). Projection :
  - `Action = observe`, sauf `banned`, qui devient `block` ;
  - `RuleID`, `Severity` via `sevToInt` : critical 90, high 75, medium 50, low 25, **autre 40** (`threatlog.go:96-109`) ;
  - `BehaviorTags` = catégorie, puis negative space, puis traits.
- **Profileur et campagnes** : `sbxwaf --correlate`, par l'unité `secubox-waf-campaigns` toutes les 5 min (`NG/systemd/secubox-waf-campaigns.service:30`, `SBX/profiler.go:196`, `construireProfils` `profiler.go:87-133`).
- **Panneau** : compteurs « observés » séparés des « bloqués » pour `action == "detect"` (`api/main.py:644-653`).

### 3.3 Politique de blocage nftables

| Mécanisme | Seuils et durée | Code |
|---|---|---|
| Réponse graduée du mode block | Fenêtre de 300 s, seuil 3 : 403 d'avertissement puis 403 de ban. Plafond de 100 000 IP. | `main.go:1361`, `SBX/ban.go:29-89`, `main.go:702-769` |
| Ban nft natif | Table `inet secubox`, sets `waf_ban` / `waf_ban6` (timeout et compteur), chaîne `waf_drop` en hook input, priorité -100, politique accept. Durée `--nft-ban-duration` **4 h**. Anti-tempête de 30 s par IP. Journal `/var/lib/secubox/waf/bans.jsonl`. | `SBX/nftban.go:85-95`, `124-141`, `179-237` ; `main.go:1166-1174`, `1403-1430` |
| Exceptions | IP privée, boucle locale et lien-local refusées au dernier moment (`nftban.go:180-182`). Robots vérifiés jamais bannis (`:188-195`). LAN exempté de l'inspection (`main.go:524`). Plages protégées `--actor-ban-protegees 82.67.100.75/32,2a01:e0a:dec:c4e0::/60` (unité `:147`). | |
| Escalade | Compteur séparé, fenêtre 24 h, seuil 3 (`main.go:1227-1230`, `1363`, `674-701`) | |
| #2238 ban de leurre | Ban au premier coup, 1 h / 24 h / 7 j selon la récidive (`SBX/leurreban.go:46-68`). Drapeau `--leurre-ban` **absent de l'unité livrée**, présent dans le drop-in d'exemple `NG/conf/honeypot.conf` (installé en `/usr/share/…`, inactif tel quel). Activation sur la box : « inconnu ». | |
| #2238 ban de campagne | `--campagne-ban auto` (unité `:144`). Fenêtre 24 h, au moins 5 sondes par IP, au moins 2 sondes de haute valeur par campagne, au moins 2 membres. Plafond 30 par heure. Durée 4 h / 24 h / 7 j. | `SBX/campagneban.go:20-44`, `85-88`, `117-180` |
| Ban par acteur | `--actor-ban auto` : au moins 2 sanctions **locales** (bans) dans 24 h, plafond 20 par heure | `SBX/actorban.go:25`, `82`, `122-211` |
| Échelle de réponse | `--mesures auto` : délai, défi, ralentissement, refus, selon le risque et la confiance d'actord | `main.go:1463-1474`, `internal/actor/mesure/mesure.go:27-95` |
| Limitation de débit | Table `inet secubox_waf_ratelimit` : SYN 80/443 au-delà de 30/s, rafale de 50, offenders pendant 5 min, liste blanche RFC1918 | `NG/config/secubox-waf-ratelimit.nft` |

### 3.4 Le mode `detect` n'est inerte que dans sbxwaf

Dans sbxwaf, `detect` n'appelle ni `s.ban.Record`, ni `appliquerBan`, ni nft (`main.go:652-673`). C'est testé (`main_test.go:515`, `713`). En aval, en revanche :

- **actord** : une ligne `detect` de gravité `critical` devient une enveloppe `observe`, `Severity = 90`. actord compte « hostile » tout événement de gravité ≥ 40, **quelle que soit l'action** (`cmd/sbx-actord/radar.go:115-123`). La gravité ≥ 80 ajoute aussi au risque (`internal/actor/analysis/analysis.go:331-333`). Comme l'unité active `--mesures auto`, des événements `detect` répétés d'une même adresse peuvent conduire à des mesures, jusqu'au refus (DENY), si le risque et la confiance d'actord suivent.
  Effet de bord déjà présent : `sevToInt("audit") = 40`. Chaque ligne `body-inspect-truncated` d'un utilisateur externe légitime (gros envoi) compte déjà comme hostile.
- **Campagnes** : `profilsDuJournal` n'écarte que les robots et l'auto-test (`campagneban.go:101-105`). Les lignes `detect` comptent comme `Sondes` (`profiler.go:108`). Une catégorie `php2shell` n'est pas « haute valeur » (`negativespace.go:60-63`), mais elle aide une IP déjà dans une campagne de haute valeur à franchir `minSondes = 5`.
- **Conséquence pour l'étape 4** : il faut décider comment journaliser et émettre les nouvelles détections pour tenir « detect ne bloque pas » (§ 7, décision 4).

---

## 4. CrowdSec dans le périmètre WAF

| Référence | Nature | Statut |
|---|---|---|
| `go.mod`, `vendor/modules.txt`, `SBX/*.go` (hors commentaire) | Aucune | — |
| `SBX/main.go:193` : « routage, réveil…, journal des menaces, CrowdSec. » | Commentaire **obsolète** (le pont a été retiré) | À corriger dans le périmètre touché |
| `SBX/nftban.go:20-30` : « relais externe (→ bouncer → nft) » | Commentaire historique, explique #1218 | Garder |
| `NG/debian/control:19-35,42-44` : `Conflicts/Replaces: secubox-crowdsec` | **Relation de paquet active, mais d'exclusion** : elle force le retrait de l'ancien paquet (#1319) | Garder (c'est l'inverse d'une dépendance) |
| `NG/sudoers/secubox-waf-ng` | Vidé ; le commentaire évoque « source de blocage externe » sans nommer l'outil | Historique |
| Unités `NG/systemd/*`, AppArmor `NG/debian/secubox-waf-ng.apparmor`, `NG/composants/waf/**` | Aucune occurrence | — |
| `NG/debian/changelog` (lignes 406-412, 509, 1111-1114, 1133-1136, 1205-1220, 1320-1332, 1429-1430, 1497) | Historique : retrait du pont `crowdsec.go` le 2026-09-05 (commit `241297b85`), retrait de `--crowdsec-url` (#1218) | Garder |
| `docs/superpowers/specs/2026-06-26-waf-go-sbxwaf-design.md` (bridge LAPI, `crowdsec.go`) | Conception historique | Garder (daté) |
| `docs/superpowers/specs|plans/2026-07-17-sbxwaf-mode-detect*.md` (« pas d'appel CrowdSec ») | Historique | Garder |
| `docs/wiki/Architecture-Security.md:31,90-94`, `docs/MODULES.md:157,175-187`, `docs/PROJECT-OVERVIEW.md:246,386,441`, `docs/wiki/Configuration-Advanced.md:50-57` | Documentation **obsolète** qui présente CrowdSec comme actif. Hors du strict périmètre sbxwaf. | À signaler ; corriger seulement si le chantier touche ces pages |
| `.wiki/WAF.md`, `.wiki/WAF-FR.md` | Aucune occurrence | — |
| `packages/secubox-crowdsec/` | N'existe plus | — |

**Aucune dépendance opérationnelle active.**

---

## 5. Paquets, unités, build, tests

### 5.1 Paquets

| Paquet | Version (changelog) | Arch | Rôle |
|---|---|---|---|
| `secubox-waf-ng` | **1.30.7-1~trixie1** (2026-10-27) | `any` | **Construit sbxwaf** et sbx-actord depuis `../secubox-toolbox-ng` (`NG/debian/rules:34-45`). Installe `/usr/sbin/sbxwaf`, l'unité `secubox-waf-ng`, le corpus en `/usr/share`, `waf-rules-sync`, l'API Python et le panneau. |
| `secubox-toolbox-ng` | 0.13.1-1~bookworm1 (restampillé `~trixie1` au build selon AGENTS.md) | `any` | Source Go (module, `vendor/`). **Ne construit pas sbxwaf** (`debian/rules` : sbxmitm, sbx-sentinel, sbx-authwatch, sbxdpi). Modifier `cmd/sbxwaf` impose de reconstruire **secubox-waf-ng** (`NG/debian/control:50-54`). |

- **Build** : `GOARCH = $(dpkg-architecture -qDEB_HOST_ARCH)`, `CGO_ENABLED=0`, `-mod=vendor`, `GOPROXY=off`, `GOTOOLCHAIN=local`, `-trimpath -ldflags=-s` (`NG/debian/rules:18-24`). La cible arm64 est obtenue en compilation croisée.
- **Aucun test au build** (`override_dh_auto_test` vide, `:47-49`).
- La CI exécute `go test ./...` du module sur ubuntu-24.04 x86_64 avec `CGO_ENABLED=0` (`.github/workflows/backend-tests.yml:237-281`).
- Binaires locaux ignorés par git : `NG/sbxwaf` (x86-64 statique, 27/10) et `SBX/sbxwaf` (x86-64 dynamique, 26/08). Ce sont des artefacts, pas des livrables arm64.
- **Unité `secubox-waf-ng`** :
  - `User=secubox-waf`, `CAP_NET_ADMIN`, `ProtectSystem=strict`, `MemoryHigh=256M`, `MemoryMax=384M`, `TasksMax=512`, `RuntimeMaxSec=12h` (`secubox-waf-ng.service:41-217`) ;
  - `NoNewPrivileges=false` (`:173`) : écart à RULES-CODE § 10, à vérifier par rapport aux exceptions listées.

### 5.2 Tests Go lancés (résultat réel)

Environnement : `GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local`, `GOCACHE` dans le scratchpad, `go1.22.2 linux/amd64`, CPU i9-13900H. Pas d'ARM64 disponible.

| Commande (depuis `packages/secubox-toolbox-ng`) | Résultat |
|---|---|
| `go test -count=1 ./cmd/sbxwaf/` | `ok … 3.991s` |
| `go test -count=1 -v ./cmd/sbxwaf/` | 335 `--- PASS` de premier niveau, 124 sous-tests, 0 FAIL, 0 SKIP. Parité : `allow=7 warn=34 ban=1 skip=11 known_gap=3 total=53`. |
| `go test -count=1 -race ./cmd/sbxwaf/` | `ok … 7.523s` |
| `go vet ./cmd/sbxwaf/` | rc 0 |
| `go test -count=1 ./...` | 25 paquets `ok` (sbxwaf, sbx-actord, sbxmitm, internal/actor/*…) |
| `go test -run '^$' -bench . -benchmem -count=3 ./cmd/sbxwaf/` | `BenchmarkWAFParityDecision` : 1284 à 1414 ns/op, 231 à 235 B/op, 7 allocs/op |

Python (`.venv`) : `test_detect_exclusion.py` et `test_waf_rules_sync.py` donnent **10 réussis**.

`BenchmarkWAFParityDecision` (`parity_test.go:295-317`) ne mesure qu'un GET court qui touche `sqli-001` dès le premier motif. **Il ne représente pas un corps** : c'est le seul banc existant.

### 5.3 Mesures complémentaires (copie jetable, hors dépôt)

Le module a été copié dans `scratchpad/bench-mod/`, avec le banc `cmd/sbxwaf/zz_audit_bench_test.go`. Rien n'a été écrit dans le dépôt. Résultats sur x86 i9-13900H :

| Mesure | Résultat |
|---|---|
| `MatchDetail`, corps texte bénin de 1 Mio, **corpus livré 1.5.2** (aucune correspondance, donc tous les motifs balayés) | **1,48 à 1,59 s/op**, 4,5 Mo/op, environ 6 600 allocs/op. Coût linéaire : 64 Kio ≈ 117 ms, 256 Kio ≈ 402 ms, 1 Mio ≈ 1,66 s. Motifs les plus chers : `scan-007` (213 ms/Mio), `scan-001`, `sqli-003`, `waf-fp-008`, `sqli-005`. |
| Balayage multipart (`mime/multipart.NextRawPart`, sans conservation des corps de parties) : 901 parties `files[R%05d][a][a][a]` + `PHP_SESSION_UPLOAD_PROGRESS`, 980 Ko | **2,9 à 3,4 ms/op**, environ 1,06 Mo/op, environ 13 570 allocs/op |
| Balayage multipart d'un envoi légitime (1 fichier) tronqué à 1 Mio | **0,09 à 0,11 ms/op**, environ 6,9 Ko/op, 33 allocs/op |
| Statuts obtenus par le prototype | Corps complet : `analyse` (901 parties, 900 fichiers, profondeur 4, progress=true). Coupé à moitié avec `tronque=true` : `tronque` (451 parties). Coupé avec un corps déclaré complet : `malforme`. Plafond de 500 parties : `limite`. Non-multipart : `malforme`. |

Le facteur pour ARM64 (Armada, Cortex-A72) n'est **pas mesuré**. Il faut rejouer le banc sur la cible.

---

## 6. Faisabilité

### 6.1 Analyseur multipart

- **Il n'en existe pas** dans le code. Seules mentions du mot : `corpsbinaire.go:38` et un commentaire dans `leurrehttp.go:154`.
- La bibliothèque standard convient :
  - `multipart.NewReader(bytes.NewReader(préfixe), boundary)` avec `NextRawPart()` : pas de décodage quoted-printable, et la limite interne de 10 000 en-têtes par partie s'applique ;
  - `ReadForm` est à proscrire : il matérialise les fichiers ;
  - `mime.ParseMediaType` pour extraire `boundary`. Un échec doit donner `malforme`, jamais `non_applicable`.
- Un analyseur fait maison n'apporterait qu'un contrôle fin des différences de lecture avec PHP (`rfc1867.c`). À évaluer dans l'étape 2 : le prototype montre que la bibliothèque standard suffit pour compter et pour donner les statuts.

### 6.2 Où l'insérer sans relire le corps deux fois

Point d'insertion : la branche `binaire` de `SBX/main.go:561-568`, **pour `multipart/form-data` seulement** :

1. Lire le préfixe avec le **même** code que `main.go:575-582` : une seule lecture, rejouée par `MultiReader`. C'est une factorisation de l'existant.
2. Appeler l'analyseur sur `préfixe`, sans copie et sans `string()`.
3. **Ne pas** passer le préfixe à `MatchDetail`. Le corps reste vide pour les regex, ce qui préserve le correctif du faux positif Mastodon (`corpsbinaire_test.go`).
4. Évaluer les signatures structurelles **après** `MatchDetail`, hors de la règle « première correspondance gagne » : une détection structurelle ne masque jamais une catégorie `block`, et réciproquement.

Variante sans tampon : un `TeeReader` vers l'analyseur pendant que le proxy relaie. Pas de latence ajoutée, mais la décision tombe après l'envoi au backend : acceptable en `detect`, impossible pour un futur `block`. À arbitrer (décision 5).

Questions de placement à trancher :

- Les contournements actuels (`ncBypass`, `isTrustedHost`, `privateCIDR`) court-circuitent **tout**. Les chemins « statiques » (`/status`, `/health`, suffixe `.js`) sautent le corps. Or PHP analyse le multipart **avant** d'exécuter le script : un POST multipart vers `/status.php` (qui contient `/status`) ou vers `/index.php/login/v2/` échappe donc à toute analyse.
- Le classement par Content-Type doit suivre celui de PHP. `corpsBinaire` coupe à `;`. D'après mémoire du code PHP (`main/SAPI.c`, à vérifier), PHP coupe aussi à `,` et à l'espace. Un `multipart/form-data, x` serait alors multipart pour PHP mais texte pour sbxwaf : il passerait en regex et pas dans l'analyseur.

### 6.3 Limite de corps et statuts explicites

- Calculer `tronque` proprement :
  - lire `cap+1` octets, ou comparer `r.ContentLength > cap` quand il est connu ;
  - traiter `ContentLength = -1` (encodage chunked) ;
  - **conserver l'erreur de lecture** au lieu de l'ignorer (`main.go:580`).
- Statuts : `analyse | tronque | malforme | limite | non_applicable`.
  - Seul `analyse` sans signal vaut « rien vu ».
  - `tronque`, `malforme` et `limite` écrivent une ligne d'audit avec leurs compteurs partiels. Gravité < 40 pour ne pas nourrir actord (§ 3.4). Jamais de contenu.
- Bornes : nombre de parties (`limite`), taille des en-têtes de partie (bornée de fait par le préfixe), aucune lecture au-delà du préfixe. Le temps est borné par la linéarité du balayage (3 ms pour 900 parties sur x86). Un budget explicite par nombre de parties suffit ; un minuteur serait superflu.

### 6.4 Coût mémoire sur ARM64 1 Go

- **Par requête multipart analysée** : préfixe ≤ 1 Mio, plus environ 1 Mo d'allocations transitoires pour 900 parties (environ 7 Ko pour un envoi légitime). Avec 20 envois simultanés : environ 40 Mo au pire. Ça tient dans `MemoryHigh=256M` / `MemoryMax=384M`.
- Recommandé : un sémaphore de concurrence pour l'analyse multipart, ou une fenêtre réduite (par exemple 256 Kio). Les indicateurs sourcés (« ~900 parties en moins de 1 Mo ») tiennent dans 1 Mio ; une fenêtre plus petite reste à mesurer.
- **Coût déjà payé aujourd'hui** :
  - un corps **texte** de 1 Mio coûte environ 1,6 s de CPU en regex sur x86 et environ 4,5 Mo d'allocations (`strings.Join`, `ToLower`, copie `string(bodyBytes)`), doublés si la phase G re-vérifie ;
  - l'analyseur multipart ne doit pas prendre ce chemin ;
  - ce coût regex est un sujet séparé (déni de service par corps urlencoded de 1 Mio, qui touche aussi la variante urlencoded de CVE-2026-109618).

### 6.5 Constats annexes (hors PHP2Shell, à ouvrir à part)

- **`waf-fp-004` et `waf-fp-008`** (`waf_fingerprint`, block, medium) sont compilés en `(?i)`. Ils correspondent donc à **tout** `select`, `union` ou `script`. Mesuré sur la copie : chemin `/description` → `waf-fp-008` ; `/api/v1/users/me/subscriptions` → `waf-fp-008` ; corps `{"lang":"javascript"}` → bloqué.
- **`check` ignoré** : `scan-001` (`(nikto|nmap|sqlmap|burp|zap|acunetix)`, marqué `user-agent`) s'applique au corps. Le corps `{"texte":"je vais zapper la pub"}` est bloqué en `scanners`.
- `testdata/waf-rules.json` (1.3.0) n'est pas le corpus livré (1.5.2) : la non-régression SQLi/XSS/LFI/RCE ne teste pas ce qui part en production.
- `Integrite()` n'est pas exposée ; la mise à jour de `_meta` par `waf-rules-sync` non plus (§ 2.5).

Ces faux positifs pèseront sur toute mesure de « taux de faux positifs » faite sur le journal.

---

## 7. Plan de changements (A à D) fondé sur les fichiers réels

**A. Analyseur et câblage, sans changer les décisions existantes**

- A1. `SBX/multipart.go` (nouveau). Fonction pure `analyserMultipart(préfixe []byte, contentType string, contentLength int64, lectureErr error, lim Limites) Resultat`. Elle rend :
  - le statut, les nombres de parties et de parties fichiers ;
  - la profondeur maximale des noms (`[`), la longueur maximale d'un nom ;
  - la présence et la position de `PHP_SESSION_UPLOAD_PROGRESS` par rapport aux parties fichiers ;
  - les marqueurs dans `filename` (`<?php`, `|O:`), sous forme de booléens et sans le contenu.
- A2. `SBX/main.go:561-601` :
  - factoriser la lecture du préfixe ;
  - pour le multipart, lire, analyser, mais **sans** passer le préfixe à `MatchDetail` ;
  - corriger le calcul de `tronque` et la gestion de l'erreur de lecture.
  Les autres binaires restent inchangés.
- A3. `SBX/threatlog.go` : champs `mode`, `decision` et `signals` en omitempty dans `logEntry` et `ThreatRecord`. `action` garde sa sémantique (consommateurs : `api/main.py:649`, `profiler.go:43`, `campagneban.go:103`). Ligne d'audit `multipart-<statut>`.
- A4. Tests : `multipart_test.go` (statuts, frontières, CRLF/LF, boundary entre guillemets, en-têtes en double, `filename*`, préfixe coupé dans un en-tête), `FuzzAnalyserMultipart` (fuzz natif Go 1.18+), `BenchmarkAnalyserMultipart`.

**B. Moteur de signatures structurelles**

- B1. Schéma. Dans `waf-rules.json`, une catégorie `php2shell` (`mode: "detect"`, `severity`, `enabled`) portant `patterns: []` et un nouveau tableau `structural: [{id, desc, cve, source, confidence, check, params}]`.
  - Avec `patterns` vide, l'API Python et un vieux sbxwaf l'ignorent sans risque. Les champs inconnus sont ignorés par Go (`rules.go:176-187`).
  - `waf-rules-sync` et wafgen préservent la catégorie (`waf-rules-sync:41-45`, `emit.py:84-87`).
- B2. `SBX/rules.go` : charger et valider `structural` (types de `check` connus, paramètres présents). Les compter dans `declares/charges/rejetes`, pour que chaque signature soit **chargée ou rejetée nommément**, et exposer `Integrite()`.
- B3. Évaluation **après** `MatchDetail`, seulement si le multipart a été analysé (ou si un statut anormal est apparu). Ne court-circuite jamais une catégorie `block`.

**C. Signatures PHP2Shell (mode `detect` uniquement)**

| Identifiant | Condition (sourcée) | Seuil |
|---|---|---|
| `php2shell_cve_2026_109619_progress` | `PHP_SESSION_UPLOAD_PROGRESS` + au moins 2 parties fichiers après lui (la seconde déclenche) | Aucun seuil numérique : structure seule |
| `php2shell_cve_2026_109618_files` | Nombre de parties ou de parties fichiers « anormal » (sources : 149 parties `t[]`, environ 900 parties en moins de 1 Mo) | **À mesurer** ; 50 non sourcé |
| `php2shell_cve_2026_109618_nested` | Noms imbriqués machine `files[R00001][a][a][a]`, profondeur et longueur de nom | **À mesurer** ; 12 non sourcé |
| `php2shell_cve_2026_109618_urlencoded` (suggestion) | urlencoded tronqué, `Content-Length` de plusieurs Mo, NUL dans un nom du préfixe | **À mesurer** |
| `php2shell_payload_filename` (suggestion) | `filename` contenant `<?php` ou `\|O:` (Splunk) | Structure seule |
| `php2shell_tool_fingerprint` | Marqueur d'outil ou UA, **confiance faible**, jamais suffisant seul | — |

Provenance dans chaque signature : CVE, URL de la source (Datadog, Akamai, Splunk, tracker Debian), `confidence`.

**D. Catalogue, événements, paquet, documentation**

- D1. `_meta.version` 1.6.0 et changelog du corpus. Corriger `waf-rules-sync` pour propager `_meta`, avec un test Python.
- D2. Synchroniser `testdata/waf-rules.json` sur le livré, **ou** faire tourner la parité sur le livré. Ajouter des fixtures multipart (positifs, négatifs, envois Nextcloud, Roundcube et PeerTube légitimes).
- D3. Émission vers actord : appliquer la décision 4 (gravité projetée < 40 pour `detect`/audit, ou étiquette `mode:detect`, ou non-émission). Ajouter le test « detect PHP2Shell ⇒ ni `s.ban`, ni nft, ni sonde de campagne de haute valeur ».
- D4. Retirer « CrowdSec » de `SBX/main.go:193` ; mettre à jour `NG/docs/CUTOVER.md:196-229` (multipart désormais analysé) et le README de secubox-waf-ng.
- D5. Monter `secubox-waf-ng` en 1.31.0-1~trixie1. Déploiement canari :
  - gk1 d'abord, en `detect` ; observer quelques jours les lignes `php2shell_*` et `multipart-*` ainsi que le CPU et la RSS de sbxwaf ;
  - puis gk2 ;
  - retour arrière : `enabled: false` sur la catégorie (rechargement à chaud, sans redémarrage) ou paquet précédent par apt.

### Risques

| Risque | Atténuation |
|---|---|
| Faux positifs `PHP_SESSION_UPLOAD_PROGRESS` légitime (barres de progression) | `detect` seulement ; exiger au moins 2 parties fichiers après le champ ; jamais seul |
| Gros envois Nextcloud et PeerTube | Nextcloud envoie surtout en PUT WebDAV par morceaux (pas du multipart). PeerTube en mode reprise envoie du `octet-stream`. Mesurer avant tout seuil. Coût borné au préfixe (environ 0,1 ms par envoi de 1 Mio). |
| Corps tronqués | Statut `tronque` explicite et journalisé, jamais « sûr » |
| Différences de lecture entre Go et PHP | `malforme` journalisé ; s'aligner sur le découpage du Content-Type de PHP ; fuzz |
| Latence et mémoire du tampon de 1 Mio sur chaque envoi multipart | Sémaphore ou fenêtre réduite, ou variante `TeeReader` en `detect` |
| `detect` nourrissant actord, mesures et campagnes (§ 3.4) | Décision 4 et test dédié |
| Masquage par l'ordre des catégories | Signatures structurelles hors de la règle « première correspondance gagne » ; si un motif regex `detect` est ajouté, le mettre en fin |
| Chemin `/check` de l'API Python, qui ignore `mode` | Aucune signature PHP2Shell en regex `patterns` |

### Décisions du propriétaire

1. **Seuils** (`files`, `nested`, `urlencoded`) : aucun n'est publié. Faut-il une phase de mesure de la distribution (compteurs sans signature) sur les vhosts PHP avant de fixer des valeurs, ou des seuils provisoires étiquetés « non sourcés » ?
2. **Services concernés** :
   - seulement les vhosts PHP (Nextcloud ; Roundcube/webmail dans le LXC mail, `packages/secubox-mail/lib/mail/install.sh:93-108`, PHP 8.2 + mod_php), déclarés par un nouveau service dans `vhost_profiles.json` ;
   - ou tous les vhosts.
   Que ces vhosts passent bien par sbxwaf plutôt que par `waf_bypass` dans `/etc/secubox/haproxy.toml` est « inconnu ».
3. **Contournements** : faut-il analyser le multipart même sur `ncBypass`, les chemins « statiques » et les hôtes de confiance (en `detect`) ? Le LAN reste exempté ?
4. **Émission aval** des `detect` et des statuts d'audit : quelle gravité projeter vers actord, et faut-il les exclure des sondes de campagne ? Cela touche aussi le défaut existant `sevToInt("audit") = 40`.
5. **Tampon contre flux** : lire jusqu'à 1 Mio (ou une fenêtre plus petite) avant de relayer chaque multipart, ou analyser en `TeeReader` (detect seulement) ?
6. **Constats annexes** (§ 6.5 et § 2.5) : ouvrir des issues séparées (faux positifs `waf-fp-004/008`, `check` ignoré, `testdata` figé, coût regex 1,6 s/Mio, `Integrite` non exposée, `_meta` non propagé) ?
7. **Correctif de fond** : la mise à jour de PHP dans les LXC (8.2.35 et suivantes selon la recherche) est la vraie correction ; le WAF n'est qu'une défense en profondeur. La version PHP des LXC est « inconnu ».

---

## 8. Décisions arrêtées (2026-10-29)

Réponses du propriétaire aux questions du § 7 :

1. **Seuils** : seuils provisoires, étiquetés « non sourcé » dans chaque signature : profondeur de nom **12**, nombre de parties **50**. Réglables dans `waf-rules.json` sans recompiler.
2. **Services** : **vhosts PHP seuls** (Nextcloud, Roundcube/webmail), déclarés dans `vhost_profiles.json`.
4. **Émission aval** : **gravité réelle**. Une détection PHP2Shell part vers actord avec la gravité de sa signature, comme toute ligne du journal.
5. **Lecture** : **en flux**. Aucun tampon ajouté avant le relais : une capture bornée copie le préfixe pendant que le proxy lit le corps, l'analyse a lieu après la réponse.

Arbitrages du rédacteur du plan, faute de réponse explicite (à contester dans la revue du plan) :

3. **Contournements** : sur un vhost PHP, le multipart est capturé même pour `ncBypass`, les chemins « statiques » et les hôtes de confiance, puisque PHP analyse le corps avant d'exécuter le script ; seul le **réseau local** reste exempté (`privateCIDR`). Coût si faux : des lignes `detect` sur des chemins jusque-là muets.
6. **Constats annexes** : ouverts en issues séparées (`waf-fp-004/008`, `check` ignoré, `testdata` figé en 1.3.0, coût regex 1,6 s/Mio, `Integrite()` non exposée). Seul `_meta` non propagé par `waf-rules-sync` est corrigé ici (D1).
7. **Correctif de fond** : la mise à jour de PHP dans les LXC reste le vrai correctif ; ce chantier est une défense en profondeur.
- **Gravité « audit »** : `sevToInt("audit")` passe de 40 à 10. Une ligne d'état (`multipart-tronque`, `body-inspect-truncated`…) n'est pas une menace et ne doit plus compter « hostile » chez actord (seuil 40). Coût si faux : actord voit moins d'événements « audit », qui n'étaient pas des attaques.
- **Signatures retenues** : progress + fichiers (109619), nombre de parties (109618), profondeur de nom (109618), charge dans `filename`. Écartées pour cette livraison : la variante urlencoded (elle passe par le chemin texte et sa regex) et l'empreinte d'outil (confiance faible, jamais suffisante seule).
- **Mémoire** : au plus 16 captures simultanées de 1 Mio (16 Mio). Au-delà, pas de capture et une ligne `multipart-limite`.
