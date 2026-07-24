# ProxyPAC — WPAD/DHCP autodetect + Tor `.onion` end-to-end — Design

**Date :** 2026-07-24
**Statut :** validé (design), prêt pour le plan d'implémentation
**Module :** `secubox-proxypac` (+ endpoint SOCKS dans `secubox-tor`)

---

## Objectif

Rendre le routage PAC réellement utilisable et *zéro-config quand c'est possible* :

1. **`.onion` route de bout en bout** pour tout client LAN / wg-toolbox (aujourd'hui
   la règle pointe sur un SOCKS mesh injoignable).
2. **Distribution du PAC en best-effort** selon le rôle réseau du box
   (master DHCP / résolveur DNS / esclave derrière un routeur standard), avec le
   moins d'effort client possible, **surchargeable** à tout niveau.
3. **Panneau `/proxypac/` fini** : intégration navbar + statut complet
   (PAC, endpoint Tor, échelon WPAD actif, candidats, runbook client).

## Contexte (vérifié sur gk2, 2026-07-24)

- `secubox-proxypac` **existe déjà, est mergé sur master et déployé** (1.0.0). Il
  génère `/var/lib/secubox/proxypac/proxy.pac` depuis `rules.d/*.rules` + le
  catalogue p2p `/services`, le sert en `/proxy.pac` (LAN-only, real_ip), avec
  API override/candidates, timer/path de régénération.
- La branche `feat/tor-onion-pac` (PAC servi par `secubox-tor`) **duplique**
  proxypac → **abandonnée**. Seul son endpoint SOCKS LAN est conservé.
- **Tor était `failed` depuis le 2026-07-10** : `HiddenServiceDir
  /var/lib/tor/hidden_services/webui` en `0750` (Tor exige `0700`) bloquait
  toute l'instance. Corrigé live → Tor bootstrap 100%, un `.onion` réel répond
  HTTP 200. *(Cause amont : le module d'exposition crée ce dir trop permissif —
  à traiter séparément.)*
- La règle seed `00-onion.rules` pointait `*.onion socks5 10.10.0.1:9050` — le
  **SocksPort mesh** (interface wg-mesh, `secubox-macro`), **injoignable** d'un
  client LAN ou wg-toolbox. Repointée live sur le SOCKS LAN (ci-dessous).
- `SocksPolicy` dans Tor est une option **globale** (s'applique à *tous* les
  SocksPort de l'instance) : un `reject *` unilatéral casserait le port mesh.
  Le confinement se fait donc par **bind sur IP + nft**, jamais par SocksPolicy.
- nft INPUT accepte déjà `iif eth2` (LAN) et `ip saddr 10.0.0.0/8` (couvre
  wg-toolbox 10.99.x) → un SocksPort LAN ne nécessite **aucune** règle nft.

## Décisions actées

1. **Tout le PAC vit dans `secubox-proxypac`.** Pas de second PAC. `secubox-tor`
   ne fournit que l'**endpoint SOCKS Tor** que le PAC vise.
2. **Endpoint SOCKS LAN dans `secubox-tor`** : dropin
   `/etc/tor/torrc.d/50-secubox-socks-lan.conf` ne contenant **que**
   `SocksPort <LAN_IP>:9050` — **jamais** de `SocksPolicy` (globale). L'IP LAN
   est **détectée au postinst** (jamais codée en dur), avec override.
3. **Détection de rôle passive + auto-agir.** Master si un serveur DHCP
   (dnsmasq/kea) est actif et écoute sur l'iface LAN du box ; esclave sinon.
   Aucun paquet DHCP de sonde émis. L'échelon détecté est appliqué
   automatiquement ; l'opérateur peut toujours surcharger.
4. **Échelle de distribution best-effort à 3 niveaux** (cf. tableau).
5. **Override partout** : `/etc/secubox/proxypac/proxypac.toml`
   (`role`, `wpad_domain`, `pac_url`, `socks_endpoint`) **et** toggle panneau.

## Deux mécanismes complémentaires

Le `.onion` (et les hôtes automappables) se route de deux façons, selon le
degré de contrôle du box sur le client :

### A. Transparent `.onion` — PRIMAIRE pour les clients force-routés (aucun PAC)

Quand le box maîtrise **DNS + routage** du client (cas wg-toolbox : les peers
poussent déjà `DNS = 10.99.1.1` et `AllowedIPs = 0.0.0.0/0` — vérifié), aucun
PAC n'est nécessaire. On intercepte `.onion` **transparently** :

```
client tape xxx.onion
  → DNS = Unbound (box) → forward-zone "onion." → Tor DNSPort 127.0.0.1:9053
  → AutomapHostsOnResolve → IP virtuelle dans 10.192.0.0/10
  → routée via le box (full-tunnel) → nft redirect 10.192.0.0/10 → TransPort 127.0.0.1:9040
  → Tor route dans le .onion
```

La machinerie Tor **existe déjà** (`torrc-toolbox-egress.conf` : `TransPort
9040`, `DNSPort 9053`, `AutomapHostsOnResolve 1`,
`VirtualAddrNetworkIPv4 10.192.0.0/10`), non activée pour cet usage. Câblages
manquants : (1) forward Unbound `onion.` → `127.0.0.1@9053` (+ autoriser le
range privé automap, sinon `private-address` le strip) ; (2) activer
TransPort/DNSPort/Automap dans l'instance `tor@default` (dropin torrc.d) ;
(3) nft nat redirect `10.192.0.0/10` → `127.0.0.1:9040` pour le trafic
force-routé. **Scope strict : seuls les `.onion` (hôtes automappés) sont
déviés — aucun autre trafic n'est modifié.** Toggle on/off.

### B. PAC / WPAD — fallback portable + routes de services mesh

Pour les clients **non** full-routés par le box (device LAN dont le box est
gateway mais pas forcément DNS, client hors tunnel) et pour les routes
**non-`.onion`** émises par le catalogue p2p `/services`. Distribution en
échelle best-effort à 3 niveaux :

| Niveau | Condition auto-détectée | Action | Effort client |
|---|---|---|---|
| **1. Master DHCP** | serveur DHCP actif sur l'iface LAN du box | option **DHCP 252** → `http://wpad.<domaine>/wpad.dat` | zéro (WPAD auto) |
| **2. Résolveur DNS** | pas master, mais box = résolveur DNS du LAN (Unbound) | enregistrement **`wpad.<domaine>` A → box** | zéro si client tente WPAD-DNS |
| **3. Manuel (toujours)** | routeur tiers maître du DHCP/DNS | **URL PAC** exposée dans le panneau + runbook | 1 collage d'URL |

Best-effort, non destructif : en esclave, on ne touche **jamais** au DHCP/DNS
du routeur tiers. Les niveaux 1/2 s'ajoutent sans retirer le niveau 3.

**A et B coexistent** : le transparent couvre wg-toolbox sans effort ; le PAC
sert les clients partiellement contrôlés et les services mesh. Un client
force-routé n'a pas besoin du PAC pour `.onion`, mais le PAC reste correct s'il
l'a (le SOCKS LAN répond aussi).

**Portée du transparent (décidée) : wg-toolbox + LAN.** Le nft redirect
`10.192.0.0/10` → TransPort s'applique au trafic entrant de `wg-toolbox` **et**
de l'iface LAN (`eth2`) — tout client dont le DNS+gateway est le box voit son
`.onion` auto-Toré. Les devices LAN qui utilisent un DNS externe ne sont pas
automappés → pour eux, le PAC/WPAD reste le chemin. Toggle global on/off.

## Composants

| Fichier | Rôle |
|---|---|
| `secubox-tor` : `conf/torrc.d/50-secubox-socks-lan.conf` (+ substitution postinst) | SocksPort LAN, IP détectée, sans SocksPolicy |
| `secubox-tor` : `conf/torrc.d/60-secubox-transparent.conf` | TransPort 9040 + DNSPort 9053 + AutomapHostsOnResolve + VirtualAddrNetworkIPv4 10.192.0.0/10 (activé si transparent on) |
| `secubox-tor` : `conf/unbound/onion-forward.conf` → `/etc/unbound/unbound.conf.d/` | forward-zone `onion.` → `127.0.0.1@9053` + `private-domain "onion."` (ne pas stripper le range automap) |
| `secubox-tor` : `nft.d/secubox-tor-transparent.nft` | nat redirect `10.192.0.0/10` → `127.0.0.1:9040` pour iif `wg-toolbox` + `eth2` (LAN) |
| `secubox-tor` : `sbin/torctl transparent {on\|off\|status}` | active/désactive le transparent (dropins + reload tor/unbound + nft), idempotent |
| `secubox-proxypac` : `proxypac/role.py` | détection passive master/slave + résolveur DNS |
| `secubox-proxypac` : `sbin/proxypac-wpad` | applique l'échelon (dnsmasq 252 / DNS wpad), idempotent, best-effort |
| `secubox-proxypac` : `conf/proxypac.toml` | `role/wpad_domain/pac_url/socks_endpoint/transparent` (conffile) |
| `secubox-proxypac` : `conf/rules.d/00-onion.rules` | `*.onion socks5 <LAN_IP>:9050` (substitué, plus 10.10.0.1) |
| `secubox-proxypac` : `api/main.py` | + `GET /status` (rôle, échelon, santé SOCKS+transparent, PAC), `POST /wpad/apply`, `POST /transparent`, `GET /wpad/state` |
| `secubox-proxypac` : `www/proxypac/index.html` | panneau réécrit : sidebar navbar + statut complet |
| `secubox-proxypac` : `menu.d/580-proxypac.json` | déployé dans `/usr/share/secubox/menu.d/` (navbar) |

**Note de frontière :** le transparent `.onion` (Tor TransPort/DNSPort/Unbound/nft)
vit dans `secubox-tor` — c'est de la config Tor+réseau, pas du PAC. `secubox-proxypac`
l'**expose** (statut + toggle via `torctl`, sudo scoped) mais ne l'implémente pas.

**Coordination de ports (critique) :** `TransPort 9040` et `DNSPort 9053` ne
peuvent être déclarés **qu'une seule fois** dans l'instance `tor@default` —
deux dropins qui les déclarent (le nôtre + `torrc-toolbox-egress.conf` du
toolbox si armé) = échec de bind → Tor ne démarre plus. `torctl transparent on`
doit donc être **idempotent et conscient de l'existant** : s'il détecte déjà un
`TransPort 9040`/`DNSPort 9053` actif dans `torrc.d` (dropin toolbox), il **réutilise**
ces ports (n'écrit que le forward Unbound + le nft redirect) au lieu d'ajouter un
dropin dupliqué. Sinon il livre `60-secubox-transparent.conf`. `off` ne retire
que ce que `on` a posé (jamais le dropin d'un autre paquet).

### Détection de rôle (`role.py`, pure + probes read-only)

- **Master DHCP** : un `dnsmasq`/`kea-dhcp4` actif dont la conf lie l'iface LAN
  (ou écoute UDP/67 sur l'IP LAN). Lecture d'état seulement, aucune sonde émise.
- **Résolveur DNS LAN** : le box écoute UDP/53 sur l'IP LAN (Unbound) **et** est
  annoncé comme DNS (best-effort : présence d'un service DNS local lié au LAN).
- **IP LAN** : première IP privée non-loopback de l'iface par défaut vers le LAN
  (route par défaut / iface portant la /24 LAN). Overridable.

### Application de l'échelon (`proxypac-wpad`, root, idempotent)

- **Master** : écrit `/etc/dnsmasq.d/secubox-wpad.conf` (`dhcp-option=252,...`),
  `systemctl reload dnsmasq` (best-effort, `|| true`).
- **DNS** : ajoute `wpad.<domaine>` → IP LAN dans la zone locale Unbound
  (dropin `local-data`), `unbound-control reload` (pas SIGHUP — ne recharge pas
  les local-zone). Cf. [[project_run_secubox_parent_systemic]] pour les pièges perms.
- **Esclave** : no-op réseau ; le panneau montre l'URL PAC + runbook.
- Toujours **idempotent** et **best-effort** : une étape qui échoue est loggée,
  n'interrompt pas les autres, ne laisse rien de cassé.

## Panneau `/proxypac/` (réécrit, look hybrid-dark)

- **Sidebar navbar** (`<nav class="sidebar">` + `/shared/sidebar.js`) — absente
  aujourd'hui ; + `menu.d/580-proxypac.json` déployé pour l'entrée navbar.
- **Cartes statut** : rôle détecté (master/slave), échelon WPAD actif, **santé
  endpoint Tor** (SOCKS en écoute + test `.onion` best-effort), état du PAC
  (dernière régénération, nombre de règles), URL PAC + URL WPAD.
- **Runbook client** : URL à coller, note Firefox `network.proxy.socks_remote_dns=true`.
- **Règles + override** (existant, conservé) + **candidats** (API déjà là, non
  affichée aujourd'hui).
- Jeton `sbx_token` en `localStorage` (cf. [[project_webui_token_key_sbx_token]]).

## Flux de données

Client configuré PAC (auto via WPAD niveau 1/2, ou manuel niveau 3) → requête
`xxx.onion` → PAC renvoie `SOCKS5 <LAN_IP>:9050; DIRECT` → navigateur ouvre un
SOCKS5 (nom non résolu localement) → **Tor** résout et route le `.onion`. Tout
autre hôte → `DIRECT` → chemin réseau normal (inspecté transparently sous
wg-toolbox). Le catalogue p2p `/services` peut ajouter d'autres routes (mesh).

## Tests

- **role.py** : master détecté quand un DHCP écoute sur l'IP LAN ; slave sinon ;
  résolveur DNS détecté quand UDP/53 lié au LAN ; IP LAN correctement dérivée —
  tout sur fixtures (aucune sonde réseau réelle en test).
- **proxypac-wpad** : master écrit le dropin dnsmasq option 252 ; slave = no-op ;
  idempotence (2 applications = même état) ; une étape en échec n'interrompt pas.
- **onion rule** : le PAC généré contient `SOCKS5 <LAN_IP>:9050; DIRECT` et
  jamais `10.10.0.1` après substitution.
- **SocksPort dropin** : contient `SocksPort <LAN_IP>:9050`, **aucune**
  `SocksPolicy` (test négatif), lie une IP LAN (pas `0.0.0.0`).
- **torctl transparent** : `on` sans dropin toolbox existant → livre
  `60-secubox-transparent.conf` (TransPort/DNSPort/Automap/VirtualAddr) ; `on`
  avec un `TransPort 9040` déjà présent → **ne duplique pas** (réutilise) ;
  `off` retire uniquement nos dropins ; idempotence (2×`on` = même état) — sur
  fixtures torrc.d.
- **Unbound onion-forward** : le dropin déclare `forward-zone "onion."` →
  `127.0.0.1@9053` et `private-domain "onion."` (sinon le range automap
  10.192.0.0/10 est strippé) ; JSON/syntaxe valide.
- **nft transparent** : le fichier redirige `10.192.0.0/10` → `127.0.0.1:9040`
  pour `iif { wg-toolbox, eth2 }` et rien d'autre (test de portée).
- **API** : `GET /status` renvoie rôle + échelon + santé SOCKS ; `/wpad/apply`
  délègue au ctl (jamais d'action privilégiée in-process).
- **panneau** : présence sidebar + `menu.d` valide (JSON) + cartes statut.
- **Bout en bout (manuel, board)** : `curl --socks5-hostname <LAN_IP>:9050
  http://<onion>/` → 200 ; `curl -I http://<box>/proxy.pac` → MIME
  `application/x-ns-proxy-autoconfig` ; en master, `dhcp-option=252` présent.

## Risques connus

| Risque | Traitement |
|---|---|
| `SocksPolicy` globale casse le port mesh | Le dropin LAN ne définit **jamais** de SocksPolicy ; confinement bind IP + nft |
| IP LAN codée en dur (192.168.1.200) non générique | Détectée au postinst / génération, overridable dans `proxypac.toml` |
| Slave : tentation de forcer le DHCP du routeur tiers | Interdit : niveau 3 = manuel, no-op réseau |
| Double-DHCP si master mal détecté | Détection passive lit l'état du DHCP local uniquement ; override explicite ; sonde active **hors périmètre** |
| Unbound `reload` SIGHUP ne recharge pas local-zone | Utiliser `unbound-control reload` |
| Tor `failed` → PAC mort | Corrigé (perms 0700) ; panneau affiche la santé SOCKS pour rendre la panne visible |
| Action privilégiée depuis l'API | L'API délègue à `proxypac-wpad`/`torctl` via sudo scoped (cf. [[feedback_webui_delegates_to_confined_ctl]]) |
| Double `TransPort 9040` (nous + toolbox) → Tor ne démarre plus | `torctl` réutilise un TransPort/DNSPort existant, ne duplique jamais (cf. Note de frontière) |
| Unbound strippe le range automap privé (10.192.0.0/10) | `private-domain "onion."` dans le dropin Unbound ; test dédié |
| Fuite `.onion` si un client LAN utilise un DNS externe | Attendu : transparent ne couvre que les clients en DNS-box ; le PAC/WPAD est le fallback documenté pour les autres |
| nft transparent trop large (redirige plus que 10.192.0.0/10) | Portée stricte au range automap + iif {wg-toolbox, eth2} ; test de portée ; DEFAULT DROP inchangé |
| nft dropin transparent perdu au reboot / mauvais ordre | Livré en `/etc/nftables.d/` avec préfixe d'ordre correct (cf. [[feedback_nft_layered_dropins_persistence]]) |

## Hors périmètre (YAGNI)

Sonde DHCP active (DHCPDISCOVER), sélection du pays d'exit Tor, rotation de
circuit, WPAD sur `.onion` non-HTTP, correction amont des perms du
`HiddenServiceDir` (bug du module d'exposition, ticket distinct). Backlog Tor :
[[project_tor_enhancement_queued]], [[project_tor_anticensorship_ladder]].
