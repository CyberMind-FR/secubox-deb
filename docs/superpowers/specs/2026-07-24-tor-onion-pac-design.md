<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# PAC auto-routing .onion → Tor — Design

**Date :** 2026-07-24
**Statut :** validé (design), prêt pour le plan d'implémentation
**Module :** `secubox-tor`

---

## Objectif

Un fichier PAC (proxy auto-config) qui route **automatiquement les adresses
`.onion` vers le réseau Tor** (via le SOCKS local), et laisse **tout le reste en
DIRECT** — l'inspection transparente existante (wg-toolbox → sbxmitm, DNAT) s'en
charge déjà. Le PAC ne fait qu'**une** chose : dévier les `.onion` vers Tor.

## Décisions actées

1. **Non-`.onion` = DIRECT.** Pas de proxy explicite à monter : le MITM SecuBox
   est transparent (DNAT), pas un forward-proxy, et pour un client wg-toolbox
   tout est déjà inspecté au niveau réseau. Router « tout via proxy explicite »
   serait redondant/conflictuel. Le PAC ne spécialise que `.onion`.
2. **SOCKS Tor joignable et confiné sur une seule IP.** `192.168.1.200:9050`
   (IP LAN du box, atteinte depuis le LAN **et** depuis wg-toolbox qui route déjà
   vers le box), fermé à l'extérieur par `SocksPolicy` — **jamais** un SOCKS
   ouvert (open-relay = abus).
3. **`SOCKS5` dans le PAC** (pas SOCKS4) → le navigateur laisse **Tor résoudre
   le `.onion`** (remote DNS), car `.onion` n'existe pas dans le DNS normal.
4. **Home = `secubox-tor`** (il gère déjà Tor + son torrc).

## Contexte (vérifié sur gk2, 2026-07-24)

- `secubox-tor` est `active` ; le `tor` sous-jacent est **`inactive`/`failed`**.
  → **Prérequis :** le PAC est une pièce morte tant que Tor ne sert pas le SOCKS.
  Le plan DOIT vérifier/réparer que Tor tourne réellement (sinon livrer le PAC
  seul serait trompeur).
- Aujourd'hui `SocksPort 10.10.0.1:9050` — sur l'interface **wg-mesh**
  (10.10.0.0/24, réseau P2P entre nœuds), **inaccessible** à un client LAN ou
  wg-toolbox.
- Aucun proxy forward explicite ne tourne (squid/privoxy/tinyproxy/mitmproxy
  tous inactifs). Confirme la décision « non-`.onion` = DIRECT ».
- Aucun `.pac` n'est servi actuellement.

## Composants

| Fichier | Rôle |
|---|---|
| `conf/torrc.d/50-secubox-socks-lan.conf` | Ajoute `SocksPort 192.168.1.200:9050` + `SocksPolicy` (accept LAN+wg, reject *) |
| `www/tor/tor.pac` | Le fichier PAC (statique) |
| `nginx/tor-pac.conf` | Dropin nginx servant `/tor.pac` avec le bon MIME, LAN-confiné |
| `README.md` | Runbook client (URL du PAC + `network.proxy.socks_remote_dns`) |

### 1. SOCKS Tor joignable + confiné (`torrc.d`)

```
# SOCKS local pour les clients LAN / wg-toolbox (PAC .onion → Tor).
# JAMAIS ouvert à l'extérieur : SocksPolicy ferme tout sauf LAN + wg.
SocksPort 192.168.1.200:9050
SocksPolicy accept 192.168.0.0/16
SocksPolicy accept 10.99.0.0/16
SocksPolicy reject *
```

Le `SocksPort 10.10.0.1:9050` existant (mesh) est **conservé** — on **ajoute**
un binding LAN, on ne déplace rien.

### 2. Le PAC (`www/tor/tor.pac`)

```javascript
// SecuBox :: routage automatique .onion → Tor. Tout le reste en DIRECT
// (l'inspection transparente wg-toolbox s'en charge déjà).
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.onion") || shExpMatch(host, "onion"))
        return "SOCKS5 192.168.1.200:9050";  // SOCKS5 → Tor résout le .onion
    return "DIRECT";
}
```

`shExpMatch(host, "onion")` couvre le cas d'un host `onion` nu ; `*.onion`
couvre `xxx.onion` et les sous-domaines. `SOCKS5` est requis pour que la
résolution du nom soit **déléguée à Tor** (remote DNS).

### 3. Servir le PAC (`nginx/tor-pac.conf`)

```nginx
location = /tor.pac {
    alias /usr/share/secubox/www/tor/tor.pac;
    types { } default_type application/x-ns-proxy-autoconfig;
    allow 127.0.0.1; allow 10.0.0.0/8; allow 172.16.0.0/12; allow 192.168.0.0/16;
    deny all;
}
```

MIME `application/x-ns-proxy-autoconfig` (attendu par les navigateurs pour un
PAC). LAN-confiné (allow privé / deny all). URL stable : `http://<box>/tor.pac`.

### 4. Côté client (README)

- Configurer le navigateur/OS en « auto-config URL » → `http://<box>/tor.pac`.
- **Firefox :** activer `network.proxy.socks_remote_dns = true` (sinon Firefox
  tente de résoudre le `.onion` en DNS local et échoue avant d'atteindre Tor).
  Chrome fait le remote DNS pour SOCKS5 issu d'un PAC par défaut.

## Flux de données

Navigateur configuré avec le PAC → requête vers `xxx.onion` → le PAC renvoie
`SOCKS5 192.168.1.200:9050` → le navigateur ouvre un SOCKS5 vers Tor (nom non
résolu localement) → **Tor** résout et route le `.onion` dans le réseau Tor.
Toute autre requête → `DIRECT` → chemin réseau normal (inspecté transparently
pour un client wg-toolbox).

## Tests

- **PAC (fonction pure)** : évaluer `FindProxyForURL` avec un moteur JS
  (`duktape`/`node`) sur des cas — `x.onion` → `SOCKS5 …`, `a.b.onion` → SOCKS,
  `onion` nu → SOCKS, `example.com` → `DIRECT`, `onion.example.com` → `DIRECT`
  (ne PAS matcher un domaine qui contient « onion » sans être un TLD `.onion`).
- **torrc** : `tor --verify-config` accepte le dropin ; `SocksPolicy reject *`
  bien en dernier (ordre = premier match).
- **Confinement** : le SOCKS `192.168.1.200:9050` refuse une source hors
  LAN/wg (test de policy) ; le PAC nginx refuse une source non-LAN.
- **MIME** : `curl -I http://<box>/tor.pac` renvoie
  `application/x-ns-proxy-autoconfig`.
- **Bout en bout (manuel)** : Tor actif + un `.onion` connu résout via le SOCKS
  (`curl --socks5-hostname 192.168.1.200:9050 http://<onion>/`).

## Risques connus

| Risque | Traitement |
|---|---|
| Tor `inactive`/`failed` → PAC mort | Prérequis : le plan vérifie/répare que Tor sert le SOCKS avant de livrer |
| SOCKS ouvert = open-relay/abus | `SocksPolicy` ferme tout sauf LAN + wg ; binding sur l'IP LAN, pas `0.0.0.0` |
| Firefox résout `.onion` en local | Documenté : `network.proxy.socks_remote_dns=true` |
| Faux match sur un host contenant « onion » | `shExpMatch("*.onion")` ne matche que le TLD `.onion` ; test dédié |

## Hors périmètre (YAGNI)

WPAD auto-discovery, `.onion` hors HTTP(S), sélection du pays d'exit, rotation
de circuit — sujets Tor distincts déjà au backlog
([[project_tor_enhancement_queued]], [[project_tor_anticensorship_ladder]]).
