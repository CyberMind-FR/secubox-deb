<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-toolbox-ng — Go MITM engine (migration spike, #662 Phase 1)

De-risking PoC for migrating the R3 toolbox MITM engine off Python **mitmproxy**
(GIL-bound, ~1 core) onto a multi-core **Go** core, **without losing the
18-addon feature set**. See:
- Analysis: `docs/superpowers/specs/2026-06-18-mitm-engine-migration-analysis.md`
- Phased plan: `docs/superpowers/plans/2026-06-18-mitm-engine-migration.md`

> **Status: Phase 1 — PoC only. NOT wired into the live R3 path.** The live
> tunnel still runs on the Python mitmproxy workers (8081-8084). This binary is
> a standalone CONNECT-proxy spike that proves the risky capabilities.

## What the PoC proves (the discriminating risks from the analysis)
- **CA-compat forging** — loads the *existing* `ca-wg/{ca.pem,key.pem}` and forges
  per-host leaf certs the R3 clients already trust (no re-enroll). Cached per host.
- **request 204** — short-circuit block (ad_ghost / privacy_guard).
- **response body inject** — marker before `</head>`/`</body>` (banner / ad-CSS).
- **SNI splice** — raw passthrough, no MITM, by SNI suffix (tls_splice).
- **JA4 material capture** — `crypto/tls` `GetCertificate` receives the
  `ClientHelloInfo` (SNI, cipher suites, ALPN, TLS versions) → proves the `ja4`
  addon's handshake fingerprint is reachable in Go (full JA4 extension-hash needs
  a raw-ClientHello peek — Phase 4).

All stdlib (no external modules → builds offline). Tests are network-free
(localhost handshake + temp self-signed CA).

## Build & test
```sh
cd packages/secubox-toolbox-ng
go test ./...                                   # network-free PoC tests
GOOS=linux GOARCH=arm64 go build -o sbxmitm ./cmd/sbxmitm   # appliance target
```

## Try it (CONNECT proxy, against the board CA)
```sh
./sbxmitm --ca-cert /etc/secubox/toolbox/ca-wg/ca.pem \
          --ca-key  /etc/secubox/toolbox/ca-wg/key.pem --listen :8090
curl -x localhost:8090 --cacert /etc/secubox/toolbox/ca-wg/ca.pem https://doubleclick.net/   # → 204
curl -x localhost:8090 --cacert /etc/secubox/toolbox/ca-wg/ca.pem https://example.com/        # → body has the sbx-ng marker
# logs print `ja4 t0304_cNN_a... sni=...` per handshake
```

## Capability → engine map (recap)
Go covers request-204 / body-rewrite / header-cookie-mod / splice / async-sidecars
cleanly; JA4 needs the ClientHello shim (proven here); streaming inject + the
anti-track HMAC-jar/poison port land in Phase 3/4. Heavy analysis (social-graph,
classify, DB/report writers) stays in the existing Python sidecars, fed
fire-and-forget over unix sockets.

## Roadmap (do NOT cut over without the gates)
1. ✅ PoC (this) — forge + 204 + inject + splice + ClientHello capture, compiled + tested.
2. arm64 packaging + board bench on :8090 (no DNAT) — forge/throughput vs mitmproxy.
3. Hot-path feature parity (block lists + allowlist + own-infra guard, header/cookie strip, banner, splice) — parity harness vs the Python addons.
4. Analysis sidecars (unix-socket fire-and-forget) + anti-track HMAC-jar/forge port (exhaustively tested vs `privacy.py`).
5. **Shadow run** — mirror a fraction of R3, compare outputs. No client served yet.
6. **Cutover** — flip nft `numgen` fanout 8081-8084 → 8090-8093; mitmproxy stays up for instant rollback.
7. Decommission mitmproxy after a stable soak.

Rollback is an nft DNAT-map edit at every step; the Python engine is the live
path until Phase 6.

## sbx-authwatch : réseau et campagnes (#3919, 0.19.0)

Chaque alerte écrite dans `waf-threats.log` porte `asn`, `asn_org`, `reseau_classe` et, si le compte visé est l'objet
d'une campagne établie, son identifiant (8 hex du SHA-256 du compte). Le comportement de ban ne change pas.

| Option | Défaut |
|---|---|
| `--geoip-asn` | `/var/lib/GeoIP/GeoLite2-ASN.mmdb` (`""` = désactivé) |
| `--reseaux-classes` | `/usr/share/secubox/waf/reseaux-classes.toml,/etc/secubox/waf/reseaux-classes.toml` (livré par secubox-waf-ng ≥ 1.44.0 ; absent : `inconnu`) |
| `--campagnes-etat` | `/run/secubox-authwatch/campagnes.json` (`""` = désactivé) |

`campagnes.json` (dossier propre au service, `RuntimeDirectory=secubox-authwatch`, effacé à l'arrêt ; 0644, renommage atomique toutes les 60 s) : tableau de `{id, compte, sources, premier,
dernier}`, `compte` masqué au-delà de 3 caractères, aucune adresse. Lu par le relevé des populations du WAF.

## sbx-authwatch : leurres de messagerie (#3924, 0.20.0)

Pendant l'arrêt du conteneur de courrier, authwatch répond à sa place. **Éteint par défaut.** Pour l'armer :

```bash
install -m 0640 /dev/null /etc/secubox/authwatch/authwatch.env
echo 'SBX_MAIL_CONTENEUR=10.100.0.10' > /etc/secubox/authwatch/authwatch.env
systemctl restart secubox-authwatch
```

Pour l'éteindre : retirer la ligne (ou le fichier) et relancer l'unité. Une adresse invalide éteint ces leurres et le dit
au journal ; la surveillance continue.

| Port | Réponse | Signal |
|---|---|---|
| 25 | SMTP sans STARTTLS ; `451 4.3.2` à MAIL, RCPT, DATA | AUTH menée à son terme |
| 587 | SMTP, `AUTH PLAIN LOGIN` annoncé, `454 4.7.0` | AUTH menée à son terme |
| 465, 993, 995 | alerte TLS et fermeture, sans certificat | aucun : adresse et cadence comptées, **jamais de ban** |
| 110, 143 | permanents (si rien d'autre n'y écoute) ; `-ERR [SYS/TEMP]`, `NO [UNAVAILABLE]` | authentification menée à son terme |

- **Échecs temporaires seulement** : jamais de 5xx ni de 354 ; l'expéditeur garde son message et le représente.
- **Mot de passe** : lu dans un tampon fixe, effacé, jamais converti en chaîne, journalisé, haché ni rendu. **Compte** :
  masqué au journal des menaces et dans journald ; en clair seulement comme clé en mémoire.
- **Bans** : règles ordinaires (compte inexistant, campagne, compteur), catégories `auth_smtp:leurre`,
  `auth_smtp:leurre_submission`, `auth_imap:leurre`, `auth_imap:leurre_pop3` (famille `messagerie`). Gravité `medium` :
  un essai sur un compte réel pèse deux fois moins qu'un échec SASL de Postfix. Une visite sans AUTH n'est rien. LAN,
  maillage, conteneurs, 100.64.0.0/10 et liste blanche : servis ou non redirigés, jamais inscrits.
- **Modes** (page Modes du WAF, `leurres-modes.json`) : `smtp`, `submission`, `imap`, `pop3` ; `observer` journalise sans
  bannir. `smtps`, `imaps`, `pop3s` observent toujours.
- **Bornes** : 64 connexions par leurre, 4 par adresse, 10 s par ligne, 30 s par connexion, 1 Kio par ligne, 8 Kio par
  connexion, 32 commandes, 3 authentifications.

**Bascule.** Sonde TCP du conteneur toutes les 30 s (`--mail-sonde`, 5 s à 5 min ; connexion sous 2 s) : port 25, ou à
défaut l'un des autres ports relayés, pour ne jamais masquer un Dovecot qui sert. Deux échecs d'affilée posent
`table ip secubox_leurres_mail` ; une réussite la retire aussitôt. Crochet prerouting en priorité -120, avant la règle DNAT
du site (-100), qui n'est jamais modifiée : le premier verdict NAT l'emporte. Seules les adresses publiques à destination
de la box sont redirigées, IPv4 seulement ; le crochet output (Postfix de l'hôte) n'est pas touché. Les ports locaux (18025, 18465, 18587,
18993, 18995) ne sont ouverts que pendant la bascule et refusés hors redirection.

**Sûreté.** La table est reposée à chaque sonde et ses éléments expirent en trois périodes (90 s) ; `ExecStopPost` la
retire à l'arrêt comme au plantage. Un authwatch mort ne masque donc jamais un courrier qui fonctionne.

| Option | Défaut |
|---|---|
| `--mail-conteneur` | vide (éteint) |
| `--mail-sonde` | `30s` |
| `--mail-etat` | `/run/secubox-authwatch/leurres-mail.json` (0600 ; `""` = désactivé) |

Sous une base nftables dont le WAN n'est pas de confiance, secubox-hardening ≥ 1.7.1 accepte les ports locaux, par la
redirection seulement (`/etc/nftables.d/secubox-leurres-mail.nft`) ; 110 et 143 y restent fermés.
