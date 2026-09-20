<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SBX-SIGNAL — passerelle Signal

Envoyer et recevoir des messages Signal depuis une SecuBox, et **faire sortir
les alertes Sentinel vers un téléphone**.

> **Pré-release.** Phase 1 : appairage, envoi, cardlet. Voir la
> [RFC](docs/RFC-SBX-SIGNAL.md) §12 pour ce qui reste.

## Pour l'exploitant

### Installer

```bash
apt install secubox-signal          # tire secubox-signal-engine
systemctl enable --now secubox-signal
```

`signal-cli` **n'est dans aucune Debian** ; `secubox-signal-engine` l'embarque,
exactement comme `secubox-ndpid-engine` embarque nDPI.

### Appairer

La box se lie comme **appareil secondaire** d'un compte existant. Elle ne
s'enregistre jamais comme appareil primaire : cela demanderait un numéro dédié
et rendrait la box responsable d'une identité.

1. Ouvrir `https://signal.gk2.secubox.in/` (ou la carte Signal du Hall).
2. **Générer un QR d'appairage**.
3. Sur le téléphone : Signal → *Paramètres* → *Appareils liés* → **+**.
4. Scanner. Le QR expire en 10 minutes.

Le QR est tracé **côté serveur** : l'URI d'appairage — qui lie quiconque la
scanne — ne quitte jamais le démon autrement qu'en image.

### Alertes Sentinel

Dans `/etc/secubox/signal.toml` :

```toml
[sentinel]
enabled = true
destination = "+33600000000"   # ou un identifiant de groupe
max_per_hour = 20
```

`max_per_hour` n'est pas un réglage de confort. Au-delà du seuil, les alertes
sont **agrégées en un message de synthèse** : une tempête d'événements ne doit
devenir ni une tempête de notifications, ni un épuisement du quota Signal du
compte lié.

### Ce qui est conservé, et ce qui ne l'est pas

**Le contenu des messages n'est pas conservé.** La base ne retient qu'un
horodatage, un expéditeur haché, une taille et un identifiant — 24 h par
défaut.

`retention.store_body = true` existe. Avant de l'activer : une box qui archive
des conversations chiffrées de bout en bout devient une cible d'un intérêt
tout autre, et déplace la responsabilité juridique sur son exploitant. Le
démon le journalise bruyamment au démarrage, et l'interface l'affiche en
rouge.

### Diagnostic

```bash
systemctl status secubox-signal
journalctl -u secubox-signal -f
curl --unix-socket /run/secubox/signal.sock http://x/api/v1/signal/healthz
```

| symptôme | cause probable |
|---|---|
| `backend: unlinked` | aucun compte lié — appairer |
| `backend: down` | `signal-cli` absent ou JVM en échec |
| 401 sur toutes les routes | jeton absent : passer par le Hall |
| cardlet vide dans le Hall | CSP — vérifier `frame-ancestors` du vhost |

## Pour le développeur

### Construire

```bash
cd packages/secubox-signal
GOFLAGS=-mod=vendor GOPROXY=off go build ./cmd/sbx-signald
go test ./internal/...
bash tests/integration/smoke.sh ./sbx-signald
```

L'essai d'intégration **ne demande ni `signal-cli` ni compte lié** : il vérifie
que le démon sert, refuse ce qu'il doit refuser, et s'arrête proprement.

### Structure

| chemin | rôle |
|---|---|
| `cmd/sbx-signald` | point d'entrée, socket, arrêt propre |
| `internal/config` | lecteur TOML minimal — refuse les clés inconnues |
| `internal/signalcli` | JSON-RPC sur stdio vers `signal-cli` |
| `internal/store` | métadonnées SQLite, expéditeur haché |
| `internal/ws` | RFC 6455 côté serveur, sans bibliothèque |
| `internal/pairing` | QR d'appairage en SVG |
| `internal/sentinel` | relais d'alertes + garde-fou |
| `internal/api` | surface REST (cf. `docs/openapi.yaml`) |
| `internal/web` | documents embarqués (`go:embed`) |

### Deux dépendances, et pas une de plus

`modernc.org/sqlite` et `github.com/skip2/go-qrcode` — **toutes deux déjà
vendorisées ailleurs dans le parc**. Pas de parseur TOML (la config est plate,
80 lignes suffisent), pas de bibliothèque WebSocket (la poignée de main et le
tramage texte tiennent dans `internal/ws`).

Avant d'en ajouter une : ce module tient les clés d'un lien Signal. Chaque
dépendance est du code à auditer.

### Contribuer

1. Lire la [RFC](docs/RFC-SBX-SIGNAL.md) — surtout §2 (ce que le module n'est
   pas) et §7 (rétention).
2. `docs/openapi.yaml` fait foi pour l'API. Le modifier avant le code.
3. Suivi : [#1309](https://github.com/CyberMind-FR/secubox-deb/issues/1309).
