# Fédération SBX v2 (GK2)

> Épopée #1388 · phase 1 livrée : #1389 (`secubox-federation` 0.1.0, déployé sur gk2)

Chaque SecuBox reste **autonome**. Elle rejoint la fédération GK2 quand elle le
décide, avec un **certificat SBX** signé par l'autorité, et va chercher —
elle-même, quand elle le veut — ce que ce certificat lui ouvre : App Store,
flux WAF, métablogs, sites, dépôts. Aucune dépendance permanente au cloud,
aucune télémétrie, aucune connexion entrante imposée.

```
SecuBox ──(certificat SBX, requêtes signées ; mTLS en P2)──▶ GK2
                                                            ├── App Store fédéré (P5)
                                                            ├── Flux WAF signés (P4)
                                                            ├── Métablogs · sites (P5)
                                                            ├── Dépôts apt stable/beta/alpha (P3)
                                                            └── Rétributions (métadonnées, P6)
SecuBox ◀──(MirrorNet, réplication différée)──▶ SecuBox (P6)
```

## 1. Principe : étendre, pas doubler

Le cahier des charges décrivait une pile Go neuve (`internal/federation`,
`ca`, `appstore`, `waf`, `mesh`). Le dépôt contient déjà l'essentiel du socle ;
créer une seconde autorité de confiance, une seconde notion de canal et un
second maillage aurait laissé deux mondes à réconcilier. Décision (2026-09-25) :
**étendre l'existant**.

| Besoin | Brique existante | Ce que la fédération y ajoute |
|---|---|---|
| Identité d'une box | `secubox-annuaire` : `did:plc:<sha256(clé)[:32]>`, clé Ed25519 `/etc/secubox/secrets/annuaire/node.key` | le **sujet** du certificat SBX est ce DID |
| Signatures, canonicalisation | `annuaire.crypto.canonical_bytes` + `verify` | le Go produit **les mêmes octets** (`internal/canon`) : un certificat se vérifie en Python |
| Droits, délégations | annuaire : `ServiceOffer`, `Subscription`, `Grant`, `RevocationNotice` | P2 : l'émission est inscrite au journal chaîné |
| Canaux de dépôt | `secubox-release` (anneaux) + dépôt apt signé sur gk2 | P3 : stable / beta / alpha ouverts par le certificat |
| Réplication | `secubox-p2p` (MirrorNet, WireGuard) | P6 : objets SBX et métablogs |
| Catalogue | `secubox-appstore` (déjà des tiers) | P5 : type générique `SBXObject` |
| Sites | `secubox-metablogizer`, chaîne de publication vhost | P5 : paquets `.sbx` |
| Clé de la CA | fichier 0600 aujourd'hui | le Coffre (#1364/#1367) la scellera |

## 2. Le certificat SBX v2

Présenté en YAML, **signé sur la forme canonique JSON** des mêmes champs
(tous sauf `signature`) — exactement comme tout objet de l'annuaire.

```yaml
version: 2
serial: SBX-2026-0002
box_id: did:plc:04637c9028cb4e43ada5fabe680c457d   # = empreinte de pubkey
owner: CyberMind
tier: premium
channels: [stable, beta, alpha]                   # ordre fixé à l'émission
rights: {appstore: true, metapack: true, mesh: true, support: true, waf_pro: true}
issued: "2026-09-25T06:31:24Z"
expires: "2027-09-25"
issuer: did:plc:983c9c6d07816cf9d4ed9b20a90ee19f   # DID de la CA
pubkey: ed25519:<hex, 32 octets>                   # clé de la box
signature: ed25519:<hex, 64 octets>                # signature de la CA
```

Écarts assumés avec le cahier des charges :

- **`box_id` est un DID, pas un UUID.** Il est l'empreinte de la clé : le sujet
  est auto-certifiant, on ne peut pas présenter la clé d'une box sous le nom
  d'une autre (refusé à la vérification).
- **`issued` et `issuer` en plus** : pour dater, et pour savoir quelle clé vérifie.
- **Premium garde `stable`** en plus d'alpha et beta.

Vérification complète (`Certificat.Verification`) : forme, sujet
auto-certifiant, émetteur attendu, signature, échéance (jusqu'à la fin du jour
UTC), liste de révocation.

## 3. Niveaux d'abonnement

Valeurs par défaut (le tableau du cahier des charges), toutes surchargeables
dans `/etc/secubox/federation.yaml` :

| Tier | Sync WAF | Canaux | App Store | Droits |
|---|---|---|---|---|
| community | 24 h | stable | public | appstore, mesh |
| standard | 6 h | stable | public + sites | + metapack |
| pro | 5 min | stable, beta | complet | + waf_pro, support |
| premium | temps réel (`0`) | stable, beta, alpha | complet + dev | tous |

- **C'est le certificat qui fait le tier**, jamais le fichier de config : un
  `tier: premium` écrit à la main n'ouvre rien (`tier_certifie: false`).
- **Le tier est un plancher de fréquence** : une box peut synchroniser *moins*
  souvent que son abonnement ne le permet, jamais plus.

```yaml
# /etc/secubox/federation.yaml — absent : box autonome, hors fédération
role: member            # member | authority
tier: pro               # tier DEMANDÉ à l'adhésion
owner: CyberMind
federation:
  url: https://admin.gk2.secubox.in
sync: {waf: 5m, appstore: 15m, metapack: 30m}
# autorité : ca: {duree_jours: 365, auto_join: false} ; tiers: {pro: {sync: {waf: 1m}}}
```

## 4. Adhésion, renouvellement, révocation

1. **Adhésion** — `sbxctl federation join --url …` : la box récupère la clé de
   la CA, **l'épingle** (confiance au premier usage, empreinte affichée à
   comparer), puis envoie une demande **signée par sa clé de nœud**
   (fenêtre de rejeu ±15 min).
2. **Décision** — sur l'autorité : `sbxctl cert demandes` puis
   `sbxctl cert issue --did …`. Rien n'est émis automatiquement sauf
   `ca.auto_join: true`, posé explicitement.
3. **Récupération** — `sbxctl federation fetch` : liste de révocation d'abord,
   puis certificat vérifié contre la CA épinglée **avant** d'être installé.
4. **Renouvellement** — `sbxctl cert renew` : certificat courant + preuve de
   possession de la clé ; accepté jusqu'à 30 jours après échéance ; réémis aux
   conditions **actuelles** du tier.
5. **Révocation** — `sbxctl cert revoke SERIAL --motif …` : la liste est
   re-signée ; une liste retouchée est refusée par les boxes.

Une CA ne se crée jamais d'elle-même (`sbxctl ca init`, refusé si une clé
existe) : un fichier perdu ne doit pas faire naître en silence une seconde
autorité.

## 5. API (sbx-certd, `/run/secubox/federation.sock`)

| Méthode | Route | Qui | Rôle |
|---|---|---|---|
| GET | `/api/federation/status` | toute box | état **mesuré** (certificat vérifié, tier certifié, intervalles) |
| GET | `/api/federation/ca` | autorité | DID et clé publique de la CA |
| POST | `/api/federation/join` | autorité | demande signée → 202 en attente (201 si auto_join) |
| GET | `/api/federation/join/{did}` | autorité | 200 certificat · 202 en attente · 404 |
| POST | `/api/cert/renew` | autorité | renouvellement avec preuve |
| GET | `/api/cert/crl` | autorité | liste de révocation signée (YAML) |

Les écritures n'exigent pas de jeton : elles exigent une **preuve**, la
signature de la clé dont le demandeur réclame l'identité. Servies par la route
`secubox-routes.d/federation.conf` (serveur d'administration) ; l'exposition
WAN passera par mTLS (P2).

## 6. CLI

```
sbxctl ca init
sbxctl federation status [--json] | join --url URL [--tier T] [--owner O] | fetch
sbxctl cert demandes | issue --did DID [--tier T] | revoke SERIAL [--motif M]
sbxctl cert renew | export [--out F] | verify FICHIER
```

## 7. Phases

| Phase | Contenu | État |
|---|---|---|
| **P1** | CA, certificat v2, adhésion/renouvellement/révocation, tiers, API, `sbxctl` | ✅ #1389 — déployé sur gk2 (CA `did:plc:983c…`, gk2 certifié premium) |
| **P2** | mTLS dérivé du certificat SBX ; `sbx-fed` : synchronisation initiée par la box au rythme du tier ; inscription des émissions au journal de l'annuaire | à faire |
| **P3** | canaux apt stable/beta/alpha (anneaux de secubox-release) ouverts par le certificat ; alpha réservé à premium | à faire |
| **P4** | flux WAF `community` / `pro` / `premium` signés, incrémentaux (`/feeds/waf/<niveau>`) | à faire |
| **P5** | `SBXObject` (app, site, metablog, waf, dataset, archive, config, template), paquets `.sbx`, `sbxctl install/clone`, App Store fédéré et vues Fédération du Hall | à faire |
| **P6** | réplication MirrorNet des objets, métadonnées de rétribution (`author`, `wallet`, `license`, `support_url`) | à faire |

## 8. Sécurité

- Signatures Ed25519 partout, canonicalisation unique (Go = Python, testé).
- Sujet auto-certifiant ; demande et renouvellement avec preuve de clé ;
  fenêtre de rejeu ; file de demandes bornée ; corps limités à 16 Kio.
- Clé de la CA 0600 au compte du démon ; scellement par le Coffre prévu.
- Aucune émission sans décision humaine par défaut ; aucune connexion
  entrante ; mode hors ligne intégral (sans fichier de config, rien ne change).

L'exemple `ganimed.sbx` du cahier des charges visait un site décommissionné le
2026-09-14 ; l'exemple de paquet `.sbx` (P5) prendra un site encore en service.
