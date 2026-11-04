<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Distributed Hosting — publication automatique, nom court, manifeste de module, adaptateur (#3429, phase B)

CONCEPTION, non implémentée. Composant N1. Reprend `docs/hosting/site-characterization.md` (proposition #3420) en y
appliquant les arbitrages du 2026-11-03 et la **vision du propriétaire** (`architecture.md` § 0, « Vision du
propriétaire » et « Conflit de nom court », qui font foi). Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

## 1. Principe (vision du 2026-11-03, décision 1)

MirrorNet est **automatique** : un site ou service publié sur un nœud (`toto.<nœud>.secubox.in`, y compris depuis une
clé USB branchée sur ce nœud) devient disponible sous `toto.secubox.in`, est miroité d'office sur un autre nœud, et ses
visites sont réparties entre les copies. **Aucun geste du propriétaire, aucune signature** n'est requis pour diffuser.

| Qui | Rôle | Exemple |
|---|---|---|
| **Nœud publieur** (nœud source) | publie localement (webui du module, clé USB) ; son identité dans le maillage (`did` + clé WireGuard du `NodeRecord`) fait l'authenticité du contenu en A21 | gk2, gk9 |
| **Module** | maître de ses services : empaquette, vérifie, installe, sert, redémarre ; déclare son comportement P2P | metablogizer (vhosts statiques), streamlit (applis), modules sur mesure |
| **`secubox-mirrornet`** | plan de contrôle : détecte les publications, annonce les noms, tranche l'antériorité, place les miroirs, pilote sbxwaf, transporte des objets opaques | panneau de master control |

Mirrornet ne touche jamais au contenu et passe toujours par l'adaptateur du module.

## 2. Authenticité en Alpha 21 (décision 3 REPORTÉE)

La signature OpenPGP des sites par une personne (ancienne décision 3) est **reportée** : metablogizer ne signe rien
aujourd'hui (seul HMAC du webhook Gitea, `secubox-metablogizer/api/webhook.py:41`, EXISTANT) et la crypto actuelle est
propre au maître (Hall, mail, APT).

| Élément | Alpha 21 |
|---|---|
| Qui atteste une version | le **nœud source** : l'annonce est une entrée du journal de l'annuaire signée Ed25519 par sa box (EXISTANT, `secubox-annuaire/annuaire/log.py:112-140`) |
| Qui atteste le transport | WireGuard wg-mesh (EXISTANT, `secubox-p2p/api/mesh.py:164`) : un objet ne vient que d'un pair enrôlé |
| Intégrité | BLAKE2b-256 de l'archive, annoncé par le nœud source, vérifié par chaque miroir |
| Qui peut publier | tout nœud de niveau ≥ LIMITED (`federated-trust.md` § 3) ; niveaux **affichés** en A21, le filtrage effectif suit en A22 |
| Révocation | celle du nœud (`RevocationNotice`, EXISTANT `model.py:361-391`) retire ses publications (§ 7) |

Chantier ultérieur (hors A21) : signature locale des sites (clé de propriétaire, record `Proprietaire`, `gpgv` par
service, support USB signé, délégués). Rien de l'A21 n'en dépend ; le format d'annonce garde un champ `sig_contenu`
vide réservé.

## 3. Manifeste P2P de module `/usr/share/secubox/mirrornet.d/<module>.toml` (NOUVEAU)

Modèle EXISTANT : `capabilities.d` (`/usr/share/secubox/capabilities.d/*.json`), installé par le `debian/rules` du
module (`secubox-radio/debian/rules:56-57`), lu par ZIA (`secubox-zia/api/capabilities.py:35` `CAP_DIR`, `:162-174`) :
un fichier par module, livré par son paquet, un manifeste invalide est ignoré sans abattre le registre. Différences
voulues : TOML, schéma strict (clé inconnue = manifeste ignoré + audit), lu par `secubox-mirrornet`. Il vient du paquet
(signé par apt) et décrit une capacité, pas une instance. **Inchangé** par la vision.

```toml
[module]
nom          = "metablogizer"
version_api  = 1                            # version de l'API adaptateur (§ 4)
types        = ["statique"]                 # types de service que ce module sait servir
classe       = ""                           # classe de service équivalent (§ 8), vide = aucune

[replication]
quoi         = "fichiers"                   # fichiers | base | rien
mode         = "lecture"                    # lecture | ecriture (A22, quorum)
basculement  = "auto"                       # auto | manuel

[publication]
detection    = "evenement"                  # evenement (l'adaptateur notifie) | scrutation (etat lu toutes les 60 s)

[sante]
chemin       = "/.secubox/version"          # GET sur le point de service ; rend l'empreinte installée
delai_s      = 2

[service]                                   # point de service d'une copie, cible des routes sbxwaf
port         = 8472                         # sur 127.0.0.1 et sur l'IP wg-mesh (nft : wg-mesh seulement)

[adaptateur]
socket       = "/run/secubox/metablogizer.sock"
prefixe      = "/api/v1/metablogizer/mirrornet"
```

Un module sans manifeste n'est pas distribuable (affiché « non déclaré » dans le panneau) ; ses sites restent servis
localement comme aujourd'hui.

## 4. API adaptateur (NOUVEAU, côté module, inchangée sauf `publications`)

Routes exposées par **le module** sur sa propre socket, appelées par `secubox-mirrornet` seul (garde de service à
définir, voir points ouverts) :

| Route | Effet | Notes |
|---|---|---|
| `GET <prefixe>/publications` | liste des services publiés localement `{nom, type, empreinte_courante, publie_le}` | base de la détection automatique (§ 5) |
| `POST <prefixe>/exporter {service}` | archive de la version courante → `{chemin, empreinte, taille}` | mirrornet la range en objet opaque |
| `POST <prefixe>/installer {service, empreinte, chemin}` | vérifie et installe la version X **à côté** de la courante | extraction confinée du module (metablogizer : `_extract_archive`, `composants/publish/api/main.py:812`, EXISTANT) |
| `POST <prefixe>/activer {service, empreinte}` | bascule atomique sur X | idempotent |
| `POST <prefixe>/desinstaller {service, empreinte}` | purge une version | jamais la courante |
| `GET <prefixe>/etat {service}` | versions installées, courante, santé | lu par le panneau |

Chaque route est idempotente, bornée en durée, rend un refus motivé que mirrornet audite ; aucun réessai aveugle.

## 5. Publication automatique (NOUVEAU)

```
publication locale (webui du module, ou clé USB lue sur ce nœud, usb-master-source.md)
  │ adaptateur : notification, ou scrutation GET publications (manifeste [publication])
  ▼
secubox-mirrornet du nœud source
  1 exporter → objet opaque /data/mirrornet/objets/<empreinte>
  2 annonce de version (ConfigBlob service.<nom>.v.<empreinte16>, replication.md § 2)
  3 annonce de nom (ConfigBlob nom.<nom>.<nœud>, § 6) : revendique <nom>.secubox.in
  4 manifeste de service généré /etc/secubox/services/<nom>@<nœud>.toml (§ 9), 4R
  5 nom de nœud <nom>.<nœud>.secubox.in exposé tout de suite (load-balancing.md § 6)
  ▼
tous les nœuds (mesh_sync, pull) : registre des noms → titulaire de <nom>.secubox.in (§ 6)
  ▼
placement automatique d'au moins un miroir (§ 7) ; routes multi-cibles quand le titulaire est établi
```

Aucune étape n'attend un geste. L'administrateur n'intervient que pour **arbitrer** un conflit bloqué (§ 6.4) ou
retirer un service.

## 6. Nom court : conflit et antériorité (validé 2026-11-03, NOUVEAU)

### 6.1 Annonce de nom

Chaque nœud qui publie `toto` écrit une entrée signée par sa box :

```
ConfigBlob scope "nom.toto.<nœud>"   (publisher = did du nœud ; un écrivain par scope, pas de dispute)
payload = { nom: "toto", noeud: "<did>", empreinte_tete: "b2:…", chaine_racine: "b2:…",
            annonce_le: "2026-11-03T10:00:00Z", sig_contenu: "" }
```

`chaine_racine` = empreinte de la première version de la chaîne (identifie le **contenu** dans la durée, même quand la
tête avance). Le motif de scope existant `^[a-z0-9][a-z0-9._:-]*$` (`model.py:538-575`) admet `nom.toto.gk9`.

### 6.2 Établissement de l'antériorité

L'antériorité est **calculée** par chaque nœud depuis le journal, comme les niveaux (fonction pure, jamais stockée) :

1. **Horodatage d'annonce** : `annonce_le` de l'entrée signée, corrigé de rien (l'horloge du nœud fait foi) mais
   **borné** : une annonce dont `annonce_le` précède sa réception par le premier pair qui la voit de plus de
   `marge_horloge` (proposé 120 s) est réputée **datée à sa réception** (empêche l'antidatage).
2. **Écart significatif** : A est antérieur à B si `annonce_le(A) + marge_horloge < annonce_le(B)`. Sous cette marge,
   les deux annonces sont **simultanées**.
3. **Convergence** : une revendication devient **titulaire** quand elle est restée sans revendication concurrente
   antérieure ou simultanée pendant `fenetre_convergence` (proposé 10 min, ≥ 3 cycles `mesh_sync` de 60 s), **et** que
   les nœuds vivants qui ont synchronisé depuis l'ont vue (accusé implicite : leur tête de journal postérieure à
   l'annonce). Avant cela : état `en-attente`, seul le nom de nœud est servi.
4. **Annuaire non convergé** : un nœud dont le dernier `mesh_sync` réussi date de plus de `fenetre_convergence` ne
   conclut rien ; il garde l'état précédent connu, ou `en-attente`.

| Situation | Résultat |
|---|---|
| A antérieure, contenu différent de B | A titulaire de `toto.secubox.in` ; B reste sur `toto.<nœudB>.secubox.in` (état `refuse`, visible) |
| A et B simultanées, contenus différents | **bloqué** : aucun nom court, chaque copie sur son nom de nœud, jusqu'à arbitrage administrateur |
| A antérieure mais concurrente découverte après convergence avec `annonce_le` plus ancienne (partition) | **bloqué** (antériorité contestée) ; le titulaire en place n'est pas retiré d'office : il continue d'être servi, marqué « contesté », jusqu'à arbitrage |
| même `chaine_racine` ou même `empreinte_tete` | **pas un conflit** : miroir (§ 6.3) |

Les paramètres sont dans `/etc/secubox/mirrornet.toml` et doivent être identiques sur le maillage (valeur publiée par
gk2 en `ConfigBlob` scope `mirrornet.parametres`, EXISTANT comme mécanisme).

### 6.3 Même contenu, même propriétaire = miroir

En A21, sans signature de personne, « même propriétaire » se ramène au **même contenu** : une publication dont
l'empreinte de tête ou la racine de chaîne est déjà connue pour `toto` rejoint le titulaire comme copie supplémentaire
(répartition), quel que soit le nœud. Une version **nouvelle** de la chaîne ne peut être produite que par le nœud
titulaire (seul écrivain de sa chaîne). Le rattachement d'un même propriétaire publiant un contenu nouveau depuis un
autre nœud demande la signature reportée, ou un arbitrage administrateur (point ouvert).

### 6.4 Arbitrage administrateur

`POST /api/v1/mirrornet/nom/arbitrer {nom, titulaire: <did> | null}` (`require_jwt`, gk2 ; audit) publie un
`ConfigBlob` scope `nom.<nom>.arbitrage` écrit par le maître ancré (`secubox-p2p/api/ancre.py:62`). Un arbitrage
prime sur le calcul d'antériorité ; `null` = nom gelé. A22 : geste relayé depuis `admin.secubox.in`.

### 6.5 Nœud source disparu

| Cas | Effet |
|---|---|
| source **indisponible** (éteint, hors maillage) | les miroirs continuent de servir la dernière version ; le nom court reste au titulaire ; aucune nouvelle version possible ; panneau : « source absente depuis … » |
| source absente au-delà de `delai_abandon` (proposé 30 j) | alerte ; le nom reste attribué ; seul un arbitrage administrateur peut le réattribuer ou le geler (jamais automatique) |
| source **révoquée** (`RevocationNotice`) | ses annonces cessent de compter : nom court suspendu, routes retirées, objets gardés `garder` jours puis purgés ; audit ; arbitrage pour réattribuer |
| source revenue | reprend sa chaîne ; ses nouvelles versions avancent les miroirs (fast-forward, `replication.md` § 4) |
| source réinstallée (nouveau `did`, ré-adhésion A21) | nouveau nœud : son annonce est une revendication nouvelle (même contenu → miroir ; sinon conflit) ; arbitrage pour reprendre la titularité |

## 7. Placement automatique des miroirs (NOUVEAU)

- Dès qu'un service est publié, mirrornet du nœud source choisit au moins `minimum_copies - 1` autres nœuds (défaut
  `mirrornet.toml` : 2 copies au total) parmi les pairs vivants qui ont le module déclaré dans `mirrornet.d`, `/data`
  monté et la place (quota par service), niveau ≥ LIMITED affiché ; préférence : gk2 (entrée Internet, sert sans
  wg-mesh), puis disponibilité.
- Le choix est **publié** (`ConfigBlob` scope `copies.<nom>`, écrit par le nœud titulaire) ; chaque nœud élu tire
  l'objet et l'installe par son adaptateur (`replication.md` § 3). Un nœud peut **refuser** (quota, module absent) :
  refus annoncé, un autre est choisi.
- Un administrateur de nœud peut exclure son nœud de l'hébergement (`mirrornet.toml` `[hebergement] accepter = false`).
- Les équivalences `<nom>.<nœud>.secubox.in` sont **dérivées** des copies, jamais saisies.

## 8. Services locaux distribués et services équivalents (conception ; adaptateur Alpha 22)

- Un service **local** (ex. Voice Studio sur gk3) est un service de type `dynamique` : son module déclare `classe`
  (ex. `voicestudio`) dans `mirrornet.d`. Publication et nom court suivent §§ 5-6 ; la réplication suit le type
  (actif-passif, état non répliqué).
- **Services équivalents** : deux nœuds qui offrent la même `classe` (même module, même `version_api`) se partagent les
  ressources : le nom court de classe (ex. `voicestudio.secubox.in`) route vers toutes les instances saines, pondérées
  par la charge (A22, `load-balancing.md` § 4). Un service équivalent n'est pas un conflit de nom : la classe est un
  nom réservé à la fonction, distinct des noms de contenu.
- **gk3 est intouchable au banc** : rien n'y est installé ni testé ; la conception est validée sur gk6/gk4 avec un
  service factice de la même classe. Adaptateur Voice Studio : **Alpha 22**.

## 9. Manifeste de service `/etc/secubox/services/<nom>@<nœud>.toml` (NOUVEAU, généré)

**Généré** par mirrornet à la publication, jamais saisi ni signé par une personne. Schéma strict.

```toml
[service]
nom          = "toto"                       # [a-z0-9-]{1,63}
type         = "statique"                   # statique | blog | microblog | cms | dynamique | api | media
module       = "metablogizer"
classe       = ""                           # § 8

[source]
noeud        = "gk9"                        # nœud publieur (résolu en did via NodeRecord)
origine      = "usb"                        # local | usb ; usb : id de support, usb-master-source.md

[copies]                                    # DÉRIVÉ du placement (§ 7)
noeuds       = ["gk9", "gk2"]
quota_mo     = 512
garder       = 5

[equivalences]                              # DÉRIVÉ
"gk9" = "toto.gk9.secubox.in"
"gk2" = "toto.gk2.secubox.in"

[nom_court]                                 # DÉRIVÉ du registre (§ 6)
etat         = "titulaire"                  # en-attente | titulaire | refuse | bloque | conteste | suspendu
nom          = "toto.secubox.in"

[disponibilite]
politique    = "priorite"                   # priorite | tourniquet
waf_bypass   = false                        # seule valeur admise
```

Exclus : clés privées, mots de passe, jetons. Application locale 4R (shadow `/etc/secubox/services/.shadow/`, schéma,
renommage atomique, retour arrière) comme `secubox-annuaire/annuaire/config_apply.py` (EXISTANT). `site.json` de
metablogizer (EXISTANT, `secubox-metablogizer/schema/site.json.schema.json`) reste le manifeste du module, tenu par
l'adaptateur.

Noms réservés (refus de revendication) : noms de nœuds, `admin`, `apt`, `live`, et les classes déclarées (§ 8).

## 10. Écriture par type (arbitrage, inchangé)

| Type | Écriture | Disponibilité | Calendrier |
|---|---|---|---|
| statique (metablogizer) | lecture seule partout ; nouvelle version produite par le nœud source | actif-actif en lecture | **A21** |
| blog | généré par le nœud source, copies en lecture | actif-actif en lecture | A22 |
| microblog | multi-écriture avec quorum (`failover.md` § 5) | lecture partout ; écriture si quorum | A22 |
| cms | écrivain unique, promotion **manuelle** | lecture seule sans l'écrivain | A22 |
| dynamique (streamlit, Voice Studio, sur mesure) | actif-passif ; équivalents en partage de charge (§ 8) | redémarrage ailleurs sur promotion | A22 |
| api | actif-actif si `sans_etat = true` prouvé, sinon actif-passif | | A22 |
| media | objets immuables par empreinte | actif-actif en lecture | A22 |

Un type non pris en charge par la version installée est refusé (pas de comportement silencieux). Le manifeste du module
peut être plus strict que le type, jamais plus laxiste.

## 11. Cycle de vie

```
 publié (local) ──annonce──▶ en-attente ──convergence──▶ titulaire (nom court) ──retrait──▶ retiré
                                  │ concurrente antérieure ──▶ refuse (nom de nœud seul)
                                  └ simultanée / contestée ──▶ bloque ──arbitrage──▶ titulaire | refuse
```

Retrait : dépublication dans le module (détectée) ou geste administrateur ; mirrornet retire les routes, libère le nom
court (nouvelle annonce `retire = true`), demande `desinstaller` aux copies, garde les objets `garder` jours.

## 12. Intégration à l'existant

| Existant | Rôle | Statut |
|---|---|---|
| metablogizer `site_publish` (`secubox-metablogizer/sbin/metablogizerctl:134`), `/srv/metablogizer/sites` (`:8`) | reste le chemin de service et le point de publication détecté | À ÉTENDRE (adaptateur, L5b) |
| `metablog-sync` (`git reset --hard`, `sbin/metablog-sync:7-23`) | non réutilisé (écrasement aveugle, R1) | EXISTANT, écarté |
| `haproxyctl vhost add` (`secubox-haproxy/sbin/haproxyctl:619`) | pose `<nom>.secubox.in` et les noms de nœud sur gk2 | EXISTANT |
| `secubox-waf-route` (`secubox-core/usr/sbin/secubox-waf-route`) | route multi-cibles | À ÉTENDRE |
| streamlit (#982), Voice Studio | adaptateurs, services équivalents | A22 |
| Publication d'un geste (#3423) | une publication locale suffit à diffuser | lié |

## 13. Tests (résumé ; détail `testing.md`)

Manifeste de module strict (cassé ignoré, registre servi). Publication détectée sans geste ; nom de nœud immédiat ; nom
court après convergence. Antériorité : A puis B différent → B refusé ; simultanées → bloqué ; antidatage borné par
`marge_horloge` ; partition → contesté. Même empreinte sur un autre nœud → miroir. Nom réservé → refus. Source
révoquée → suspendu. Placement : au moins une copie hors du nœud source ; refus de quota → autre nœud. 4R. Mirrornet
n'écrit jamais sous l'arbre du module (AppArmor).
