# Audit — SBX Identity Mesh (nœuds, clés, données par personne)

> #1417 · 2026-09-25 · complète [AUDIT_AUTHENTICATION.md](AUDIT_AUTHENTICATION.md)
> (cookies, JWT, sessions, magasins, BBS, Billets, services) sans le répéter.
> Suite : [AUTH_V3.md](AUTH_V3.md).

## 1. Identité du nœud

**LA clé du nœud** : `/etc/secubox/secrets/annuaire/node.key` — graine Ed25519 (hex,
0600), `did:plc:<sha256(pub)[:32]>`. Créée par `annuairectl init`
(`secubox-annuaire/sbin/annuairectl:97-123`), lue par l'annuaire, la fédération
(sujet du certificat SBX), p2p (DHT, battements masterlink), assist, release.

| # | Clé / identifiant | Où | Usage | Constat |
|---|---|---|---|---|
| A | clé annuaire (canonique) | `secrets/annuaire/node.key` | tout ce qui précède | **à garder comme unique** |
| B | clé « primary » de secubox-identity | `/var/lib/secubox/identity/keys/primary.key` | pairs et confiance de secubox-identity | **seconde paire, autre `did:plc`**, jamais réconciliée ; `rotate_key` change le DID sans lien ; **`POST /identity/sign` signe tout message pour tout JWT** (oracle) |
| B' | X25519 de secubox-identity | `keys/primary_x25519.key` | scellement (`seal_for`/`open_from`), courtier de jetons | réutilisable pour sceller un paquet de migration |
| C | clé de la CA fédérale | `secrets/federation/ca.key` | émission des certificats SBX (nœud autorité) | — |
| D | clé WireGuard du maillage | `/var/lib/secubox/p2p/wg_mesh.json` | transport | la jonction master-link s'authentifie par **jeton partagé**, pas par signature |
| E | `node.id` | `/var/lib/secubox/p2p/node.id` (`sb-<mac>`) | invitation / jonction | chaîne, pas une identité cryptographique |

**Clones** : `export-preseed.sh`, `export-c3box-clone.sh` et la restauration de
`secubox-cloner` copient `node.key`, `identity/keys/*` et la clé WireGuard : deux box
portent alors **le même `did:plc`**.

## 2. Transport des enregistrements signés

- Forme canonique **octet pour octet identique** en Python (`annuaire/crypto.py:149`,
  `canonical_bytes`) et en Go (`federation/internal/canon`) ; **pas de flottant**.
- Journal en ajout seul (SQLite, chaînage BLAKE2b) ; `append` **vérifie la signature
  Ed25519 avant de chaîner** ; l'auteur d'une entrée est **forcément un `did:plc`**
  (`model.py:890`) — un appareil (P-256) ne peut pas signer une entrée : sa signature
  voyage **dans** la charge utile.
- Réplication en tirage (`mesh_sync`, 300 s) de `/log/export` via le maillage WireGuard ;
  `import_entries` vérifie DID et signature, **rejette un `op` inconnu** : une nouvelle
  sorte d'enregistrement exige d'abord la mise à jour de la flotte.
- Ordre entre nœuds = ordre d'import local, pas l'horloge de l'auteur : un état
  utilisateur a besoin d'une **époque** explicite (modèle : `ConfigBlob.version`).
- **Le journal est public et indélébile** : tout pair le lit (`/log/export`), rien ne s'y
  efface. Aucune donnée personnelle ne doit y entrer (RGPD).
- Modèles à deux signataires déjà présents : `Grant`, `Invitation` — gabarits d'un
  certificat de migration. Motif d'ajout d'un verbe : modèle `extra="forbid"` → `Op` →
  verbe `sign(priv, canonical_bytes(payload))` → `journal.append` → lecteur d'état → route.
  Ne **pas** copier les routes existantes qui reçoivent des **clés privées dans le corps**
  (`*_priv_hex`) : signer dans le processus avec `node.key`.

## 3. Données par personne à faire voyager

| Application | Où | Clé | Portabilité aujourd'hui |
|---|---|---|---|
| Hall (préférences) | `localStorage` de l'origine Hall (`sbx.hall.<profil>.*`, favoris, dock…) | **nom affiché**, ou rien | aucune : ni serveur, ni `user_uuid` |
| Hall (délégations) | `/etc/secubox/secrets/webos-acces/<qui>/<svc>.json` | `sub` | à ré-émettre, pas à copier |
| Jetons d'applications | `/var/lib/secubox/identity/jetons-app.jsonl` | did + service | révoquer, ré-émettre |
| BBS | `/var/lib/secubox/bbs/` (contenu, fichiers, `index.db`) | `users.id` + `handle` | sauvegarde **de tout le forum** ; messages en fichiers avec `author:` ; pas d'export par personne |
| Billets | `billets.db`, `media/` | `author.username` ; **billet sans auteur** | par box seulement |
| Nextcloud | `/data/volumes/nextcloud/data/<user>` + base | nom | sauvegarde d'instance ; `occ user:export` non branché **(à vérifier)** |
| Courrier | `/data/volumes/mail/vmail/<dom>/<user>` (Maildir) | adresse | Maildir portable par nature ; préférences Roundcube à part |
| PeerTube | LXC, Postgres | nom (`-`→`_`) | pas d'export par personne ici |
| PhotoPrism | `/data/shared/photos` | **un seul compte `admin`** | pas par personne |
| Métablogs | `/srv/metablogizer/sites/<nom>` | **aucun propriétaire** | `.sbxsite` / `.sbx` par site |
| Radio | `radio.db` | entier choisi par le client | non rattachable |
| Avatar | `identities.json` | uuid4 isolé | JSON + fichiers |

**Rien ne déplace une personne** : tous les outils (migration, preseed, clone, cloner,
sauvegardes d'applications) opèrent sur une box entière.

## 4. Briques réutilisables pour la double signature

- **Appareil** : `appareil.js` — `identite()` (P-256 non exportable), `signe(paire, hex)`
  signe n'importe quels octets ; serveur : `identite.py:verifie_signature(point, message,
  sig)`, `charge_cle` (contrôle de courbe).
- **Nœud** : `annuaire.crypto` — `sign`, `verify`, `did_from_pubkey`, `canonical_bytes` ;
  Go : `sbxcert.Signe/Verifie`, `canon.Encode`, `ca.VerifiePreuve` (requête signée
  horodatée ± 15 min, anti-rejeu).
- **Scellement** : `secubox_core.crypto.Session` / `seal_for` (X25519 → HKDF →
  AES-256-GCM) pour un paquet destiné au seul nœud d'accueil.

## 5. Nouvelles failles (ajoutées au P0 de #1405)

| # | Faille | Priorité |
|---|---|---|
| S8 | `POST /identity/sign` : tout porteur de JWT fait signer n'importe quoi par une clé du nœud | P0 |
| S9 | Clone / preseed / restauration : `node.key`, clés d'identité et WireGuard dupliqués → deux box au même `did:plc` | P1 (bloquant pour le Mesh) |
| S10 | Deux `did:plc` de nœud non réconciliés (annuaire / secubox-identity) | P1 |
