# Le Coffre — idée et conception

> Issue #1364 · statut : **conception, pas de code** · maquette : [`maquette.html`](maquette.html)

Le Coffre est l'endroit unique où une SecuBox garde ce qui ne doit jamais
traîner en clair sur un disque : la clé qui signe le dépôt apt, les secrets
des services, les graines TOTP, les clés GPG des utilisateurs, les jarres de
cookies, la clé de récupération de Nextcloud. Tant qu'un humain authentifié
ne l'a pas ouvert, ce qu'il protège est inutilisable, **même pour root**.
Il s'ouvre par une authentification, y compris à distance.

Le Coffre n'est pas un nouveau module : c'est **secubox-vault 2.0**. Le paquet
existe déjà, il est inactif et vide sur gk2, et sa conception actuelle
(clé Fernet posée à côté des données chiffrées) ne protège de rien.

---

## 1. Ce qu'on a mesuré (gk2, 2026-09-24)

| Élément | État mesuré | Gravité |
|---|---|---|
| Clé de signature apt `219BA872…BC7E` (apt@secubox.in, rsa4096, **sans expiration**) | `(private-key` **en clair**, sans phrase de passe, en **deux copies** : `/root/.gnupg` et `/data/secubox-repo/gpg` | critique |
| Publication apt.secubox.in | Le dépôt est hébergé **sur gk2** (`/srv/apt → /data/apt`) et signé sur place (dernier `Release.gpg` : 2026-09-21). La CI GitHub n'a aucun secret (`GPG_PRIVATE_KEY`, `DEPLOY_SSH_KEY` : 0) | décision |
| Ancienne clé `31848880…6DB9` citée dans la doc | N'est pas la clé publiée ; introuvable. **Aucune redistribution nécessaire** : les clients font déjà confiance à `219BA872` | info |
| secubox-vault 1.1.0 | Inactif, répertoire vide ; clé Fernet (AES-128-CBC) dans `.key` à côté de `secrets.enc` | élevée |
| Graines TOTP de `admin` et `gk2` | En clair dans `/etc/secubox/users.json` (0640 secubox) ; les codes de secours sont, eux, hachés | élevée |
| `/etc/secubox/secrets/` | ~35 secrets à plat, en clair, propriétaires variés (smb, jellyfin, mqtt×5, rustdesk, grafana, mastodon, privacy-jar.key…) | moyenne |
| `/var/lib/secubox/auth/audit.log` | **0666** (modifiable par n'importe qui) | élevée |
| Webmail (Roundcube, LXC `mail`) | Plugin `enigma` présent, **liste des plugins vide** | manque |
| Nextcloud (LXC `nextcloud`) | Conteneur **arrêté** ; chiffrement non mesurable ; rien dans le paquet | à mesurer |

## 2. Principes

1. **Scellé par défaut.** Au démarrage, le Coffre est scellé. Rien de ce
   qu'il garde en niveau 1 n'est accessible, ni par un service ni par root.
2. **Ouvrir, c'est s'authentifier.** Ouvrir le Coffre exige une session
   Hall valide (mot de passe + TOTP) **et** un secret d'ouverture. L'un sans
   l'autre ne suffit pas, que la demande vienne du LAN, du WAN ou de SSH.
3. **Une clé maîtresse, plusieurs serrures.** Comme LUKS : une clé maîtresse
   aléatoire, emballée séparément par chaque serrure. Ajouter ou retirer une
   serrure ne re-chiffre rien.
4. **Deux niveaux, pas un.** Certains secrets servent à démarrer sans humain
   (mot de passe MQTT, graines TOTP pour vérifier une connexion). Ils ne
   peuvent pas être scellés par un humain. On le dit, et on les protège
   autrement (niveau 0).
5. **Pas de deuxième API.** Le Coffre parle le protocole sbx existant ; ZIA
   et le Hall le pilotent comme le reste.
6. **Honnêteté sur le recouvrement.** Un TOTP est un secret partagé *que la
   box connaît déjà* : il ne peut pas, seul, reconstituer une clé qu'elle ne
   connaît pas. Le « recouvrement par OTP » passe donc par d'autres boxes
   (§6).

## 3. Modèle de clés

```
                    ┌──────────────── serrures (emballages de MK) ───────────────┐
 phrase d'admin ──► argon2id ──► KEK₁ ─┐
 clé d'appareil ──► WebAuthn PRF ─► KEK₂ ├──► AES-256-GCM(MK) ── coffre.db
 code de secours ─► argon2id ──► KEK₃ ─┤
 parts du maillage (2 sur 3) ─► Shamir ─┘
                                          │
                              MK (256 bits, en mémoire verrouillée, jamais écrite)
                                          │
                    HKDF(MK, "compartiment:<nom>") ──► clé de compartiment
                                          │
                     AES-256-GCM(secret, AAD = id ‖ version ‖ compartiment)
```

- **MK** : 256 bits aléatoires, tenue en mémoire `mlock`, effacée au
  rescellement (délai d'inactivité, commande, redémarrage).
- **Serrures** : chaque serrure est une ligne `(type, sel, paramètres
  argon2, MK emballée)`. Argon2id à 256 Mio / 3 passes — réglé pour ~1 s sur
  un Cortex-A72 ; à mesurer sur gk2 avant de figer.
- **Compartiments** : `box` (secrets du système), et un par humain
  (`gk2`, `admin`, …). Le compartiment d'un humain peut porter une serrure
  supplémentaire dérivée de **son** mot de passe : il reste lisible par lui
  seul, même quand l'admin a ouvert le Coffre.
- **Stockage** : SQLite `/var/lib/secubox/coffre/coffre.db` (0600 root).
  Sauvegarde **par `.backup`**, jamais par `cp` (fichier en WAL). Le fichier
  est sans valeur sans une serrure : il peut partir tel quel sur le SSD de
  sauvegarde.
- **Crypto** : `cryptography` (AESGCM, HKDF, X25519) + `python3-argon2`,
  deux paquets Debian. Fernet est abandonné.

### Niveaux

| Niveau | Qui ouvre | Exemples | Protection |
|---|---|---|---|
| **1 — scellé** | un humain, par serrure | clé de signature apt, clés GPG, clé de récupération Nextcloud, exports d'identité DID, jarres de cookies | MK, absente du disque |
| **0 — démarrage** | le système, sans humain | graines TOTP, secret de session JWT, mots de passe MQTT/SMB/service | `systemd-creds` (clé d'hôte, `LoadCredentialEncrypted=`) : illisible dans une copie du disque ou une sauvegarde, lisible par root vivant — on ne prétend pas mieux |

## 4. Ouvrir le Coffre

| Chemin | Authentification | Secret d'ouverture | Remarque |
|---|---|---|---|
| Hall, LAN | session + TOTP | phrase **ou** clé d'appareil | cas quotidien |
| Hall, WAN (via sbxwaf) | session + TOTP **frais** (< 60 s) | phrase **ou** clé d'appareil | limité à 5 essais / h / identité ; alerte courriel à chaque ouverture distante |
| SSH | clé SSH root | phrase (`coffrectl ouvrir`) | secours sans navigateur |
| MirrorNet | TOTP sur **un autre** nœud | 2 parts sur 3 (§6) | recouvrement, pas usage courant |

La **clé d'appareil** utilise l'extension WebAuthn **PRF** (`hmac-secret`) :
l'authentificateur (clé FIDO, Touch ID, téléphone) rend 32 octets
déterministes pour ce Coffre, sans jamais exposer de clé à long terme. Le
navigateur ne voit que le résultat, qui ne sert qu'à dériver KEK₂.
Conséquence (cf. *identité d'appareil par origine*) : la serrure est liée à
l'origine du Hall ; elle doit être enrôlée et utilisée depuis le Hall.

La phrase transite dans le canal TLS de la session, n'est jamais journalisée
ni stockée, et le serveur ne garde que la MK dérivée.

**Rescellement** : inactivité (15 min par défaut), bouton, `coffrectl
sceller`, redémarrage. Une *session de signature* (§5) garde la MK au plus
le temps de sa durée propre.

## 5. Ce que le Coffre garde

### 5.1 Clé de signature du dépôt apt

Pas de nouvelle clé : `219BA872` est déjà celle qu'approuvent les clients.

1. **Hygiène immédiate (P0)** : export hors ligne de la clé + certificat de
   révocation (imprimés / clé USB), puis **phrase de passe** sur la clé
   (`gpg --passwd`), puis retrait de la copie en double dans
   `/root/.gnupg`. `conf/options` a déjà `ask-passphrase`.
2. **Coffre (P2)** : la phrase de la clé GPG entre au Coffre (niveau 1).
   `secubox-releasectl` demande une **session de signature** : le Coffre
   ouvert pousse la phrase dans `gpg-agent` via `gpg-preset-passphrase` pour
   15 min, puis l'oublie (`--forget`). Le fichier de clé sur disque reste
   chiffré en permanence.
3. **CI** : aucune clé privée sur GitHub. La CI construit ; gk2 signe et
   publie. Le workflow `publish-packages.yml` devient « déposer dans
   `incoming/` », ou est retiré. **Décision à prendre.**
4. **Expiration** : la clé n'expire pas. Proposer une date (2 ans) prolongée
   par le Coffre ; livrer la clé publique dans un paquet
   `secubox-archive-keyring` pour que les rotations futures passent par apt.

### 5.2 Secrets des services

Migration de `/etc/secubox/secrets/*` et des secrets de `secubox.conf` vers
le niveau 0 (`systemd-creds`), service par service, avec la même règle que le
reste du dépôt : on livre par paquet, on garde l'ancien chemin en lecture le
temps de la bascule, on vérifie sur gk2.

### 5.3 Utilisateurs : root, gk2, admin, secubox

| Compte | Nature | Compartiment |
|---|---|---|
| `root` | système, SSH | aucun : root administre le Coffre, il n'y lit pas le niveau 1 sans serrure |
| `secubox` | compte de service | niveau 0 uniquement |
| `gk2`, `admin` | humains du Hall | un compartiment chacun, serrure personnelle possible |
| `operator` | humain, rôle restreint | compartiment sans accès au compartiment `box` |

- **Graines TOTP** : chiffrées (niveau 0) dans `users.json`, déchiffrées par
  `secubox-auth` au moment de vérifier.
- **Cookies** : le secret qui signe les sessions (JWT) passe au niveau 0 avec
  rotation. Les **jarres de cookies** du relais de navigation (BiB,
  `privacy-jar.key`) passent au compartiment de l'humain concerné : une
  jarre ne se lit qu'avec le Coffre ouvert *et* la session de son
  propriétaire.

### 5.4 Courriel chiffré — optionnel, par boîte

| Brique | Rôle | Où vit la clé privée |
|---|---|---|
| Roundcube **enigma** | signer / chiffrer / déchiffrer PGP dans le webmail | compartiment de l'utilisateur ; poussée à enigma le temps de la session webmail |
| **WKD** (`/.well-known/openpgpkey/`) | publier les clés publiques des adresses `@secubox.in` | — (public) |
| **Autocrypt** | annoncer la clé dans les en-têtes sortants | — (public) |
| Dovecot **mail_crypt** | chiffrer la boîte au repos, clé par utilisateur dérivée de son mot de passe | serveur, emballée par le mot de passe |

Chaque brique s'active séparément, boîte par boîte, depuis la carte Coffre
ou la carte Mail. Aucune n'est activée par défaut.

### 5.5 Nextcloud

| Brique | Rôle | Lien au Coffre |
|---|---|---|
| Chiffrement côté serveur (app `encryption`) | fichiers chiffrés sur le stockage | la **clé de récupération** administrateur vit au niveau 1 |
| `config.php` : `secret`, `passwordsalt`, mot de passe BDD | secrets d'instance | niveau 0 |
| App `end_to_end_encryption` | dossiers chiffrés par les clients | hors Coffre (clés chez les clients) ; option documentée |
| Connexion | deux facteurs | via secubox-auth (OIDC) ou app `twofactor_totp` : à trancher |

Le conteneur est arrêté sur gk2 : tout ce paragraphe est à **mesurer**
avant d'être conçu plus finement.

## 6. Recouvrement

| Moyen | Ce qu'il faut | Quand |
|---|---|---|
| Code de secours | un des 5 codes imprimés à la création (chacun est une serrure argon2id) | phrase oubliée |
| Maillage MirrorNet | TOTP validé sur **2 des 3** nœuds désignés, qui rendent chacun leur part Shamir de KEK₄, chiffrée pour la X25519 de la box (secubox-identity) | box isolée de son admin, clé d'appareil perdue |
| Rien | — | tout perdu : le niveau 1 est perdu. C'est le prix d'un coffre réel ; le dire à l'enrôlement |

Le recouvrement par le maillage est la réponse honnête au « recouvrement
par OTP » : l'OTP autorise un **pair** à rendre sa part ; il ne contient
jamais la clé.

## 7. Journal

Chaque ouverture, scellement, lecture de niveau 1, ajout ou retrait de
serrure est inscrit dans un journal **chaîné** (chaque ligne porte le hash de
la précédente), 0640 root:secubox, affiché dans la carte. Au passage,
`/var/lib/secubox/auth/audit.log` repasse en 0640.

## 8. Interface

La maquette ([`maquette.html`](maquette.html)) montre la carte **Coffre**
du Hall dans ses trois états :

1. **Scellé** — les trois façons d'ouvrir, l'origine de la demande
   (LAN / WAN) et ce qu'elle exige ;
2. **Ouvert** — serrures, compartiments, secrets par niveau et par
   consommateur, session de signature du dépôt, courriel chiffré, Nextcloud,
   journal ;
3. **Recouvrement** — parts du maillage.

## 9. Étapes

| Phase | Contenu | Dépend de |
|---|---|---|
| **P0** | Hygiène : export hors ligne + révocation de `219BA872`, phrase de passe, retrait de la copie double ; `audit.log` 0640 | — |
| **P1** | secubox-vault 2.0 : MK, serrures phrase + codes de secours, compartiments, `coffrectl`, API sbx, journal chaîné | — |
| **P2** | Session de signature du dépôt ; décision CI | P0, P1 |
| **P3** | Niveau 0 : `systemd-creds`, migration de `/etc/secubox/secrets`, graines TOTP, secret JWT | P1 |
| **P4** | Carte Coffre dans le Hall ; ouverture distante ; clé d'appareil WebAuthn PRF | P1 |
| **P5** | Compartiments humains : jarres de cookies, clés GPG personnelles | P1, P4 |
| **P6** | Courriel : enigma, WKD, Autocrypt, mail_crypt (optionnels) | P5 |
| **P7** | Nextcloud : mesure, puis clé de récupération et secrets d'instance | P3 |
| **P8** | Recouvrement par le maillage (Shamir 2/3 via secubox-p2p) | P1, MirrorNet |

## 10. Questions ouvertes

- **CI** : retirer `publish-packages.yml` ou le transformer en dépôt vers
  `incoming/` signé sur gk2 ?
- **Expiration** de la clé apt : 2 ans, prolongée par le Coffre ?
- **Deux facteurs Nextcloud** : OIDC via secubox-auth, ou `twofactor_totp`
  propre à Nextcloud ?
- **Délai de rescellement** par défaut : 15 min conviennent-elles à l'usage
  quotidien ?
- **Nœuds de recouvrement** : lesquels, sachant que c3box est éteint et la
  VM de test éphémère ?
