<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WAF : signatures équivalentes à PHP2Shell (#3273) — spec

Suite de #3257 (`2026-10-29-waf-php2shell-design.md`, secubox-waf-ng 1.31.0, fusionnée le 29/10/2026).

## Décisions du propriétaire (29/10/2026)

- **Toutes** les vulnérabilités équivalentes retenues par la recherche ci-dessous, et les compléments C1 à C5.
- But premier : **repérer les attaquants**, même quand l'attaque ne passe plus (box à jour ou composant absent). Une sonde vers une faille corrigée reste un signal d'attaquant, transmis à actord avec sa gravité réelle.
- Toutes les règles naissent en **mode detect**, comme #3257. Mêmes règles qu'en #3257 : R12 (tous les clients analysés ; adresses privées journalisées « local », jamais envoyées à actord), analyse en flux, aucun tampon ajouté au-delà de la fenêtre de #3257 (min(max-body-inspect, 1 Mio)).
- Les seuils marqués « proposition, non sourcée » dans la recherche restent provisoires et étiquetés comme tels dans le code (même convention que les seuils 12/50 de #3257).

## Constats sur gk2 (lus le 29/10/2026)

- Conteneurs `roundcube` et `mail` : `roundcube-core 1.6.5+dfsg-1+deb12u12` (vulnérable aux CVE corrigées par 1.6.20 : 113386, 114720, 114724, 114725, 114727) ; `php8.2 8.2.35-1~deb12u1` ; `session.serialize_handler = php` (C5 / CVE-2026-115560 non exploitable) ; `php-imagick` absent (114727 non exploitable : R-IMG1 reste une détection de sonde).
- Conteneur `nextcloud` : arrêté (réveil à la demande par le waker) ; version de la source `32.0.10` ; fédération et fournisseurs d'aperçu non vérifiables (conteneur arrêté). R-NC1 suit donc la variante « fédération inutilisée » par défaut, réglable.

## Arbitrages du contrôleur (révisables par le propriétaire)

- R-NC1 : chaque POST anonyme sur les chemins exacts = signal moyen ; un réglage par vhost « fédération utilisée » bascule sur le seuil du correctif (> 5 appels / 1 200 s / IP = signal haut).
- R-RC3 : `_to`, `_cc`, `_bcc` exclus (zones de texte multi-lignes), comme le propose la recherche.
- Étiquettes d'outil (boundary de la PoC 49113, sondes `-d allow_url_include`, ownCloud `graphapi`/`OC-Signature`, `%0a`/`%0d` dans le chemin pour CVE-2019-11043) : aggravantes seulement, jamais un signal seul… sauf pour un vhost PHP où la sonde `-d allow_url_include` vaut un signal moyen d'attaquant (le but est de repérer l'outil).

---

# Recherche sourcée (référence)

Date : 29 octobre 2026. Recherche en lecture seule : aucune modification du dépôt, aucune connexion à une box.
Sources consultées le jour même : catalogue KEV de la CISA (version `2026.10.28`), tracker de sécurité Debian, avis GHSA de PHP et de Nextcloud, versions et commits de Roundcube, enregistrements cve.org.

---

## 0. Synthèse

- **Le plus urgent, côté webmail.** Le Roundcube de SecuBox vient du paquet Debian bookworm (`1.6.5+dfsg-1+deb12u12`). Au 29/10/2026, le tracker Debian le marque **vulnérable** aux 20 CVE corrigées par Roundcube 1.6.20 (19/10/2026). Trois d'entre elles laissent une trace nette dans la requête : CVE-2026-113386, CVE-2026-114720 et CVE-2026-114724.
- **Seule faille de la pile à la fois exploitée (KEV) et visible dans la requête**, en dehors de PHP2Shell : **CVE-2025-49113** (Roundcube, désérialisation via `_from`). Debian l'a corrigée, mais son indicateur est gratuit et sert aussi à CVE-2026-114724, de la même famille. Le marqueur `|O:` déjà prévu dans `filename` **ne voit pas** le nom de fichier de la preuve de concept publique (§ 3.1).
- **Nextcloud.** La source du dépôt épingle `NC_VERSION="32.0.10"`. Cette version est touchée par **CVE-2026-77167** (déni de service anonyme par partage fédéré, corrigé en 32.0.13 le 27/10/2026). La trace est un simple couple chemin + méthode.
- **Côté PHP.** Les failles d'analyse de requête des années 2023 à 2025 (CVE-2023-0662, CVE-2023-3823, CVE-2024-2756, CVE-2024-8925) sont corrigées dans bookworm et absentes de trixie. Leurs contrôles coûtent presque rien et réduisent les écarts d'analyse entre sbxwaf et PHP. Je les retiens en second rang.
- **Les avis primaires de PHP2Shell** (GHSA, php.net, observations de TU Delft) décrivent trois vecteurs d'OOM que les signatures déjà décidées ne couvrent pas : requête **sans Content-Length utilisable**, **flot d'en-têtes dans une partie**, **champs fichier vides**. Ils relèvent de la même CVE que l'existant (§ 4).
- **Écartées.** Injections d'arguments PHP-CGI (Windows ou php-cgi seulement). XSS de Roundcube portées par le courriel, même celles du KEV : l'attaque arrive par SMTP, pas dans une requête HTTP distinctive. ownCloud n'est pas Nextcloud.

---

## 1. Pile réelle (lue dans le dépôt, à confirmer sur la box)

| Élément | Constat | Où |
|---|---|---|
| Roundcube | Conteneur LXC **bookworm**, paquets Debian `roundcube roundcube-core roundcube-plugins roundcube-sqlite3`, **Apache + `libapache2-mod-php8.2`**, sessions et données en **SQLite** | `packages/secubox-mail/lib/mail/install.sh:105-110`, `:504`, `:521` |
| Roundcube, PHP | `post_max_size = 160M`, `memory_limit = 256M` | `install.sh:497-498` |
| Nextcloud | Conteneur LXC **bookworm**, **nginx + php8.2-fpm**, `php-imagick` installé, Redis | `packages/secubox-nextcloud/sbin/nextcloudctl:130-143`, `:231-235` |
| Nextcloud, version | `NC_VERSION="32.0.10"` (version de la source, pas forcément celle de la box) | `nextcloudctl:54` |
| Nextcloud, PHP-FPM | `upload_max_filesize = 16G`, `post_max_size = 16G`, `memory_limit = 512M` | `nextcloudctl:314-316` |
| Nextcloud, nginx | `fastcgi_split_path_info ^(.+?\.php)(/.*)$`, `fastcgi_request_buffering off` | `nextcloudctl:378`, `:389` |
| sbxwaf aujourd'hui | Le multipart n'est jamais lu. Hors User-Agent, aucun en-tête n'est inspecté (Cookie, Content-Type, Content-Disposition compris). L'analyseur multipart borné est prévu par #3257. | spec `docs/superpowers/specs/2026-10-29-waf-php2shell-design.md` §1.2 et §6 (branche `feature/3257-…`) |

Paquets PHP dans Debian au 29/10/2026 : bookworm `php8.2` `8.2.32-1~deb12u1` (point) et `8.2.35-1~deb12u1` (sécurité) ; trixie `php8.4` `8.4.24-1~deb13u1` (point) et `8.4.27-1~deb13u1` (sécurité). Nextcloud serveur **n'est pas empaqueté** dans Debian : sources.debian.org ne connaît que `nextcloud-desktop`, `nextcloud-spreed-signaling` et `prometheus-nextcloud-exporter`.

---

## 2. Tableau récapitulatif

Gravités CVSS selon le CNA (cve.org). « Debian » se lit bookworm / trixie. « R-… » renvoie aux contrôles détaillés au § 3.

| # | CVE | Logiciel, versions touchées (CVSS) | Debian (bookworm / trixie) | KEV | Indicateur HTTP | Contrôle proposé | Faux positifs (usage légitime) |
|---|---|---|---|---|---|---|---|
| 1 | **CVE-2025-49113** | Roundcube < 1.5.10, 1.6.x < 1.6.11 (9.9) | corrigée (`1.6.5+dfsg-1+deb12u9`) / corrigée | **Oui** (20/02/2026) | `GET _from` sur `_task=settings&_action=upload` hors `[\w.-]` après retrait de `add-`/`edit-` ; `filename` contenant `\|` et des fragments `b:0;`, `s:N:` | **R-RC1** jeu de caractères de `_from` ; **R-RC2** marqueurs de sérialisation dans `filename` ; étiquette d'outil (boundary de la PoC) | ≈ 0 pour R-RC1 (c'est le contrôle du correctif) ; très faibles pour R-RC2 |
| 2 | **CVE-2026-114724** | Roundcube < 1.6.20, 1.7.x < 1.7.5 (7.4) | **vulnérable** (`deb12u12`) / point 1.6.18 vulnérable, sécurité 1.6.20 corrigée | Non | Clé de session préfixée par `!`. Aucun vecteur HTTP public autre que la classe `_from`. | Couverte par R-RC1 et R-RC2 | ≈ 0 |
| 3 | **CVE-2026-113386**, **CVE-2026-114720**, CVE-2026-75002, CVE-2026-35538, CVE-2026-114725 | Roundcube (7.1, 7.1, 7.1, 3.1, 5.0) | 113386, 114720, 114725 : **vulnérables** / sécurité corrigée. 75002 : corrigée en sécurité. 35538 : corrigée. | Non | CR ou LF dans `_uid` (headers, viewsource) ; dans `_flag` (mark), avec en plus `[\x00-\x20\x7f(){"*%]` ; dans `_q` et `_filter` (search) ; dans les champs d'en-tête de `send` | **R-RC3** caractères de contrôle dans des paramètres mono-ligne nommés | ≈ 0. Seule exception : `_to`, `_cc`, `_bcc`, à mesurer. |
| 4 | **CVE-2026-114727** | Roundcube < 1.6.20, 1.7.x < 1.7.5 (8.3) | **vulnérable** / sécurité corrigée | Non | SVG ou EPS envoyé comme photo de contact (`_action=upload-photo`) ou image de réglages (`settings/upload`), puis traité par ImageMagick | **R-IMG1** octets magiques non raster dans la partie fichier | faibles (avatar SVG rare). N'est exploitable que si Imagick ou `im_convert_path` est présent (§ 6). |
| 5 | CVE-2026-104190 | Nextcloud < 32.0.13, 33.0.7, 34.0.2 (7.4, GHSA) | non empaqueté | Non | Fichier corrompu d'un type passé à ImageMagick (HEIC, AI, PDF, PSD, PS, SGI, TGA, TIFF, polices), puis demande d'aperçu | **R-IMG2** type déclaré ≠ octets magiques sur `PUT` WebDAV | faibles à moyens. Ne concerne que des fournisseurs d'aperçu **non activés par défaut**. |
| 6 | **CVE-2026-77167** | Nextcloud 22 à 34, corrigée en 32.0.13, 33.0.7, 34.0.2 (7.5) | non empaqueté | Non | `POST` anonyme sur `/ocm/shares`, `/index.php/ocm/shares`, `/ocs/v1.php/cloud/shares`, `/ocs/v2.php/cloud/shares` | **R-NC1** tout appel si la fédération est inutilisée ; plus de 5 appels par 1 200 s et par IP (limite du correctif) | nuls si la fédération n'est pas utilisée |
| 7 | CVE-2026-45281 | Nextcloud < 32.0.9, 33.0.3 (8.1) | non empaqueté | Non | `PROPPATCH` (`group-member-set`) sur `/remote.php/dav/principals/users/<uid>/calendar-proxy-read` ou `-write` | **R-NC2** méthode + chemin ; `<uid>` différent de l'utilisateur Basic | faibles. La version de la source (32.0.10) est déjà corrigée. |
| 8 | CVE-2023-0662 | PHP 8.0 < 8.0.28, 8.1 < 8.1.16, 8.2 < 8.2.3 (7.5) | corrigée / non listée (8.4 publiée après le correctif) | Non | Plus de `max_input_vars + max_file_uploads` parties, soit 1 020 par défaut | **R-PHP1** compteur de parties (déjà prévu) avec seuil sourcé | ≈ 0 |
| 9 | CVE-2023-3823 | PHP 8.0 < 8.0.30, 8.1 < 8.1.22, 8.2 < 8.2.8 (8.6) | corrigée / non listée | Non | `<!DOCTYPE` ou `<!ENTITY` dans le prologue XML d'une requête DAV (PoC : `PROPFIND` Nextcloud) | **R-PHP2** balayage borné du prologue XML | ≈ 0, à mesurer |
| 10 | CVE-2024-2756 (suite de CVE-2022-31629) | PHP 8.1 < 8.1.28, 8.2 < 8.2.18, 8.3 < 8.3.5 (6.5) | corrigée / non listée | Non | Nom de cookie qui devient `__Host-` ou `__Secure-` après normalisation par PHP (ex. `_[Host-`). Nextcloud s'appuie sur `__Host-nc_sameSiteCookie*`. | **R-PHP3** analyse des noms de cookies | ≈ 0 |
| 11 | CVE-2024-8925 | PHP 8.1 < 8.1.30, 8.2 < 8.2.24, 8.3 < 8.3.12 (3.1) | corrigée / non listée | Non | Boundary multipart de plus de 5 Kio (préfixe partiel entre 5 et 8 Kio) | **R-PHP4** boundary de plus de 70 caractères (RFC 2046) ⇒ `malforme` | 0 |

Compléments à CVE-2026-109618 et CVE-2026-109619 (pas de nouvelle CVE) : voir § 4, contrôles C1 à C5.

---

## 3. Fiches

### Règle transversale : normaliser les noms de paramètres comme PHP

Toute règle portant sur un **nom** de paramètre (`_from`, `_uid`, `_flag`…) doit d'abord normaliser le nom comme PHP le fait. Sinon, `?.from=…` ou `?[from=…` contourne une règle écrite pour `_from`. D'après `main/php_variables.c` (branche PHP-8.2) :
- les espaces en tête sont ignorés ;
- ` ` et `.` deviennent `_` ;
- un `[` sans `]` correspondant devient `_` ;
- le nom est coupé au premier octet nul (« not binary safe »).

Le manuel PHP le documente en partie : « Dots and spaces in variable names are converted to underscores ».
Entrées : chaîne de requête et corps urlencoded. Coût : linéaire sur les noms seulement.

---

### 3.1 Roundcube : désérialisation par la session (CVE-2025-49113 et CVE-2026-114724)

**Logiciel et versions**
- CVE-2025-49113 : Roundcube avant 1.5.10 et 1.6.x avant 1.6.11. Corrigée le 01/06/2025.
- CVE-2026-114724 : avant 1.6.20 et 1.7.x avant 1.7.5. Corrigée le 19/10/2026.

**Debian**
- CVE-2025-49113 : corrigée dans bookworm (`1.6.5+dfsg-1+deb12u9` et suivantes) et dans trixie.
- CVE-2026-114724 : **vulnérable dans bookworm** (`deb12u12`, aucun correctif publié). Dans trixie, la version du point (1.6.18) est vulnérable ; `1.6.20+dfsg-0+deb13u1` (DSA-6579-1) la corrige.

**Exploitation**
- CVE-2025-49113 est au **KEV** depuis le 20/02/2026, échéance 13/03/2026. Le SSVC de la CISA indique « Exploitation : active ». Une preuve de concept publique existe : `fearsoff-org/CVE-2025-49113`, publiée le 06/06/2025. BleepingComputer a rapporté la vente d'un exploit.
- CVE-2026-114724 : SSVC « none ».

**Mécanisme.** `_from` (lu en GET seulement : `rcube_utils::get_input_string('_from', rcube_utils::INPUT_GET)`) sert à fabriquer une clé de session. Une clé préfixée par `!` désynchronise `rcube_session::unserialize()` : la suite des données de session est lue comme une valeur sérialisée, ce qui donne une injection d'objet. CVE-2026-114724 est la même primitive vue côté désérialiseur ; son correctif (commit `833770d`) rejette toute clé commençant par `!`.

**Indicateurs sourcés**
1. Le correctif 1.6.11 (`program/actions/settings/upload.php`) retire `add-` ou `edit-` de `_from`, puis exige `rcube_utils::is_simple_string`, c'est-à-dire `preg_match('/^[\w.-]+$/i')`.
2. Requête de la PoC : `POST /?_from=edit-!";i:0;O:16:"Crypt_GPG_Engine":…&_task=settings&_framed=1&_remote=1&_id=1&_uploadid=1&_unlock=1&_action=upload`. **La PoC brouille `_from`** : elle insère un octet de `0xC0` à `0xC9` après chaque caractère (`CVE-2025-49113.php:309`). Une regex de contenu sur `O:16:` ne le voit donc pas ; un contrôle de jeu de caractères, si.
3. Partie multipart `name="_file[]"` avec `filename="x|b:0;preferences_time|b:0;preferences|s:179:\"a:3:{i:0;s:57:\".png"` (article FearsOff et PoC `:307`). **Ce nom ne contient pas `|O:`** : l'objet est dans `_from`, le nom de fichier ne porte que des fragments de session.
4. Empreinte d'outil : `boundary=------a_rule_for_WAF_to_block_fool_exploitation` (PoC `:185`). À utiliser comme étiquette aggravante seulement.

**Contrôles proposés**
- **R-RC1** (gravité critique, mode detect). Sur le vhost Roundcube, si le paramètre de requête **normalisé** `_from` existe et que, après retrait de `^(add|edit)-`, il ne vérifie pas `^[A-Za-z0-9_.-]+$`, alors c'est un signal. Entrées : chemin, chaîne de requête. Bonus : `!` en tête de la valeur restante.
- **R-RC2** (gravité haute). Dans les parties multipart du même vhost, un `filename` qui contient `|` **et** un jeton de sérialisation PHP (`[abdisNO]:` suivi d'un chiffre ou de `;`). Il suffit d'étendre les booléens « marqueurs dans `filename` » de l'analyseur #3257 (aujourd'hui `<?php` et `|O:`) avec `|b:`, `|s:`, `|a:`, `|i:`. La regex ne porte que sur un nom de 255 octets au plus.
- Étiquette aggravante : la boundary de la PoC.

**Faux positifs.** R-RC1 : nuls par construction, puisque Roundcube corrigé rejette exactement ces valeurs. Les valeurs légitimes, comme `edit-identity`, passent. R-RC2 : très faibles. Windows interdit `|` dans les noms de fichiers, et la combinaison `|` + `b:0;` + `s:N:` n'apparaît pas dans un nom réel.

---

### 3.2 Roundcube : injection CR/LF vers IMAP et vers les en-têtes de courrier

**CVE couvertes**

| CVE | Paramètre | CVSS | Debian bookworm | Debian trixie |
|---|---|---|---|---|
| CVE-2026-113386 | `_uid` de `mail/headers` et `mail/viewsource` | 7.1 | **vulnérable** | corrigée en `1.6.20+dfsg-0+deb13u1` |
| CVE-2026-114720 | `_flag` de `mail/mark` | 7.1 | **vulnérable** | idem |
| CVE-2026-114725 | References, In-Reply-To, Message-ID, From à l'envoi | 5.0 | **vulnérable** | idem |
| CVE-2026-75002 | recherche, désynchronisation LITERAL+ | 7.1 | corrigée en `deb12u12` | corrigée |
| CVE-2026-35538 | recherche, injection IMAP SEARCH et contournement CSRF | 3.1 | corrigée | corrigée |

Versions corrigées : 1.6.20 et 1.7.5 pour les trois premières, 1.6.18 et 1.7.3 pour 75002, 1.6.14 et 1.5.14 pour 35538. Aucune n'est au KEV ; SSVC « none ». Toutes demandent une session authentifiée.

**Indicateurs sourcés (commits de correctif)**
- `f62879d` : `_uid` (GET ou POST pour `headers`, GET pour `viewsource`) est rejeté s'il contient `[\r\n]`.
- `242c6d6` : un drapeau est rejeté s'il contient `[\x00-\x20\x7f(){"*%]` (`rcube_imap_generic::modFlag`). Il vient de `_flag`, en POST.
- `b18a8fa` (1.6.14) puis `73233ab` (1.6.18) : CR et LF sont retirés de `_filter`, transmis tel quel à `SEARCH`, et de `_q`.
- `79adcfc` : normalisation de tous les en-têtes construits à l'envoi. Les paramètres lus par `rcmail_sendmail` sont `_to`, `_cc`, `_bcc`, `_subject`, `_from`, `_replyto`, `_followupto`, `_charset` et `_store_target`. La version 1.6.19 ajoute « bare CR in the subject field ».

**Contrôle proposé : R-RC3** (gravité haute pour `_uid`, `_flag`, `_filter` et `_q` ; moyenne pour l'envoi). Sur le vhost Roundcube, après décodage URL et normalisation des noms :
- présence de `\r`, `\n` ou `\0` dans `_uid`, `_flag`, `_q`, `_filter`, `_headers`, `_scope`, `_mbox`, `_search`, `_subject`, `_from`, `_replyto`, `_followupto` ou `_charset` ;
- et, pour `_flag`, présence de l'un des caractères du correctif.

Entrées : chaîne de requête et corps `application/x-www-form-urlencoded`. On ne lit que les valeurs nommées, jamais le corps entier. En option, à faible poids : `_uid` passé dans la **chaîne de requête** d'un `POST` vers l'action `markasjunk` (CVE-2026-114719, contournement CSRF).

**Faux positifs.** Quasi nuls. L'interface n'envoie jamais de saut de ligne dans ces champs : le HTML retire les sauts de ligne d'un `<input type="text">` (« value sanitization algorithm: strip newlines »), et `_uid`, `_flag`, `_filter` et `_mbox` sont produits par le JavaScript de Roundcube. `_to`, `_cc` et `_bcc` sont des zones de texte dans Elastic : à exclure, ou à mesurer sur du trafic réel avant de les inclure. Le corps `_message` est multi-ligne par nature et reste exclu.

---

### 3.3 Contenu non raster passé à ImageMagick (Roundcube CVE-2026-114727, Nextcloud CVE-2026-104190)

**Roundcube CVE-2026-114727** (8.3). Versions avant 1.6.20 et 1.7.x avant 1.7.5.
- Debian : **vulnérable dans bookworm** ; dans trixie, corrigée en sécurité (1.6.20).
- Mécanisme : SVG et EPS étaient acceptés à l'envoi d'une photo de contact (`_task=addressbook&_action=upload-photo`) et à la conversion. Ces formats peuvent référencer des ressources externes et appeler des délégués ImageMagick.
- Le correctif `895d88a` réduit les types redimensionnés à `bmp, gif, jp2, jpg, png, tif`. `settings/upload` acceptait aussi `eps` et `svg` (liste `IMAGE_TYPES` de 1.6.11).
- **Condition** : Roundcube n'appelle ImageMagick que si `im_convert_path` est réglé ou si l'extension `Imagick` est chargée (`rcube_image.php:112-124` ; défaut `im_convert_path = null`). `roundcube-core` (bookworm) ne dépend pas d'Imagick et ne le recommande pas, et `install.sh` ne l'installe pas. **Probablement non exploitable sur SecuBox** : à vérifier (§ 6).

**Nextcloud CVE-2026-104190** (7.4 selon le GHSA ; enregistrement cve.org **pas encore publié** au 29/10).
- Corrigée en 32.0.13, 33.0.7 et 34.0.2 (27/10/2026). La version de la source (32.0.10) est touchée.
- Mécanisme : demander l'aperçu d'un fichier corrompu peut déclencher une RCE dans ImageMagick (avant 6.9.13-48 ou 7.1.2-24). Seuls sont concernés les fournisseurs d'aperçu **non activés par défaut** : HEIC, Illustrator, PDF, Photoshop, Postscript, SGI, TGA, TIFF, et Font d'après les contournements. Il faut un compte ou un lien de partage en écriture.
- `php-imagick` est installé dans le conteneur. Le dépôt ne règle pas `enabledPreviewProviders`, donc les valeurs par défaut s'appliquent.

**Contrôles proposés**
- **R-IMG1** (Roundcube, gravité haute). Pour une partie fichier sur `upload-photo` ou `settings/upload`, on lit les 64 premiers octets. Signal si on y trouve `<svg`, ou `<?xml` suivi de `<svg` ou de `<image`, ou `%!PS`, `\xC5\xD0\xD3\xC6` (EPS DOS), `%PDF-` ou `push graphic-context`. Coût : 64 octets par partie, lus dans l'analyseur multipart.
- **R-IMG2** (Nextcloud, gravité moyenne, conditionnel). Pour un `PUT` WebDAV (`/remote.php/dav/files/…`, et premier segment de `/remote.php/dav/uploads/…`), signal si l'extension annoncée est raster (jpg, png, gif, webp) alors que les octets magiques désignent PS, EPS, PDF, SVG ou MVG. Ne pas signaler un PDF ou un SVG bien nommé : Nextcloud en stocke légitimement.

**Faux positifs.** R-IMG1 : faibles (avatar SVG). R-IMG2 : faibles, mais l'envoi en segments de Nextcloud complique la mise en œuvre, car seul le premier segment porte l'en-tête du fichier. **Meilleur levier : la configuration.** Garder les fournisseurs par défaut et mettre à jour Nextcloud.

---

### 3.4 Nextcloud : déni de service anonyme par partage fédéré (CVE-2026-77167)

- **Versions** : serveur 22 à 34 ; corrigée en 32.0.13, 33.0.7 et 34.0.2, publiée le 27/10/2026. CVSS 3.0 7.5 (CNA HackerOne), `AV:N/AC:L/PR:N/UI:N/A:H`. La source du dépôt (32.0.10) est **touchée**.
- **Debian** : non empaqueté. **KEV** : non.
- **Mécanisme** : le point d'entrée de partage fédéré permet d'écrire des lignes arbitraires dans `oc_share_external`. Elles ne sont jamais purgées et provoquent trois dénis de service qui se renouvellent toutes les 24 h. Contournement de l'éditeur : désactiver la réception des partages fédérés.
- **Indicateur sourcé** : le correctif (PR `nextcloud/server#62091`) ajoute `#[FederationRateLimit(limit: 5, period: 1200)]` sur deux actions publiques (`#[PublicPage]`, `#[NoCSRFRequired]`) :
  - `RequestHandler#addShare` : `POST` sur `/ocm/shares` (racine `/ocm`), soit `/ocm/shares` ou `/index.php/ocm/shares` ;
  - `RequestHandler#createShare` : route OCS `POST /cloud/shares`, soit `/ocs/v1.php/cloud/shares` et `/ocs/v2.php/cloud/shares`, **chemin exact**, sans les sous-chemins `/{id}/…`.

  La limite ne vaut pas pour une requête signée par un serveur de confiance.
- **Contrôle proposé : R-NC1.** `POST` sur l'un de ces chemins exacts, sans session Nextcloud ni `Authorization`.
  - Si SecuBox n'utilise pas la fédération (box unique) : chaque appel est un signal moyen.
  - Sinon : plus de 5 appels par fenêtre glissante de 1 200 s et par IP source donnent un signal haut, en reprenant le seuil du correctif.

  Entrées : méthode, chemin, en-têtes d'authentification, horloge et compteur par IP.
- **Faux positifs** : nuls sans fédération. Avec fédération, les partages entrants sont déclenchés par des humains et restent rares.

---

### 3.5 Nextcloud : prise de contrôle d'agenda par `group-member-set` (CVE-2026-45281)

- **Versions** : corrigée en 33.0.3 et 32.0.9 (Enterprise : 31.0.14.5, etc.). CVSS 8.1, authentifiée. **Déjà corrigée dans la version de la source (32.0.10)** : défense en profondeur seulement.
- **Indicateur sourcé** : le contournement de l'éditeur consiste à bloquer `remote.php/dav/principals/users/<userid>/calendar-proxy-read` et `…/calendar-proxy-write`. L'attaque met à jour `group-member-set`.
- **Contrôle proposé : R-NC2** (gravité moyenne). Méthode `PROPPATCH` sur ces chemins. Si la requête porte un `Authorization: Basic`, signal haut quand `<userid>` diffère de l'utilisateur authentifié. Entrées : méthode, chemin, en-tête `Authorization`.
- **Faux positifs** : faibles. La délégation d'agenda légitime écrit sur son propre principal.

---

### 3.6 PHP : déni de service par le nombre de parties (CVE-2023-0662)

- **Versions** : 8.0 < 8.0.28, 8.1 < 8.1.16, 8.2 < 8.2.3. CVSS 7.5. GHSA-54hq-v5wp-fqgv : nombre illimité de parties fichier et champ, avertissements sans borne, déni de service non authentifié **avant tout script**.
- **Debian** : bookworm corrigée (`php8.2`) ; trixie non listée (8.4 publiée après le correctif). **KEV** : non ; SSVC « none », « automatable : yes ».
- **Seuil sourcé** : le correctif crée `max_multipart_body_parts`, dont la valeur par défaut `-1` vaut « Sum of max_input_vars and max_file_uploads » (`php.ini-production`). Avec les défauts (1 000 + 20), cela fait **1 020 parties**.
- **Contrôle proposé : R-PHP1.** Utiliser le compteur de parties de l'analyseur #3257 : plus de 1 020 parties ⇒ dépassement certain d'une limite PHP. Le plafond d'analyse de 500 du prototype (statut `limite`) suffit pour le signaler.
- **Faux positifs** : ≈ 0. Roundcube envoie au plus 20 fichiers (`max_file_uploads`), et le client web de Nextcloud envoie par WebDAV (`PUT`), pas en multipart.

---

### 3.7 PHP : XXE par l'état global de libxml (CVE-2023-3823)

- **Versions** : 8.0 < 8.0.30, 8.1 < 8.1.22, 8.2 < 8.2.8. CVSS 8.6.
- **Debian** : bookworm corrigée ; trixie non listée. **KEV** : non.
- **Origine** : le GHSA-3qrf-m4j2-pcrr a été ouvert par Nextcloud. Sa PoC est un `PROPFIND /remote.php/dav/files/<username>/` dont le corps commence par `<!DOCTYPE root [<!ENTITY % remote SYSTEM "https://…"> %remote; %intern; %trick;]>`. Le rapport précise : reproduit avec **Apache + mod_php sur Debian**, « never able to produce it on Nginx with PHP-FPM ». Le Nextcloud de SecuBox tourne sous nginx + FPM : pertinence plus faible.
- **Contrôle proposé : R-PHP2** (gravité haute). Sur les méthodes WebDAV, CalDAV et CardDAV (`PROPFIND`, `PROPPATCH`, `REPORT`, `SEARCH`, `LOCK`, `MKCOL`, `MKCALENDAR`), ou sur un `Content-Type` `application/xml` ou `text/xml`, chercher `<!DOCTYPE` ou `<!ENTITY` dans le **prologue** : du début du corps jusqu'au premier élément racine, borné par exemple à 4 Kio (proposition, non sourcée). Coût : quelques Kio au plus, pas de balayage du corps.
- **Faux positifs** : ≈ 0. Aucun client DAV courant n'envoie de DTD. À confirmer sur le trafic réel.

---

### 3.8 PHP : faux cookie `__Host-` ou `__Secure-` (CVE-2024-2756, suite de CVE-2022-31629)

- **Versions** : 8.1 < 8.1.28, 8.2 < 8.2.18, 8.3 < 8.3.5. CVSS 6.5 ; SSVC « poc ».
- **Debian** : bookworm corrigée ; trixie non listée. **KEV** : non.
- **Mécanisme** (GHSA-wpj3-hf5j-x4v4) : PHP normalise les noms de cookies. `curl -b '_[Host-x=y'` donne `{"__Host-x":"y"}`. Un attaquant réseau ou de même site pose ainsi un cookie non sécurisé que l'application prend pour un cookie `__Host-`.
- **Exposition** : Nextcloud fonde son contrôle de cookie strict (garde CSRF) sur `__Host-nc_sameSiteCookiestrict` et `__Host-nc_sameSiteCookielax` (`lib/private/AppFramework/Http/Request.php`, `getProtectedCookieName`, `passesStrictCookieCheck`).
- **Contrôle proposé : R-PHP3** (gravité moyenne). Découper l'en-tête `Cookie` en noms, puis appliquer la normalisation PHP (espaces en tête ignorés ; ` ` et `.` vers `_` ; `[` sans `]` vers `_`). Si le nom normalisé commence par `__Host-` ou `__Secure-` alors que le nom brut ne commence pas ainsi, c'est un signal. Entrée : en-tête `Cookie`, qui n'est pas inspecté aujourd'hui.
- **Faux positifs** : ≈ 0.

---

### 3.9 PHP : boundary multipart anormale (CVE-2024-8925)

- **Versions** : 8.1 < 8.1.30, 8.2 < 8.2.24, 8.3 < 8.3.12. CVSS 3.1 (faible) ; SSVC « poc ».
- **Debian** : bookworm corrigée ; trixie non listée. **KEV** : non.
- **Mécanisme** (GHSA-9pqp-7h25-4f32) : avec un préfixe X de la boundary B tel que 5 Kio < |X| < |B| < 8 Kio, PHP extrait mal le contenu entre deux délimiteurs. On peut ainsi faire disparaître des données. C'est aussi un **écart d'analyse** possible entre l'analyseur Go de sbxwaf et `rfc1867.c`.
- **Seuil sourcé** : RFC 2046 §5.1.1, une boundary « must be no longer than 70 characters, not counting the two leading hyphens ».
- **Contrôle proposé : R-PHP4.** Une boundary de plus de 70 caractères donne le statut `malforme` et un signal moyen ; au-delà de 5 120 octets, un signal haut. Entrée : en-tête `Content-Type`.
- **Faux positifs** : nuls si l'on suit la RFC. À vérifier sur le trafic de la box.

---

## 4. Compléments à CVE-2026-109618 et CVE-2026-109619, tirés des avis primaires

Ce ne sont pas de nouvelles vulnérabilités, mais des vecteurs « équivalents » que l'éditeur décrit ou que des capteurs ont observés, et que les quatre signatures déjà décidées ne couvrent pas.

**Ce que dit l'éditeur**
- GHSA-w8hw-w9fx-j79w (109618) liste trois stratégies d'OOM qui restent sous les limites apparentes :
  1. « A multipart request without a usable declared content length may pass the initial post_max_size check » ;
  2. « A multipart part can contain an unrestricted number of headers » ;
  3. « Empty file controls do not count towards max_file_uploads … Nested field names multiply the generated array work ».
- Avis php.net du 21/10/2026 : « Consider enforcing limits at the web server or proxy level for decoded request size, input field count, multipart part count, header count, and nesting depth. These limits must also cover requests without a usable Content-Length. »

**Ce qu'observe TU Delft** (21 au 29/10/2026, 73 065 requêtes, 668 IP)

| Technique | Requêtes | IP |
|---|---|---|
| OOM : empty file fields | 2 646 | 45 |
| OOM : header-line flood | 484 | 8 |
| OOM : deeply nested names | 3 116 | 55 |
| OOM : hundreds of parts | 1 310 | 80 |
| PHP code in progress field | 10 433 | 35 |
| PHP code in filename | 1 464 | 35 |

**Contrôles proposés**

| Id | Indicateur | Contrôle | Entrées | Faux positifs |
|---|---|---|---|---|
| C1 | `POST` multipart ou urlencoded **sans `Content-Length`**, ou avec `Transfer-Encoding: chunked` | Signal haut sur les vhosts PHP. La spec #3257 prévoit déjà `ContentLength = -1`. | en-têtes | faibles : les navigateurs envoient toujours `Content-Length` pour un formulaire |
| C2 | Nombre d'en-têtes **par partie** | Signal au-delà de 8 en-têtes (proposition, non sourcée ; une partie légitime en a 1 à 3). Mémoriser aussi le maximum. | en-têtes de partie | ≈ 0 |
| C3 | Nombre de parties `filename=""` (champs fichier vides) | Signal au-delà de 20 (proposition alignée sur `max_file_uploads` ; le manuel confirme que les champs vides ne comptent pas dans cette limite). À croiser avec la profondeur des noms. | en-têtes de partie | ≈ 0 pour Roundcube et Nextcloud, qui envoient en JavaScript |
| C4 | Nombre de variables urlencoded supérieur à `max_input_vars` (1 000) | Signal moyen. Le manuel PHP dit que les variables en trop donnent un `E_WARNING` et sont tronquées. | corps et requête urlencoded | ≈ 0 |
| C5 | CVE-2026-115560 (annoncée le 23/10/2026, avis complet à paraître) | Déjà couverte côté requête par la présence de `PHP_SESSION_UPLOAD_PROGRESS`. **Roundcube appelle `ini_set('session.serialize_handler', 'php')` à l'exécution** (`rcube_session.php:116`, 1.6.20), ce qui remplit la moitié de la condition. L'autre moitié, un `php.ini` à `php_binary` ou `php_serialize`, n'est pas le défaut Debian. À vérifier dans le conteneur (§ 6). | — | — |

**Constat annexe.** L'éditeur recommande `post_max_size = 8M`, ou `32M` avec des envois de fichiers. SecuBox a `16G` pour Nextcloud et `160M` pour Roundcube. Avec ces valeurs, PHP laisse passer en entier la variante urlencoded de 3 à 60 Mo ; seul sbxwaf, qui n'inspecte que le premier Mio, peut la voir.

---

## 5. Écartées

| CVE | Raison |
|---|---|
| CVE-2024-4577, CVE-2024-8926 (KEV pour 4577) | PHP-CGI sous **Windows** (conversion « Best-Fit » des pages de code). **Non applicable** à mod_php ou FPM sous Linux. Les sondes `?-d+allow_url_include…` servent au plus d'étiquette d'outil aggravante. |
| CVE-2012-1823 (KEV) | Concerne `php-cgi` lancé en CGI avec une chaîne de requête sans `=` transmise en argv. mod_php et FPM ne passent pas la chaîne de requête en argv : **non applicable**. Même remarque sur l'étiquette d'outil. |
| CVE-2024-8927 | `cgi.force_redirect` contourné via `HTTP_REDIRECT_STATUS` : SAPI CGI seulement. |
| CVE-2019-11043 (KEV) | PHP-FPM 7.1 à 7.3 seulement : 8.2 et 8.4 ne sont pas touchés, même si le nginx de Nextcloud utilise le motif `fastcgi_split_path_info` concerné. Contrôle gratuit facultatif : `%0a` ou `%0d` dans le chemin. |
| CVE-2024-9026, CVE-2026-91768, CVE-2026-6735 (FPM) | Journaux des enfants, ACL IPv6 de `listen.allowed_clients`, XSS de la page de statut : rien à voir dans une requête HTTP publique (FPM écoute en local). |
| CVE-2023-3824, CVE-2026-6103, CVE-2026-7260 (Phar) | Il faut que l'application ouvre une archive phar contrôlée par l'attaquant : la requête n'a pas de forme reconnaissable. |
| CVE-2025-6491, CVE-2025-14181, CVE-2026-91765, CVE-2026-6722, CVE-2026-7261, CVE-2026-7262 (SOAP) | Ni Nextcloud ni Roundcube n'exposent de serveur SOAP. |
| CVE-2025-1217, -1219, -1734, -1736, -1861, CVE-2026-91766, -93682, -12184 | Client HTTP sortant de PHP : la trace serait dans des réponses distantes, pas dans la requête entrante. |
| CVE-2024-11235, CVE-2025-14177, -14178, CVE-2026-7568, -7258, -7259, -17544… | Bogues de fonctions du cœur ou de la bibliothèque standard, atteints selon le code de l'application : pas de forme de requête générique. |
| CVE-2024-3096 | `password_verify` avec un octet nul en tête : il faut que le mot de passe de la **victime** commence par NUL. Rien à détecter côté attaquant. |
| CVE-2024-5458, GHSA-ch8v-r6jh-4vvr | Contournements de `filter_var` : dépendent du code de l'application (sans CVE pour le second). |
| XSS de Roundcube portées par le courriel : CVE-2024-42009, CVE-2024-37383, CVE-2025-68461, CVE-2023-5631, CVE-2023-43770 (toutes au KEV), CVE-2026-35539, CVE-2026-54432, CVE-2026-54433, et les contournements de blocage d'images ou de CSS | Le vecteur est un **courriel reçu par SMTP**. La requête HTTP vers le webmail est une lecture de message banale. Cela relève du filtrage de courrier (rspamd), pas du WAF. |
| CVE-2026-114730, -114731, -75006, CVE-2026-48843, CVE-2026-62643 (SSRF via le proxy CSS de Roundcube) | Déclenchées par le HTML d'un courriel : la cible de l'URL n'est pas choisie dans la requête de l'attaquant. |
| CVE-2026-35537, CVE-2026-48847 (Roundcube, sessions Redis ou memcache, avant authentification) | SecuBox stocke les sessions Roundcube en SQLite : **non applicable** (et corrigées dans bookworm). Le vecteur HTTP n'est pas publié. |
| CVE-2026-48842 (plugin `virtuser_query`), CVE-2026-74997 (`markasjunk` `cmd_learn`), CVE-2026-75007 (LDAP), CVE-2026-114714 (`squirrelmail_usercopy`), CVE-2026-114715 et CVE-2026-75010 (Modoboa), CVE-2026-114732 (multi-hôte) | Dépendent d'un greffon ou d'une configuration que l'installation de SecuBox n'active pas, à vérifier. Pour 114714, contrôle gratuit possible : `/` dans `_user` au login. |
| CVE-2026-45545, CVE-2026-45722 (Nextcloud Tables, SQLi) | Authentifiées, application optionnelle, pas d'exploitation connue. Si Tables est installée : contrôler les énumérations (`type` de colonne ∈ {number, text, selection, datetime, usergroup}, tri ∈ {ASC, DESC}). |
| CVE-2026-45156 (`user_oidc`, ID4me) | Ne s'applique que si `user_oidc` et ID4me sont activés. |
| CVE-2026-29059 (Nextcloud Flow, Windmill) | Application externe Docker (AppAPI) : non applicable, puisque SecuBox n'utilise que LXC. |
| CVE-2026-45690, CVE-2026-45691 (contournements de 2FA) | Rejeu d'un identifiant de session : pas de forme structurelle dans la requête. |
| CVE-2023-32319, -32320, -35172, -49792 (protections anti-force brute de Nextcloud) | Corrigées dans des versions bien antérieures à 32.x. Hygiène résiduelle : HAProxy doit **remplacer**, et non compléter, un `X-Forwarded-For` reçu du client (CVE-2023-49792). |
| CVE-2023-49103, CVE-2023-49105 (KEV) | **ownCloud**, pas Nextcloud. Les sondes `/apps/graphapi/…/GetPhpInfo.php` ou `OC-Signature`, `OC-Credential` dans la requête relèvent du bruit de reconnaissance (étiquette d'outil). |
| HashDoS ou débordement de `max_input_vars` | Aucune CVE PHP des années 2023 à 2026 trouvée. `max_input_vars` limite `$_GET`, `$_POST` et `$_COOKIE`, mais pas le JSON décodé par l'application. Contrôle de robustesse retenu en C4, sans CVE. |
| Apache httpd, nginx, HAProxy | Hors du périmètre demandé (PHP, Nextcloud, Roundcube). |

---

## 6. Reste à confirmer

1. **Versions réellement déployées** sur la box : Nextcloud (la source dit 32.0.10, ce qui expose à 77167 et 104190), Roundcube (`dpkg -l roundcube-core`) et `php8.2` (8.2.35 attendu dans les deux conteneurs pour 109618 et 109619).
2. **Conteneur Roundcube** :
   - `session.serialize_handler` dans `/etc/php/8.2/apache2/php.ini` doit valoir `php` (défaut) pour écarter CVE-2026-115560 ;
   - présence de `php-imagick` ou d'`im_convert_path`, pour CVE-2026-114727 ;
   - greffons activés (`markasjunk`, `password`, `virtuser_query`, `squirrelmail_usercopy`).
3. **Nextcloud** : fédération utilisée ou non (R-NC1) ; `enabledPreviewProviders` (CVE-2026-104190) ; application Tables installée ou non.
4. **Enregistrements non publiés** : CVE-2026-104190 et CVE-2026-115560 n'existent pas encore sur cve.org au 29/10, et 115560 manque au tracker Debian. L'avis complet de 115560 est annoncé pour la prochaine version de PHP.
5. **CVE ImageMagick sous-jacente** de CVE-2026-104190 : non identifiée. Le GHSA ne cite que les versions (6.9.13-48 et 7.1.2-24). L'état du paquet Debian `imagemagick` n'a pas été vérifié.
6. **Vecteur HTTP de CVE-2026-114724** : non publié. Je le rattache à la classe `_from` par analogie de mécanisme (clé `!`), pas sur une source explicite.
7. **Seuils marqués « proposition »** (8 en-têtes par partie, 20 champs fichier vides, fenêtre de prologue XML de 4 Kio) : ce sont des choix d'auteur, à étalonner sur le trafic réel en mode detect.
8. **Hypothèse non confirmée** : les avertissements émis pendant l'analyse du corps (dépassement de `max_input_vars`, avertissements multipart de CVE-2023-0662) pourraient servir de « consommateurs » au sens de GHSA-6wmf-4rv5-p3rp. L'avis ne cite comme consommateurs confirmés que les diagnostics INI et la progression d'envoi de session.
9. **Effet de `fastcgi_request_buffering off`** (Nextcloud) sur un corps `chunked` transmis à FPM, donc sur le vecteur « sans Content-Length » : non vérifié, la documentation nginx n'en dit rien.
10. **`_to`, `_cc`, `_bcc` dans Elastic** : vérifier si ces zones de texte peuvent légitimement contenir un saut de ligne avant de les inclure dans R-RC3.

---

## 7. Sources

**CISA**
- Catalogue KEV, JSON, version `2026.10.28` : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Alerte du 21/10/2026 (révisée le 26/10) : https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching

**PHP**
- Avis du 21/10/2026 : https://www.php.net/archive/2026.php#2026-10-21-5
- Avis informatif du 23/10/2026 (CVE-2026-115560) : https://www.php.net/archive/2026.php#2026-10-23-1
- ChangeLog 8.x : https://www.php.net/ChangeLog-8.php
- GHSA PHP2Shell : https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w et https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CVE-2023-0662 : https://github.com/php/php-src/security/advisories/GHSA-54hq-v5wp-fqgv
- CVE-2023-3823 : https://github.com/php/php-src/security/advisories/GHSA-3qrf-m4j2-pcrr
- CVE-2024-2756 : https://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4
- CVE-2024-8925 : https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32
- CVE-2024-4577 : https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv
- CVE-2024-8927 : https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp
- `php.ini-production` (`max_multipart_body_parts`, l. 428-431) : https://github.com/php/php-src/blob/PHP-8.2/php.ini-production
- Normalisation des noms : https://github.com/php/php-src/blob/PHP-8.2/main/php_variables.c
- Manuel : https://www.php.net/manual/en/info.configuration.php (`max_input_vars`, `max_input_nesting_level`), https://www.php.net/manual/en/ini.core.php (`max_file_uploads`, `post_max_size`), https://www.php.net/manual/en/language.variables.external.php

**PHP2Shell, sources tierces**
- NCSC-NL : https://github.com/NCSC-NL/php2shell
- Observations de TU Delft : https://php2shell.delftintellab.com/

**Roundcube**
- Avis 1.6.11 : https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10
- Avis 1.6.20 : https://roundcube.net/news/2026/10/19/security-updates-1.6.20-and-1.7.5
- Notes de version : https://github.com/roundcube/roundcubemail/releases/tag/1.6.20, https://github.com/roundcube/roundcubemail/releases/tag/1.6.18, https://github.com/roundcube/roundcubemail/releases/tag/1.6.14
- Correctifs :
  - https://github.com/roundcube/roundcubemail/commit/c069be58979a (validation de `_from`, #9865)
  - https://github.com/roundcube/roundcubemail/commit/833770d3d3c35cfde74cc2614d368f25a75b6f99 (114724)
  - https://github.com/roundcube/roundcubemail/commit/f62879defc0330ae240c72b83b2d00a8ab337447 (113386)
  - https://github.com/roundcube/roundcubemail/commit/242c6d6a150c850bd96d20d400261e71f8d11f9b (114720)
  - https://github.com/roundcube/roundcubemail/commit/79adcfc0c48012bbbe930278471425027fd7331c (114725)
  - https://github.com/roundcube/roundcubemail/commit/895d88af37720d2b46e4553f524013b2e1cb7665 (114727)
  - https://github.com/roundcube/roundcubemail/commit/b18a8fa8e815 (35538)
  - https://github.com/roundcube/roundcubemail/commit/73233abe581b (75002)
- Code : `program/lib/Roundcube/rcube_session.php` (`ini_set('session.serialize_handler', 'php')`, l. 116 en 1.6.20), `program/lib/Roundcube/rcube_image.php`, `config/defaults.inc.php` (`im_convert_path`)
- FearsOff : https://fearsoff.org/research/roundcube ; PoC : https://github.com/fearsoff-org/CVE-2025-49113 (`CVE-2025-49113.php`, l. 185, 211, 306-309)
- BleepingComputer (exploit en vente) : https://www.bleepingcomputer.com/news/security/hacker-selling-critical-roundcube-webmail-exploit-as-tech-info-disclosed/

**Nextcloud**
- CVE-2026-77167 : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5572-968j-v7g5 ; correctif : https://github.com/nextcloud/server/pull/62091 ; routes : `apps/cloud_federation_api/appinfo/routes.php`, `apps/federatedfilesharing/appinfo/routes.php`
- CVE-2026-104190 : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-7hwf-8pcj-33h4
- CVE-2026-45281 : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-hrrv-mp25-26vv
- Tables : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-x43f-gmgh-vvjj et https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5h2w-c7px-hp4j
- `user_oidc` : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qqgv-fqwp-mjpp
- Windmill : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-g7vj-98x3-qvjf
- CVE-2023-49792 : https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5j2p-q736-hw98
- Cookies `__Host-` : https://github.com/nextcloud/server/blob/master/lib/private/AppFramework/Http/Request.php

**Debian**
- Paquets : https://security-tracker.debian.org/tracker/source-package/roundcube, https://security-tracker.debian.org/tracker/source-package/php8.2, https://security-tracker.debian.org/tracker/source-package/php8.4
- Pages par CVE : https://security-tracker.debian.org/tracker/CVE-2025-49113, …/CVE-2026-113386, …/CVE-2026-114720, …/CVE-2026-114724, …/CVE-2026-114725, …/CVE-2026-114727, …/CVE-2026-75002, …/CVE-2026-35538, …/CVE-2023-0662, …/CVE-2023-3823, …/CVE-2024-2756, …/CVE-2024-8925, …/CVE-2026-109618, …/CVE-2026-109619
- Absence de Nextcloud serveur : https://sources.debian.org/api/search/nextcloud/
- `debian/control` de roundcube bookworm : https://sources.debian.org/data/main/r/roundcube/1.6.5+dfsg-1+deb12u9/debian/control

**Enregistrements CVE (CVSS, SSVC, KEV)** : https://cveawg.mitre.org/api/cve/CVE-2025-49113 (même forme pour les autres identifiants cités)

**Normes**
- RFC 2046 §5.1.1 : https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
- HTML, assainissement des champs texte : https://html.spec.whatwg.org/multipage/input.html#text-(type=text)-state-and-search-state-(type=search)

**Autres**
- ownCloud CVE-2023-49105 : https://owncloud.com/security-advisories/webdav-api-authentication-bypass-using-pre-signed-urls/
- nginx `fastcgi_request_buffering` : https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html
