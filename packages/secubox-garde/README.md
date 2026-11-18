# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# secubox-garde — détecteur d'intrusion, d'évasion et d'infection (#3794)

Répondeur automatique : une menace détectée devient une décision (`decisions`), appliquée sans attendre
l'administrateur, notifiée, puis levée ou échue. Livré : squelette, sources, politique, notifications,
moteur, registre d'appareils, API et page `/garde/`.

## Fichiers

- Base : `/var/lib/secubox/garde/garde.db` — tables `decisions`, `positions`, `liberations`, `file_notifs`, `recidives`,
  `adresses` (adresses posées par décision), `decision_noms` (noms DoH fermés), `appareils` et `appareil_ips`
  (registre), `etat_moteur` (repères du résumé horaire et de l'alerte de masse).
- Réglages : `/etc/secubox/garde.toml` (semé une fois, 0640 root:secubox). Défauts : `automatique = true`,
  `courriel = ""`, `sms_utilisateur = ""`, `sms_bans = false`, `quarantaines_max = 3`, `rafale_bans = 50`.
- Secret d'envoi des SMS : `/etc/secubox/secrets/garde-sms` (0600), jamais dans le TOML.

## API (`/run/secubox/garde.sock`, route nginx `/api/v1/garde/`)

| Méthode | Route | Garde |
|---|---|---|
| GET | `/health` | ouverte |
| GET | `/etat` | `require_lecture` — `{tuiles:{isoles,evasions,bannis,recidivistes,notifs_24h:{sms,courriel},en_attente}, actives, automatique, quarantaines_max, demandes, releve, session_requise}` |
| GET | `/historique?heures=24` (1…720) | `require_lecture` — `{heures, lignes}` (bans groupés par heure, libérations) |
| GET | `/reglages` | `require_lecture` — 4 réglages + `cle_sms_enregistree`, `cle_sms_en_attente`, `en_attente` ; jamais la clé |
| POST | `/liberer` `{id}` | `require_jwt` — infection seulement |
| POST | `/rouvrir` `{id}` | `require_jwt` — évasion seulement |
| POST | `/debannir` `{ip}` | `require_jwt` — seulement une adresse d'une décision `intrusion` active de la garde (404 sinon) |
| POST | `/reglages` `{automatique?, courriel?, sms_utilisateur?, sms_bans?}` | `require_jwt` |
| POST | `/cle-sms` `{cle}` (lettres et chiffres, vide = retirer) | `require_jwt` |
| POST | `/tester` `{canal: sms\|courriel}` | `require_jwt` |

Lecteur anonyme du tableau de bord (permis par `require_lecture` depuis le LAN) : chiffres seulement, aucun appareil,
aucune adresse, aucun contact (`session_requise: true`).

### Demandes exécutées par le passage

L'API tourne sous le profil `secubox-garde` : ni sudo, ni clé du WAF, ni secrets, ni écriture dans `/etc`. Chaque
action est donc une **demande**, exécutée par le passage suivant (≤ 60 s) ; la page affiche « en cours » :

- `liberer`, `rouvrir`, `debannir`, `tester` → table `demandes` (`en_attente` → `faite` | `reprise` | `echec`), une seule
  demande en attente par (action, cible). `garde/demandes.py::executer`, appelé par `secubox-garde-passage` avant les
  décisions : libérer/rouvrir = levée de chaque adresse par `effets` (`leve_par = utilisateur`, état `levee` ; levée
  incomplète → `levee_en_cours`, reprise par le moteur) ; débannir = `effets.debannir` (`POST /garde/unban` du WAF,
  même jeton que le ban ; il ne lève qu'un ban de la garde encore tenu par elle) puis décision `levee` ; refus `409 etranger` (le WAF a vu l'adresse
  reprise plus longtemps par un autre mécanisme) = issue FINALE : décision `levee` (`leve_par = autre`), demande
  `faite` « ban repris par un autre mécanisme », aucun nouvel essai, affichée sur la page ; tester = mise en file d'une notification d'essai. Aucun verrou ad-guard
  n'est pris par l'API.
- Libérer / rouvrir enregistrent dès la demande `liberations(cle, signe, maintenant + 7 j)` : pas de nouvelle mesure
  pour ce signe sur cet appareil pendant 7 jours. L'exemption est posée au moment de la DEMANDE et reste acquise même si
  l'exécution échoue (levée incomplète ou refusée) : l'administrateur a tranché pour ce signe.
- Réglages et clé SMS → fichiers 0600 dans `/var/lib/secubox/garde/depot/` (`reglages.json`, `cle-sms`), appliqués par
  l'aide root `/usr/lib/secubox/garde/secubox-garde-depots` (`ExecStartPre=+` du passage) : fichier ordinaire du compte
  `secubox-garde`, sans suivre de lien, ≤ 4 Kio, tout revalidé ; `garde.toml` mis à jour EN PLACE (seules les 4 clés de premier niveau, avant toute
  `[table]` ; commentaires, tables et tableaux gardés ; tampon relu par tomllib et comparé à l'attendu, sinon refus
  audité ; fichier non UTF-8 : refus), `.prec` gardé, remplacement atomique, clé posée en `/etc/secubox/secrets/garde-sms` 0600 `secubox-garde`. La clé n'est jamais
  relue par l'API ; le passage note seulement `etat_moteur.cle_sms_presente` (0/1).
- Audit : l'API écrit `<action>-demande` dans `audit.log` (ajout seul, AppArmor `a`), l'aide et les effets l'exécution.

## Page `/garde/` (`www/garde/index.html`)

Aurora (maquette approuvée #3794), coque de l'administration (menu latéral partagé, hors `?embed=1` et `?demo=1`), CSP
stricte par hachage du script, jeton `sbx_token`. Bandeau des appareils isolés, quatre tuiles, cartes « En cours » —
UN appareil = UNE carte (nom du registre, toutes ses adresses en petit), les bans d'Internet groupés en une carte avec
liste et « Débannir » —, historique 24 h, réglages, aperçus. Libérer, rouvrir et débannir demandent une confirmation
intégrée. `?demo=1` : données fictives, aucune écriture.

## Page de quarantaine (`www/garde/isole.html`)

Statique (aucun script, aucun bouton, CSP `default-src 'none'` + hachage du style), installée dans
`/usr/share/secubox/www/garde/isole.html`. Voie retenue pour la servir (branchement en T9, après repérage sur gk7 de
la réponse actuelle à `curl -H 'Host: inconnu.example' http://<ip box>/` — HAProxy → sbxwaf « unrouted ») : déclaration
par le mécanisme déclaratif de routes (`secubox-waf-route` / `/etc/secubox/haproxy.toml`), jamais à la main, pour qu'un
Host inconnu en HTTP sur l'adresse de la box renvoie ce fichier.

## Unités

`secubox-garde.service` (API, compte `secubox-garde`, profil `secubox-garde`), `secubox-garde-passage.service`
+ `.timer` (`/usr/sbin/secubox-garde-passage` toutes les 60 s, profil `secubox-garde-passage`, groupes `secubox` et
`secubox-garde`, `NoNewPrivileges=no` pour sudo, patron de `secubox-ad-guard-auto.service`).

## Sources (capteurs)

`garde/sources.py` lit : `/var/lib/secubox/dns-guard/alerts.jsonl` (incrémental, inode + offset),
`/run/secubox/actord-propositions.json`, `ip -j neigh` (IP → MAC) et la liste DoH d'ad-guard
(`/usr/share/secubox/ad-guard/lists/resolveurs-doh.txt`, noms seulement). Requêtes DNS par client
pour la détection DoH : table `dnstv_recents` de `/var/lib/secubox/ad-guard/dnstv/dnstv.db`
(ad-guard). Droits : base, `-wal`, `-shm` en 0640 secubox:secubox, dossiers 0755 ; `secubox-garde`
est du groupe `secubox` (lecture seule). Ouverture `mode=ro`, repli unique `mode=ro&immutable=1` avec
avertissement ; deux échecs : liste vide. Les positions de lecture sont enregistrées après la lecture :
au plus une fois (jamais de doublon, un signal peut se perdre en cas de chute du moteur).

## Moteur (`garde/moteur.py`)

Un passage : voisins (`ip -j neigh`), signaux de la dernière heure (alertes DNS, propositions d'actord, DoH), mise à
jour du registre, échéances, suivi des adresses, `decider`, application, notifications, vidage de la file.

- Une décision n'est `active` que si son effet a réussi (au moins une adresse pour un appareil) ; sinon alerte dans
  `audit.log` et nouvel essai au passage suivant. Ban `409 deja_actif` : enregistré « déjà banni ailleurs », sans
  nouvel essai. Récidives = bans de l'adresse sur 7 j dans `decisions`.
- Noms d'une évasion : DoH = nom résolu, tunnel = `domain` de l'alerte dns-guard (domaine enregistré, tel quel) ;
  refusés : moins de deux libellés ou forme `<2-3 lettres>.<2 lettres>` (suffixe public probable) ; aucun nom → signalé.
- Infection / évasion portent sur l'APPAREIL : posées sur chacune de ses adresses (une entrée ad-guard par IP), puis
  suivies : une adresse quittée est levée, une nouvelle posée ; un appareil absent des voisins garde ses mesures.
- Levée échouée : la décision passe `levee_en_cours`, seules les adresses levées quittent `adresses`, nouvel essai à
  chaque passage (et au rapprochement), une alerte au début. Rafale : un SMS par rafale. Alertes d'échec d'effet et
  enregistrements « signalé » : un par (appareil, signe) et par heure.
- Échéances : intrusion `echue` (le timeout nft fait foi) ; évasion levée (`rouvrir`) puis `echue` ; infection
  réévaluée : signal d'infection de l'appareil depuis le début de la période → prolongée de 24 h, sinon levée
  (`levee`, `leve_par = reevaluation`). ad-guard garde les mesures échues : le moteur les lève toujours explicitement.
- Notifications : infection/évasion → SMS (1 par appareil et par heure) + courriel, nommant l'appareil ; bans →
  résumé horaire par courriel (SMS si `sms_bans`), SMS `rafale` au-delà de `rafale_bans` bans en 10 min ; alerte
  de masse une seule fois tant qu'elle dure.
- `rapprocher` : au premier passage d'un démarrage (`boot_id` noté dans `/var/lib/secubox/garde/boot_id`), les
  décisions actives non échues sont réappliquées jusqu'à leur fin d'origine (un ban de moins d'une heure restante
  n'est pas reposé, minimum du WAF), les autres levées et marquées `echue`.
- Protégées (`garde/reseau.py`, `ip -j`) : adresses de la box, passerelles par défaut (Freebox), voisins des ponts
  `lxcbr*` (LXC), réseaux des interfaces `wg*` (maillage). `lan_prefixes` : préfixes IPv6 globaux des interfaces
  hors `lo`/`wg*`/`lxcbr*`/`veth*`, jamais plus larges que /48 (en mode routeur, le préfixe du WAN en fait partie).

## Effecteurs (`garde/effets.py`)

- Ban : `POST /garde/ban` sur `/run/secubox/waf.sock`, `Authorization: Bearer` frappé par
  `secubox_core.compte_service.frapper_jeton` (compte `garde`, `aud` = nom de la box) avec
  `/etc/secubox/secrets/garde-ban.pem` (root:secubox-garde 0640, créée par `wafctl cle-garde-ban generer`, appelé par
  le postinst si absente). `/etc/secubox/secrets` est 0750 root:secubox (gk7, 18/11) : traversé par le groupe
  `secubox` ; à défaut le postinst pose une ACL nommée `x` sur le seul dossier.
- Quarantaine / évasion : `sudo -n /usr/sbin/secubox-adguard-tv quarantaine|evasion poser|lever …`.
- Audit : une ligne JSON `{"ts","module":"garde","action","cible","motif","resultat"}` par effet dans
  `/var/log/secubox/audit.log` (0640 secubox:secubox : ACL nommée `w` remise avant chaque passage par
  `/usr/lib/secubox/garde/secubox-garde-acl-audit`, qui refuse un lien ou un non-fichier et ne suit aucun lien ; AppArmor `a`).
- Arguments du ctl validés avant tout sudo (IP canonique, MAC, noms DNS, échéance) : refus local `ok: false`.

## Registre d'appareils (`garde/appareils.py`)

Un appareil = une MAC et toutes ses adresses IPv4/IPv6 (voisins, signaux) ; sans MAC, clé = IP provisoire, fusionnée
(adresses, décisions, libérations) dès que la MAC est connue. Nom : première source qui répond :

| Ordre | Source | Droits constatés (gk7, 18/11) |
|---|---|---|
| 1 | ad-guard / TV Privacy `/var/lib/secubox/ad-guard/dnstv/etat.json` (`clients[].nom`) | 0600 secubox:secubox : **illisible** par `secubox-garde`, source sautée |
| 2 | NAC `/var/lib/secubox/nac/devices.db` (`devices.hostname`) | 0644 secubox:secubox, lu en `mode=ro` |
| 3 | baux dnsmasq `/var/lib/misc/dnsmasq.leases`, Kea `/var/lib/kea/kea-leases4.csv` | absents sur gk7 (relais) |
| 4 | constructeur (OUI) `/usr/share/ieee-data/oui.csv` | 0644 root |

Freebox (cache en mémoire du module, aucun fichier) et mDNS (aucun cache) : pas de source lisible, non lus. Sinon
« Appareil inconnu (<mac>) ».
