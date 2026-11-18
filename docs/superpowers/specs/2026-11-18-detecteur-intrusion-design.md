# Détecteur d'intrusion, d'évasion et d'infection automatique — conception (#3794)

Date : 2026-11-18. Statut : conception, à valider par le propriétaire avant tout plan.

## Intention

Le propriétaire veut un détecteur qui **agit seul** (« auto maximum ») sur trois menaces, pour des utilisateurs lambda qui ne
regardent pas les tableaux de bord : la box détecte, décide, applique, prévient. Aujourd'hui SecuBox détecte beaucoup (page nDPId :
4,2 M de flux à risque, capteurs DNS et DPI d'Actor Intelligence) mais **n'agit presque pas** à partir de ces détections, et ne
prévient personne hors de la webapp.

Succès : une machine d'Internet qui sonde gk2 est bannie sans geste ; un appareil de la maison qui contourne le DNS de la box est
ramené dans le rang ; un appareil infecté est isolé, le propriétaire reçoit un SMS et un courriel qui disent quoi, qui, pourquoi, et
comment libérer.

## Objectifs

1. **Intrusion** (Internet → box et services exposés) : ban nft temporaire de l'adresse, durée croissante en cas de récidive.
2. **Évasion** (appareil du LAN qui contourne la box : DNS chiffré DoH/DoT, résolveur tiers, tunnel DNS) : le chemin de contournement
   de CET appareil est fermé ; l'appareil garde Internet par la box.
3. **Infection** (appareil du LAN compromis : domaine de commande connu, noms générés DGA, exfiltration par sous-domaines, réponses
   détournées) : **quarantaine DNS** automatique de l'appareil, 24 h, puis réévaluation et libération automatique si les signes ont
   disparu.
4. **Notifications** de chaque décision : webapp (panneau des décisions, bouton « libérer »), **courriel** depuis la box sous son nom
   de nœud (`gk2@secubox.in`), **SMS** par l'API de notification Free Mobile.

## Non-objectifs

- Pas de nouveau moteur de détection : on **consomme** les détecteurs existants (capteur DNS d'ad-guard, capteur DPI d'Actor dans
  sbxdpi, WAF). On n'écrit ni IDS par signatures (type Suricata) ni modèle d'apprentissage.
- Pas de mise en routeur, ni de prérequis de routage (consigne : le produit marche d'abord en **relais seul**, bêta 1).
- Pas de coupure réseau totale d'un appareil du LAN (la box en relais seul ne le peut pas, et une TV coupée = plainte).
- Pas de nouvelle page « tableau de bord » de flux : la page nDPId reste en lecture seule.

## Anti-objectifs (ce qui ferait échouer le projet même s'il « marche »)

- Couper à tort une TV, un téléphone ou un ordinateur de la maison sur un signal bruité. Les volumes de la page nDPId (1,4 M « Slow
  DoS », 462 k « DGA suspect », 327 k « DNS inhabituel ») sont surtout du trafic normal : **aucun de ces trois risques nDPI ne
  déclenche une action seul**.
- Bannir le LAN, le maillage, la Freebox, la box elle-même ou ses conteneurs LXC.
- Inonder le propriétaire de SMS (gk2 subit des centaines de sondages par jour).
- Une action sans trace : chaque décision est auditée et réversible.

## Contraintes (AGENTS.md et mémoire du projet)

- Relais seul d'abord : en relais seul la box ne voit que le **DNS** des appareils ; évasion et infection se détectent et se traitent
  par le DNS. Le DPI (sbxdpi) est un bonus quand la box route le trafic, et la source principale pour l'intrusion sur gk2.
- nftables uniquement ; ban par les ensembles existants `inet secubox waf_ban`/`waf_ban6` (moteur `NftBanner` de sbxwaf).
- Service sous utilisateur dédié, AppArmor enforce, socket Unix, aucun secret dans le code (`/etc/secubox/secrets/`).
- Chaque décision dans `/var/log/secubox/audit.log` (append-only) en plus de la trace propre au mécanisme.
- Utilisateurs lambda : actif d'office, gestes dans la webapp (jamais en console).
- Le fichier `94-secubox-adguard-tv.conf` (vues Unbound par client) a déjà plusieurs auteurs (ad-guard, webfilter, adblock-sync) :
  ne pas ajouter un auteur concurrent sans coordination.

## Ce qui existe et sera réutilisé (repérage du 18/11)

| Besoin | Brique existante |
|---|---|
| Signaux d'infection/évasion par appareil | capteur DNS `secubox-adguard-dnssensor` (`api/dnstv_anomalies.py`) : domaines malveillants listés, DGA par entropie, tunnel DNS, dérive de débit, exfiltration par sous-domaines, réponses détournées ; sorties `/run/secubox/actord.sock` et `/var/lib/secubox/dns-guard/alerts.jsonl` |
| Signaux d'intrusion par adresse | capteur DPI d'Actor dans sbxdpi (`actorsensor.go`) : risques nDPI pondérés par IP source sur 10 min (Malicious Fingerprint, Possible Exploit, Malware Host Contacted, Susp UA, Probing, TLS Susp Extn), vers actord ; WAF (leurres, règles) |
| Ban d'une adresse | `POST /api/v1/waf/ai/ban` (compte de service Ed25519, jetons à usage unique, plafonds, audit `ai-ban.jsonl`) → `NftBanner.BanFor` (refuse privé, ULA, lien-local, robots vérifiés) |
| Fermer l'évasion DNS d'un appareil | `dnstv_contournement.py` : redirection du port 53 vers la box, refus de 853 et des résolveurs DoH connus, par MAC |
| Quarantaine DNS d'un appareil | vues Unbound par client (`access-control-view`), même mécanisme que TV Privacy |
| Courriel depuis la box | relais SMTP de secubox-mail (`sendmail -t`) ; l'envoi de `secubox-metrics/api/rapport.py` (à extraire en aide générique) |
| SMS | rien : à écrire (API Free Mobile `smsapi.free-mobile.fr/sendmsg`, identifiant + clé de l'abonné) |

## Conception retenue

### Un orchestrateur, pas un détecteur : `secubox-garde` (nom de travail)

Nouveau module `packages/secubox-garde/` : il **lit** les signaux existants, **décide** selon une politique, **applique** par les
mécanismes existants, **prévient**. Service `secubox-garde` sous utilisateur `secubox-garde`, API FastAPI sur
`/run/secubox/garde.sock`, état en SQLite (`/var/lib/secubox/garde/garde.db`), politique en TOML (`/etc/secubox/garde.toml`).

Entrées (abonnement, pas de sondage lourd) : les enveloppes `dns` et `dpi` d'actord, les alertes `alerts.jsonl` du capteur DNS, les
bans du WAF (`bans.jsonl`) pour le compte de récidive.

### Décisions automatiques

| Menace | Déclencheur (signal net) | Action | Durée |
|---|---|---|---|
| Intrusion | adresse **publique** (jamais privée, ULA, maillage, Freebox, box) dépassant le seuil du capteur DPI d'Actor, ou touchant un leurre du WAF | ban par `/api/v1/waf/ai/ban` | 4 h, ×4 à chaque récidive sur 7 j, plafond 30 j |
| Évasion | appareil du LAN vu en DoH/DoT ou résolveur tiers (capteur DNS / conntrack), ou tunnel DNS | fermer le contournement pour cet appareil (mécanisme `dnstv_contournement`) | tant que l'appareil le tente, revue à 24 h |
| Infection | appareil du LAN : domaine **listé malveillant** (commande), OU au moins **deux familles** de signes distinctes en 1 h parmi DGA, exfiltration, réponses détournées | **quarantaine DNS** (vue Unbound `quarantaine` : seuls les noms indispensables résolus) | 24 h puis réévaluation |

Règle de prudence : un signe unique et bruité (DGA seul, « DNS inhabituel », « Slow DoS ») n'agit jamais ; il est seulement compté et
affiché.

Quarantaine DNS : l'appareil garde la résolution de la box (`*.secubox.in` locaux), de l'heure, des mises à jour de son système
(liste par famille d'appareil) ; tout le reste répond REFUSED. La TV ou le téléphone affiche « pas d'Internet » : c'est voulu, et le
SMS dit pourquoi.

### Garde-fous

- Jamais : la box, ses conteneurs, la Freebox, le maillage, une adresse privée pour le ban. La liste protégée est celle d'actorban
  (`--actor-ban-protegees`) plus le maillage.
- Un appareil **libéré par le propriétaire** n'est plus mis en quarantaine pour la même famille de signe pendant 7 j (il reste
  surveillé et notifié).
- Plafonds : au plus N quarantaines simultanées (défaut 3) ; au-delà, alerte SMS « comportement de masse anormal » sans nouvelle
  quarantaine (protège contre un faux positif systémique).
- Un interrupteur général « mode alerte seule » existe dans la webapp, mais le défaut est l'automatique.
- Chaque décision : ligne dans `/var/log/secubox/audit.log`, trace dans `garde.db`, et la trace propre au mécanisme (ai-ban.jsonl).

### Notifications

- Webapp : panneau des décisions en cours et passées (menace, appareil ou adresse, motif lisible, heure, fin prévue, bouton
  « libérer » / « débannir »).
- Courriel : expéditeur `<nœud>@secubox.in` (ici `gk2@secubox.in`) par le relais local ; destinataire réglable dans la webapp.
- SMS : API Free Mobile ; identifiant et clé dans `/etc/secubox/secrets/garde-sms` (0600, lus par le service seulement).
- Rythme : quarantaine et évasion → SMS + courriel immédiats ; bans d'intrusion → résumé horaire par courriel, SMS seulement sur
  rafale anormale (seuil réglable) ; au plus 1 SMS par appareil et par heure.

### Interface

Page Aurora `/garde/` (maquette AVANT tout code, consigne du projet) : bandeau d'état, décisions en cours, historique, réglages
(destinataires, test d'envoi courriel/SMS, mode alerte seule, seuils). Lien depuis la page nDPId « Risques ».

## Précisions après relecture (18/11)

### Décidé par le propriétaire

- **Appareil en quarantaine : page d'explication.** Toute page web ouverte sur l'appareil aboutit à une page servie par la box
  (« Cet appareil est isolé depuis HH:MM : <motif lisible>. Le propriétaire a été prévenu. »). Les noms demandés en quarantaine
  hors liste indispensable répondent l'adresse de la box (pas REFUSED), qui sert cette page en HTTP ; en HTTPS, l'appli affichera
  une erreur de certificat ou « pas d'Internet » : accepté. La page est sans action (aucun bouton de libération), lecture seule.
- **Libération : l'administrateur seulement** (`require_jwt`), depuis la webapp ou par le lien du courriel (lien vers la page
  d'administration, qui demande la connexion ; aucun jeton de libération dans le courriel).

### Décidé par l'assistant (à vérifier)

- **Évasion en relais seul** : signal = l'appareil résout un nom de résolveur chiffré connu (`resolveurs-doh.txt` : `dns.google`,
  `cloudflare-dns.com`…) ou un tunnel DNS (capteur DNS). Réponse = refus de ces noms pour CET appareil + notification. Une
  connexion directe à l'adresse IP d'un résolveur n'est visible qu'en mode routé (fermeture par `dnstv_contournement`) : limite dite.
  Le tunnel DNS compte comme **évasion** (pas comme infection) : pas de double déclenchement.
- **Identité d'un appareil** : MAC, lue dans la table des voisins (ARP/NDP, visible en relais seul) ; repli sur l'IP. Une MAC
  aléatoire qui change = nouvel appareil (limite dite) ; la quarantaine suit l'IP tant que la MAC est inconnue.
- **Application de la quarantaine** : primitive `quarantaine poser|lever <mac|ip>` ajoutée au ctl root d'ad-guard (seul auteur des
  vues Unbound), appelée par `secubox-garde` via sudoers restreint. La vue `quarantaine` **conserve** les protections TV Privacy de
  l'appareil (#3674 : jamais désactivable) et la levée rend la vue d'origine.
- **Ban** : compte de service dédié `garde` pour `/api/v1/waf/ai/ban` (clé dans `/etc/secubox/secrets/`) ; vérifier au plan que les
  plafonds de l'ai-ban admettent 30 j, sinon lot WAF. L'expiration est celle du WAF (timeout nft), pas un débannissement par garde.
- **Seuils** : garde consomme les **verdicts** des capteurs (seuil du capteur DPI d'Actor, alertes du capteur DNS) ; il ne refait
  pas la détection. Familles d'infection : domaine malveillant listé, DGA, exfiltration par sous-domaines, réponses détournées.
- **Courriel** : toutes les box envoient par le relais SMTP de gk2 au travers du maillage, expéditeur `<nœud>@secubox.in` (SPF/DKIM
  portés par gk2) ; sans maillage ni relais, bandeau dans la webapp.
- **SMS** : un compte Free Mobile (celui du propriétaire), réglable par box ; en échec (API, WAN), file d'attente persistée et
  bandeau dans la webapp.
- **Redémarrage** : `garde.db` fait foi ; au démarrage, rapprochement : bans et quarantaines en cours réappliqués avec leur heure de
  fin d'origine ; la réévaluation à 24 h part de l'heure de la décision.

## Laissé au constructeur

- Mécanique exacte d'abonnement à actord (socket, relecture de fichier) selon ce qu'actord permet.
- Liste des noms « indispensables » de la quarantaine par famille d'appareil (point de départ : heure, box, mises à jour système).
- Découpage en lots ; ordre suggéré : (1) notifications courriel/SMS, (2) intrusion → ban, (3) infection → quarantaine, (4) évasion,
  (5) page.

## Décisions prises par l'assistant (à vérifier par le propriétaire)

- Nom `secubox-garde`, module séparé plutôt qu'extension d'ad-guard ou du WAF (il croise les deux).
- Durées : ban 4 h ×4 par récidive (plafond 30 j) ; quarantaine 24 h ; non-récidive 7 j après libération.
- Seuil « infection » : domaine listé malveillant seul, ou deux familles de signes en 1 h.
- Plafond de 3 quarantaines simultanées.
- Bans d'intrusion résumés par heure plutôt qu'un SMS chacun.
