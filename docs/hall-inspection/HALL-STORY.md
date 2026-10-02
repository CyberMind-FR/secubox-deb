# HALL-STORY — présenter SecuBox à quelqu'un qui ne connaît pas le produit

Parcours idéal en **8 minutes**, en visiteur invité, sur https://hall.gk2.secubox.in/. Chaque étape ne s'appuie que sur ce que Chromium a réellement affiché et fait fonctionner (voir HALL-SCREENS.md pour les captures). Les écrans cassés sont **évités** ; ils sont listés à la fin.

**Préparer** : fenêtre de navigateur en 1440×900 ou plus, thème papier, son coupé au début (deux lecteurs démarrent seuls), onglet neuf pour que la fenêtre de bienvenue s'affiche. Depuis le LAN on voit en plus Freebox TV, DPI, Zigbee et Lyrion ; **pour une démonstration publique, restez sur ce qu'un visiteur externe voit.**

## Le fil rouge
> « Vous avez déjà des services chez vous : musique, vidéos, courriel, fichiers. SecuBox les rassemble dans un bureau, chez vous, et chacun reste maître de ses données. »

| # | Temps | Action | Ce qui s'affiche | Ce qu'on dit |
|---|---|---|---|---|
| 1 | 0:00 | Ouvrir le Hall, lire la fenêtre de bienvenue, cliquer **« Entrer dans le Hall → »** | « Le Hall vous accueille. Ce n'est pas un portail de liens » + quatre gestes | « C'est un bureau, pas un annuaire de liens : chaque service y vit dans une carte. » |
| 2 | 0:45 | Laisser l'accueil se charger, pointer le pied d'écran | mosaïque de cartes vivantes ; « 81 en ligne · 113 modules » ; invité non connecté | « Tout ce que vous voyez est en direct, sur une seule petite boîte. Je suis ici simple visiteur. » |
| 3 | 1:30 | **Radio** : écouter, regarder « L'antenne » et la playlist | piste en cours, auditeurs, chat du parc | « Une radio de la maison que tout le monde écoute au même endroit du morceau. » |
| 4 | 2:30 | Cliquer **📡** (pastille de la barre du haut) | une vidéo « Direct » en grand | « Quelqu'un propose un morceau au parc : on le rejoint, comme une télé partagée. » |
| 5 | 3:15 | **MetaNews** puis **Podcaster** (un épisode) | actualités regroupées par sujets avec plusieurs sources ; épisodes avec lecteur | « L'actualité sans pub : un fait, plusieurs sources. Les podcasts sont téléchargés chez vous. » |
| 6 | 4:15 | **Forums** (BBS puis Billets), puis **Messagerie** | fils, billets, mur public | « Un lieu d'écriture pour la communauté de la box. En visiteur, on lit ; on écrit une fois admis. » |
| 7 | 5:15 | Menu **Services ▾** puis **Tout le parc…** | 31 services puis 113 modules en six familles | « Voici toute la boîte : une muraille de sécurité, un esprit, un maillage… Ce sont des modules, pas des applis disparates. » |
| 8 | 6:15 | Taper une adresse dans la barre (par exemple `example.com`) | page relayée, bandeau « relayé, pisteurs coupés » | « Même le web passe par la boîte : pisteurs, pubs et cookies coupés. » |
| 9 | 7:00 | Profil **Invité → Demander un accès…** | écran Accès : « Une invitation ouvre une session à un appareil » | « On n'entre pas avec un mot de passe partagé : on demande un accès, un administrateur compare l'empreinte de l'appareil. » |
| 10 | 7:30 | **◐** (thème nuit), puis le **« ? »** d'une carte | tout le Hall change de thème ; une bulle explique la carte | « Chaque carte s'explique elle-même. » |

**Conclusion (30 s)** : revenir à l'accueil, montrer la devise du pied d'écran : « mon bureau numérique souverain : mes services et mes données, hébergés chez moi, sous mon contrôle ».

## Si la personne veut aller plus loin (avec une session)
Les écrans ci-dessous existent mais ne se montrent pas en invité : Mes comptes, Mon coffre et Coffre (la clé maîtresse et les compartiments de chacun), Sécurité (le pare-feu applicatif SBXWAF), Renseignement (les attaquants et la défense graduée), Nextcloud, webmail, Photos. Les présenter après une connexion, dans cet ordre : **Sécurité → Renseignement → Coffre**.

## À éviter en direct (affichés mais non fonctionnels le jour du test)
- **Lexie** : répond « Service vocal injoignable (HTTP 401) ».
- **Photos** (PhotoPrism) : « 504 — Délai dépassé ».
- **Lyrion** : interface visible, mais « Pas de platine » et appels qui échouent.
- **Mood** : « HORS LIGNE », demande un micro.
- **Mes comptes** : « Identité injoignable pour le moment ».
- **Sécurité / Renseignement en cadre** : textes sans données tant qu'on n'est pas connecté.
- **SBX OS embarqué dans un grand cadre** : reste blanc ; l'ouvrir seule (`/sbxos/`) fonctionne et montre « Votre Hall — GUEST ».
- **Nextcloud, PeerTube (compte), Mail** : mènent à un formulaire de connexion.

## Les trois plans qui feraient une bonne vidéo de 60 secondes
1. L'accueil qui se charge, cartes qui s'animent, pied d'écran « 113 modules ».
2. La radio et la diffusion en direct qui démarrent sans clic.
3. La vue « Tout le parc » défilant les six familles.
