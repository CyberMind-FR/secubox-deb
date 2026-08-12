# Design system documentaire

## Ce que les illustrations doivent produire

Les deux impressions du projet, **en même temps** :

> « C'est simple, je peux le faire. »
> « Derrière cette simplicité, le système est sérieux. »

Une illustration trop enfantine détruit la seconde. Une illustration trop
austère détruit la première. Le point d'équilibre est un univers **soigné et
tangible**, pas un univers mignon.

## Fond clair, contraste élevé

Le fond est **majoritairement clair**.

Ce n'est pas une préférence esthétique. La documentation sera :

- lue sur un téléphone en plein jour ;
- projetée dans une salle éclairée ;
- **imprimée** — un fond sombre y consomme l'encre et perd le texte fin.

Éviter en particulier la dominante ambrée ou sombre : c'est le réflexe
« cyberpunk » attendu, il se lit mal et il date déjà.

## Univers 2D½

Volume léger, ombres portées douces, profondeur de champ courte. L'objet doit
sembler **posé** sur la page, pas dessiné dessus.

Référence : la pâte à modeler et la miniature. Matière mate, arêtes arrondies,
imperfections assumées. Ce qui est modelé à la main inspire plus confiance
qu'un rendu parfait — et vieillit beaucoup mieux.

## Les bulles de savon

Les concepts et les actions sont contenus dans des **bulles**.

Elles disent l'essentiel sans l'écrire : ce qu'elles contiennent est **léger,
manipulable, et peut éclater**. C'est exactement ce qu'est une action réversible
dans une interface — et cela prépare, sans discours, l'idée qu'on peut essayer
sans casser.

Une bulle contient **une** idée. Deux idées dans une bulle, c'est deux bulles.

## Les Zanimalos

Les personnages sont des **guides**, jamais des décorations.

Règle absolue : **un Zanimalo ne recouvre jamais la zone d'action**. Le lecteur
regarde ce qu'il doit faire ; le guide l'accompagne depuis la marge.

Rôles récurrents :

| Rôle | Intervient pour |
|---|---|
| Guide utilisateur | les gestes du quotidien |
| Administrateur | ce qui engage la machine |
| Sécurité | mots de passe, chiffrement, accès |
| Réseau | connexion, VPN, DNS |
| Fichiers | stockage, partage, synchronisation |
| Communication | courriel, messages, forum |
| Média | audio, vidéo, diffusion |
| Dépannage | quand ça ne marche pas |

Le rôle se reconnaît **avant** le personnage : c'est lui qui porte l'information.

## Emplacements fixes

Une place constante pour chaque élément — le lecteur cesse alors de la chercher
et peut regarder le contenu.

```text
┌─────────────────────────────────────────────┐
│ TITRE                          n° · niveau  │
│                                    · durée  │
│                                             │
│                                             │
│            ZONE D'ACTION                    │
│         (jamais recouverte)                 │
│                                             │
│                                             │
│  ◆ conseil            ▲ avertissement       │
│                                             │
│ [guide]                    QR · étape suiv. │
└─────────────────────────────────────────────┘
```

| Zone | Contenu | Position |
|---|---|---|
| Titre | Titre du tutoriel | haut gauche |
| Repères | n° d'épisode, niveau, durée | haut droite |
| Action | l'écran, le geste | centre |
| Conseil | ce qui fait gagner du temps | bas gauche |
| Avertissement | ce qui peut mal tourner | bas centre |
| Guide | le Zanimalo | bas gauche, en marge |
| Suite | QR ou lien, étape suivante | bas droite |

## Couleurs

Palette **dynamique** : chaque famille de sujets porte sa teinte, ce qui permet
de reconnaître un domaine avant d'avoir lu le titre.

La couleur ne porte **jamais** seule une information : elle double toujours une
forme ou un mot. Un lecteur daltonien, une impression en noir et blanc, une
projection délavée — trois cas courants où la couleur seule disparaît.

`À documenter` — les valeurs exactes restent à arrêter avec la charte
SecuBox/Zanimalos existante. Voir `.claude/DESIGN-CHARTER.md`, qui fait autorité
pour l'interface et dont la documentation ne doit pas s'écarter sans raison.

## Ce qu'on ne fait pas

- Pas de capture d'écran non datée : elle contredira l'interface sans prévenir.
- Pas de texte incrusté dans l'image quand il peut rester du texte : l'image
  n'est ni traduisible, ni sélectionnable, ni lisible par un lecteur d'écran.
- Pas d'icône propriétaire sans nécessité.
- Pas de personnage qui commente l'action au lieu de la montrer.
