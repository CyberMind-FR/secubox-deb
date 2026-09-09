# Guide d'export vers l'imprimeur

Procédure pas-à-pas pour passer de la maquette terminée aux fichiers remis à
l'imprimeur et au bon à tirer. Les réglages détaillés d'InDesign et de Scribus
sont dans [PRINT_PIPELINE.md](PRINT_PIPELINE.md) ; le choix des profils dans
[COLOR_MANAGEMENT.md](COLOR_MANAGEMENT.md). Comptez une demi-journée pour un
livret, une journée pour un livre, en incluant les vérifications.

## Sommaire

1. [Avant de commencer : le devis](#1-avant-de-commencer--le-devis)
2. [Étape 1 — Geler la maquette](#2-étape-1--geler-la-maquette)
3. [Étape 2 — Vérifier les liens et les images](#3-étape-2--vérifier-les-liens-et-les-images)
4. [Étape 3 — Vérifier le texte](#4-étape-3--vérifier-le-texte)
5. [Étape 4 — Vérifier les couleurs](#5-étape-4--vérifier-les-couleurs)
6. [Étape 5 — Exporter le PDF/X-4](#6-étape-5--exporter-le-pdfx-4)
7. [Étape 6 — Contrôler le PDF](#7-étape-6--contrôler-le-pdf)
8. [Étape 7 — Nommer et livrer](#8-étape-7--nommer-et-livrer)
9. [Étape 8 — Bon à tirer](#9-étape-8--bon-à-tirer)
10. [Étape 9 — Archiver](#10-étape-9--archiver)
11. [Particularités par gabarit](#11-particularités-par-gabarit)
12. [En cas de problème](#12-en-cas-de-problème)

## 1. Avant de commencer : le devis

Le devis de l'imprimeur, ou sa fiche technique, fixe des paramètres que
l'export doit respecter. Relever, et si une information manque, la demander
par écrit :

| Information | Exemple | Où elle intervient |
|-------------|---------|--------------------|
| Format fini | 148 × 210 mm | TrimBox |
| Fond perdu demandé | 3 mm (parfois 5 mm) | BleedBox, réglage d'export |
| Norme PDF | PDF/X-4 (parfois X-1a) | Préréglage d'export |
| Profil ICC de sortie | ISO Coated v2 300 % (ECI) | Destination et Output Intent |
| Papier intérieur et couverture | Couché mat 135 g/m², 250 g/m² | Choix du profil, noir riche |
| Reliure | Piqûre à cheval | Multiple de pages, chasse |
| Épaisseur du dos (dos carré collé) | 6,2 mm pour 96 pages en 90 g/m² | Largeur du document de couverture |
| Pages simples ou planches | Pages simples | Réglage d'export |
| Compensation de la chasse | À la charge de l'imprimeur | À demander |
| Surimpression du noir au RIP | Oui | Évite de la gérer objet par objet dans Scribus |
| Mode de livraison | Portail web, WeTransfer, FTP | Étape 7 |
| Épreuve | Contractuelle sur 4 pages + couverture | Étape 8 |

## 2. Étape 1 — Geler la maquette

1. Terminer toutes les corrections éditoriales ; la relecture finale sur
   papier (épreuve de bureau à 100 %) est faite et intégrée.
2. Incrémenter la version du document (`v03` → `v04`) et l'enregistrer sous
   ce nouveau nom, en conservant l'ancienne version intacte.
3. Supprimer ou masquer les calques de travail (grilles SVG, commentaires,
   variantes) ; ne laisser visibles que les calques imprimables.
4. Supprimer les objets hors page (table de montage) : InDesign les ignore
   à l'export mais Scribus peut les signaler ; dans tous les cas ils alourdissent
   le fichier.
5. Vérifier le nombre de pages et l'ordre : pages simples, page 1 en recto,
   multiple attendu par la reliure, pages blanches présentes là où le chemin
   de fer les prévoit.

## 3. Étape 2 — Vérifier les liens et les images

1. Ouvrir le panneau des liens (InDesign : « Fenêtre › Liens » ; Scribus :
   « Extras › Gérer les images »). Aucun lien manquant, aucun lien modifié
   non actualisé.
2. Contrôler la **résolution effective** de chaque image : la colonne « PPP
   réels » d'InDesign ou le vérificateur de Scribus. Toute image en tons
   continus sous 250 ppp est remplacée par un fichier de meilleure
   définition ou réduite d'emprise (jamais rééchantillonnée vers le haut).
3. Vérifier que les images placées sont les versions de travail finales
   (`CH03_012_…tif`) et non les aperçus `_web.jpg`.
4. Vérifier que chaque image RVB porte un profil ; attribuer le profil aux
   images non étiquetées dans le logiciel d'image, puis actualiser le lien.
5. Vérifier les images à fond perdu : le bloc dépasse bien de 3 mm hors
   page, et l'image remplit le bloc (pas de bande blanche dans le fond perdu).
6. Vérifier les images en pleine ouverture : le sujet est hors du pli, et
   sur un dos carré collé le recouvrement est prévu.

## 4. Étape 3 — Vérifier le texte

1. Rechercher les **débordements** : InDesign, « Contrôle en amont »
   (« Texte en excès ») ; Scribus, vérificateur (« Débordement de texte »).
   Aucun toléré.
2. Rechercher les **polices manquantes** ou substituées (« Texte › Rechercher
   une police ») ; toutes les polices doivent être installées et incorporables.
3. Vérifier les **styles** : tout paragraphe porte un style `MB-P/` sans
   surcharge locale non voulue (« Fenêtre › Styles › Effacer les remplacements »
   pour repérer les écarts).
4. Contrôler la **typographie française** : rechercher `?`, `!`, `;`, `:`,
   `«`, `»` précédés ou suivis d'une espace ordinaire au lieu d'une espace
   insécable ; rechercher les apostrophes droites `'` ; rechercher les doubles
   espaces.
5. Contrôler les **veuves, orphelines et lignes creuses** page par page en
   affichage « planches » à taille réduite : une ligne seule en haut ou en bas
   de colonne, un mot seul en dernière ligne de paragraphe.
6. Vérifier les **folios et titres courants** : présents sur les pages
   courantes, masqués sur les liminaires et les pleines pages ; le titre
   courant du recto correspond bien au chapitre.
7. Vérifier le **sommaire** : chaque entrée pointe vers le bon folio (mettre
   à jour la table des matières automatique si elle existe).
8. Vérifier les **mentions légales** de la page 4 (ou C2) : ISBN, dépôt légal
   (« Dépôt légal : mois année »), achevé d'imprimer avec le nom de
   l'imprimeur, crédits, mention de droits.

## 5. Étape 4 — Vérifier les couleurs

1. Ouvrir le nuancier : supprimer les couleurs inutilisées ; convertir en
   CMJN toute couleur RVB restante ; convertir en quadri les tons directs non
   prévus au devis.
2. Rechercher le **noir quadri** : InDesign, « Aperçu de la séparation »
   avec la seule plaque K affichée, puis chaque plaque C, M, J : aucun texte
   ne doit apparaître sur C, M ou J. Scribus : « Affichage › Aperçu de la
   sortie » avec les plaques.
3. Vérifier la **limite d'encrage** : « Aperçu de la séparation › Limite
   d'encre » à la valeur du profil (300 %) ; aucune zone rouge. Corriger les
   aplats fautifs en noir riche 60 / 40 / 40 / 100.
4. Vérifier la **surimpression** : InDesign, « Affichage › Aperçu de la
   surimpression » ; le texte noir sur fond coloré ne doit pas montrer de
   liseré blanc ; aucun objet coloré ne doit disparaître (surimpression
   accidentelle d'un objet clair sur un fond sombre).
5. Activer l'**épreuvage à l'écran** avec le profil de sortie et parcourir
   les images une dernière fois ; noter celles qui appellent une épreuve
   contractuelle.

## 6. Étape 5 — Exporter le PDF/X-4

Appliquer le préréglage « MatrixBook X-4 » décrit dans
[PRINT_PIPELINE.md](PRINT_PIPELINE.md#9-export-depuis-indesign) (InDesign) ou
[PRINT_PIPELINE.md](PRINT_PIPELINE.md#10-export-depuis-scribus) (Scribus),
en adaptant :

1. **Destination et Output Intent** = profil du devis.
2. **Fond perdu** = valeur du devis (3 mm par défaut).
3. **Pages** = « Pages simples », sauf demande de planches.
4. **Traits de coupe** = oui, décalage 3 mm ; pas d'autres repères sauf
   demande.
5. Exporter l'**intérieur** et la **couverture** dans deux PDF séparés,
   sauf pour la carte postale (un PDF de 2 pages : recto, verso) et sauf si
   l'imprimeur demande un fichier unique pour un livret agrafé (alors
   C1, C2, pages intérieures, C3, C4 dans l'ordre de lecture).
6. Ne jamais exporter « pour le web », « taille minimale » ni « PDF/A » pour
   l'imprimeur.

Le nom du fichier suit la nomenclature (étape 7) dès l'export.

## 7. Étape 6 — Contrôler le PDF

Ouvrir le PDF exporté, **pas le document source**, et dérouler la liste de
contrôle de [PRINT_PIPELINE.md](PRINT_PIPELINE.md#6-vérification-prépresse) :

1. **Contrôle en amont** (Acrobat Pro, profil « Conformité PDF/X-4 ») ou, sans
   Acrobat, la série de commandes libres :

   ```bash
   pdffonts  MB_projet_format_interieur_v04_X4.pdf        # toutes « emb yes »
   pdfimages -list MB_projet_format_interieur_v04_X4.pdf  # x-ppi / y-ppi ≥ 250
   exiftool -PDFXVersion -OutputIntent* MB_projet_format_interieur_v04_X4.pdf
   pdfcpu info MB_projet_format_interieur_v04_X4.pdf      # TrimBox, BleedBox
   gs -q -o - -sDEVICE=inkcov MB_projet_format_interieur_v04_X4.pdf
   ```

2. **Boîtes de page** : TrimBox au format fini exact ; BleedBox = TrimBox +
   fond perdu ; identiques sur toutes les pages.
3. **Nombre de pages** et ordre ; feuilleter en mode « deux pages, page de
   couverture séparée » pour voir les doubles pages comme le lecteur.
4. **Aperçu de la sortie** (Acrobat : « Outils › Impression › Aperçu de la
   sortie ») : plaques, noir quadri, TAC.
5. **Zoom à 400 %** sur trois pages au hasard : netteté des images, absence
   de pavés d'aplatissement, texte vectoriel.
6. **Impression d'une épreuve de bureau** à 100 % avec les traits de coupe
   d'au moins une double page et de la couverture, pour vérifier les
   dimensions au réglet.

Toute correction se fait dans le document source, suivie d'un nouvel export
sous une nouvelle version. On ne corrige jamais un PDF à la main pour
l'imprimeur.

## 8. Étape 7 — Nommer et livrer

### 8.1 Nommage

Conformément à la [nomenclature](DESIGN_SYSTEM.md#9-nomenclature-des-fichiers) :

```text
MB_<projet>_<format>_<partie>_v<version>_X4.pdf

MB_le-cruet_livret-a5_interieur_v04_X4.pdf
MB_le-cruet_livret-a5_couverture_v04_X4.pdf
MB_le-cruet_carte-postale_serie-01_v02_X4.pdf
```

Sans accent, sans espace, sans « final ». Le numéro de version du PDF est
celui du document source dont il est issu.

### 8.2 Bordereau

Joindre un court bordereau (courriel ou fichier texte `LISEZMOI.txt`) qui
reprend :

- le nom du projet et la référence du devis ;
- la liste des fichiers avec leur rôle (intérieur, couverture) et leur nombre
  de pages ;
- le format fini, le fond perdu, le profil de sortie utilisé, la norme PDF ;
- le papier et la reliure tels que devisés ;
- les demandes explicites : compensation de la chasse, surimpression du noir
  au RIP, épaisseur du dos utilisée pour la couverture ;
- les pages pour lesquelles une épreuve contractuelle est souhaitée ;
- un contact et un délai de réponse pour le bon à tirer.

### 8.3 Transfert

Utiliser le canal indiqué par l'imprimeur (portail, WeTransfer, FTP). Ne pas
compresser les PDF dans une archive protégée par mot de passe. Après envoi,
vérifier le poids des fichiers reçus (l'imprimeur confirme) et conserver
l'accusé de réception.

## 9. Étape 8 — Bon à tirer

1. L'imprimeur renvoie une **épreuve** : PDF de contrôle basse résolution
   (« ozalid numérique »), parfois une maquette pliée, et l'épreuve
   contractuelle couleur si elle a été commandée.
2. Vérifier sur l'épreuve numérique : ordre des pages, imposition, sens de
   lecture, position du dos, absence de page manquante ou dupliquée,
   fond perdu visible, folios. C'est le dernier moment pour repérer une
   inversion de pages.
3. Vérifier sur l'épreuve contractuelle : la couleur des pages critiques,
   sous lumière du jour ou D50, à côté de l'écran en épreuvage.
4. Toute correction implique un nouvel export, une nouvelle version et une
   nouvelle épreuve. L'imprimeur facture souvent les épreuves
   supplémentaires : d'où l'importance des étapes 2 à 6.
5. Signer le **bon à tirer** (BAT) sur le document de l'imprimeur ; conserver
   une copie nommée `…_BAT.pdf` avec la date. Le BAT engage : ce qui n'a pas
   été vu sur l'épreuve signée ne peut être reproché à l'imprimeur.

## 10. Étape 9 — Archiver

Après le tirage, archiver ensemble, dans un dossier daté :

| Élément | Format |
|---------|--------|
| Document source de la version BAT, avec assemblage (InDesign : « Fichier › Assemblage » ; Scribus : « Fichier › Rassembler pour la sortie ») | Dossier complet : document, liens, polices (si la licence le permet) |
| Export IDML (InDesign) ou copie SLA (Scribus) de la version BAT | Fichier interopérable |
| PDF/X-4 intérieur et couverture livrés | PDF |
| BAT signé | PDF |
| Devis, bordereau, échanges avec l'imprimeur | PDF ou texte |
| Inventaire du corpus et chemin de fer | Markdown ou tableur |
| Un exemplaire imprimé | Papier |

L'archive permet une réimpression à l'identique, ou une réédition en changeant
seulement ce qui doit l'être. Conserver aussi les sources d'images (`SRC_…`)
dans leur dossier propre.

## 11. Particularités par gabarit

### Carte postale

- Un seul PDF de 2 pages (recto, verso), ou deux PDF si l'imprimeur le
  demande ; les deux faces au même format avec fond perdu.
- Vérifier que le verso est orienté comme le recto (pas de tête-bêche) et
  que la zone d'adresse et le rectangle du timbre sont dans la zone sûre.
- Pour une série, un PDF par carte ou un PDF multipage dans l'ordre de la
  série ; le numéro de série figure sur le verso.
- Papier 300 à 350 g/m² : demander si un vernis ou un pelliculage est prévu
  au recto (il modifie légèrement les couleurs et interdit l'écriture au
  stylo sur cette face).

### Livret agrafé A5

- Nombre de pages intérieures multiple de 4 ; couverture en 4 pages simples
  ou intégrée à l'intérieur si l'imprimeur le demande (« autocouverture »).
- Demander la compensation de la chasse au-delà de 32 pages.
- Sur les pages centrales, vérifier qu'aucun texte n'est à moins de 7 mm
  du bord extérieur si le livret dépasse 48 pages.

### Livre A5 et A4, dos carré collé

- Intérieur et couverture en PDF séparés ; couverture **à plat** (C4 + dos +
  C1) dans un document dont la largeur inclut l'épaisseur de dos fournie par
  l'imprimeur ; texte du dos centré, sens de lecture de haut en bas (usage
  français).
- Prévoir un recouvrement de 3 à 5 mm au pli pour les images en pleine
  ouverture, ou fournir ces images en continu à l'imprimeur.
- Vérifier la marge intérieure (14 mm en A5, 20 mm en A4) sur toutes les
  pages : un texte trop proche du dos est illisible sans casser le livre.
- Demander une **maquette en blanc** (livre vierge au bon papier et au bon
  nombre de pages) pour valider l'épaisseur du dos avant d'exporter la
  couverture.

## 12. En cas de problème

| Message de l'imprimeur | Signification | Action |
|------------------------|---------------|--------|
| « Il manque le fond perdu » | Les images ne dépassent pas du format fini ou l'export n'a pas inclus le fond perdu | Étendre les blocs à 3 mm hors page ; réexporter avec « Utiliser les paramètres de fond perdu du document » |
| « Polices non incorporées » | Une police protégée refuse l'incorporation, ou l'export est en PDF générique | Remplacer la police par une famille libre autorisée ; réexporter en X-4 |
| « Images basse résolution » | Résolution effective sous 250 ppp | Remplacer l'image ou réduire son emprise |
| « Noir en quadri sur le texte » | Texte RVB ou noir converti | Appliquer `MB-Noir texte` ; supprimer les couleurs RVB du nuancier |
| « Dépassement d'encrage » | TAC au-delà de 300 % | Noir riche 60 / 40 / 40 / 100 ; conversion par profil des images |
| « Profil non conforme » | Output Intent différent du devis | Réexporter avec le bon profil |
| « Nombre de pages incorrect » | Pas multiple de 4 (agrafé) ou de 16 (cousu) | Ajouter une respiration ou une page de sources |
| « Épaisseur de dos erronée » | Couverture calculée avec une autre épaisseur | Redemander l'épaisseur exacte ; recomposer la couverture |
| « Éléments hors zone de sécurité » | Texte ou logo à moins de 5 mm de la coupe | Déplacer ; vérifier la zone sûre du gabarit |
| « Transparence non aplatie » | L'imprimeur demande du X-1a | Réexporter en X-1a avec le préréglage d'aplatissement « Haute résolution » et contrôler page par page |

Aucun de ces messages ne se règle en retouchant le PDF : on corrige la source,
on incrémente la version, on réexporte, on recontrôle.
