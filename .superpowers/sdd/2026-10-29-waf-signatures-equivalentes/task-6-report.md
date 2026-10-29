# Tâche 6 : compléments C1 à C5 — rapport

## Fait
- `multipart.go` : `ResultatMultipart.EntetesPartieMax` (compteur de lignes non vides du bloc d'en-têtes dans `entetes()`, continuations comprises, maximum sur les parties) et `FichiersVides` (branche fichier, filename vide, sautée ou non). Signaux `entetes_partie_max` et `fichiers_vides` dans `ResultatMultipart.Signaux()`.
- `entreephp.go` : `corpsSansLongueur(r)` (C1), `EntreePHP.SansLongueur` posé par `nouvelleEntreePHP` (en-têtes seulement), `variablesMax()` et signal `variables` (max requête/corps, bruts).
- `rules.go` : cinq contrôles (`corps_sans_longueur`, `entetes_partie`, `fichiers_vides`, `variables_nombre`, `upload_progress_present`) dans `parametreRequis` et `declenche` ; `variables_nombre` inscrit dans `controlesRequete` (la requête n'est lue que si C4 est chargée).
- Corpus de test propre dans `complements_test.go` (php2shell-005..008, php-006 ; seuils C2/C3 avec le champ `"seuil": "provisoire, non sourcé (2026-10-29)"`). Le catalogue réel `waf-rules.json` est laissé à la tâche 8.

## Preuves TDD
Tests écrits d'abord ; premier lancement : échec de compilation (`corpsSansLongueur`, `EntetesPartieMax`, `FichiersVides`, `SansLongueur` inconnus), ce que le brief attend. Puis vert : `go test -race -run 'SansLongueur|EntetesPartie|FichiersVides|Complements'` ok.
Tests : TestCorpsSansLongueur, TestAnalyserMultipartEntetesPartie (12/13 lignes, légitime 2, maximum sur parties), TestAnalyserMultipartFichiersVides, TestComplementsSignatures (seuils 9/8, 21/20, 1001/1000 corps et requête, php-006 seul, gravités), TestComplementsSignaux, TestCorpsChunkedSansLongueurJournalise (banc HTTP, backend reçoit tout, aucune sanction), TestComplementsVariablesRequeteJournalise, TestComplementsVariablesCorpsTronque, TestComplementsGETSansLigne.

## Vérifications
gofmt propre, `go vet ./cmd/sbxwaf/` propre, `go test -race ./...` : tout vert sauf `cmd/sbx-authwatch` (4 tests, préexistants : TestCampagneBannitDesLaPremiereTentative, TestCompteInexistantBannitDesLaPremiereTentative, TestLeurreBannitDesLePremierContact, TestJournalAttendLaRepetition). Fuzz FuzzAnalyserMultipart 30 s : PASS.

## Relecture du diff
Rien n'est calculé avant le relais sauf C1 (en-têtes seulement, coût constant). C2/C3 se lisent dans l'analyseur déjà en place (aucune lecture de plus). C4 : requête lue seulement si la signature est chargée ; corps tronqué : ne compte que le vu. Journal : compteurs seulement.

## Préoccupations
- TestComplementsVariablesCorpsTronque était vert d'emblée (la fenêtre de 4096 octets ne voit que ~600 variables) : il garde un comportement, il n'a pas été vu rouge.
- Un corps urlencoded tronqué en milieu de segment peut compter un dernier segment partiel (+1 au plus).
- Le catalogue `waf-rules.json` n'a pas encore les signatures C1 à C5 : tâche 8.
