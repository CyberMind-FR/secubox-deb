# Tâche 3 : rapport

Construit : packages/secubox-ai/api/contexte_auto.py (lire_meta_gguf, kv_par_jeton, contexte_auto) et
tests/test_contexte_auto_3583.py (GGUF synthétiques).
- Lecteur GGUF v2/v3 stdlib : types 0-12, tableaux imbriqués (profondeur <= 4), saute les valeurs non demandées
  (seek), s'arrête dès que toutes les clés sont trouvées. Bornes : paires <= 100 000, clé <= 1 Kio, chaîne lue
  <= 1 Mio, tableau lu <= 65 536, tout saut/lecture borné par la taille du fichier. Malformé -> ValueError.
- contexte_auto(chemin, dispo_mo, memoire_max_mo, reserve_mo=512) : budget = min(dispo - reserve, max - poids du fichier),
  multiple de 1024, borné 4096-32768 et par context_length du modèle ; illisible -> 4096. Cache par (chemin, mtime).
- Sans import FastAPI/httpx/reglages.
TDD : tests et implémentation écrits ensemble, pas de RED exécuté séparément (concern mineur).
GREEN : `.venv/bin/python -m pytest packages/secubox-ai/tests -q` -> 27 passed (qwen35 = 32768, llama = 114688).
Concern : le .venv n'existe pas dans le worktree ; utilisé celui du checkout principal.

## Correctif, tour 1
1. kv_par_jeton : seules les valeurs entières > 0 (hors booléens ; listes d'entiers > 0 pour head_count*) sont
   acceptées ; sinon (None, None) -> 4 096 ; context_length illisible = plafond ignoré. contexte_auto ne lève plus.
2. Budget : min(dispo - reserve - poids, memoire_max - poids). Docstring mise à jour ; test avec fichier creux de 1000 Mo.
3. lire_meta_gguf : os.open(O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) + fstat + S_ISREG, taille fstat ; kv_par_jeton
   et contexte_auto passent par un lstat gardé (jamais d'ouverture d'un FIFO) ; cache clé (chemin, mtime_ns, taille).
Tests ajoutés : métadonnées inexploitables (7 cas), context_length illisible (3), poids, FIFO, lien symbolique.
Commande : .venv/bin/python -m pytest packages/secubox-ai/tests -q -> 40 passed.
