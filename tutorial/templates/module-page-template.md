# Modèle — page de module

Une page par module du catalogue. Elle répond à trois questions, dans cet
ordre : **à quoi ça sert**, **comment je m'en sers**, **où c'est branché**.

---

## <Nom lisible du module>

> Une phrase, sans jargon, qui dit à quoi ça sert.
> Pas la description technique du manifeste — celle-ci est destinée aux machines.

### À quoi ça sert

Deux ou trois phrases, du point de vue de l'utilisateur.

### Pour l'utilisateur

| Je veux… | Tutoriel |
|---|---|
| … | [lien](…) |

### Pour l'administrateur

| Je veux… | Tutoriel |
|---|---|
| … | [lien](…) |

### Ce que ça remplace

Le service commercial équivalent, s'il existe. C'est souvent la phrase qui fait
comprendre le module d'un coup.

### Repères techniques

| | |
|---|---|
| Identifiant | `secubox-<nom>` |
| Catégorie | … |
| Dépend de | … |
| Interface web | … |
| CLI | … |
| API | … |
| Conteneur | oui / non |

### Source technique

```text
package:  packages/secubox-<nom>/
service:  …
api:      …
web:      …
```

---

<!--
RÈGLES DE LA PAGE MODULE

- Les « Repères techniques » se recopient depuis tutorial/catalog/modules.yaml,
  qui est GÉNÉRÉ. Ne pas les ressaisir de mémoire : ils divergeraient.
- « Ce que ça remplace » n'est pas du marketing — c'est souvent l'accroche qui
  rend le module intelligible à quelqu'un qui n'en a jamais entendu parler.
- Si le module n'a pas de tutoriel, l'écrire : une page module sans tutoriel est
  une page de catalogue, pas de la documentation.
-->
