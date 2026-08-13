# Modèle — fiche de dépannage

Une fiche de dépannage part **du symptôme**, jamais de la cause.

L'utilisateur ne sait pas que son certificat a expiré ; il voit « connexion non
privée ». Une fiche classée par cause lui est inutilisable : il ne peut pas la
trouver.

---

## <Ce que l'utilisateur voit>

**Exemple exact du message**, recopié tel quel :

```text
<message>
```

### Ce qui se passe

Deux phrases, sans jargon. Ce que le système a réellement fait, et pourquoi.

### À vérifier, dans cet ordre

Du plus fréquent au plus rare — l'ordre est le service rendu.

1. **<Vérification>** → si <constat>, alors <remède>
2. **<Vérification>** → si <constat>, alors <remède>
3. **<Vérification>** → si <constat>, alors <remède>

### Si rien n'y fait

Ce qu'il faut transmettre à un administrateur, pour qu'il n'ait pas à
redemander :

- l'heure exacte de la tentative ;
- le message affiché, en entier ;
- ce qui a été tenté.

### Côté administrateur

```bash
# Commandes de diagnostic — jamais de correctif à l'aveugle
```

---

<!--
RÈGLES DU DÉPANNAGE

- Le TITRE est le symptôme, mot pour mot. C'est ce que l'utilisateur va
  chercher, souvent par copier-coller.
- L'ordre des vérifications suit la FRÉQUENCE réelle, pas la logique technique.
- Aucune commande destructive dans la partie utilisateur.
- « Redémarrer le service » n'est pas un diagnostic : cela masque la cause et la
  fait revenir plus tard, quand plus personne ne fera le lien.
-->
