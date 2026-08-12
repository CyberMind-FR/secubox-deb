# Parcours administrateur

Vous tenez la SecuBox — pour vous, ou pour d'autres. Ce que vous changez ici a
des conséquences que les utilisateurs subiront.

Prérequis : les parcours [débutant](beginner-path.md) et
[utilisateur](user-path.md). On n'administre pas correctement un service dont on
ne s'est jamais servi.

## Les comptes

- Créer un compte
- Réinitialiser un mot de passe
- Désactiver un compte — jamais le supprimer

## Les modules

- Installer un module
- Comprendre le catalogue
- Démarrer, arrêter, redémarrer un service
- Lire l'état d'un module

## Exposer sur internet

- Publier un service
- Obtenir un certificat
- Comprendre la chaîne : HAProxy → WAF → nginx → module

> Trois défauts de cette chaîne ont été relevés en documentant. Ils sont
> consignés dans [CODE-ISSUES-DISCOVERED](../CODE-ISSUES-DISCOVERED.md) et non
> corrigés ici.

## Surveiller

- Lire les journaux
- Surveiller les ressources
- Comprendre une alerte

## Quand ça casse

- Un service ne répond plus
- Un site répond 403, 421, 502 ou 504
- Un certificat a expiré

## Deux règles

**Ne jamais corriger à la main sur la board.** Une correction hors paquet
disparaît à la prochaine mise à jour, et personne ne saura pourquoi le problème
est revenu. La correction se fait dans le paquet.

**Un redémarrage n'est pas un diagnostic.** Il masque la cause et la fait
revenir plus tard, quand plus personne ne fera le lien.
