# secubox-freebox

Connecteur de l'API Freebox OS (v0.1, lecture). Conception : `docs/dossiers/connecteur-freebox.md`.

- **Autorisation** : `POST /api/v1/freebox/autoriser` (admin), puis appui sur ✓ sur la Freebox ; droits réglés dans
  Freebox OS → Paramètres → Gestion des accès → Applications. Le jeton d'application reste dans
  `/var/lib/secubox/freebox/app.json` (0600) et n'est jamais renvoyé ni journalisé.
- **Lecture** (`require_lecture`) : `/status`, `/appareils`, `/connexion`, `/pare-feu`, `/redirections`, `/autoriser/etat`.
- **Admin** (`require_jwt`) : `/autoriser`, `/revoquer`, `/explorer` (liste blanche de chemins).
- Panneau : `/freebox/` (menu Réseau). Socket `/run/secubox/freebox.sock`, utilisateur `secubox-freebox`, sans capacité.
- Écriture (redirections de ports) : v0.2, avec confirmation explicite et journal d'audit.
