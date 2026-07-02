# Issue: Évolutions secubox-p2p - DHT, Fédération, Master-Link

**ID:** P2P-EVO-2026-07-001  
**Créé:** 2026-07-02  
**Priorité:** HIGH  
**Statut:** IN_PROGRESS  
**Branche:** feature/p2p-dht-federation  
**Worktree:** ../secubox-p2p-evolutions  

---

## 📋 Description

Implémenter trois évolutions majeures pour le module **secubox-p2p** afin d'améliorer la découverte de pairs, la fédération de services et la gestion de topologies hiérarchiques.

## 🎯 Objectifs

### 1. **Découverte améliorée via DHT distribuée**
- **Problème:** La découverte actuelle repose principalement sur mDNS qui a des limitations en termes de portée réseau
- **Solution:** Implémenter une DHT (Distributed Hash Table) pour une découverte globale et résiliente
- **Technologie:** Utilisation de libp2p ou implémentation custom basée sur Kademlia
- **Avantages:** 
  - Découverte de pairs à travers des NAT
  - Résilience aux nœuds temporairement hors ligne
  - Scalabilité pour grand nombre de nœuds

### 2. **Fédération de services entre nœuds**
- **Problème:** Les services ne sont pas fédérés entre les nœuds P2P
- **Solution:** Créer un système de service discovery et de fédération
- **Fonctionnalités:**
  - Annonce de services disponibles sur chaque nœud
  - Découverte de services à travers le mesh
  - Gestion des versions et compatibilité
  - Système de health checks distribués

### 3. **Master-Link pour topologie hiérarchique**
- **Problème:** La topologie actuelle est plate (full mesh)
- **Solution:** Implémenter une topologie hiérarchique avec master/satellite
- **Avantages:**
  - Meilleure scalabilité
  - Gestion centralisée des politiques
  - Optimisation du routage
  - Contrôle d'accès renforcé

---

## 📁 Fichiers concernés

### Modules à créer/modifier:
- `packages/secubox-p2p/api/dht.py` - Implémentation DHT
- `packages/secubox-p2p/api/federation.py` - Fédération de services  
- `packages/secubox-p2p/api/masterlink.py` - Master-Link amélioré
- `packages/secubox-p2p/api/main.py` - Intégration des nouveaux endpoints
- `packages/secubox-p2p/api/mesh.py` - Extensions pour DHT

### Nouveaux endpoints API:
- `GET /p2p/dht/peers` - Liste des pairs découverts via DHT
- `POST /p2p/dht/announce` - Annonce d'un service via DHT
- `GET /p2p/federation/services` - Liste des services fédérés
- `POST /p2p/federation/register` - Enregistrement d'un service
- `GET /p2p/masterlink/topology` - Topologie hiérarchique
- `POST /p2p/masterlink/promote` - Promotion d'un nœud en master

---

## 🚀 Tâches

### Phase 1: DHT Distribuée ⭐
- [ ] Créer le module `dht.py` avec implémentation Kademlia
- [ ] Intégrer la DHT avec le mesh WireGuard existant
- [ ] Ajouter endpoints API pour la gestion DHT
- [ ] Implémenter la persistance des données DHT
- [ ] Tests unitaires pour la DHT

### Phase 2: Fédération de Services ⭐⭐
- [ ] Créer le module `federation.py`
- [ ] Implémenter le registry de services
- [ ] Ajouter système de discovery de services
- [ ] Intégrer avec la DHT pour propagation
- [ ] Health checks et monitoring
- [ ] Tests d'intégration

### Phase 3: Master-Link Hiérarchique ⭐⭐⭐
- [ ] Étendre `masterlink.py` existant
- [ ] Implémenter la promotion/démotion de nœuds
- [ ] Gestion des politiques de routage
- [ ] Système de heartbeats et failover
- [ ] Intégration avec OPAD pour sécurité
- [ ] Tests de résilience

---

## 📊 Critères d'acceptation

### DHT Distribuée
✅ Découverte de pairs à travers différents sous-réseaux  
✅ Résilience: maintien du mesh avec 30% de nœuds hors ligne  
✅ Temps de convergence < 5 secondes pour 100 nœuds  
✅ Intégration transparente avec WireGuard existant  

### Fédération de Services
✅ Enregistrement et découverte de services fonctionnel  
✅ Propagation des informations de services via DHT  
✅ Health checks automatiques toutes les 30 secondes  
✅ Gestion des versions et rétrocompatibilité  

### Master-Link Hiérarchique
✅ Topologie master/satellite opérationnelle  
✅ Promotion automatique en cas de failover  
✅ Optimisation du routage (latence < 10ms intra-cluster)  
✅ Intégration avec le système OPAD existant  

---

## 🔐 Considérations de sécurité

### OPAD Compliance
- Toutes les évolutions doivent respecter les principes OPAD:
  - **Détection passive par défaut**
  - **Réaction off-path opt-in**
  - **Journalisation systématique**
  - **Consentement explicite** pour toute inspection

### Chiffrement
- Maintenir le chiffrement WireGuard existant
- Ajouter chiffrement des données DHT sensibles
- Sécuriser les communications de fédération

### Accès
- Contrôle d'accès basé sur les rôles (RBAC)
- Authentification JWT pour les endpoints sensibles
- Audit logging de toutes les opérations

---

## 🧪 Tests

### Tests unitaires
```bash
# Tests DHT
pytest tests/test_dht.py -v

# Tests Fédération
pytest tests/test_federation.py -v  

# Tests Master-Link
pytest tests/test_masterlink.py -v
```

### Tests d'intégration
```bash
# Test découverte DHT
pytest tests/test_dht_integration.py -v

# Test fédérations multi-nœuds
pytest tests/test_federation_multi_node.py -v

# Test topologie hiérarchique
pytest tests/test_masterlink_hierarchy.py -v
```

### Tests de performance
- Temps de découverte: < 100ms pour 10 nœuds, < 1s pour 100 nœuds
- Consommation mémoire: < 100MB pour 1000 services fédérés
- CPU: < 10% sur Armada 7040 pour 100 pairs

---

## 📚 Documentation

- [ ] Mettre à jour README.md du module p2p
- [ ] Documenter les nouveaux endpoints API
- [ ] Créer un guide d'utilisation pour les évolutions
- [ ] Documenter les considérations de sécurité
- [ ] Exemples de configuration pour différentes topologies

---

## 🔗 Liens

- **Spec MESH:** `docs/specs/CM-MESH-MPCIE-2026-06.md`
- **Doctrine OPAD:** `docs/specs/CM-WALL-OPAD-2026-05.md`
- **Code existant:** `packages/secubox-p2p/`
- **Worktree:** `/home/reepost/CyberMindStudio/secubox-deb/secubox-p2p-evolutions`

---

## 💬 Commentaires

*Issue créée automatiquement pour le suivi des évolutions P2P*  
*Assigné à: Team CyberMind*  
*Label: enhancement, p2p, dht, federation, masterlink*

---

**Dernière mise à jour:** 2026-07-02  
**Prochaine review:** 2026-07-09