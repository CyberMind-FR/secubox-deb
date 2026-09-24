package api

// Réglages persistants du module, tenus par l'administration (#1371).
//
// TROIS RÉGLAGES, PAS DAVANTAGE. Ce qui fait la probité du module — le plafond
// de confiance, le seuil d'anonymat de la lecture commune, l'absence de tout
// échantillon audio sur le disque — n'est PAS réglable : ce sont des garanties
// testées, et un curseur les rendrait négociables. Le panneau les AFFICHE.
//
// Ce qui se règle, c'est ce que la board GARDE : combien de temps, et si elle
// garde quelque chose du tout.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	RetentionMinJours = 1
	RetentionMaxJours = 90
)

// ValeursReglages : la forme échangée avec le panneau et écrite sur disque.
type ValeursReglages struct {
	// Historique : les agrégats par minute sont-ils conservés ?
	Historique bool `json:"historique"`
	// MemoireVoix : la référence d'une voix (quinze nombres) survit-elle d'une
	// visite à l'autre ? Coupée, chaque visite repart d'un étalonnage neuf.
	MemoireVoix bool `json:"memoire_voix"`
	// RetentionJours : au-delà, la purge efface.
	RetentionJours int `json:"retention_jours"`
}

type Reglages struct {
	mu     sync.RWMutex
	chemin string
	v      ValeursReglages
}

// ChargeReglages lit le fichier ; absent ou illisible, les valeurs par défaut
// (celles de la ligne de commande) valent — un fichier abîmé ne doit pas
// empêcher le module de démarrer.
func ChargeReglages(chemin string, retention time.Duration) *Reglages {
	jours := int(retention / (24 * time.Hour))
	if jours < RetentionMinJours {
		jours = RetentionMinJours
	}
	r := &Reglages{chemin: chemin, v: ValeursReglages{
		Historique: retention > 0, MemoireVoix: true, RetentionJours: jours}}
	if chemin == "" {
		return r
	}
	if b, err := os.ReadFile(chemin); err == nil {
		var lu ValeursReglages
		if json.Unmarshal(b, &lu) == nil && valides(lu) == nil {
			r.v = lu
		}
	}
	return r
}

func valides(v ValeursReglages) error {
	if v.RetentionJours < RetentionMinJours || v.RetentionJours > RetentionMaxJours {
		return errors.New("rétention hors bornes (1 à 90 jours)")
	}
	return nil
}

func (r *Reglages) Valeurs() ValeursReglages {
	if r == nil {
		return ValeursReglages{Historique: true, MemoireVoix: true, RetentionJours: 14}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.v
}

func (r *Reglages) Retention() time.Duration {
	return time.Duration(r.Valeurs().RetentionJours) * 24 * time.Hour
}

// Ecrit valide, persiste ATOMIQUEMENT, puis applique. Si l'écriture échoue,
// rien n'est appliqué : un réglage qui ne survivrait pas au redémarrage
// mentirait sur ce que fait la board.
func (r *Reglages) Ecrit(v ValeursReglages) error {
	if err := valides(v); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chemin != "" {
		b, _ := json.MarshalIndent(v, "", "  ")
		tmp := r.chemin + ".tmp"
		if err := os.MkdirAll(filepath.Dir(r.chemin), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(tmp, b, 0o640); err != nil {
			return err
		}
		if err := os.Rename(tmp, r.chemin); err != nil {
			return err
		}
	}
	r.v = v
	return nil
}
