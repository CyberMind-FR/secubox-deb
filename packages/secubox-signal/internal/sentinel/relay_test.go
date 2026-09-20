// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package sentinel

import (
	"context"
	"strings"
	"sync"
	"testing"
)

type envoyeurFactice struct {
	mu    sync.Mutex
	corps []string
}

func (e *envoyeurFactice) Envoyer(_ context.Context, _, corps string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.corps = append(e.corps, corps)
	return nil
}

func (e *envoyeurFactice) nombre() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.corps)
}

// LE test du module : une tempete d'evenements ne doit produire qu'un nombre
// borne de notifications.
func TestGardeFouAntiAvalanche(t *testing.T) {
	env := &envoyeurFactice{}
	r := New("/inexistant", "+33600000000", 3, env)

	for i := 0; i < 50; i++ {
		r.traiter(context.Background(), alerte{Niveau: "warn", Source: "waf", Message: "x"})
	}
	if env.nombre() != 3 {
		t.Fatalf("seuil a 3 : %d notification(s) emises sur 50 alertes", env.nombre())
	}
}

// Ce qui est supprime doit etre COMPTE, pas perdu : la notification suivante
// porte la synthese.
func TestLesAlertesSupprimeesSontAgregees(t *testing.T) {
	env := &envoyeurFactice{}
	r := New("/inexistant", "+33600000000", 1, env)

	r.traiter(context.Background(), alerte{Message: "premiere"})
	for i := 0; i < 5; i++ {
		r.traiter(context.Background(), alerte{Message: "supprimee"})
	}
	// Fenetre videe a la main : on teste l'agregation, pas l'horloge.
	r.mu.Lock()
	r.fenetre = nil
	r.mu.Unlock()
	r.traiter(context.Background(), alerte{Message: "suivante"})

	if env.nombre() != 2 {
		t.Fatalf("2 envois attendus, %d", env.nombre())
	}
	if !strings.Contains(env.corps[1], "+5 alerte") {
		t.Errorf("la synthese doit mentionner les 5 supprimees : %q", env.corps[1])
	}
}

// Sans destination, le relais ne doit pas tourner — et surtout pas planter.
func TestSansDestinationLeRelaisSArrete(t *testing.T) {
	r := New("/inexistant", "", 10, &envoyeurFactice{})
	fini := make(chan struct{})
	go func() { r.Run(context.Background()); close(fini) }()
	<-fini
}
