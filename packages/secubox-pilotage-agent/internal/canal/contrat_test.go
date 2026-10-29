// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package canal

// Contrat Go ↔ Python (M14 de la relecture finale L1) : ce test fait tourner le VRAI client contre un faux maître et
// fige, dans testdata/contrat/, les enveloppes réellement émises (bonjour, GET_RESP avec « failed » et avec « tronque »,
// GET_SUPPORTED_DM_RESP, OPERATE_RESP, ERROR, NOTIFY). Le maître Python les rejoue contre son vrai canal
// (packages/secubox-pilotage/tests/test_contrat_go.py). Une fixture qui ne correspond plus à ce que le client émet
// fait échouer ce test ; on la régénère, puis le test Python relit la nouvelle :
//
//	SECUBOX_CONTRAT_MAJ=1 go test ./internal/canal -run TestContratEnveloppesEmises

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

const dossierContrat = "testdata/contrat"

type sourceFixe struct {
	nom     string
	chemins []string
	params  map[string]any
	err     error
}

func (s sourceFixe) Nom() string       { return s.nom }
func (s sourceFixe) Chemins() []string { return s.chemins }
func (s sourceFixe) Lire(context.Context) (map[string]any, error) {
	return s.params, s.err
}

// modeleContrat : valeurs fixes (fixtures déterministes), une source en échec (systemctl figé), une liste longue.
func modeleContrat() *modele.Modele {
	paquets := map[string]any{}
	for i := 1; i <= 400; i++ {
		paquets[fmt.Sprintf("Device.X_SECUBOX_Packages.%d.Name", i)] = fmt.Sprintf("secubox-paquet-%03d", i)
		paquets[fmt.Sprintf("Device.X_SECUBOX_Packages.%d.Version", i)] = "1.2.3-1~trixie1"
	}
	return modele.NouveauModele(
		sourceFixe{nom: "systeme",
			chemins: []string{"Device.DeviceInfo.UpTime", "Device.DeviceInfo.ModelName", "Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available",
				"Device.DeviceInfo.ProcessStatus.CPUUsage"},
			params: map[string]any{"Device.DeviceInfo.UpTime": uint64(2036), "Device.DeviceInfo.ModelName": "Globalscale Marvell ESPRESSOBin Board V7",
				"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": uint64(262144), "Device.DeviceInfo.ProcessStatus.CPUUsage": 12.5}},
		sourceFixe{nom: "systemd", chemins: []string{"Device.X_SECUBOX_Services.FailedNumberOfEntries", "Device.X_SECUBOX_Services.{i}.Name"},
			err: errors.New("systemctl : délai dépassé")},
		sourceFixe{nom: "exposition", chemins: []string{"Device.X_SECUBOX_Exposure.Names"},
			params: map[string]any{"Device.X_SECUBOX_Exposure.Names": []string{"admin.gk5.secubox.in", "hub.gk5.secubox.in"}}},
		sourceFixe{nom: "paquets", chemins: []string{"Device.X_SECUBOX_Packages.{i}.Name", "Device.X_SECUBOX_Packages.{i}.Version"}, params: paquets},
	)
}

// requetesContrat : ce que le maître dépose (msg_id fixes), dans l'ordre ; nom de la fixture de chaque réponse.
var requetesContrat = []struct {
	fixture, msgID, typ, corps string
}{
	{"get_resp_failed", "00000000000000a1", "GET", `{"paths":["Device.DeviceInfo.","Device.X_SECUBOX_Services.","Device.X_SECUBOX_Exposure.Names"]}`},
	{"get_resp_tronque", "00000000000000a2", "GET", `{"paths":["Device.X_SECUBOX_Packages."]}`},
	{"get_supported_dm_resp", "00000000000000a3", "GET_SUPPORTED_DM", `{}`},
	{"operate_resp", "00000000000000a4", "OPERATE", `{"command":"Device.X_SECUBOX_Releve.Mesurer()","args":{"duree_s":10}}`},
	{"error", "00000000000000a5", "OPERATE", `{"command":"Device.Reboot()","args":{}}`},
}

type fixtureContrat struct {
	Route   string          `json:"route"`
	Requete json.RawMessage `json:"requete,omitempty"` // {type, body} déposé par le maître (réponses seulement)
	Envoi   json.RawMessage `json:"envoi"`             // corps (ou élément de la liste) tel que le client l'a posté
}

func TestContratEnveloppesEmises(t *testing.T) {
	lot := "["
	for i, r := range requetesContrat {
		if i > 0 {
			lot += ","
		}
		lot += fmt.Sprintf(`{"msg_id":%q,"type":%q,"body":%s}`, r.msgID, r.typ, r.corps)
	}
	f := &fauxMaitre{requetes: []string{lot + "]"}}
	// trois événements en file AVANT le démarrage : un seul POST /notifs, déterministe
	ev := make(chan notifs.Evenement, 4)
	ev <- notifs.Evenement{Type: notifs.TypeDemarrage, Valeur: 120, Instant: 1793000000}
	ev <- notifs.Evenement{Type: notifs.TypeBoucle, Unite: "nginx.service", Valeur: 3, Instant: 1793000060}
	ev <- notifs.Evenement{Type: notifs.TypeMemoire, Instant: 1793000120} // valeur nulle : « value » omis
	operer := func(ctx context.Context, cmd string, args map[string]any) (any, error) {
		return map[string]any{"duree_s": 10, "cpu_pct": 37, "ctxt_par_s": 5120, "ecritures_ko_s": 48, "mem_dispo_mo": 256, "swap_mo": 23,
			"top": []map[string]any{{"nom": "uvicorn", "cpu_pct": 21.5, "pss_mo": 98}, {"nom": "nginx", "cpu_pct": 4.25, "pss_mo": 12}}}, nil
	}
	stop := demarrerAvec(t, f, modeleContrat(), operer, ev, func(c *Client) {
		c.cfg.TailleMax = 8 << 10 // force la troncature des listes {i} sur une fixture de taille raisonnable
		c.cfg.Version = "0.0.0-contrat"
		c.cfg.BootID = "00000000-0000-4000-8000-000000000000"
	})
	recues := map[string]json.RawMessage{}
	attendreCond(t, f, "les cinq réponses et les notifications", func() bool {
		for _, b := range f.reponses {
			var l []json.RawMessage
			if json.Unmarshal(b, &l) != nil {
				continue
			}
			for _, e := range l {
				var x struct {
					MsgID string `json:"msg_id"`
				}
				if json.Unmarshal(e, &x) == nil {
					recues[x.MsgID] = e
				}
			}
		}
		return len(recues) == len(requetesContrat) && len(f.notifs) == 1 && len(f.bonjour) >= 1
	})
	stop()

	f.mu.Lock()
	fixtures := map[string]fixtureContrat{
		"bonjour": {Route: "/canal/v1/bonjour", Envoi: f.bonjour[0]},
		"notify":  {Route: "/canal/v1/notifs", Envoi: f.notifs[0]},
	}
	f.mu.Unlock()
	for _, r := range requetesContrat {
		rq, _ := json.Marshal(map[string]json.RawMessage{"type": json.RawMessage(fmt.Sprintf("%q", r.typ)), "body": json.RawMessage(r.corps)})
		fixtures[r.fixture] = fixtureContrat{Route: "/canal/v1/reponses", Requete: rq, Envoi: recues[r.msgID]}
	}
	// ce que les fixtures doivent montrer, sans quoi le contrat ne couvre plus le cas
	for nom, sous := range map[string]string{"get_resp_failed": `"failed":["systemd"]`, "get_resp_tronque": `"tronque":true`,
		"error": `"type":"ERROR"`, "operate_resp": `"type":"OPERATE_RESP"`, "get_supported_dm_resp": `"type":"GET_SUPPORTED_DM_RESP"`} {
		if !bytes.Contains(fixtures[nom].Envoi, []byte(sous)) {
			t.Fatalf("%s ne contient pas %s : %.300s", nom, sous, fixtures[nom].Envoi)
		}
	}

	maj := os.Getenv("SECUBOX_CONTRAT_MAJ") == "1"
	if maj {
		if err := os.MkdirAll(dossierContrat, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for nom, fx := range fixtures {
		b, err := json.MarshalIndent(fx, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		chemin := filepath.Join(dossierContrat, nom+".json")
		if maj {
			if err := os.WriteFile(chemin, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		actuel, err := os.ReadFile(chemin)
		if err != nil || !bytes.Equal(actuel, b) {
			t.Errorf("fixture de contrat %s périmée ou absente (%v) : le client n'émet plus ce que le maître rejoue ; "+
				"SECUBOX_CONTRAT_MAJ=1 go test ./internal/canal -run TestContratEnveloppesEmises, puis les tests du maître", chemin, err)
		}
	}
	if !maj {
		presentes, _ := filepath.Glob(filepath.Join(dossierContrat, "*.json"))
		if len(presentes) != len(fixtures) {
			t.Errorf("%d fixtures dans %s, %d attendues (fixture orpheline ?)", len(presentes), dossierContrat, len(fixtures))
		}
	}
}
