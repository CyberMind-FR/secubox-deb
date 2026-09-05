// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Journal de bans persistant (#1070, phase B).
//
// Le compteur de ban en mémoire est perdu au redémarrage : un scanner banni
// repartait à zéro. BanStore journalise chaque ban/unban en JSONL append-only ;
// au démarrage on relit les bans encore actifs et on les ré-injecte dans nft.
// C'est ce qui rend le WAF AUTONOME : les bans survivent au restart, sans
// dépendre d'un relais externe.

// BanRecord est une ligne du journal.
type BanRecord struct {
	IP       string `json:"ip"`
	Category string `json:"cat"`
	Severity string `json:"sev"`
	At       int64  `json:"at"`     // unix : quand la décision a été prise
	Expires  int64  `json:"exp"`    // unix : échéance du ban (0 = via unban explicite)
	Action   string `json:"action"` // "ban" | "unban"
}

// BanStore sérialise l'accès à un fichier JSONL append-only.
type BanStore struct {
	path string
	mu   sync.Mutex
}

func NewBanStore(path string) *BanStore {
	if path == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &BanStore{path: path}
}

// Append ajoute une ligne au journal (best-effort : une erreur d'écriture ne
// doit pas casser le chemin de requête, elle est seulement journalisée par
// l'appelant s'il le souhaite).
func (s *BanStore) Append(rec BanRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// ActiveBans relit le journal et renvoie, par IP, les bans ENCORE actifs à
// l'instant `now` : le dernier « ban » l'emporte sauf s'il est suivi d'un
// « unban » ou si son échéance est dépassée. C'est ce que le démarrage
// ré-injecte dans nft, et ce que le balayage réconcilie.
func (s *BanStore) ActiveBans(now int64) []BanRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return nil // journal absent = aucun ban
	}
	defer f.Close()

	dernier := map[string]BanRecord{} // ip → dernière décision
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var r BanRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.IP == "" {
			continue // ligne corrompue : on l'ignore, on ne casse pas la relecture
		}
		dernier[r.IP] = r
	}

	var actifs []BanRecord
	for _, r := range dernier {
		if r.Action != "ban" {
			continue // dernier état = unban
		}
		if r.Expires != 0 && r.Expires <= now {
			continue // échu
		}
		actifs = append(actifs, r)
	}
	return actifs
}
