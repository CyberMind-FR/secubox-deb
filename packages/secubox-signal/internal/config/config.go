// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package config lit /etc/secubox/signal.toml.
//
// POURQUOI UN LECTEUR MAISON. Les demons Go du parc se configurent par
// drapeaux ; le CLAUDE.md impose un /etc/secubox/<module>.toml pour
// l'exploitant. Concilier les deux avec un parseur TOML complet ajouterait
// une dependance a auditer pour une configuration PLATE : des sections, des
// cles, trois types. Ce lecteur couvre ce sous-ensemble et REFUSE ce qu'il ne
// comprend pas, plutot que de l'ignorer en silence — une cle mal orthographiee
// doit se voir au demarrage, pas se deviner a l'usage.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	SocketPath string
	LogDir     string
	StateDir   string

	SignalCLI  string
	TimeoutSec int

	StoreBody      bool
	RetentionHours int

	AttachMaxBytes int64
	AttachHours    int

	SentinelSocket  string
	SentinelEnabled bool
	SentinelDest    string
	SentinelMaxHour int
}

// Defaults porte les memes valeurs que conf/signal.toml. Elles existent ici
// pour qu'un fichier absent donne un demon qui demarre et se plaint, plutot
// qu'un demon qui ne demarre pas du tout.
func Defaults() Config {
	return Config{
		SocketPath: "/run/secubox/signal.sock",
		LogDir:     "/var/log/secubox/signal",
		StateDir:   "/var/lib/secubox/signal",
		SignalCLI:  "/usr/lib/secubox/signal/bin/signal-cli",
		TimeoutSec: 60,
		// store_body reste FAUX par defaut, et ce n'est pas un choix
		// technique : cf. RFC §7.
		StoreBody:       false,
		RetentionHours:  24,
		AttachMaxBytes:  104857600,
		AttachHours:     24,
		SentinelSocket:  "/run/secubox/sentinel-events.sock",
		SentinelEnabled: true,
		SentinelMaxHour: 20,
	}
}

func Load(path string) (Config, error) {
	c := Defaults()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // defauts, le demon le journalisera
		}
		return c, err
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	for ligne := 1; sc.Scan(); ligne++ {
		t := strings.TrimSpace(sc.Text())
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]")
			continue
		}
		cle, val, ok := strings.Cut(t, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d : ni section ni affectation : %q", path, ligne, t)
		}
		cle = strings.TrimSpace(cle)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		if err := c.set(section, cle, val); err != nil {
			return c, fmt.Errorf("%s:%d : %w", path, ligne, err)
		}
	}
	return c, sc.Err()
}

func (c *Config) set(section, cle, val string) error {
	entier := func() (int, error) { return strconv.Atoi(val) }
	switch section + "." + cle {
	case "daemon.socket":
		c.SocketPath = val
	case "daemon.log_dir":
		c.LogDir = val
	case "daemon.state_dir":
		c.StateDir = val
	case "backend.signal_cli":
		c.SignalCLI = val
	case "backend.timeout_sec":
		n, err := entier()
		if err != nil {
			return err
		}
		c.TimeoutSec = n
	case "retention.store_body":
		c.StoreBody = val == "true"
	case "retention.hours":
		n, err := entier()
		if err != nil {
			return err
		}
		c.RetentionHours = n
	case "attachments.max_bytes":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		c.AttachMaxBytes = n
	case "attachments.hours":
		n, err := entier()
		if err != nil {
			return err
		}
		c.AttachHours = n
	case "sentinel.events_socket":
		c.SentinelSocket = val
	case "sentinel.enabled":
		c.SentinelEnabled = val == "true"
	case "sentinel.destination":
		c.SentinelDest = val
	case "sentinel.max_per_hour":
		n, err := entier()
		if err != nil {
			return err
		}
		c.SentinelMaxHour = n
	default:
		// REFUSER plutot qu'ignorer : une cle inconnue est presque toujours
		// une faute de frappe, et une faute de frappe silencieuse sur
		// `store_body` ou `max_per_hour` se paie cher.
		return fmt.Errorf("cle inconnue : %s.%s", section, cle)
	}
	return nil
}
