// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Resolution : réponse de ytsas GET /resolve.
type Resolution struct {
	VideoID     string `json:"video_id"`
	Etat        string `json:"state"`
	PeertubeURL string `json:"peertube_url"`
	StreamURL   string `json:"stream_url"`
	Titre       string `json:"title"`
}

// ClientYtsas interroge la SAS ytsas. Base = origine (http://10.100.0.180:8091).
type ClientYtsas struct {
	Base string
	HTTP *http.Client
}

// Resoudre demande à ytsas la meilleure source locale pour une URL YouTube.
func (c *ClientYtsas) Resoudre(media string) (Resolution, error) {
	adr := c.Base + "/api/v1/ytsas/resolve?url=" + url.QueryEscape(media)
	resp, err := c.HTTP.Get(adr)
	if err != nil {
		return Resolution{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("ytsas /resolve : code %d", resp.StatusCode)
	}
	var r Resolution
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Resolution{}, err
	}
	return r, nil
}
