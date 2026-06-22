// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: secubox-dpi :: flow collector (#687, Phase 2)
//
// Per-device cloud-exfiltration detection from nDPI flow records. Reads
// ndpiReader CSV (the flow producer on wg-toolbox), maps each flow's source
// 10.99.1.x to its R3 device identity (sha256(wg_pubkey)[:16] from
// wg-peers.json), detects external clouds (by SNI / dst), runs the exfil
// scenarios, and writes JSON state for the secubox-dpi dashboard.
//
// Pure Go stdlib — no external deps — so it cross-compiles to arm64 with zero
// vendoring. The CSV producer is swappable for an nDPId JSON socket later.
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	upExfilBytes   = 5 << 20 // >=5 MB outbound to a cloud → volume alert
	beaconMinFlows = 6       // >=6 flows same dst → candidate beacon
	beaconCVMax    = 0.25    // iat coefficient-of-variation <= 0.25 → periodic
	topN           = 12
)

var (
	wgPeersPath = env("SECUBOX_WG_PEERS", "/var/lib/secubox/toolbox/wg-peers.json")
	statePath   = env("SECUBOX_DPI_STATE", "/var/lib/secubox/dpi/state.json")
	seenPath    = env("SECUBOX_DPI_SEEN", "/var/lib/secubox/dpi/seen.json")
)

// Cloud SNI suffixes that matter for exfiltration (storage / generic compute).
var cloudSuffix = map[string]string{
	"amazonaws.com": "AWS", "cloudfront.net": "AWS CloudFront", "s3.amazonaws.com": "AWS S3",
	"googleapis.com": "Google", "googleusercontent.com": "Google", "storage.googleapis.com": "Google Storage",
	"blob.core.windows.net": "Azure Blob", "core.windows.net": "Azure", "azureedge.net": "Azure CDN",
	"digitaloceanspaces.com": "DigitalOcean", "backblazeb2.com": "Backblaze B2", "wasabisys.com": "Wasabi",
	"dropboxusercontent.com": "Dropbox", "dropbox.com": "Dropbox", "box.com": "Box",
	"oraclecloud.com": "Oracle Cloud", "ovh.net": "OVH", "scw.cloud": "Scaleway", "hetzner.com": "Hetzner",
	"firebaseio.com": "Firebase", "supabase.co": "Supabase", "pastebin.com": "Pastebin",
	"telegram.org": "Telegram", "discord.com": "Discord", "mega.nz": "MEGA", "transfer.sh": "transfer.sh",
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.Split(host, ":")[0], "."))
	p := strings.Split(host, ".")
	if len(p) <= 2 {
		return host
	}
	return strings.Join(p[len(p)-2:], ".")
}

// detectCloud → provider name ("" if not a recognised cloud).
func detectCloud(sni, dstIP string) string {
	s := strings.ToLower(strings.TrimSpace(sni))
	if s != "" {
		for suf, name := range cloudSuffix {
			if s == suf || strings.HasSuffix(s, "."+suf) {
				return name
			}
		}
	}
	return ""
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()
}

// ── wg-peers.json : { "peers": { "<pubkey>": { "ip": "10.99.1.X", ... } } } ──
func loadDeviceMap() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(wgPeersPath)
	if err != nil {
		return m
	}
	var doc struct {
		Peers map[string]struct {
			IP string `json:"ip"`
		} `json:"peers"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return m
	}
	for pk, meta := range doc.Peers {
		if meta.IP != "" {
			sum := sha256.Sum256([]byte(pk))
			m[meta.IP] = hex.EncodeToString(sum[:])[:16]
		}
	}
	return m
}

type agg struct {
	Device   string  `json:"device"`
	Dst      string  `json:"dst"`
	Cloud    string  `json:"cloud,omitempty"`
	Proto    string  `json:"proto"`
	Up       int64   `json:"up_bytes"`
	Down     int64   `json:"down_bytes"`
	Flows    int     `json:"flows"`
	iatAvg   float64 // accumulators
	iatStd   float64
	external bool
}

type alert struct {
	Device  string `json:"device"`
	Kind    string `json:"kind"`
	Dst     string `json:"dst"`
	Cloud   string `json:"cloud,omitempty"`
	Up      int64  `json:"up_bytes"`
	Down    int64  `json:"down_bytes"`
	Detail  string `json:"detail"`
	TS      int64  `json:"ts"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: secubox-dpi-collector <flows.csv> [now_epoch]")
		os.Exit(2)
	}
	now := time.Now().Unix()
	if len(os.Args) >= 3 {
		if v, err := strconv.ParseInt(os.Args[2], 10, 64); err == nil {
			now = v
		}
	}
	devmap := loadDeviceMap()
	seen := loadSeen()

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "collector: open %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		// no flows this batch — still refresh state timestamp, exit clean.
		writeState(map[string]*agg{}, nil, now)
		return
	}
	col := indexCols(rows[0])
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	atoi := func(s string) int64 { v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return v }
	atof := func(s string) float64 { v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return v }

	aggs := map[string]*agg{}
	for _, rec := range rows[1:] {
		src := get(rec, "src_ip")
		dev, ok := devmap[src]
		if !ok || !strings.HasPrefix(src, "10.99.1.") {
			continue // only attributed R3 devices
		}
		dstIP := get(rec, "dst_ip")
		sni := get(rec, "server_name_sni")
		proto := get(rec, "ndpi_proto")
		cloud := detectCloud(sni, dstIP)
		dst := sni
		if dst == "" {
			dst = dstIP
		}
		key := dev + "|" + dst
		a := aggs[key]
		if a == nil {
			a = &agg{Device: dev, Dst: dst, Cloud: cloud, Proto: proto, external: !isPrivate(dstIP)}
			aggs[key] = a
		}
		a.Up += atoi(get(rec, "c_to_s_bytes"))
		a.Down += atoi(get(rec, "s_to_c_bytes"))
		a.Flows++
		a.iatAvg += atof(get(rec, "iat_flow_avg"))
		a.iatStd += atof(get(rec, "iat_flow_stddev"))
	}

	var alerts []alert
	newseen := map[string]bool{}
	for _, a := range aggs {
		// 1) volume exfil: lots OUT to a cloud, more out than in
		if a.Cloud != "" && a.Up >= upExfilBytes && a.Up > a.Down {
			alerts = append(alerts, alert{a.Device, "exfil_volume", a.Dst, a.Cloud, a.Up, a.Down,
				fmt.Sprintf("%s envoyé vers %s", human(a.Up), a.Cloud), now})
		}
		// 2) new cloud destination for this device
		if a.Cloud != "" {
			sk := a.Device + "|" + a.Cloud
			newseen[sk] = true
			if !seen[sk] {
				alerts = append(alerts, alert{a.Device, "new_cloud", a.Dst, a.Cloud, a.Up, a.Down,
					"première sortie vers " + a.Cloud, now})
			}
		}
		// 3) beaconing: many flows, low inter-arrival variance
		if a.Flows >= beaconMinFlows {
			avg := a.iatAvg / float64(a.Flows)
			std := a.iatStd / float64(a.Flows)
			if avg > 0 && std/avg <= beaconCVMax {
				alerts = append(alerts, alert{a.Device, "beaconing", a.Dst, a.Cloud, a.Up, a.Down,
					fmt.Sprintf("%d flux périodiques (~%.0f ms)", a.Flows, avg), now})
			}
		}
		// 4) unclassified flow to an external host with notable upload
		if a.external && a.Up >= upExfilBytes &&
			(a.Proto == "" || strings.Contains(strings.ToLower(a.Proto), "unknown")) {
			alerts = append(alerts, alert{a.Device, "unclassified_external", a.Dst, a.Cloud, a.Up, a.Down,
				human(a.Up) + " sortie non classifiée", now})
		}
	}
	// merge seen (persist union so new_cloud only fires once)
	for k := range seen {
		newseen[k] = true
	}
	saveSeen(newseen)
	writeState(aggs, alerts, now)
	fmt.Printf("collector: %d flows-agg, %d alerts @ %d\n", len(aggs), len(alerts), now)
}

func indexCols(header []string) map[string]int {
	m := map[string]int{}
	for i, h := range header {
		m[strings.TrimPrefix(strings.TrimSpace(h), "#")] = i
	}
	return m
}

func human(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f Go", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f Mo", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f Ko", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d o", b)
}

func loadSeen() map[string]bool {
	m := map[string]bool{}
	b, err := os.ReadFile(seenPath)
	if err != nil {
		return m
	}
	var keys []string
	if json.Unmarshal(b, &keys) == nil {
		for _, k := range keys {
			m[k] = true
		}
	}
	return m
}

func saveSeen(m map[string]bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeJSON(seenPath, keys)
}

func writeState(aggs map[string]*agg, alerts []alert, now int64) {
	// per-device rollup
	type devstat struct {
		Device   string  `json:"device"`
		Flows    int     `json:"flows"`
		UpBytes  int64   `json:"up_bytes"`
		Clouds   []*agg  `json:"clouds"`
		Alerts   []alert `json:"alerts"`
	}
	devs := map[string]*devstat{}
	for _, a := range aggs {
		d := devs[a.Device]
		if d == nil {
			d = &devstat{Device: a.Device}
			devs[a.Device] = d
		}
		d.Flows += a.Flows
		d.UpBytes += a.Up
		if a.Cloud != "" {
			d.Clouds = append(d.Clouds, a)
		}
	}
	for _, al := range alerts {
		if d := devs[al.Device]; d != nil {
			d.Alerts = append(d.Alerts, al)
		}
	}
	list := make([]*devstat, 0, len(devs))
	for _, d := range devs {
		sort.Slice(d.Clouds, func(i, j int) bool { return d.Clouds[i].Up > d.Clouds[j].Up })
		if len(d.Clouds) > topN {
			d.Clouds = d.Clouds[:topN]
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpBytes > list[j].UpBytes })
	out := map[string]any{
		"generated_at": now,
		"devices":      list,
		"alerts":       alerts,
		"alert_count":  len(alerts),
	}
	writeJSON(statePath, out)
}

func writeJSON(path string, v any) {
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "collector: mkdir %s: %v\n", dir(path), err)
		return
	}
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, path)
	}
}

func dir(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
