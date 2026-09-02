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

	"github.com/oschwald/maxminddb-golang"
)

const (
	upExfilBytes   = 5 << 20 // >=5 MB outbound to a cloud → volume alert
	beaconMinFlows = 6       // >=6 flows same dst → candidate beacon
	beaconCVMax    = 0.25    // iat coefficient-of-variation <= 0.25 → periodic
	// #692 — period band (ndpiReader iat is in ms). Real C2 beacons sit at
	// seconds-to-minutes; sub-second cadence is app polling / media chunks /
	// websocket keepalives, not exfil. Only flag a steady period in this band.
	beaconMinIntervalMs = 1000.0    // >=1 s between flows
	beaconMaxIntervalMs = 3600000.0 // <=1 h between flows
	topN                = 12
)

var (
	wgPeersPath = env("SECUBOX_WG_PEERS", "/var/lib/secubox/toolbox/wg-peers.json")
	statePath   = env("SECUBOX_DPI_STATE", "/var/lib/secubox/dpi/state.json")
	seenPath    = env("SECUBOX_DPI_SEEN", "/var/lib/secubox/dpi/seen.json")
	// #705 — cumulative per-device rollup so the kbin report shows 7d history,
	// not just the last 60s window (state.json). Same consumer schema as state.json.
	cumulPath = env("SECUBOX_DPI_CUMUL", "/var/lib/secubox/dpi/cumulative.json")
	// #718 — ASN DB: classify SNI-less flows (IP-only/QUIC) by destination ASN.
	asnDBPath = env("SECUBOX_DPI_ASN", "/var/lib/GeoIP/GeoLite2-ASN.mmdb")
	// #720 — per-device DAILY history buckets for the timeline view.
	historyPath = env("SECUBOX_DPI_HISTORY", "/var/lib/secubox/dpi/history.json")
)

const historyDays = 14 // keep two weeks of daily buckets

// #718 — ASN-org name fragments that mark a destination as cloud/hosting egress
// (lowercase substring match). Used only when there is no SNI category, so a big
// upload to an IP-only AWS/Google/etc host is still caught as cloud exfil.
var cloudASNHints = []string{
	"amazon", "aws", "google", "microsoft", "azure", "cloudflare", "akamai",
	"fastly", "ovh", "hetzner", "digitalocean", "oracle", "linode", "scaleway",
	"leaseweb", "vultr", "g-core", "gcore", "alibaba", "tencent", "contabo",
	"upcloud", "datacamp", "hosting", "datacenter", "data center", "cloud",
}

// asnReader is opened once at startup; nil if the mmdb is absent (fail-soft).
var asnReader *maxminddb.Reader

// asnOrg returns the destination IP's autonomous-system organisation ("" on miss).
func asnOrg(ip string) string {
	if asnReader == nil {
		return ""
	}
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	var rec struct {
		Org string `maxminddb:"autonomous_system_organization"`
	}
	if err := asnReader.Lookup(p, &rec); err != nil {
		return ""
	}
	return rec.Org
}

// cloudByASN → ("cloud", org) when org looks like a hosting/cloud provider, else "".
func cloudByASN(org string) (string, string) {
	o := strings.ToLower(org)
	for _, h := range cloudASNHints {
		if strings.Contains(o, h) {
			return "cloud", org
		}
	}
	return "", ""
}

const (
	cumulRetention   = 7 * 24 * 3600 // drop devices/alerts not seen in 7d
	cumulMaxServices = 80            // cap services per device to bound file size
)

// svc = (category, human service name) for a known SNI suffix. Categories are
// nDPI-style buckets so the dashboard shows *what* each device talks to, not
// just whether it's a cloud. Exfil scenarios only fire on categories where an
// uncontrolled upload is a real data-leak concern (see exfilCat()).
type svc struct{ cat, name string }

// SNI suffix → service. Longest matching suffix wins (deterministic), so add
// specific suffixes (s3.amazonaws.com) alongside broad ones (amazonaws.com).
var serviceSuffix = map[string]svc{
	// ── cloud storage / compute (exfil-relevant) ──
	"amazonaws.com": {"cloud", "AWS"}, "s3.amazonaws.com": {"cloud", "AWS S3"}, "cloudfront.net": {"cloud", "AWS CloudFront"},
	"googleapis.com": {"cloud", "Google APIs"}, "googleusercontent.com": {"cloud", "Google"}, "storage.googleapis.com": {"cloud", "Google Storage"},
	"blob.core.windows.net": {"cloud", "Azure Blob"}, "core.windows.net": {"cloud", "Azure"}, "azureedge.net": {"cloud", "Azure CDN"},
	"digitaloceanspaces.com": {"cloud", "DigitalOcean"}, "backblazeb2.com": {"cloud", "Backblaze B2"}, "wasabisys.com": {"cloud", "Wasabi"},
	"oraclecloud.com": {"cloud", "Oracle Cloud"}, "ovh.net": {"cloud", "OVH"}, "scw.cloud": {"cloud", "Scaleway"}, "hetzner.com": {"cloud", "Hetzner"},
	"firebaseio.com": {"cloud", "Firebase"}, "supabase.co": {"cloud", "Supabase"},

	// ── file-host / paste / drop (classic exfil channels) ──
	"dropboxusercontent.com": {"filehost", "Dropbox"}, "dropbox.com": {"filehost", "Dropbox"}, "box.com": {"filehost", "Box"},
	"mega.nz": {"filehost", "MEGA"}, "transfer.sh": {"filehost", "transfer.sh"}, "pastebin.com": {"filehost", "Pastebin"},
	"wetransfer.com": {"filehost", "WeTransfer"}, "anonfiles.com": {"filehost", "AnonFiles"}, "gofile.io": {"filehost", "Gofile"},

	// ── messaging (can tunnel data out) ──
	"telegram.org": {"messaging", "Telegram"}, "t.me": {"messaging", "Telegram"}, "discord.com": {"messaging", "Discord"},
	"discordapp.com": {"messaging", "Discord"}, "whatsapp.net": {"messaging", "WhatsApp"}, "signal.org": {"messaging", "Signal"},

	// ── AI services (uploads = data egress to 3rd-party models) ──
	"openai.com": {"ai", "OpenAI"}, "oaistatic.com": {"ai", "OpenAI"}, "anthropic.com": {"ai", "Anthropic"},
	"claude.ai": {"ai", "Claude"}, "perplexity.ai": {"ai", "Perplexity"}, "x.ai": {"ai", "xAI"}, "mistral.ai": {"ai", "Mistral"},

	// ── media / streaming ──
	"nflxvideo.net": {"media", "Netflix"}, "netflix.com": {"media", "Netflix"}, "googlevideo.com": {"media", "YouTube"},
	"youtube.com": {"media", "YouTube"}, "ytimg.com": {"media", "YouTube"}, "ttvnw.net": {"media", "Twitch"}, "twitch.tv": {"media", "Twitch"},
	"spotify.com": {"media", "Spotify"}, "scdn.co": {"media", "Spotify"}, "dssott.com": {"media", "Disney+"}, "disneyplus.com": {"media", "Disney+"},
	"primevideo.com": {"media", "Prime Video"}, "aiv-cdn.net": {"media", "Prime Video"}, "deezer.com": {"media", "Deezer"},
	"dailymotion.com": {"media", "Dailymotion"}, "vimeo.com": {"media", "Vimeo"}, "molotov.tv": {"media", "Molotov"},

	// ── gaming ──
	"steampowered.com": {"game", "Steam"}, "steamcontent.com": {"game", "Steam"}, "steamserver.net": {"game", "Steam"},
	"epicgames.com": {"game", "Epic"}, "playstation.net": {"game", "PlayStation"}, "playstation.com": {"game", "PlayStation"},
	"xboxlive.com": {"game", "Xbox"}, "riotgames.com": {"game", "Riot"}, "battle.net": {"game", "Battle.net"},
	"roblox.com": {"game", "Roblox"}, "nintendo.net": {"game", "Nintendo"}, "ea.com": {"game", "EA"}, "ubisoft.com": {"game", "Ubisoft"},

	// ── social ──
	"facebook.com": {"social", "Facebook"}, "fbcdn.net": {"social", "Facebook"}, "instagram.com": {"social", "Instagram"},
	"tiktokcdn.com": {"social", "TikTok"}, "tiktokv.com": {"social", "TikTok"}, "tiktok.com": {"social", "TikTok"},
	"twitter.com": {"social", "X"}, "x.com": {"social", "X"}, "twimg.com": {"social", "X"}, "snapchat.com": {"social", "Snapchat"},
	"reddit.com": {"social", "Reddit"}, "redditmedia.com": {"social", "Reddit"}, "pinterest.com": {"social", "Pinterest"},

	// ── adult ──
	"pornhub.com": {"adult", "Pornhub"}, "phncdn.com": {"adult", "Pornhub"}, "xvideos.com": {"adult", "XVideos"},
	"xnxx.com": {"adult", "XNXX"}, "xnxx-cdn.com": {"adult", "XNXX"}, "redtube.com": {"adult", "RedTube"},
	"youporn.com": {"adult", "YouPorn"}, "xhamster.com": {"adult", "xHamster"}, "onlyfans.com": {"adult", "OnlyFans"},
	"chaturbate.com": {"adult", "Chaturbate"}, "stripchat.com": {"adult", "Stripchat"},
}

// exfilCat → does an uncontrolled upload to this category constitute data egress?
func exfilCat(cat string) bool {
	switch cat {
	case "cloud", "filehost", "messaging", "ai":
		return true
	}
	return false
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

// classify → (category, service) for a flow's SNI. Longest matching suffix
// wins so specific entries (s3.amazonaws.com) beat broad ones (amazonaws.com).
// Returns ("","") when the SNI is unknown.
func classify(sni, dstIP string) (string, string) {
	s := strings.ToLower(strings.TrimSpace(sni))
	if s == "" {
		return "", ""
	}
	bestLen := -1
	var bestCat, bestName string
	for suf, v := range serviceSuffix {
		if s == suf || strings.HasSuffix(s, "."+suf) {
			if len(suf) > bestLen {
				bestLen, bestCat, bestName = len(suf), v.cat, v.name
			}
		}
	}
	return bestCat, bestName
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()
}

// deviceLabels : hash device → nom lisible, dérivé des peers WG (label de
// provisioning + IP de tunnel). Rempli par loadDeviceMap ; consommé par
// updateCumulative pour écrire cumDev.Name. Le collector a l'accès légitime à
// wg-peers.json (la FastAPI, elle, ne l'a pas — séparation CSPN).
var deviceLabels = map[string]string{}

// prettyLabel réduit un label de provisioning (souvent un User-Agent) à un nom
// court, suffixé du dernier octet de l'IP de tunnel pour distinguer les doublons.
func prettyLabel(label, ip string) string {
	l := strings.TrimSpace(label)
	low := strings.ToLower(l)
	switch {
	case strings.Contains(low, "mozilla/") || strings.Contains(low, "gecko") || strings.Contains(low, "applewebkit"):
		switch {
		case strings.Contains(low, "iphone"):
			l = "iPhone"
		case strings.Contains(low, "ipad"):
			l = "iPad"
		case strings.Contains(low, "android"):
			l = "Android"
		case strings.Contains(low, "windows"):
			l = "Windows"
		case strings.Contains(low, "macintosh"), strings.Contains(low, "mac os"):
			l = "Mac"
		case strings.Contains(low, "linux"):
			l = "Linux"
		default:
			l = "Navigateur"
		}
	default:
		if i := strings.IndexByte(l, '/'); i > 0 && len(l) < 24 {
			l = l[:i] // curl/7.88.1, wget/… → curl
		}
	}
	if l == "" {
		l = "R3"
	}
	if i := strings.LastIndexByte(ip, '.'); i >= 0 {
		l = l + " · ." + ip[i+1:]
	}
	return l
}

// ── wg-peers.json : { "peers": { "<pubkey>": { "ip": "10.99.1.X", "label": … } } } ──
func loadDeviceMap() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(wgPeersPath)
	if err != nil {
		return m
	}
	var doc struct {
		Peers map[string]struct {
			IP    string `json:"ip"`
			Label string `json:"label"`
		} `json:"peers"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return m
	}
	for pk, meta := range doc.Peers {
		if meta.IP != "" {
			sum := sha256.Sum256([]byte(pk))
			h := hex.EncodeToString(sum[:])[:16]
			m[meta.IP] = h
			deviceLabels[h] = prettyLabel(meta.Label, meta.IP)
		}
	}
	return m
}

type agg struct {
	Device   string `json:"device"`
	Dst      string `json:"dst"`
	Category string `json:"category,omitempty"` // cloud|filehost|messaging|ai|media|game|social|adult
	Service  string `json:"service,omitempty"`  // human service name (Netflix, AWS S3, …)
	Cloud    string `json:"cloud,omitempty"`    // back-compat: = Service when exfilCat(Category)
	Proto    string `json:"proto"`
	Up       int64  `json:"up_bytes"`
	Down     int64  `json:"down_bytes"`
	Flows    int    `json:"flows"`
	iatAvg   float64 // accumulators
	iatStd   float64
	external bool
}

type alert struct {
	Device   string `json:"device"`
	Kind     string `json:"kind"`
	Dst      string `json:"dst"`
	Category string `json:"category,omitempty"`
	Service  string `json:"service,omitempty"`
	Cloud    string `json:"cloud,omitempty"` // back-compat
	Up       int64  `json:"up_bytes"`
	Down     int64  `json:"down_bytes"`
	Detail   string `json:"detail"`
	TS       int64  `json:"ts"`
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

	// #718 — open the ASN DB once (fail-soft: nil reader → enrichment skipped).
	if rdr, err := maxminddb.Open(asnDBPath); err == nil {
		asnReader = rdr
		defer asnReader.Close()
	}

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
		cat, service := classify(sni, dstIP)
		// #718 — no SNI match: fall back to the destination ASN. A big upload to
		// an IP-only AWS/Google/etc host is still cloud exfil.
		if cat == "" && !isPrivate(dstIP) {
			if c, org := cloudByASN(asnOrg(dstIP)); c != "" {
				cat, service = c, org
			}
		}
		cloud := ""
		if exfilCat(cat) {
			cloud = service // back-compat field, only set for exfil-relevant dests
		}
		dst := sni
		if dst == "" {
			dst = dstIP
		}
		key := dev + "|" + dst
		a := aggs[key]
		if a == nil {
			a = &agg{Device: dev, Dst: dst, Category: cat, Service: service, Cloud: cloud,
				Proto: proto, external: !isPrivate(dstIP)}
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
		base := func(kind, detail string) alert {
			return alert{Device: a.Device, Kind: kind, Dst: a.Dst, Category: a.Category,
				Service: a.Service, Cloud: a.Cloud, Up: a.Up, Down: a.Down, Detail: detail, TS: now}
		}
		exfilDest := exfilCat(a.Category)
		label := a.Service
		if label == "" {
			label = a.Dst
		}
		// 1) volume exfil: lots OUT to a cloud/filehost/ai/messaging, more out than in
		if exfilDest && a.Up >= upExfilBytes && a.Up > a.Down {
			alerts = append(alerts, base("exfil_volume",
				fmt.Sprintf("%s envoyé vers %s", human(a.Up), label)))
		}
		// 2) new exfil-relevant destination for this device
		if exfilDest {
			sk := a.Device + "|" + a.Service
			newseen[sk] = true
			if !seen[sk] {
				alerts = append(alerts, base("new_cloud", "première sortie vers "+label))
			}
		}
		// 3) beaconing: many flows, low inter-arrival variance, at a C2-plausible
		//    cadence (1 s–1 h), to an external dest that is exfil-relevant or
		//    unclassified. Excludes sub-second app chatter and periodic fetches
		//    to known media/game/social CDNs (#692).
		if a.Flows >= beaconMinFlows && a.external && (exfilDest || a.Category == "") {
			avg := a.iatAvg / float64(a.Flows)
			std := a.iatStd / float64(a.Flows)
			if avg >= beaconMinIntervalMs && avg <= beaconMaxIntervalMs && std/avg <= beaconCVMax {
				alerts = append(alerts, base("beaconing",
					fmt.Sprintf("%d flux périodiques (~%.1f s)", a.Flows, avg/1000)))
			}
		}
		// 4) unclassified flow to an external host with notable upload
		if a.external && a.Category == "" && a.Up >= upExfilBytes &&
			(a.Proto == "" || strings.Contains(strings.ToLower(a.Proto), "unknown")) {
			alerts = append(alerts, base("unclassified_external", human(a.Up)+" sortie non classifiée"))
		}
	}
	// merge seen (persist union so new_cloud only fires once)
	for k := range seen {
		newseen[k] = true
	}
	saveSeen(newseen)
	writeState(aggs, alerts, now)
	updateCumulative(aggs, alerts, now)
	updateHistory(aggs, alerts, now)
	fmt.Printf("collector: %d flows-agg, %d alerts @ %d\n", len(aggs), len(alerts), now)
}

// #720 — per-device DAILY history. Adds THIS window's increments to today's
// bucket (exact, no double counting), prunes to historyDays. JSON-backed (the
// static collector has no CGO SQLite driver); rich SQL can be layered later.
func updateHistory(aggs map[string]*agg, alerts []alert, now int64) {
	type bucket struct {
		Day       string         `json:"day"`
		Device    string         `json:"device"`
		Flows     int            `json:"flows"`
		UpBytes   int64          `json:"up_bytes"`
		DownBytes int64          `json:"down_bytes"`
		Alerts    int            `json:"alerts"`
		ByCat     map[string]int `json:"by_category"`
		TS        int64          `json:"ts"`
	}
	day := time.Unix(now, 0).UTC().Format("2006-01-02")
	// load existing → index by day|device
	idx := map[string]*bucket{}
	if b, err := os.ReadFile(historyPath); err == nil {
		var rows []*bucket
		if json.Unmarshal(b, &rows) == nil {
			for _, r := range rows {
				if r.ByCat == nil {
					r.ByCat = map[string]int{}
				}
				idx[r.Day+"|"+r.Device] = r
			}
		}
	}
	// add this window's per-device increments
	for _, a := range aggs {
		k := day + "|" + a.Device
		bk := idx[k]
		if bk == nil {
			bk = &bucket{Day: day, Device: a.Device, ByCat: map[string]int{}}
			idx[k] = bk
		}
		bk.Flows += a.Flows
		bk.UpBytes += a.Up
		bk.DownBytes += a.Down
		if a.Category != "" {
			bk.ByCat[a.Category] += a.Flows
		}
		bk.TS = now
	}
	for _, al := range alerts {
		if bk := idx[day+"|"+al.Device]; bk != nil {
			bk.Alerts++
		}
	}
	// prune to historyDays, sort by day then device
	cutoff := time.Unix(now, 0).UTC().AddDate(0, 0, -historyDays).Format("2006-01-02")
	out := make([]*bucket, 0, len(idx))
	for _, bk := range idx {
		if bk.Day >= cutoff {
			out = append(out, bk)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day < out[j].Day
		}
		return out[i].Device < out[j].Device
	})
	writeJSON(historyPath, out)
}

// cumDev is the persisted per-device cumulative rollup. Superset of the state
// device schema (adds last_seen/first_seen) so the report's _dpi_stats reads it
// unchanged.
type cumDev struct {
	Device    string         `json:"device"`
	Name      string         `json:"name,omitempty"` // nom lisible du peer WG (label + IP tunnel)
	Flows     int            `json:"flows"`
	UpBytes   int64          `json:"up_bytes"`
	DownBytes int64          `json:"down_bytes"`
	ByCat     map[string]int `json:"by_category"`
	Services  []*agg         `json:"services"`
	Clouds    []*agg         `json:"clouds"`
	Alerts    []alert        `json:"alerts"`
	FirstSeen int64          `json:"first_seen"`
	LastSeen  int64          `json:"last_seen"`
}

// updateCumulative merges this window's aggs+alerts into the persistent 7d
// cumulative store and rewrites it in state.json's consumer schema (devices[] +
// top_apps/top_protocols/alerts). Idempotent-ish: best-effort, never fatal.
func updateCumulative(aggs map[string]*agg, alerts []alert, now int64) {
	devs := map[string]*cumDev{}
	if b, err := os.ReadFile(cumulPath); err == nil {
		var doc struct {
			Devices []*cumDev `json:"devices"`
		}
		if json.Unmarshal(b, &doc) == nil {
			for _, d := range doc.Devices {
				if d.ByCat == nil {
					d.ByCat = map[string]int{}
				}
				devs[d.Device] = d
			}
		}
	}
	// per-device service index (key = dst) for O(1) merge
	svcIdx := map[string]map[string]*agg{}
	for dev, d := range devs {
		m := map[string]*agg{}
		for _, s := range d.Services {
			m[s.Dst] = s
		}
		svcIdx[dev] = m
	}
	for _, a := range aggs {
		d := devs[a.Device]
		if d == nil {
			d = &cumDev{Device: a.Device, ByCat: map[string]int{}, FirstSeen: now}
			devs[a.Device] = d
			svcIdx[a.Device] = map[string]*agg{}
		}
		d.Flows += a.Flows
		d.UpBytes += a.Up
		d.DownBytes += a.Down
		d.LastSeen = now
		if n := deviceLabels[a.Device]; n != "" {
			d.Name = n // nom lisible du peer WG, rafraîchi à chaque fenêtre
		}
		if a.Category != "" {
			d.ByCat[a.Category] += a.Flows
		}
		si := svcIdx[a.Device]
		if s := si[a.Dst]; s != nil {
			s.Up += a.Up
			s.Down += a.Down
			s.Flows += a.Flows
			if s.Category == "" {
				s.Category = a.Category
			}
			if s.Service == "" {
				s.Service = a.Service
			}
			if s.Cloud == "" {
				s.Cloud = a.Cloud
			}
			if s.Proto == "" {
				s.Proto = a.Proto
			}
		} else {
			cp := *a
			cp.iatAvg, cp.iatStd = 0, 0
			si[a.Dst] = &cp
		}
	}
	for _, al := range alerts {
		if d := devs[al.Device]; d != nil {
			d.Alerts = append(d.Alerts, al)
		}
	}

	// finalise: prune stale, cap services, rebuild slices + global rollups
	type rollup struct {
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
		Flows int    `json:"flows"`
	}
	apps := map[string]*rollup{}
	protos := map[string]*rollup{}
	var allAlerts []alert
	list := make([]*cumDev, 0, len(devs))
	for dev, d := range devs {
		if now-d.LastSeen > cumulRetention {
			continue // device idle >7d → drop
		}
		// rebuild services from the merged index, sort + cap
		svcs := make([]*agg, 0, len(svcIdx[dev]))
		for _, s := range svcIdx[dev] {
			svcs = append(svcs, s)
		}
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].Up > svcs[j].Up })
		if len(svcs) > cumulMaxServices {
			svcs = svcs[:cumulMaxServices]
		}
		d.Services = svcs
		d.Clouds = d.Clouds[:0]
		for _, s := range svcs {
			if s.Cloud != "" {
				d.Clouds = append(d.Clouds, s)
			}
			an := s.Service
			if an == "" {
				an = s.Dst
			}
			if an != "" {
				if apps[an] == nil {
					apps[an] = &rollup{Name: an}
				}
				apps[an].Bytes += s.Up + s.Down
				apps[an].Flows += s.Flows
			}
			pn := s.Proto
			if pn == "" {
				pn = "unknown"
			}
			if protos[pn] == nil {
				protos[pn] = &rollup{Name: pn}
			}
			protos[pn].Bytes += s.Up + s.Down
			protos[pn].Flows += s.Flows
		}
		// prune old alerts, cap
		fresh := d.Alerts[:0]
		for _, al := range d.Alerts {
			if now-al.TS <= cumulRetention {
				fresh = append(fresh, al)
			}
		}
		if len(fresh) > 50 {
			fresh = fresh[len(fresh)-50:]
		}
		d.Alerts = fresh
		allAlerts = append(allAlerts, fresh...)
		if len(d.Clouds) > topN {
			d.Clouds = d.Clouds[:topN]
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpBytes > list[j].UpBytes })
	rank := func(m map[string]*rollup) []*rollup {
		out := make([]*rollup, 0, len(m))
		for _, r := range m {
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
		if len(out) > topN {
			out = out[:topN]
		}
		return out
	}
	out := map[string]any{
		"generated_at":  now,
		"window_days":   cumulRetention / 86400,
		"devices":       list,
		"alerts":        allAlerts,
		"alert_count":   len(allAlerts),
		"top_apps":      rank(apps),
		"top_protocols": rank(protos),
	}
	writeJSON(cumulPath, out)
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
		Device    string         `json:"device"`
		Flows     int            `json:"flows"`
		UpBytes   int64          `json:"up_bytes"`
		DownBytes int64          `json:"down_bytes"`
		Services  []*agg         `json:"services"`        // all classified egress (any category)
		Clouds    []*agg         `json:"clouds"`          // back-compat: exfil-relevant subset
		ByCat     map[string]int `json:"by_category"`     // category → flow count
		Alerts    []alert        `json:"alerts"`
	}
	devs := map[string]*devstat{}
	// global rollups (incl. uncategorised dests) for the dashboard list cards
	type rollup struct {
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
		Flows int    `json:"flows"`
	}
	apps := map[string]*rollup{}   // by service||dst
	protos := map[string]*rollup{} // by nDPI proto
	for _, a := range aggs {
		d := devs[a.Device]
		if d == nil {
			d = &devstat{Device: a.Device, ByCat: map[string]int{}}
			devs[a.Device] = d
		}
		d.Flows += a.Flows
		d.UpBytes += a.Up
		d.DownBytes += a.Down
		if a.Category != "" {
			d.Services = append(d.Services, a)
			d.ByCat[a.Category] += a.Flows
		}
		if a.Cloud != "" {
			d.Clouds = append(d.Clouds, a)
		}
		// global app rollup (service name if classified, else the dst host)
		an := a.Service
		if an == "" {
			an = a.Dst
		}
		if an != "" {
			r := apps[an]
			if r == nil {
				r = &rollup{Name: an}
				apps[an] = r
			}
			r.Bytes += a.Up + a.Down
			r.Flows += a.Flows
		}
		// global protocol rollup
		pn := a.Proto
		if pn == "" {
			pn = "unknown"
		}
		r := protos[pn]
		if r == nil {
			r = &rollup{Name: pn}
			protos[pn] = r
		}
		r.Bytes += a.Up + a.Down
		r.Flows += a.Flows
	}
	for _, al := range alerts {
		if d := devs[al.Device]; d != nil {
			d.Alerts = append(d.Alerts, al)
		}
	}
	list := make([]*devstat, 0, len(devs))
	for _, d := range devs {
		sort.Slice(d.Services, func(i, j int) bool { return d.Services[i].Up > d.Services[j].Up })
		if len(d.Services) > topN {
			d.Services = d.Services[:topN]
		}
		sort.Slice(d.Clouds, func(i, j int) bool { return d.Clouds[i].Up > d.Clouds[j].Up })
		if len(d.Clouds) > topN {
			d.Clouds = d.Clouds[:topN]
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpBytes > list[j].UpBytes })

	// rank the global rollups, cap at topN
	rank := func(m map[string]*rollup) []*rollup {
		out := make([]*rollup, 0, len(m))
		for _, r := range m {
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
		if len(out) > topN {
			out = out[:topN]
		}
		return out
	}
	// active flows = the individual aggs (incl. uncategorised), top by total bytes
	flows := make([]*agg, 0, len(aggs))
	for _, a := range aggs {
		flows = append(flows, a)
	}
	sort.Slice(flows, func(i, j int) bool { return (flows[i].Up + flows[i].Down) > (flows[j].Up + flows[j].Down) })
	if len(flows) > 20 {
		flows = flows[:20]
	}

	out := map[string]any{
		"generated_at":  now,
		"devices":       list,
		"alerts":        alerts,
		"alert_count":   len(alerts),
		"top_apps":      rank(apps),
		"top_protocols": rank(protos),
		"active_flows":  flows,
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
