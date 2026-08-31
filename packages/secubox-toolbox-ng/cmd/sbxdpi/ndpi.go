// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: nDPIsrvd distributor stream consumer
//
// nDPIsrvd frames every JSON message as a fixed-width 5-digit ASCII length
// prefix immediately followed by the JSON object, e.g. "00513{...}\n". The
// 5-digit value is the length of the BODY that follows the digits (the JSON
// object plus its trailing newline) — NOT the total including the digits. So
// the next frame starts at offset 5+prefix. Verified empirically against
// nDPIsrvd 1.7.0-pre on the wire (nDPId config.h NETWORK_BUFFER_LENGTH_DIGITS=5,
// NETWORK_BUFFER_MAX_SIZE=33792 bounds one body). We reproduce this framing
// exactly rather than newline-splitting, because packet-event bodies are large
// and contain their own newline inside the counted body.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// nDPId config.h NETWORK_BUFFER_LENGTH_DIGITS.
	frameDigits = 5
	// nDPId config.h NETWORK_BUFFER_MAX_SIZE — hard ceiling on a single
	// framed message; anything larger is a desync, not a real message.
	frameMaxSize = 33792
)

// dpiEvent is the tolerant projection of an nDPId flow-event JSON line. Only
// the fields sbxdpi aggregates are declared; nDPId ships many more per event
// and encoding/json ignores the rest. Numeric ids arrive as JSON numbers,
// proto/category/hostname as strings, flow_risk/confidence as string-keyed
// objects.
type dpiEvent struct {
	FlowEventName string `json:"flow_event_name"`
	FlowID        uint64 `json:"flow_id"`
	L4Proto       string `json:"l4_proto"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       int    `json:"src_port"`
	DstPort       int    `json:"dst_port"`
	SrcPackets    uint64 `json:"flow_src_packets"`
	DstPackets    uint64 `json:"flow_dst_packets"`
	SrcBytes      uint64 `json:"flow_src_tot_l4_payload_len"`
	DstBytes      uint64 `json:"flow_dst_tot_l4_payload_len"`
	NDPI          struct {
		Proto    string `json:"proto"`    // "TLS.Google" (master.app)
		ProtoID  string `json:"proto_id"` // "91.126"
		Category string `json:"category"` // "Web", "Cloud", ...
		Hostname string `json:"hostname"` // SNI / DNS name
		FlowRisk map[string]struct {
			Risk     string `json:"risk"`
			Severity string `json:"severity"`
		} `json:"flow_risk"`
	} `json:"ndpi"`
}

// master returns the protocol before the dot ("TLS" from "TLS.Google"); the
// whole string is the "app". Empty proto → "Unknown".
func (e *dpiEvent) master() string {
	p := e.NDPI.Proto
	if p == "" {
		return "Unknown"
	}
	if i := strings.IndexByte(p, '.'); i > 0 {
		return p[:i]
	}
	return p
}

func (e *dpiEvent) app() string {
	if e.NDPI.Proto == "" {
		return "Unknown"
	}
	return e.NDPI.Proto
}

func (e *dpiEvent) category() string {
	if e.NDPI.Category == "" {
		return "Unrated"
	}
	return e.NDPI.Category
}

func (e *dpiEvent) bytes() uint64 { return e.SrcBytes + e.DstBytes }

// consumeDistributor dials the nDPIsrvd distributor socket and feeds every
// framed flow event through the filter into the aggregator, reconnecting with
// backoff on any dial/read error until ctx is cancelled.
func consumeDistributor(ctx context.Context, cfg Config, agg *aggregator, filt *filter) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.Dial("unix", cfg.DistributorSock)
		if err != nil {
			agg.setConnected(false)
			if sleepCtx(ctx, cfg.DialBackoff) {
				return
			}
			continue
		}
		agg.setConnected(true)
		log.Printf("sbxdpi: connected to nDPIsrvd distributor %s", cfg.DistributorSock)

		// Close the conn when ctx is cancelled to unblock the reader.
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()

		readFrames(conn, agg, filt)
		_ = conn.Close()
		agg.setConnected(false)

		select {
		case <-ctx.Done():
			return
		default:
			log.Printf("sbxdpi: distributor stream ended, reconnecting")
			if sleepCtx(ctx, cfg.DialBackoff) {
				return
			}
		}
	}
}

// readFrames parses the 5-digit-prefixed framing until the connection errors
// or EOFs. A single malformed frame is fatal to the connection (the stream is
// byte-aligned — a bad length desyncs everything after it), so we return and
// let consumeDistributor reconnect from a clean state.
func readFrames(conn net.Conn, agg *aggregator, filt *filter) {
	br := bufio.NewReaderSize(conn, 64*1024)
	hdr := make([]byte, frameDigits)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("sbxdpi: frame header read: %v", err)
			}
			return
		}
		// The 5-digit prefix is the BODY length (JSON + newline) that follows
		// the digits, not the total-including-digits.
		bodyLen, err := strconv.Atoi(strings.TrimSpace(string(hdr)))
		if err != nil || bodyLen <= 0 || bodyLen > frameMaxSize {
			log.Printf("sbxdpi: bad frame length %q (desync) — reconnecting", hdr)
			return
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			log.Printf("sbxdpi: frame body read: %v", err)
			return
		}
		var ev dpiEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			// Malformed JSON inside a correctly-framed message: skip the one
			// message, keep the (still byte-aligned) stream.
			continue
		}
		ingest(agg, filt, &ev)
	}
}

// ingest applies go-level filtering then updates the aggregator. Flows are
// counted once at detection (immediate liveness); bytes are attributed at flow
// end (accurate final volume); risks are surfaced whenever present and not
// muted.
func ingest(agg *aggregator, filt *filter, ev *dpiEvent) {
	switch ev.FlowEventName {
	case "detected", "detection-update", "guessed":
		d := filt.classify(ev)
		if d.drop {
			agg.countFiltered()
			return
		}
		agg.recordFlow(ev, d.firstParty)
		agg.recordRisks(ev, filt)
	case "end", "idle":
		d := filt.classify(ev)
		if d.drop {
			return
		}
		agg.recordBytes(ev)
		agg.recordRisks(ev, filt)
	}
}

// sleepCtx sleeps for d or until ctx is cancelled; returns true if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}
