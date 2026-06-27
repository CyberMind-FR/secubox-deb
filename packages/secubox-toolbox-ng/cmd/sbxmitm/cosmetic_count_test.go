// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package main

import "testing"

func TestCosmeticCounterSnapshotClears(t *testing.T) {
	a := newAdStats()
	a.recordCosmetic()
	a.recordCosmetic()
	if got := a.snapshotCosmetic(); got != 2 {
		t.Fatalf("snapshotCosmetic = %d, want 2", got)
	}
	if got := a.snapshotCosmetic(); got != 0 {
		t.Fatalf("snapshot must clear; second call = %d, want 0", got)
	}
}
