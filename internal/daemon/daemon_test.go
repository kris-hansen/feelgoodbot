package daemon

import (
	"testing"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
	"github.com/kris-hansen/feelgoodbot/internal/snapshot"
)

func TestChangesSinceLastScanDoesNotReplayBaselineDrift(t *testing.T) {
	baseline := map[string]*scanner.FileInfo{
		"/stable":  {Path: "/stable", Hash: "v1"},
		"/drifted": {Path: "/drifted", Hash: "old"},
	}
	lastScan := &snapshot.Snapshot{Files: map[string]*scanner.FileInfo{
		"/stable":  {Path: "/stable", Hash: "v1"},
		"/drifted": {Path: "/drifted", Hash: "new"},
	}}
	current := map[string]*scanner.FileInfo{
		"/stable":    {Path: "/stable", Hash: "v1"},
		"/drifted":   {Path: "/drifted", Hash: "new"},
		"/intrusion": {Path: "/intrusion", Hash: "unexpected"},
	}

	if baselineChanges := scanner.Compare(baseline, current); len(baselineChanges) != 2 {
		t.Fatalf("baseline comparison = %d changes, want 2", len(baselineChanges))
	}

	incremental := changesSinceLastScan(lastScan, current)
	if len(incremental) != 1 {
		t.Fatalf("incremental comparison = %d changes, want 1", len(incremental))
	}
	if incremental[0].Path != "/intrusion" || incremental[0].Type != "added" {
		t.Errorf("incremental change = %#v, want added /intrusion", incremental[0])
	}
}

func TestChangesSinceLastScanMissingCheckpointDoesNotBackfill(t *testing.T) {
	current := map[string]*scanner.FileInfo{
		"/changed": {Path: "/changed", Hash: "v2"},
	}
	if got := changesSinceLastScan(nil, current); len(got) != 0 {
		t.Errorf("missing checkpoint produced %d changes, want 0", len(got))
	}
}
