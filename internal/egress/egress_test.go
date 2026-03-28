package egress

import (
	"testing"
	"time"
)

func TestParseLsof(t *testing.T) {
	output := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
loginwindow 123   user    6u  IPv4 0x1234      0t0  TCP 192.168.1.10:54321->93.184.216.34:443 (ESTABLISHED)
node       5678   user    22u IPv4 0x5678      0t0  TCP 127.0.0.1:3000->127.0.0.1:5432 (ESTABLISHED)
Safari     9012   user    15u IPv4 0x9012      0t0  TCP 10.0.0.5:55555->151.101.1.69:443 (ESTABLISHED)
node       5678   user    23u IPv4 0x5679      0t0  TCP 192.168.1.10:54322->api.openai.com:443 (LISTEN)
Dropbox    3456   user    10u IPv4 0xaaaa      0t0  TCP *:17500 (LISTEN)
`

	conns := parseLsof(output)

	// Should only get ESTABLISHED connections
	if len(conns) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(conns))
	}

	// Check first connection
	if conns[0].Process != "loginwindow" {
		t.Errorf("expected loginwindow, got %s", conns[0].Process)
	}
	if conns[0].Destination != "93.184.216.34:443" {
		t.Errorf("expected 93.184.216.34:443, got %s", conns[0].Destination)
	}

	// Check node connection
	if conns[1].Process != "node" {
		t.Errorf("expected node, got %s", conns[1].Process)
	}
	if conns[1].Destination != "127.0.0.1:5432" {
		t.Errorf("expected 127.0.0.1:5432, got %s", conns[1].Destination)
	}
}

func TestCompareToBaseline(t *testing.T) {
	baseline := &Baseline{
		Processes: map[string]*ProcessProfile{
			"node": {
				Destinations: map[string]bool{
					"api.openai.com:443": true,
					"localhost:*":        true,
				},
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			},
		},
		Ignored: []string{"curl"},
	}

	conns := []Connection{
		{Process: "node", Destination: "api.openai.com:443"},     // known
		{Process: "node", Destination: "127.0.0.1:5432"},         // matches localhost:*
		{Process: "node", Destination: "evil.com:443"},           // new destination
		{Process: "mystery", Destination: "bad.server.com:8080"}, // new process
		{Process: "curl", Destination: "anything.com:443"},       // ignored
	}

	anomalies := CompareToBaseline(baseline, conns)

	if len(anomalies) != 2 {
		t.Fatalf("expected 2 anomalies, got %d", len(anomalies))
	}

	// Check that node->evil.com is detected
	found := false
	for _, a := range anomalies {
		if a.Type == "new_destination" && a.Process == "node" && a.Destination == "evil.com:443" {
			found = true
		}
	}
	if !found {
		t.Error("expected new_destination anomaly for node->evil.com:443")
	}

	// Check that mystery process is detected
	found = false
	for _, a := range anomalies {
		if a.Type == "new_process" && a.Process == "mystery" {
			found = true
		}
	}
	if !found {
		t.Error("expected new_process anomaly for mystery")
	}
}

func TestMatchesDestination(t *testing.T) {
	profile := &ProcessProfile{
		Destinations: map[string]bool{
			"api.openai.com:443": true,
			"localhost:*":        true,
			"10.0.0.1:*":         true,
		},
	}

	tests := []struct {
		dest  string
		match bool
	}{
		{"api.openai.com:443", true},
		{"api.openai.com:80", false},
		{"127.0.0.1:5432", true}, // matches localhost:*
		{"127.0.0.1:3000", true}, // matches localhost:*
		{"10.0.0.1:443", true},   // matches 10.0.0.1:*
		{"10.0.0.1:8080", true},  // matches 10.0.0.1:*
		{"10.0.0.2:443", false},  // different host
		{"evil.com:443", false},
	}

	for _, tt := range tests {
		got := matchesDestination(profile, tt.dest)
		if got != tt.match {
			t.Errorf("matchesDestination(%q) = %v, want %v", tt.dest, got, tt.match)
		}
	}
}

func TestWildcardAll(t *testing.T) {
	profile := &ProcessProfile{
		Destinations: map[string]bool{
			"*": true,
		},
	}

	if !matchesDestination(profile, "anything.com:443") {
		t.Error("wildcard * should match anything")
	}
}

func TestMergeIntoBaseline(t *testing.T) {
	b := NewBaseline()

	conns := []Connection{
		{Process: "node", Destination: "api.openai.com:443"},
		{Process: "node", Destination: "localhost:3000"},
		{Process: "Safari", Destination: "example.com:443"},
	}

	MergeIntoBaseline(b, conns)

	if len(b.Processes) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(b.Processes))
	}

	nodeProfile := b.Processes["node"]
	if nodeProfile == nil {
		t.Fatal("expected node profile")
	}
	if len(nodeProfile.Destinations) != 2 {
		t.Errorf("expected 2 destinations for node, got %d", len(nodeProfile.Destinations))
	}
}

func TestAddIgnored(t *testing.T) {
	b := NewBaseline()

	if !AddIgnored(b, "curl") {
		t.Error("first add should return true")
	}
	if AddIgnored(b, "curl") {
		t.Error("duplicate add should return false")
	}
	if len(b.Ignored) != 1 {
		t.Errorf("expected 1 ignored, got %d", len(b.Ignored))
	}
}

func TestIgnoredProcessSkipped(t *testing.T) {
	b := NewBaseline()
	b.Ignored = []string{"curl"}

	conns := []Connection{
		{Process: "curl", Destination: "anything.com:443"},
		{Process: "node", Destination: "api.openai.com:443"},
	}

	MergeIntoBaseline(b, conns)

	if _, exists := b.Processes["curl"]; exists {
		t.Error("curl should be ignored during merge")
	}
	if _, exists := b.Processes["node"]; !exists {
		t.Error("node should be in baseline")
	}
}
