package main

import "testing"

// Checks the cron-line parsing + interval gate — the logic the whole feature rides on.

func TestTokenAfter(t *testing.T) {
	line := `0 * * * * "/x/subhound" -d bugcrowd.com -every 48 -push https://h/ingest -auth sh_k >> "/l" 2>&1 # subhound:bugcrowd.com`
	for flag, want := range map[string]string{"-auth": "sh_k", "-push": "https://h/ingest", "-d": "bugcrowd.com", "-nope": ""} {
		if got := tokenAfter(line, flag); got != want {
			t.Fatalf("tokenAfter(%q)=%q want %q", flag, got, want)
		}
	}
}

func TestCronLineHours(t *testing.T) {
	if h := cronLineHours(`50 * * * * "/x" -d t.com -every 48 -push u -auth k # subhound:t.com`); h != 48 {
		t.Fatalf("new-format hours=%d want 48", h)
	}
	if h := cronLineHours(`0 */12 * * * "/x" -d b.com -push u -auth k # subhound:b.com`); h != 12 {
		t.Fatalf("old-format hours=%d want 12", h) // backward-compat with pre-gate lines
	}
}

func TestCloudBase(t *testing.T) {
	for _, in := range []string{"https://h.workers.dev/ingest", "https://h.workers.dev/ingest/"} {
		if b := cloudBase(in); b != "https://h.workers.dev" {
			t.Fatalf("cloudBase(%q)=%q", in, b)
		}
	}
}

func TestGate(t *testing.T) {
	d := "gatetest-" + timestamp() + ".example" // unique so reruns don't collide
	if !cronGateAllows(d, 12) {
		t.Fatal("first call should allow (no prior run)")
	}
	if cronGateAllows(d, 12) {
		t.Fatal("immediate second call should block (interval not elapsed)")
	}
}
