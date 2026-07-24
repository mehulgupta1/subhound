package main

import "testing"

// TestExcluder guards the -exclude matcher against the substring footgun: a bare
// label must match only whole dotted labels, a domain must match itself + its
// subdomains (not lookalikes), and re: is an explicit regex escape hatch.
func TestExcluder(t *testing.T) {
	cases := []struct {
		spec, name string
		drop       bool
	}{
		{"api", "api.tesla.com", true},          // bare label, matches as a label
		{"api", "x.api.tesla.com", true},        // label anywhere in the name
		{"api", "rapids.tesla.com", false},      // NOT substring inside another label
		{"api", "therapist.tesla.com", false},   // NOT substring
		{"akamai", "x.akamai.com", true},        // used to be a silent no-op (^akamai$)
		{"akamai", "notakamai.com", false},      // label boundary respected
		{"akamai.com", "x.akamai.com", true},    // domain drops its subdomains
		{"akamai.com", "akamai.com", true},      // and the domain itself
		{"akamai.com", "notakamai.com", false},  // but not a lookalike domain
		{"corp", "corporate.example.com", false},
		{"re:rap.ds", "rapids.tesla.com", true}, // explicit regex still available
	}
	for _, c := range cases {
		if got := loadExcluder(c.spec).match(c.name); got != c.drop {
			t.Errorf("exclude %q vs %q: got drop=%v want %v", c.spec, c.name, got, c.drop)
		}
	}
}
