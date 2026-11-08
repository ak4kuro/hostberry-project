package adblock

import (
	"strings"
	"testing"
)

func TestParseAdblockListDomainsHostsFormat(t *testing.T) {
	input := `# comentario
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.org other.example.net
0.0.0.0
invalid line without ip
||rule.example.com^
`
	domains, err := parseAdblockListDomains(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"ads.example.com", "tracker.example.org", "other.example.net", "rule.example.com"} {
		if !domains[want] {
			t.Errorf("missing domain %q", want)
		}
	}
	if len(domains) != 4 {
		t.Errorf("got %d domains, want 4", len(domains))
	}
}

func TestParseAdblockListDomainsAdblockRules(t *testing.T) {
	input := `! Title: test
||doubleclick.net^
||pagead2.googlesyndication.com^$third-party
@@||whitelist.example.com^
||sub.domain.example.com^$script
`
	domains, err := parseAdblockListDomains(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !domains["doubleclick.net"] {
		t.Error("missing doubleclick.net")
	}
	if !domains["pagead2.googlesyndication.com"] {
		t.Error("missing pagead2.googlesyndication.com")
	}
	// La regla de whitelist @@||... no debe capturar el dominio como bloqueo
	// porque el regex exige que la línea empiece por ||.
	if domains["whitelist.example.com"] {
		t.Error("whitelist rule should not be parsed as block domain")
	}
	// /path no forma parte del dominio
	if !domains["sub.domain.example.com"] {
		t.Error("missing sub.domain.example.com")
	}
}

func TestParseAdblockListDomainsEmpty(t *testing.T) {
	if _, err := parseAdblockListDomains(strings.NewReader("# solo comentarios\n")); err == nil {
		t.Fatal("expected error for empty domain list")
	}
}

func TestParseAdblockListDomainsCaseInsensitive(t *testing.T) {
	domains, err := parseAdblockListDomains(strings.NewReader("0.0.0.0 ADS.Example.COM\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !domains["ads.example.com"] {
		t.Error("domain should be lowercased")
	}
}
