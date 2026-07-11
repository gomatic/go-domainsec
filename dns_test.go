package domainsec

import (
	"context"
	"errors"
	"net"
	"testing"
)

// errLookup is a sentinel used by fakeResolver to simulate lookup failures.
var errLookup = errors.New("lookup failed")

// fakeResolver answers TXT lookups from an in-memory table and can fail
// specified names, exercising every assessment branch without real DNS.
type fakeResolver struct {
	txt  map[string][]string
	fail map[string]bool
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.fail[name] {
		return nil, errLookup
	}
	return f.txt[name], nil
}

func TestLookupSPF(t *testing.T) {
	cases := []struct {
		name       string
		wantPolicy SPFPolicy
		records    []string
		fail       bool
		wantHas    bool
	}{
		{
			name:       "strict",
			records:    []string{"v=spf1 include:_spf.example.com -all"},
			wantHas:    true,
			wantPolicy: spfStrict,
		},
		{name: "soft", records: []string{"v=spf1 ~all"}, wantHas: true, wantPolicy: spfSoft},
		{name: "neutral", records: []string{"v=spf1 ?all"}, wantHas: true, wantPolicy: spfNone},
		{name: "no spf record", records: []string{"some other txt"}, wantHas: false, wantPolicy: ""},
		{name: "empty", records: nil, wantHas: false, wantPolicy: ""},
		{name: "lookup error", fail: true, wantHas: false, wantPolicy: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fakeResolver{
				txt:  map[string][]string{"example.com": c.records},
				fail: map[string]bool{"example.com": c.fail},
			}
			has, policy := lookupSPF(context.Background(), r, "example.com")
			if has != c.wantHas || policy != c.wantPolicy {
				t.Fatalf("lookupSPF = (%v, %q), want (%v, %q)", has, policy, c.wantHas, c.wantPolicy)
			}
		})
	}
}

func TestLookupDKIM(t *testing.T) {
	cases := []struct {
		txt     map[string][]string
		fail    map[string]bool
		name    string
		wantSel DKIMSelector
		wantHas bool
	}{
		{
			name:    "default selector valid",
			txt:     map[string][]string{"default._domainkey.example.com": {"v=DKIM1; k=rsa; p=AAAA"}},
			wantHas: true, wantSel: "default",
		},
		{
			name:    "later selector valid",
			txt:     map[string][]string{"k1._domainkey.example.com": {"v=DKIM1; p=BBBB"}},
			wantHas: true, wantSel: "k1",
		},
		{
			name:    "record without dkim marker",
			txt:     map[string][]string{"default._domainkey.example.com": {"not a dkim key"}},
			wantHas: false, wantSel: "",
		},
		{
			name: "all selectors error",
			fail: map[string]bool{
				"default._domainkey.example.com":   true,
				"google._domainkey.example.com":    true,
				"k1._domainkey.example.com":        true,
				"s1._domainkey.example.com":        true,
				"selector1._domainkey.example.com": true,
			},
			wantHas: false, wantSel: "",
		},
		{name: "no records", wantHas: false, wantSel: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fakeResolver{txt: c.txt, fail: c.fail}
			has, sel := lookupDKIM(context.Background(), r, "example.com")
			if has != c.wantHas || sel != c.wantSel {
				t.Fatalf("lookupDKIM = (%v, %q), want (%v, %q)", has, sel, c.wantHas, c.wantSel)
			}
		})
	}
}

func TestLookupDMARC(t *testing.T) {
	cases := []struct {
		name       string
		wantPolicy DMARCPolicy
		records    []string
		fail       bool
		wantHas    bool
	}{
		{
			name:       "reject",
			records:    []string{"v=DMARC1; p=reject; rua=mailto:r@example.com"},
			wantHas:    true,
			wantPolicy: dmarcReject,
		},
		{name: "quarantine", records: []string{"v=DMARC1; p=quarantine"}, wantHas: true, wantPolicy: dmarcQuarantine},
		{name: "none", records: []string{"v=DMARC1; p=none"}, wantHas: true, wantPolicy: dmarcDefault},
		{
			name:       "no p tag defaults none",
			records:    []string{"v=DMARC1; rua=mailto:r@example.com"},
			wantHas:    true,
			wantPolicy: dmarcDefault,
		},
		{name: "not a dmarc record", records: []string{"v=spf1 -all"}, wantHas: false, wantPolicy: ""},
		{name: "empty", records: nil, wantHas: false, wantPolicy: ""},
		{name: "lookup error", fail: true, wantHas: false, wantPolicy: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fakeResolver{
				txt:  map[string][]string{"_dmarc.example.com": c.records},
				fail: map[string]bool{"_dmarc.example.com": c.fail},
			}
			has, policy := lookupDMARC(context.Background(), r, "example.com")
			if has != c.wantHas || policy != c.wantPolicy {
				t.Fatalf("lookupDMARC = (%v, %q), want (%v, %q)", has, policy, c.wantHas, c.wantPolicy)
			}
		})
	}
}

func TestNewDefaultResolver(t *testing.T) {
	if newDefaultResolver(timeoutDial) == nil {
		t.Fatal("newDefaultResolver returned nil")
	}
}

// TestAdaptDial verifies the bridge to net.Resolver.Dial converts the bare
// string arguments to the typed seam and propagates the dial result.
func TestAdaptDial(t *testing.T) {
	var gotNetwork dialNetwork
	var gotAddress dialAddress
	fake := func(_ context.Context, network dialNetwork, address dialAddress) (net.Conn, error) {
		gotNetwork, gotAddress = network, address
		return nil, errLookup
	}

	conn, err := adaptDial(fake)(context.Background(), "udp", "192.0.2.1:53")
	if conn != nil {
		t.Fatalf("expected nil conn, got %v", conn)
	}
	if !errors.Is(err, errLookup) {
		t.Fatalf("expected errLookup, got %v", err)
	}
	if gotNetwork != "udp" || gotAddress != "192.0.2.1:53" {
		t.Fatalf("dial received (%q, %q), want (%q, %q)", gotNetwork, gotAddress, "udp", "192.0.2.1:53")
	}
}

// TestTimeoutDial exercises the production dial seam without a successful
// network round-trip: a cancelled context makes DialContext return promptly.
func TestTimeoutDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := timeoutDial(ctx, "udp", "192.0.2.1:53"); err == nil {
		t.Fatal("expected dial error on cancelled context")
	}
}
