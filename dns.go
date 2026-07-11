package domainsec

import (
	"context"
	"net"
	"strings"
	"time"
)

// Domain is a DNS domain name being assessed (e.g. "example.com").
type Domain string

// queryName is a fully-qualified TXT lookup name (e.g. "_dmarc.example.com").
type queryName string

// txtRecord is a single TXT record string returned by a resolver.
type txtRecord string

// SPFPolicy is the enforcement strength derived from a domain's SPF record.
type SPFPolicy string

// DMARCPolicy is the value of a DMARC record's p= tag ("none", "quarantine",
// "reject"). It is a string so it marshals to JSON exactly as the raw policy.
type DMARCPolicy string

// DKIMSelector is the DKIM selector under which a valid key was found.
type DKIMSelector string

// lookupTimeout bounds every individual TXT lookup.
const lookupTimeout = 5 * time.Second

// SPF enforcement labels derived from the record's all-mechanism qualifier.
const (
	spfStrict SPFPolicy = "strict"
	spfSoft   SPFPolicy = "soft"
	spfNone   SPFPolicy = "none"
)

// dmarcDefault is the policy reported when a DMARC record has no p= tag.
const dmarcDefault DMARCPolicy = "none"

// Record-format markers recognized during assessment.
const (
	spfPrefix     = "v=spf1"
	dkimMarker    = "v=DKIM1"
	dmarcPrefix   = "v=DMARC1"
	dmarcPolicyKV = "p="
	domainKeyHost = "._domainkey."
	dmarcHost     = "_dmarc."
	spfStrictAll  = "-all"
	spfSoftAll    = "~all"
)

// Resolver is the DNS lookup surface domainsec depends on.
//
// The single method matches net.Resolver.LookupTXT and so uses the external
// (name string, []string) signature rather than package-local named types.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// dialNetwork is the transport protocol a resolver dial uses (e.g. "udp", "tcp").
type dialNetwork string

// dialAddress is the DNS-server host:port a resolver dial connects to.
type dialAddress string

// dialContextFunc is the seam through which the production resolver opens
// connections, isolated so it is reachable from a test without a successful
// network round-trip.
type dialContextFunc func(ctx context.Context, network dialNetwork, address dialAddress) (net.Conn, error)

// timeoutDial dials with the package lookup timeout. It is the production
// Dial wired into defaultResolver.
func timeoutDial(ctx context.Context, network dialNetwork, address dialAddress) (net.Conn, error) {
	d := net.Dialer{Timeout: lookupTimeout}
	return d.DialContext(ctx, string(network), string(address))
}

// adaptDial bridges a dialContextFunc to the bare-string signature
// net.Resolver.Dial requires.
func adaptDial(dial dialContextFunc) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return dial(ctx, dialNetwork(network), dialAddress(address))
	}
}

// newDefaultResolver builds the production resolver (PreferGo) over the given
// dialer. Split from the var so the dialer seam is independently testable.
func newDefaultResolver(dial dialContextFunc) Resolver {
	return &net.Resolver{PreferGo: true, Dial: adaptDial(dial)}
}

// defaultResolver is the production resolver used when none is injected.
var defaultResolver = newDefaultResolver(timeoutDial)

// lookupTXT runs a single timeout-bounded TXT lookup and returns the records as
// txtRecord values; on any error it returns nil so callers treat a failed
// lookup as an absent record.
func lookupTXT(ctx context.Context, r Resolver, name queryName) []txtRecord {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	records, err := r.LookupTXT(ctx, string(name))
	if err != nil {
		return nil
	}
	out := make([]txtRecord, len(records))
	for i, record := range records {
		out[i] = txtRecord(record)
	}
	return out
}

// spfPolicyOf classifies an SPF record by its all-mechanism qualifier.
func spfPolicyOf(record txtRecord) SPFPolicy {
	switch {
	case strings.HasSuffix(string(record), spfStrictAll):
		return spfStrict
	case strings.HasSuffix(string(record), spfSoftAll):
		return spfSoft
	default:
		return spfNone
	}
}

func lookupSPF(ctx context.Context, r Resolver, domain Domain) (hasSPF bool, policy SPFPolicy) {
	for _, record := range lookupTXT(ctx, r, queryName(domain)) {
		if strings.HasPrefix(string(record), spfPrefix) {
			return true, spfPolicyOf(record)
		}
	}
	return false, ""
}

var dkimSelectors = []DKIMSelector{"default", "google", "k1", "s1", "selector1"}

// dkimSelectorHasKey reports whether the given selector publishes a DKIM key.
func dkimSelectorHasKey(ctx context.Context, r Resolver, domain Domain, sel DKIMSelector) bool {
	name := queryName(string(sel) + domainKeyHost + string(domain))
	for _, record := range lookupTXT(ctx, r, name) {
		if strings.Contains(string(record), dkimMarker) {
			return true
		}
	}
	return false
}

func lookupDKIM(ctx context.Context, r Resolver, domain Domain) (hasDKIM bool, selector DKIMSelector) {
	for _, sel := range dkimSelectors {
		if dkimSelectorHasKey(ctx, r, domain, sel) {
			return true, sel
		}
	}
	return false, ""
}

// dmarcPolicyOf extracts the p= policy from a DMARC record, defaulting to
// dmarcDefault when no p= tag is present.
func dmarcPolicyOf(record txtRecord) DMARCPolicy {
	for _, part := range strings.Split(string(record), ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, dmarcPolicyKV) {
			return DMARCPolicy(strings.TrimPrefix(part, dmarcPolicyKV))
		}
	}
	return dmarcDefault
}

func lookupDMARC(ctx context.Context, r Resolver, domain Domain) (hasDMARC bool, policy DMARCPolicy) {
	name := queryName(dmarcHost + string(domain))
	for _, record := range lookupTXT(ctx, r, name) {
		if strings.HasPrefix(string(record), dmarcPrefix) {
			return true, dmarcPolicyOf(record)
		}
	}
	return false, ""
}
