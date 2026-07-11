// Package domainsec assesses sender-domain SPF, DKIM, and DMARC records.
//
// It resolves a domain's email-authentication records, derives a security level
// and report, and decides whether the domain meets the security floor
// consumers gate on (e.g. alias creation): DKIM present and DMARC at
// quarantine or reject.
package domainsec

import (
	"context"
	"strings"
	"time"
)

// cacheTTL bounds how long a cached assessment is trusted before re-assessment,
// so a domain whose DKIM/DMARC posture degrades is re-evaluated within a day
// rather than staying "recommended" forever (data-model: expires_at =
// assessed_at + 24h).
const cacheTTL = 24 * time.Hour

// CacheStore persists assessed domain-security reports between lookups.
type CacheStore interface {
	Get(ctx context.Context, domain Domain) (*DomainSecurityReport, error)
	Set(ctx context.Context, report DomainSecurityReport) error
}

// Service assesses sender-domain security, optionally caching reports.
type Service struct {
	cache    CacheStore
	resolver Resolver
	now      func() time.Time
}

// NewService builds a domain-security service. A nil resolver uses the
// production default resolver.
func NewService(cache CacheStore, resolver Resolver) Service {
	if resolver == nil {
		resolver = defaultResolver
	}
	return Service{cache: cache, resolver: resolver, now: time.Now}
}

// rawDomain is a domain name exactly as supplied by an external caller —
// possibly mixed-case and padded with whitespace — before normalization.
type rawDomain string

// normalizeDomain lower-cases and trims a raw domain string.
func normalizeDomain(raw rawDomain) Domain {
	return Domain(strings.ToLower(strings.TrimSpace(string(raw))))
}

// cached returns a cached report for domain, or nil when caching is disabled,
// the lookup errors, no report is stored, or the stored report has expired (so
// a degraded domain is re-assessed rather than trusted indefinitely).
func (s Service) cached(ctx context.Context, domain Domain) *DomainSecurityReport {
	if s.cache == nil {
		return nil
	}
	report, err := s.cache.Get(ctx, domain)
	if err != nil || report == nil {
		return nil
	}
	if !s.now().Before(report.ExpiresAt) {
		return nil // expired — re-assess
	}
	return report
}

// assess performs the DKIM/DMARC/SPF lookups and computes the security level.
func (s Service) assess(ctx context.Context, domain Domain) DomainSecurityReport {
	now := s.now().UTC()
	report := DomainSecurityReport{
		Domain:     domain,
		AssessedAt: now,
		ExpiresAt:  now.Add(cacheTTL),
	}
	report.HasSPF, report.SPFPolicy = lookupSPF(ctx, s.resolver, domain)
	report.HasDKIM, report.DKIMSelector = lookupDKIM(ctx, s.resolver, domain)
	report.HasDMARC, report.DMARCPolicy = lookupDMARC(ctx, s.resolver, domain)
	return report.withLevel()
}

// store writes report to the cache when caching is enabled; a cache write
// failure is non-fatal and intentionally discarded.
func (s Service) store(ctx context.Context, report DomainSecurityReport) {
	if s.cache != nil {
		_ = s.cache.Set(ctx, report)
	}
}

// CheckDomain returns the security report for a sender domain, serving a cached
// report when available. The error return is part of the contract callers
// depend on; assessment itself never fails (a failed lookup is an absent
// record), so the returned error is always nil.
//
// domain is a plain string at this external boundary because callers in other
// packages pass values they already hold; it is normalized to a Domain here.
func (s Service) CheckDomain(ctx context.Context, domain string) (*DomainSecurityReport, error) {
	name := normalizeDomain(rawDomain(domain))

	if report := s.cached(ctx, name); report != nil {
		return report, nil
	}

	report := s.assess(ctx, name)
	s.store(ctx, report)
	return &report, nil
}
