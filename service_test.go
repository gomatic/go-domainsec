package domainsec

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeCache is an in-memory CacheStore for exercising Service cache paths.
type fakeCache struct {
	getErr    error
	setErr    error
	get       *DomainSecurityReport
	set       DomainSecurityReport
	setCalled bool
}

func (f *fakeCache) Get(_ context.Context, _ Domain) (*DomainSecurityReport, error) {
	return f.get, f.getErr
}

func (f *fakeCache) Set(_ context.Context, report DomainSecurityReport) error {
	f.set = report
	f.setCalled = true
	return f.setErr
}

func TestNewServiceNilResolverUsesDefault(t *testing.T) {
	svc := NewService(nil, nil)
	assert.Same(t, defaultResolver, svc.resolver)
}

func TestCheckDomainNormalizesAndAssesses(t *testing.T) {
	r := fakeResolver{txt: map[string][]string{
		"example.com":                    {"v=spf1 -all"},
		"default._domainkey.example.com": {"v=DKIM1; k=rsa; p=AAAA"},
		"_dmarc.example.com":             {"v=DMARC1; p=reject"},
	}}
	svc := NewService(nil, r)

	report, err := svc.CheckDomain(context.Background(), "  Example.COM  ")
	assert.NoError(t, err)
	assert.Equal(t, Domain("example.com"), report.Domain)
	assert.True(t, report.HasDKIM)
	assert.Equal(t, dmarcReject, report.DMARCPolicy)
	assert.Equal(t, spfStrict, report.SPFPolicy)
	assert.Equal(t, SecurityStrict, report.Level)
	assert.False(t, report.AssessedAt.IsZero())
	// The 24h cache TTL is stamped so a degraded domain is re-assessed.
	assert.Equal(t, report.AssessedAt.Add(cacheTTL), report.ExpiresAt)
}

func TestCheckDomainServesFreshCachedReport(t *testing.T) {
	cached := &DomainSecurityReport{Domain: "example.com", HasDKIM: true, ExpiresAt: time.Unix(100000, 0)}
	cache := &fakeCache{get: cached}
	svc := NewService(cache, fakeResolver{})
	svc.now = func() time.Time { return time.Unix(1000, 0) } // before ExpiresAt

	report, err := svc.CheckDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.Same(t, cached, report)
	assert.False(t, cache.setCalled, "a fresh cached report must not re-store")
}

func TestCheckDomainReassessesExpiredCachedReport(t *testing.T) {
	// A stale, expired cached report must NOT be trusted — the domain is
	// re-assessed so a since-degraded posture is caught.
	stale := &DomainSecurityReport{Domain: "example.com", HasDKIM: true, ExpiresAt: time.Unix(1000, 0)}
	cache := &fakeCache{get: stale}
	svc := NewService(cache, fakeResolver{})
	svc.now = func() time.Time { return time.Unix(100000, 0) } // past ExpiresAt

	report, err := svc.CheckDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.NotSame(t, stale, report, "expired cache must be re-assessed, not served")
	assert.True(t, cache.setCalled, "re-assessment must re-store the fresh report")
	assert.Equal(t, *report, cache.set, "the stored report must be the fresh assessment")
}

func TestCheckDomainCacheMissAssessesAndStores(t *testing.T) {
	cache := &fakeCache{} // Get returns (nil, nil): a cache miss
	svc := NewService(cache, fakeResolver{})

	report, err := svc.CheckDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.True(t, cache.setCalled, "a cache miss assesses and stores")
	assert.Equal(t, *report, cache.set)
}

func TestCheckDomainCacheGetErrorFallsThroughAndStores(t *testing.T) {
	cache := &fakeCache{getErr: errLookup, setErr: errLookup}
	svc := NewService(cache, fakeResolver{})

	report, err := svc.CheckDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.True(t, cache.setCalled, "fresh report must be stored despite get error")
	assert.Equal(t, *report, cache.set)
}

func TestCheckDomainCacheMissNilReportAssesses(t *testing.T) {
	cache := &fakeCache{get: nil}
	svc := NewService(cache, fakeResolver{})

	report, err := svc.CheckDomain(context.Background(), "example.com")
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.True(t, cache.setCalled)
	assert.Equal(t, *report, cache.set)
}

func TestWithLevel_Strict(t *testing.T) {
	r := DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "reject"}.withLevel()
	assert.Equal(t, SecurityStrict, r.Level)
	assert.True(t, r.IsRecommended)
}

func TestWithLevel_Moderate(t *testing.T) {
	r := DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "quarantine"}.withLevel()
	assert.Equal(t, SecurityModerate, r.Level)
	assert.True(t, r.IsRecommended)
}

func TestWithLevel_Weak_NoDKIM(t *testing.T) {
	r := DomainSecurityReport{HasDKIM: false, HasDMARC: true, DMARCPolicy: "reject"}.withLevel()
	assert.Equal(t, SecurityWeak, r.Level)
	assert.False(t, r.IsRecommended)
}

func TestWithLevel_Weak_DMARCNone(t *testing.T) {
	r := DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "none"}.withLevel()
	assert.Equal(t, SecurityWeak, r.Level)
	assert.False(t, r.IsRecommended)
}

func TestWithLevel_DoesNotMutateReceiver(t *testing.T) {
	original := DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "reject"}
	_ = original.withLevel()
	assert.Empty(t, original.Level, "withLevel must return a copy, not mutate the receiver")
	assert.False(t, original.IsRecommended)
}

func TestMeetsSecurityFloor_Strict(t *testing.T) {
	r := &DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "reject"}
	assert.True(t, r.MeetsSecurityFloor())
}

func TestMeetsSecurityFloor_Moderate(t *testing.T) {
	r := &DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "quarantine"}
	assert.True(t, r.MeetsSecurityFloor())
}

func TestMeetsSecurityFloor_RejectsNoDKIM(t *testing.T) {
	r := &DomainSecurityReport{HasDKIM: false, HasDMARC: true, DMARCPolicy: "reject"}
	assert.False(t, r.MeetsSecurityFloor())
}

func TestMeetsSecurityFloor_RejectsDMARCNone(t *testing.T) {
	r := &DomainSecurityReport{HasDKIM: true, HasDMARC: true, DMARCPolicy: "none"}
	assert.False(t, r.MeetsSecurityFloor())
}

func TestMeetsSecurityFloor_RejectsNoDMARC(t *testing.T) {
	r := &DomainSecurityReport{HasDKIM: true, HasDMARC: false}
	assert.False(t, r.MeetsSecurityFloor())
}

func TestMeetsSecurityFloor_RejectsNothing(t *testing.T) {
	r := &DomainSecurityReport{}
	assert.False(t, r.MeetsSecurityFloor())
}

// TestRawDomainIsNormalizedBeforeAnyLookupOrCacheKey names rawDomain's claim.
// It is the type that says "this came from outside and has not been
// normalized", and the normalization it awaits is what makes the cache correct:
// DNS is case-insensitive, so "Example.COM" and "example.com" are one domain,
// and keying the cache on the raw string would store a separate entry per
// spelling — every variant paying a fresh set of DNS lookups while a populated
// cache sat unused. Whitespace does the same, and a padded domain would also be
// looked up verbatim.
func TestRawDomainIsNormalizedBeforeAnyLookupOrCacheKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		raw  rawDomain
		want Domain
		why  string
	}{
		{raw: "example.com", want: "example.com", why: "an already-normal domain is unchanged"},
		{raw: "Example.COM", want: "example.com", why: "DNS is case-insensitive"},
		{raw: "  example.com  ", want: "example.com", why: "padding is not part of the name"},
		{raw: "\tExample.Com\n", want: "example.com", why: "any whitespace, and case, together"},
		{raw: "", want: "", why: "an empty domain normalizes to empty rather than to something"},
	} {
		assert.Equal(t, tc.want, normalizeDomain(tc.raw), "normalizeDomain(%q): %s", tc.raw, tc.why)
	}
}
