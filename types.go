package domainsec

import "time"

type SecurityLevel string

const (
	SecurityStrict   SecurityLevel = "strict"
	SecurityModerate SecurityLevel = "moderate"
	SecurityWeak     SecurityLevel = "weak"
)

// DMARC policy values that gate the security floor and security levels.
const (
	dmarcReject     DMARCPolicy = "reject"
	dmarcQuarantine DMARCPolicy = "quarantine"
)

type DomainSecurityReport struct {
	AssessedAt    time.Time     `json:"assessed_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Domain        Domain        `json:"domain"`
	SPFPolicy     SPFPolicy     `json:"spf_policy,omitempty"`
	DKIMSelector  DKIMSelector  `json:"dkim_selector,omitempty"`
	DMARCPolicy   DMARCPolicy   `json:"dmarc_policy,omitempty"`
	Level         SecurityLevel `json:"level"`
	HasSPF        bool          `json:"has_spf"`
	HasDKIM       bool          `json:"has_dkim"`
	HasDMARC      bool          `json:"has_dmarc"`
	IsRecommended bool          `json:"recommended"`
}

// withLevel returns a copy of the report with Level and IsRecommended derived
// from the assessed records.
func (r DomainSecurityReport) withLevel() DomainSecurityReport {
	switch {
	case r.HasDKIM && r.HasDMARC && r.DMARCPolicy == dmarcReject:
		r.Level = SecurityStrict
	case r.HasDKIM && r.HasDMARC && r.DMARCPolicy == dmarcQuarantine:
		r.Level = SecurityModerate
	default:
		r.Level = SecurityWeak
	}
	r.IsRecommended = r.HasDKIM && r.HasDMARC && r.DMARCPolicy != dmarcDefault
	return r
}

// MeetsSecurityFloor reports whether the domain meets the security floor for
// the security floor: DKIM present and DMARC at quarantine or reject.
func (r DomainSecurityReport) MeetsSecurityFloor() bool {
	return r.HasDKIM && r.HasDMARC && (r.DMARCPolicy == dmarcQuarantine || r.DMARCPolicy == dmarcReject)
}
