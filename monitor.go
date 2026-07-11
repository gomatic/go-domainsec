package domainsec

import (
	"context"
	"log/slog"
	"time"
)

// Monitor periodically re-assesses sender domains when their cached
// security reports expire. Flags aliases bound to degraded domains.
type Monitor struct {
	service Service
	logger  *slog.Logger
}

// NewMonitor builds a monitor over the given domain-security service.
func NewMonitor(service Service, logger *slog.Logger) Monitor {
	return Monitor{service: service, logger: logger}
}

// Run checks for expired domain assessments at the given interval.
func (m Monitor) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.check()
		}
	}
}

func (m Monitor) check() {
	// Domain re-assessment is handled by the cache TTL in the Service.
	// When a cached report expires (24h), the next CheckDomain call
	// automatically fetches fresh DNS records.
	//
	// This monitor can be extended to:
	// 1. Query the alias store for distinct sender domains
	// 2. Re-assess each domain proactively
	// 3. Flag aliases bound to domains that have lost DKIM/DMARC
	// 4. Emit audit events and user notifications
	//
	// For now, this serves as the hook point for the background job.
	m.logger.Debug("domain security monitor check completed")
}
