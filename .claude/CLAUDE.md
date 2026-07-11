# go-domainsec

Sender-domain email-security assessment (package `domainsec`): resolves a domain's SPF, DKIM, and DMARC records behind injectable `Resolver`/`CacheStore` seams, derives a `SecurityLevel` and `DomainSecurityReport`, and `MeetsSecurityFloor()` reports whether the domain clears the floor consumers gate on (DKIM present + DMARC quarantine/reject). `Monitor` re-checks domains over time. Generic — lives in `gomatic`; promoted from xto-email during the xto repo split (see `xto-email/_projects/specs/repo-split/`), where xtod/go-alias gate alias creation on the floor.

- Library repo (`library.go` marker); flat single-package layout at the root; stdlib only (testify for tests).
- Gate: shared Makefile from `nicerobot/tools.repository` — gofumpt, vet, staticcheck, golangci-lint, govulncheck, gocognit ≤ 7, 100% coverage. Never edit the distributed `Makefile`/`.golangci.yaml`/`.github` in-tree.
- Public docs live in `docs.go-domainsec`; the README is exactly badges + the docs link.
