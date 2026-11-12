package vulnreview

import (
	"context"
	"errors"
	"log"
	"time"
)

type outboundGuardKey struct{}
type componentResult struct {
	Checked  bool
	Findings []Finding
	Warning  string
}

func (p *CVENow) waitTurn(ctx context.Context) error {
	p.mu.Lock()
	at := p.nextRequest
	if now := time.Now(); at.Before(now) {
		at = now
	}
	p.nextRequest = at.Add(125 * time.Millisecond)
	p.mu.Unlock()
	timer := time.NewTimer(max(time.Duration(0), time.Until(at)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (p *CVENow) checkComponent(ctx context.Context, pkg Package) componentResult {
	out := componentResult{Findings: []Finding{}}
	var value struct {
		Checked  *int `json:"checked"`
		Affected []struct {
			ID       string  `json:"id"`
			Title    string  `json:"title"`
			Package  Package `json:"package"`
			Severity struct {
				CVSS *float64 `json:"cvss"`
			} `json:"severity"`
		} `json:"affected"`
	}
	if err := p.call(ctx, "check_stack", map[string]any{"packages": []Package{pkg}}, &value); err != nil {
		return out
	}
	if value.Checked == nil || *value.Checked != 1 || len(value.Affected) > 1000 {
		return out
	}
	out.Checked = true
	for _, match := range value.Affected {
		if match.ID == "" || len(match.ID) > 160 || match.Package != pkg {
			out.Warning = "Provider returned an invalid or unrequested component match"
			continue
		}
		cvss := match.Severity.CVSS
		if cvss != nil && (*cvss < 0 || *cvss > 10) {
			cvss = nil
			out.Warning = "An invalid severity value was omitted"
		}
		title := []rune(match.Title)
		if len(title) > 1000 {
			match.Title = string(title[:1000])
		}
		out.Findings = append(out.Findings, Finding{ID: match.ID, Aliases: []string{}, Package: pkg, Title: match.Title, Applicability: "affected_inventory", Evidence: "cve.now check_stack matched this individual exact package version; deployment, reachability and exploitability are not established.", CVSS: cvss, FixedVersions: []string{}, References: []string{}, URL: "https://cve.now/" + match.ID, RetrievedAt: time.Now().UTC()})
	}
	return out
}
func (s *Service) guard(ctx context.Context, run Run) error {
	active, err := s.store.Active(ctx, run.ProjectID, run.ID)
	if err != nil {
		return errors.New("review state cannot be verified; external lookup stopped")
	}
	if !active {
		return context.Canceled
	}
	return nil
}
func (s *Service) watch(ctx context.Context, run Run, cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.guard(ctx, run); err != nil {
				log.Printf("[vulnerability-review] outbound stopped for run %s: %v", run.ID, err)
				cancel()

				return
			}
		}
	}
}
