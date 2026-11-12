package vulnreview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Findings []Finding
	Checked  int
	Warnings []string
	Complete bool
}
type Provider interface {
	Check(context.Context, []Package) (Result, error)
}
type CVENow struct {
	client      *http.Client
	mu          sync.Mutex
	cache       map[string]cachedDetail
	slots       chan struct{}
	nextRequest time.Time
}
type cachedDetail struct {
	value   detail
	expires time.Time
}
type detail struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Status       string   `json:"status"`
	Exploitation struct {
		KEV json.RawMessage `json:"kev"`
	} `json:"exploitation"`
	Affected []struct {
		Ecosystem string `json:"ecosystem"`
		Package   string `json:"package"`
		Ranges    []struct {
			Fixed string `json:"fixed"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Sources []struct {
		URL string `json:"url"`
	} `json:"sources"`
}

func NewCVENow() *CVENow {
	return &CVENow{client: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, cache: map[string]cachedDetail{}, slots: make(chan struct{}, 4)}
}
func (p *CVENow) call(ctx context.Context, name string, args any, dst any) error {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://cve.now/mcp", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if err := p.waitTurn(ctx); err != nil {
			return err
		}
		if guard, ok := ctx.Value(outboundGuardKey{}).(func(context.Context) error); ok {
			if err := guard(ctx); err != nil {
				return err
			}
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return errors.New("cve.now request failed or timed out")
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
		resp.Body.Close()
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt == 0 {
			delay := time.Second
			if seconds, parseErr := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 32); parseErr == nil && seconds >= 0 {
				delay = time.Duration(seconds) * time.Second
			} else if until, parseErr := http.ParseTime(resp.Header.Get("Retry-After")); parseErr == nil {
				delay = max(time.Duration(0), time.Until(until))
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				continue
			}
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("cve.now returned HTTP %d", resp.StatusCode)
		}
		if readErr != nil || len(raw) > 8<<20 {
			return errors.New("cve.now response was unreadable or too large")
		}
		if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			scanner := bufio.NewScanner(bytes.NewReader(raw))
			scanner.Buffer(make([]byte, 4096), 8<<20)
			var data []string
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "data:") {
					data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				}
			}
			if scanner.Err() != nil {
				return errors.New("invalid MCP event stream")
			}
			raw = []byte(strings.Join(data, "\n"))
		}
		var envelope struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &envelope) != nil || len(envelope.Error) > 0 || envelope.Result.IsError {
			return errors.New("cve.now returned an invalid or failed MCP response")
		}
		for _, c := range envelope.Result.Content {
			if c.Type == "text" && json.Unmarshal([]byte(c.Text), dst) == nil {
				return nil
			}
		}
		return errors.New("cve.now returned no structured tool result")
	}
	return errors.New("cve.now retry limit exceeded")
}
func (p *CVENow) getDetail(ctx context.Context, id string) (detail, error) {
	p.mu.Lock()
	cached, ok := p.cache[id]
	p.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.value, nil
	}
	var d detail
	if err := p.call(ctx, "get_vulnerability", map[string]string{"id": id}, &d); err != nil {
		return d, err
	}
	validID := strings.EqualFold(d.ID, id)
	for _, alias := range d.Aliases {
		validID = validID || strings.EqualFold(alias, id)
	}
	encoded, _ := json.Marshal(d)
	if !validID || len(d.Aliases) > 128 || len(d.References) > 256 || len(d.Affected) > 1000 || len(encoded) > 256<<10 {
		return d, errors.New("advisory details were inconsistent or exceeded the evidence limit")
	}
	p.mu.Lock()
	if len(p.cache) >= 128 {
		p.cache = map[string]cachedDetail{}
	}
	p.cache[id] = cachedDetail{d, time.Now().Add(15 * time.Minute)}
	p.mu.Unlock()
	return d, nil
}
func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
func uniqueSorted(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		if v != "" {
			set[v] = true
		}
	}
	out := []string{}
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func canonicalID(ids []string) string {
	ids = uniqueSorted(ids)
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			return strings.ToUpper(id)
		}
	}
	if len(ids) > 0 {
		return strings.ToUpper(ids[0])
	}
	return ""
}
func (p *CVENow) Check(ctx context.Context, packages []Package) (Result, error) {
	result := Result{Findings: []Finding{}, Warnings: []string{}, Complete: true}
	details := map[string]detail{}
	detailErrors := map[string]bool{}
	rawFindings := []Finding{}
	outcomes := make([]componentResult, len(packages))
	jobs := make(chan int, len(packages))
	for i := range packages {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				outcomes[i] = p.checkComponent(ctx, packages[i])
			}
		}()
	}
	workers.Wait()
	for _, outcome := range outcomes {
		if !outcome.Checked {
			result.Complete = false
			result.Warnings = append(result.Warnings, "Some component lookups failed, timed out or returned incomplete coverage")
		} else {
			result.Checked++
		}
		if outcome.Warning != "" {
			result.Complete = false
			result.Warnings = append(result.Warnings, outcome.Warning)
		}
		available := 1000 - len(rawFindings)
		if len(outcome.Findings) > available {
			result.Complete = false
			result.Warnings = append(result.Warnings, "Review exceeded the 1000-match evidence limit; results are incomplete")
			rawFindings = append(rawFindings, outcome.Findings[:available]...)
		} else {
			rawFindings = append(rawFindings, outcome.Findings...)
		}
	}
	if result.Checked == 0 && !result.Complete {
		return result, errors.New("no component could be checked; previous evidence remains unchanged")
	}
	for i := range rawFindings {
		f := &rawFindings[i]
		d, ok := details[f.ID]
		if !ok && !detailErrors[f.ID] {
			if len(details)+len(detailErrors) >= 60 {
				detailErrors[f.ID] = true
			} else {
				var err error
				d, err = p.getDetail(ctx, f.ID)
				if err != nil {
					detailErrors[f.ID] = true
				} else {
					details[f.ID] = d
					ok = true
				}
			}
		}
		if !ok {
			result.Complete = false
			result.Warnings = append(result.Warnings, "Some advisory enrichment was unavailable or exceeded the 60-advisory enrichment limit")
		} else {
			f.Aliases = uniqueSorted(slices.Concat(d.Aliases, []string{d.ID, f.ID}))
			f.ID = canonicalID(f.Aliases)
			if d.Status == "rejected" || d.Status == "withdrawn" {
				f.Applicability = "potentially_affected"
				f.Evidence = "Provider matched this inventory, but the advisory is withdrawn or rejected; manual review is required."
			}
			f.KnownExploited = len(d.Exploitation.KEV) > 0 && string(d.Exploitation.KEV) != "null" && string(d.Exploitation.KEV) != "false"
			for _, a := range d.Affected {
				if strings.EqualFold(a.Ecosystem, f.Package.Ecosystem) && a.Package == f.Package.Name {
					for _, r := range a.Ranges {
						if r.Fixed != "" {
							f.FixedVersions = append(f.FixedVersions, r.Fixed)
						}
					}
				}
			}
			for _, ref := range d.References {
				if safeURL(ref.URL) {
					f.References = append(f.References, ref.URL)
				}
			}
			for _, ref := range d.Sources {
				if safeURL(ref.URL) {
					f.References = append(f.References, ref.URL)
				}
			}
		}
		f.FixedVersions = uniqueSorted(f.FixedVersions)
		f.References = uniqueSorted(f.References)
		f.Key = findingKey(f.Package, f.ID)
	}
	dedup := map[string]Finding{}
	for _, f := range rawFindings {
		k := f.Key + ":" + f.Package.Version
		if old, ok := dedup[k]; ok {
			f.Aliases = uniqueSorted(append(f.Aliases, old.Aliases...))
			f.FixedVersions = uniqueSorted(append(f.FixedVersions, old.FixedVersions...))
			f.References = uniqueSorted(append(f.References, old.References...))
			f.KnownExploited = f.KnownExploited || old.KnownExploited
		}
		dedup[k] = f
	}
	for _, f := range dedup {
		result.Findings = append(result.Findings, f)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.KnownExploited != b.KnownExploited {
			return a.KnownExploited
		}
		av, bv := float64(-1), float64(-1)
		if a.CVSS != nil {
			av = *a.CVSS
		}
		if b.CVSS != nil {
			bv = *b.CVSS
		}
		if av != bv {
			return av > bv
		}
		return a.ID+a.Package.Name+a.Package.Version < b.ID+b.Package.Name+b.Package.Version
	})
	result.Warnings = uniqueSorted(result.Warnings)
	return result, nil
}
