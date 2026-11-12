package vulnreview

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"
)

type Service struct {
	store    *Store
	provider Provider
	ctx      context.Context
	mu       sync.Mutex
	jobs     map[string]context.CancelFunc
	closed   bool
	wg       sync.WaitGroup
	slots    chan struct{}
}

func NewService(ctx context.Context, store *Store, provider Provider) *Service {
	return &Service{store: store, provider: provider, ctx: ctx, jobs: map[string]context.CancelFunc{}, slots: make(chan struct{}, 2)}
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (s *Service) Submit(ctx context.Context, p Project) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return Run{}, errors.New("review service is shutting down")
	}
	run := Run{ID: newID(), ProjectID: p.ID, InventoryHash: p.InventoryHash, Inventory: p.Inventory, Status: "queued", Findings: []Finding{}, Warnings: append([]string{}, p.Inventory.Warnings...), CreatedAt: time.Now().UTC(), Coverage: Coverage, Attribution: Attribution}
	if err := s.store.Enqueue(ctx, run); err != nil {
		return Run{}, err
	}
	jobCtx, cancel := context.WithCancel(s.ctx)
	s.jobs[run.ID] = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer func() { s.mu.Lock(); delete(s.jobs, run.ID); s.mu.Unlock() }()
		s.execute(jobCtx, run)
	}()
	return run, nil
}
func (s *Service) execute(ctx context.Context, r Run) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		s.finishCancelled(r)
		return
	}
	active, err := s.store.SaveRun(ctx, withStatus(r, "running"))
	if err != nil {
		log.Printf("[vulnerability-review] start run: %v", err)
		return
	}
	if !active {
		return
	}
	workCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	guardedCtx := context.WithValue(workCtx, outboundGuardKey{}, func(requestCtx context.Context) error { return s.guard(requestCtx, r) })
	watchCtx, stopWatch := context.WithCancel(workCtx)
	watchDone := make(chan struct{})
	go s.watch(watchCtx, r, cancel, watchDone)
	defer func() { stopWatch(); <-watchDone }()
	result, providerErr := s.provider.Check(guardedCtx, r.Inventory.Packages)
	log.Printf("[vulnerability-review] provider finished run %s: %v (context: %v)", r.ID, providerErr, workCtx.Err())
	now := time.Now().UTC()
	r.FinishedAt = &now
	r.Findings = result.Findings
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	r.Checked = result.Checked
	r.Warnings = uniqueSorted(append(r.Warnings, result.Warnings...))
	switch {
	case ctx.Err() != nil:
		r.Status = "cancelled"
		r.Error = "Review cancelled or application stopped; previous evidence remains unchanged"
	case providerErr != nil:
		r.Status = "failed"
		r.Error = providerErr.Error()
	case !result.Complete:
		r.Status = "partial"
	default:
		r.Status = "succeeded"
	}
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer saveCancel()
	if r.Status == "succeeded" {
		previous, err := s.store.PreviousSuccess(saveCtx, r.ProjectID, r.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			r.Status = "partial"
			r.Warnings = append(r.Warnings, "Previous baseline could not be loaded; change counts are unavailable")
		} else {
			r.Changes = compare(previous.Findings, r.Findings)
		}
	}
	if _, err := s.store.SaveRun(saveCtx, r); err != nil {
		log.Printf("[vulnerability-review] finish run: %v", err)
	}
}
func withStatus(r Run, status string) Run { r.Status = status; return r }
func (s *Service) finishCancelled(r Run) {
	r.Status = "cancelled"
	r.Error = "Review cancelled before retrieval"
	now := time.Now().UTC()
	r.FinishedAt = &now
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.store.SaveRun(ctx, r); err != nil {
		log.Printf("[vulnerability-review] cancel queued run: %v", err)
	}
}
func (s *Service) Cancel(ctx context.Context, project, id string) (Run, error) {
	r, err := s.store.GetRun(ctx, project, id)
	if err != nil {
		return r, err
	}
	if r.Status != "queued" && r.Status != "running" {
		return r, nil
	}
	now := time.Now().UTC()
	r.Status = "cancelled"
	r.Error = "Review cancelled by administrator"
	r.FinishedAt = &now
	changed, err := s.store.SaveRun(ctx, r)
	if err != nil {
		return r, err
	}
	if !changed {
		return s.store.GetRun(ctx, project, id)
	}
	s.mu.Lock()
	cancel := s.jobs[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return r, nil
}
func compare(previous, current []Finding) Changes {
	old := map[string]string{}
	next := map[string]string{}
	fingerprint := func(f Finding) string {
		return digest([]any{f.Package.Version, f.Title, f.CVSS, f.KnownExploited, f.FixedVersions, f.References, f.Applicability})
	}
	for _, f := range previous {
		old[f.Key+":"+f.Package.Version] = fingerprint(f)
	}
	for _, f := range current {
		next[f.Key+":"+f.Package.Version] = fingerprint(f)
	}
	c := Changes{}
	for k, v := range next {
		before, ok := old[k]
		if !ok {
			c.New++
		} else if before != v {
			c.Changed++
		}
	}
	for k := range old {
		if _, ok := next[k]; !ok {
			c.NoLongerObserved++
		}
	}
	return c
}
func (s *Service) Run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.closed = true
		for _, cancel := range s.jobs {
			cancel()
		}
		s.mu.Unlock()
		s.wg.Wait()
	}()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if err := s.store.Expire(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[vulnerability-review] expire leases: %v", err)
		}
		s.schedule(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (s *Service) schedule(ctx context.Context) {
	projects, err := s.store.List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[vulnerability-review] schedule: %v", err)
		}
		return
	}
	for _, p := range projects {
		if !p.Daily || p.ApprovedAt.IsZero() {
			continue
		}
		history, err := s.store.History(ctx, p.ID)
		if err != nil {
			continue
		}
		if len(history) > 0 {
			last := history[0]
			if last.Status == "queued" || last.Status == "running" {
				continue
			}
			if last.InventoryHash == p.InventoryHash && time.Since(last.CreatedAt) < 24*time.Hour {
				continue
			}
		}
		if _, err = s.Submit(ctx, p); err != nil && !errors.Is(err, ErrBusy) && ctx.Err() == nil {
			log.Printf("[vulnerability-review] scheduled submission failed: %v", err)
		}
	}
}
