package agent

import (
	"context"
	"fmt"
	"iter"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// Exclude exact catalog-native capabilities after compaction/materialization.
// Text, JSON inputs, outputs and signed thinking are never rewritten.
type nativeHistoryProvider struct {
	llm.Provider
	blocked          map[string]bool
	record           func(context.Context, string, string, string, string) error
	load             func(context.Context, string) (map[string]map[string]bool, error)
	callable         func(string) bool
	store            *transcript.Store
	session          string
	projected        bool
	projectionErr    error
	memory           []transcript.Record
	memoryBoundaries int
	initial          []transcript.Record
	initialErr       error
	scopeSession     string
}

func deferredProvider(provider llm.Provider, def DeferredInfo, store *transcript.Store) llm.Provider {
	if len(def.CatalogNativeNames) == 0 && def.CatalogUseIDs == nil {
		return provider
	}
	blocked := make(map[string]bool, len(def.CatalogNativeNames))
	for _, name := range def.CatalogNativeNames {
		blocked[name] = true
	}
	return &nativeHistoryProvider{Provider: provider, blocked: blocked,
		record: def.CatalogUse, load: def.CatalogUseIDs, callable: def.Callable,
		store: store, session: transcript.NewSessionID()}
}

func (p *nativeHistoryProvider) sessionID(ctx context.Context) string {
	if id := transcript.SessionIDFrom(ctx); id != "" {
		return id
	}
	return p.session // non-persisted runs have no history to resume
}

// ParentUUID is available before the assistant is born and identifies its exact
// slot in the persisted UUID chain. A reused provider id has a different parent.
func (p *nativeHistoryProvider) records(ctx context.Context) ([]transcript.Record, error) {
	if p.store == nil {
		return p.memory, nil
	}
	return p.store.Load(p.store.MainPath(p.sessionID(ctx)))
}

func (p *nativeHistoryProvider) request(ctx context.Context, req llm.CompletionRequest) (llm.CompletionRequest, error) {
	tools := req.Tools[:0:0]
	for _, t := range req.Tools {
		if !p.blocked[t.Name] {
			tools = append(tools, t)
		}
	}
	req.Tools = tools
	if p.projectionErr != nil {
		return req, p.projectionErr
	}
	if p.projected {
		// The ContextView filtered occurrences before SDK/NOA projection.
		return req, nil
	}
	ids := map[string]map[string]bool{}
	if p.load != nil {
		var err error
		ids, err = p.load(ctx, p.sessionID(ctx))
		if err != nil {
			return req, err
		}
	}
	records, err := p.records(ctx)
	if err != nil {
		return req, err
	}
	marks, err := catalogRecordMarks(records, ids)
	if err != nil {
		return req, err
	}
	if p.load != nil {
		working := catalogWorkingRecords(records)
		// Standalone provider calls use an unprojected suffix. Agent sessions
		// always install catalogHistory and filter before request construction.
		if len(req.Messages) > len(working) {
			return req, fmt.Errorf("catalog history: missing persisted request occurrences")
		}
		req.Messages, err = filterCatalogHistory(req.Messages, working[len(working)-len(req.Messages):], marks)
	}
	return req, err
}

func (p *nativeHistoryProvider) emission(ctx context.Context, parent, id, name string, tools []llm.ToolSchema) error {
	if p.record == nil || p.callable != nil && p.callable(name) {
		return nil
	}
	for _, tool := range tools {
		if tool.Name == name {
			return nil
		}
	}
	return p.record(ctx, p.sessionID(ctx), parent, id, name)
}

func (p *nativeHistoryProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		filtered, err := p.request(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		records, err := p.records(ctx)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for event, err := range p.Provider.Stream(ctx, filtered) {
			if err == nil && event.Type == llm.SEToolUseStart && p.record != nil {
				err = p.emission(ctx, transcript.LastUUID(records), event.ToolID, event.ToolName, filtered.Tools)
			}
			if !yield(event, err) || err != nil {
				return
			}
		}
	}
}

func (p *nativeHistoryProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	filtered, err := p.request(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	records, err := p.records(ctx)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	msg, stop, usage, err := p.Provider.Complete(ctx, filtered)
	if err == nil && p.record != nil {
		for _, use := range msg.ToolUses() {
			if err := p.emission(ctx, transcript.LastUUID(records), use.ID, use.Name, filtered.Tools); err != nil {
				return llm.Message{}, "", usage, err
			}
		}
	}
	return msg, stop, usage, err
}
