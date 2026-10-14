package agent

import (
	"context"
	"fmt"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// catalogHistory projects the exact persisted working occurrences, BEFORE SDK
// pairing or NOA pruning/argument rewriting can erase their positions.
type catalogHistory struct {
	harness.Compactor
	provider *nativeHistoryProvider
}

func configureCatalogHistory(opts *agentcore.Options) {
	p, ok := opts.Provider.(*nativeHistoryProvider)
	if !ok {
		return
	}
	if p.store != nil && opts.SessionID != "" {
		p.scopeSession = opts.SessionID
		p.initial, p.initialErr = p.store.Load(p.store.MainPath(opts.SessionID))
	}
	inner := opts.Compactor
	if inner == nil && opts.Compaction != nil {
		summary := compaction.ProviderSummarizer(p.Provider, opts.MaxTokens, opts.NonStreaming)
		inner = compaction.New(*opts.Compaction, func(ctx context.Context, head []llm.Message) (string, error) {
			filtered, err := p.history(ctx, head, true)
			if err != nil {
				p.projectionErr = err
				return "", err
			}
			// The summary input is a prefix, not the recent tail. Classify it
			// before pairForReplay or overflow retries select smaller subsets.
			return summary(ctx, filtered)
		})
	}
	opts.Compaction = nil
	opts.Compactor = &catalogHistory{Compactor: inner, provider: p}
	p.projected = true
}

func (c *catalogHistory) Pre(ctx context.Context, msgs []llm.Message, tokens int) []llm.Message {
	if !c.prepare(ctx, msgs) {
		return msgs
	}
	if c.Compactor != nil {
		return c.Compactor.Pre(ctx, msgs, tokens)
	}
	return msgs
}

func (c *catalogHistory) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	if !c.prepare(ctx, msgs) {
		return msgs, false
	}
	if c.Compactor != nil {
		return c.Compactor.Reactive(ctx, msgs)
	}
	return msgs, false
}

func (c *catalogHistory) IsOverflow(err error) bool {
	return c.Compactor != nil && c.Compactor.IsOverflow(err)
}

func (c *catalogHistory) View(ctx context.Context, msgs []llm.Message) []llm.Message {
	if c.provider.projectionErr != nil {
		return nil
	}
	if err := c.provider.syncMemory(msgs); err != nil {
		c.provider.projectionErr = err
		return nil
	}
	filtered, err := c.provider.history(ctx, llm.MessagesAfterBoundary(msgs), false)
	c.provider.projectionErr = err
	if err != nil {
		return nil // request returns the error, never an unfiltered request
	}
	if view, ok := c.Compactor.(harness.ContextView); ok {
		return view.View(ctx, filtered)
	}
	return llm.MessagesForAPI(filtered)
}

func (c *catalogHistory) prepare(ctx context.Context, msgs []llm.Message) bool {
	c.provider.projectionErr = c.provider.syncMemory(msgs)
	if c.provider.projectionErr == nil {
		_, c.provider.projectionErr = c.provider.history(ctx, llm.MessagesAfterBoundary(msgs), false)
	}
	return c.provider.projectionErr == nil
}

func catalogWorkingRecords(records []transcript.Record) []transcript.Record {
	var working []transcript.Record
	for _, rec := range records {
		if rec.Message == nil {
			continue
		}
		if llm.IsBoundaryMarker(*rec.Message) {
			working = nil
			continue
		}
		working = append(working, rec)
	}
	return working
}

func (p *nativeHistoryProvider) history(ctx context.Context, msgs []llm.Message, prefix bool) ([]llm.Message, error) {
	records, err := p.scopedRecords(ctx)
	if err != nil {
		return nil, err
	}
	ids := map[string]map[string]bool{}
	if p.load != nil {
		ids, err = p.load(ctx, p.sessionID(ctx))
		if err != nil {
			return nil, err
		}
	}
	marks, err := catalogRecordMarks(records, ids)
	if err != nil {
		return nil, err
	}
	working := catalogWorkingRecords(records)
	count := 0
	for _, msg := range msgs {
		if !llm.IsBoundaryMarker(msg) {
			count++
		}
	}
	if !prefix && count != len(working) {
		return nil, fmt.Errorf("catalog history: working occurrences=%d persisted=%d", count, len(working))
	}
	return filterCatalogHistory(msgs, working, marks)
}

func filterCatalogHistory(msgs []llm.Message, working []transcript.Record, marks map[string]map[string]bool) ([]llm.Message, error) {
	var out []llm.Message
	results := map[string]bool{}
	index := 0
	for _, msg := range msgs {
		if llm.IsBoundaryMarker(msg) {
			continue
		}
		if index >= len(working) {
			return nil, fmt.Errorf("catalog history: missing persisted occurrence %d", index)
		}
		if working[index].Message == nil || !catalogSameOccurrence(*working[index].Message, msg) {
			return nil, fmt.Errorf("catalog history: displaced working occurrence %d", index)
		}
		occurrence := marks[working[index].UUID]
		index++
		content := msg.Content[:0:0]
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse {
				results[block.ID] = occurrence[block.ID]
			}
			if block.Type == llm.BlockToolUse && results[block.ID] ||
				block.Type == llm.BlockToolResult && results[block.ToolUseID] {
				continue
			}
			content = append(content, block)
		}
		if len(content) > 0 {
			msg.Content = content
			out = append(out, msg)
		}
	}
	return out, nil
}

// Non-persisted sessions use the same occurrence chain in memory. Births are
// appended at Pre; compaction copies at View, matching the SDK recorder's steps.
func (p *nativeHistoryProvider) syncMemory(msgs []llm.Message) error {
	if p.store != nil {
		return nil
	}
	boundaries := 0
	for _, msg := range msgs {
		if llm.IsBoundaryMarker(msg) {
			boundaries++
		}
	}
	if boundaries < p.memoryBoundaries {
		return fmt.Errorf("catalog history: in-memory boundary chain changed")
	}
	appendMessage := func(msg llm.Message) {
		p.memory = append(p.memory, transcript.Record{
			Type: "message", UUID: transcript.NewSessionID(),
			ParentUUID: transcript.LastUUID(p.memory), Message: &msg,
		})
	}
	working := llm.MessagesAfterBoundary(msgs)
	if boundaries > p.memoryBoundaries {
		if len(working) == 0 {
			return fmt.Errorf("catalog history: missing in-memory boundary")
		}
		meta, ok := llm.ParseBoundaryMeta(working[0])
		if !ok {
			return fmt.Errorf("catalog history: invalid in-memory boundary")
		}
		p.memory = append(p.memory, transcript.Record{
			Type: "boundary", UUID: transcript.NewSessionID(),
			ParentUUID: transcript.LastUUID(p.memory), Boundary: &meta,
		})
		for _, msg := range working {
			appendMessage(msg)
		}
		p.memoryBoundaries = boundaries
		return nil
	}
	if len(working) > 0 && llm.IsBoundaryMarker(working[0]) {
		working = working[1:]
	}
	n := len(catalogWorkingRecords(p.memory))
	if n > len(working) {
		return fmt.Errorf("catalog history: missing in-memory occurrences")
	}
	for _, msg := range working[n:] {
		appendMessage(msg)
	}
	return nil
}
