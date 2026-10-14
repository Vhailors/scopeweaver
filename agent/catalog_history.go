package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// The wrapper only gates a failed legacy restoration. Ordinary live history has
// already had blocked births suppressed and needs no transcript reconstruction.
type catalogHistory struct {
	harness.Compactor
	provider *nativeHistoryProvider
}

func configureCatalogHistory(opts *agentcore.Options) {
	p, ok := opts.Provider.(*nativeHistoryProvider)
	if !ok {
		return
	}
	inner := opts.Compactor
	if inner == nil && opts.Compaction != nil {
		inner = compaction.New(*opts.Compaction, compaction.ProviderSummarizer(p.Provider, opts.MaxTokens, opts.NonStreaming))
	}
	opts.Compaction = nil
	opts.Compactor = &catalogHistory{Compactor: inner, provider: p}
	p.projected = true
}

func (c *catalogHistory) Pre(ctx context.Context, msgs []llm.Message, tokens int) []llm.Message {
	if c.provider.projectionErr == nil && c.Compactor != nil {
		return c.Compactor.Pre(ctx, msgs, tokens)
	}
	return msgs
}

func (c *catalogHistory) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	if c.provider.projectionErr == nil && c.Compactor != nil {
		return c.Compactor.Reactive(ctx, msgs)
	}
	return msgs, false
}

func (c *catalogHistory) IsOverflow(err error) bool {
	return c.provider.projectionErr == nil && c.Compactor != nil && c.Compactor.IsOverflow(err)
}

func (c *catalogHistory) View(ctx context.Context, msgs []llm.Message) []llm.Message {
	if c.provider.projectionErr != nil {
		return nil
	}
	if view, ok := c.Compactor.(harness.ContextView); ok {
		return view.View(ctx, msgs)
	}
	return llm.MessagesForAPI(msgs)
}

func resumeCatalogSession(ctx context.Context, s *agentcore.Session, opts agentcore.Options) {
	if err := s.Resume(opts.SessionID); err != nil {
		log.Printf("[catalog] %s: %s: %v", opts.SessionID,
			locale.Text(locale.FromContext(ctx), catalogResumeMessage), err)
		return // Keep the SDK's fresh session after failed Resume.
	}
	if p, ok := opts.Provider.(*nativeHistoryProvider); ok {
		p.projectionErr = p.restore(ctx, s.Messages(), opts.SessionID)
	}
}

func (p *nativeHistoryProvider) restore(ctx context.Context, msgs []llm.Message, session string) error {
	if p.load == nil {
		return nil
	}
	ids, err := p.load(ctx, session)
	if err != nil {
		return catalogHistoryError(ctx, err)
	}
	if len(ids) == 0 {
		return nil // No guard transcript read, even when the audit file is broken.
	}
	working := llm.MessagesAfterBoundary(msgs)
	relevant := map[string]bool{}
	for _, uses := range ids {
		for id, marked := range uses {
			if marked {
				relevant[id] = true
			}
		}
	}
	structural := false
	for _, msg := range working {
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse && relevant[block.ID] ||
				block.Type == llm.BlockToolResult && relevant[block.ToolUseID] {
				structural = true
			}
		}
	}
	if !structural {
		// Absence is safe: compaction copies retain use IDs. An ID match is
		// never sufficient to choose an occurrence or apply an exclusion.
		return nil // Includes the exact r7 boundary/marker/summary crash cut.
	}
	if len(ids[""]) > 0 {
		return catalogHistoryError(ctx, nil) // Unscoped IDs do not identify a birth.
	}
	if p.store == nil {
		return catalogHistoryError(ctx, nil)
	}
	records, err := p.store.Load(p.store.MainPath(session))
	if err != nil {
		return catalogHistoryError(ctx, err)
	}
	marks, err := catalogRecordMarks(records, ids)
	if err != nil {
		return catalogHistoryError(ctx, err)
	}
	active := catalogWorkingRecords(records)
	index := 0
	for i, msg := range working {
		if llm.IsBoundaryMarker(msg) {
			continue
		}
		// Correspondence is positional in the successfully restored SDK prefix,
		// never a suffix guess, a call-ID lookup, or content identity matching.
		if index >= len(active) || !catalogSameOccurrence(*active[index].Message, msg) {
			return catalogHistoryError(ctx, fmt.Errorf("displaced resumed occurrence %d", index))
		}
		content := msg.Content[:0:0]
		occurrence := marks[active[index].UUID]
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse && occurrence[block.ID] ||
				block.Type == llm.BlockToolResult && occurrence[block.ToolUseID] {
				continue
			}
			content = append(content, block)
		}
		working[i].Content = content
		index++
	}
	return nil
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
