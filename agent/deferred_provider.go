package agent

import (
	"context"
	"iter"

	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// New catalog-native operations are removed before SDK dispatch and persistence.
// Legacy marks are applied once, to a successfully resumed SDK working set.
type nativeHistoryProvider struct {
	llm.Provider
	blocked       map[string]bool
	tagged        func(context.Context, string) (bool, error)
	load          func(context.Context, string) (map[string]map[string]bool, error)
	callable      func(string) bool
	store         *transcript.Store
	projected     bool
	projectionErr error
}

func deferredProvider(provider llm.Provider, def DeferredInfo, store *transcript.Store) llm.Provider {
	if len(def.CatalogNativeNames) == 0 && def.CatalogUseIDs == nil && def.CatalogTagged == nil {
		return provider
	}
	blocked := make(map[string]bool, len(def.CatalogNativeNames))
	for _, name := range def.CatalogNativeNames {
		blocked[name] = true
	}
	return &nativeHistoryProvider{Provider: provider, blocked: blocked,
		tagged: def.CatalogTagged, load: def.CatalogUseIDs, callable: def.Callable, store: store}
}

func (p *nativeHistoryProvider) blocks(ctx context.Context, name string) (bool, error) {
	if p.callable != nil && p.callable(name) {
		return false, nil // Registry membership, not schema visibility or unlock state.
	}
	if p.tagged != nil {
		blocked, err := p.tagged(ctx, name)
		if err != nil {
			return false, catalogHistoryError(ctx, err)
		}
		return blocked, nil
	}
	return p.blocked[name], nil
}

func (p *nativeHistoryProvider) request(ctx context.Context, req llm.CompletionRequest) (llm.CompletionRequest, error) {
	if p.projectionErr != nil {
		return req, p.projectionErr
	}
	// A standalone marked request has no authoritative resumed occurrence set.
	if !p.projected && p.load != nil {
		ids, err := p.load(ctx, transcript.SessionIDFrom(ctx))
		if err != nil {
			return req, catalogHistoryError(ctx, err)
		}
		if len(ids) != 0 {
			return req, catalogHistoryError(ctx, nil)
		}
	}
	tools := req.Tools[:0:0]
	for _, tool := range req.Tools {
		blocked, err := p.blocks(ctx, tool.Name)
		if err != nil {
			return req, err
		}
		if !blocked {
			tools = append(tools, tool)
		}
	}
	req.Tools = tools
	return req, nil
}

func (p *nativeHistoryProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		filtered, err := p.request(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		blocked, allowed, suppressInput := 0, 0, false
		for event, err := range p.Provider.Stream(ctx, filtered) {
			if err != nil {
				yield(event, err) // Provider errors retain their original classification.
				return
			}
			if event.Type == llm.SEToolUseStart {
				suppressInput, err = p.blocks(ctx, event.ToolName)
				if err != nil {
					yield(llm.StreamEvent{}, err)
					return
				}
				if suppressInput {
					blocked++
					// v0.4.3's accumulator flushes text and signed thinking here.
					// Its harness does not terminate on SEMessageStop.
					if !yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil) {
						return
					}
					continue
				}
				allowed++
			}
			if event.Type == llm.SEToolInputJSON && suppressInput {
				continue
			}
			if !yield(event, nil) {
				return
			}
		}
		if blocked > 0 && allowed == 0 {
			yield(llm.StreamEvent{}, &catalogPolicyError{message: locale.Text(locale.FromContext(ctx), catalogBlockedMessage)})
		}
	}
}

func (p *nativeHistoryProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	filtered, err := p.request(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	msg, stop, usage, err := p.Provider.Complete(ctx, filtered)
	if err != nil {
		return msg, stop, usage, err
	}
	content := msg.Content[:0:0]
	blocked, allowed := 0, 0
	for _, block := range msg.Content {
		if block.Type == llm.BlockToolUse {
			suppress, err := p.blocks(ctx, block.Name)
			if err != nil {
				return msg, stop, usage, err
			}
			if suppress {
				blocked++
				continue
			}
			allowed++
		}
		content = append(content, block)
	}
	msg.Content = content
	if blocked > 0 && allowed == 0 {
		err = &catalogPolicyError{message: locale.Text(locale.FromContext(ctx), catalogBlockedMessage), usage: usage}
	}
	return msg, stop, usage, err
}
