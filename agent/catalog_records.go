package agent

import (
	"context"
	"fmt"
	"slices"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// A fresh SDK writer starts a new UUID root even when it appends to an existing
// file (the planner). A resumed writer continues the captured baseline instead.
func (p *nativeHistoryProvider) scopedRecords(ctx context.Context) ([]transcript.Record, error) {
	if p.scopeSession != "" && p.scopeSession != p.sessionID(ctx) {
		return nil, fmt.Errorf("catalog history: session identity changed")
	}
	if p.initialErr != nil {
		return nil, fmt.Errorf("catalog history baseline: %w", p.initialErr)
	}
	records, err := p.records(ctx)
	if err != nil {
		return nil, err
	}
	if p.store == nil {
		return records, nil
	}
	n := len(p.initial)
	if len(records) <= n || n > 0 && records[n-1].UUID != p.initial[n-1].UUID {
		return nil, fmt.Errorf("catalog history: missing or changed session append")
	}
	added := records[n:]
	parent := transcript.LastUUID(p.initial)
	fresh := added[0].ParentUUID == ""
	if fresh {
		parent = ""
	}
	for _, rec := range added {
		if rec.UUID == "" || rec.ParentUUID != parent {
			return nil, fmt.Errorf("catalog history: displaced session occurrence %q", rec.UUID)
		}
		parent = rec.UUID
	}
	if fresh {
		return added, nil
	}
	// Mirror agentcore.cleanResumed, but only in the pre-session baseline.
	// ResumeWriter still chains through omitted records; their UUIDs are retained
	// in the raw file and new births keep their actual predecessor anchors.
	base := p.initial
	for len(base) > 0 {
		last := base[len(base)-1]
		if last.Message == nil || last.Message.Role != llm.RoleAssistant || len(last.Message.ToolUses()) == 0 {
			break
		}
		base = base[:len(base)-1]
	}
	if _, err := catalogRecordMarks(base, nil); err != nil {
		return nil, err // later appends cannot fill a truncated old boundary
	}
	return append(append([]transcript.Record(nil), base...), added...), nil
}

func catalogRecordMarks(records []transcript.Record, ids map[string]map[string]bool) (map[string]map[string]bool, error) {
	marks := map[string]map[string]bool{}
	var working []transcript.Record
	legacy := map[string]bool{}
	for i, rec := range records {
		if rec.ParentUUID == "" {
			working = nil // never summarize records from a previous fresh writer
		}
		if rec.Type == "boundary" {
			if rec.Boundary == nil || rec.Boundary.MessagesSummarized < 0 || rec.Boundary.MessagesSummarized > len(working) {
				return nil, fmt.Errorf("catalog history: invalid boundary head at record %d", i)
			}
			head, skills := rec.Boundary.MessagesSummarized, len(rec.Boundary.ActiveSkills)
			remaining := len(records) - i - 1
			if remaining < 2 || skills > remaining-2 || len(working)-head > remaining-2-skills {
				return nil, fmt.Errorf("catalog history: incomplete boundary copies at record %d", i)
			}
			marker, summary := records[i+1].Message, records[i+2].Message
			if marker == nil || !llm.IsBoundaryMarker(*marker) || summary == nil || summary.Role != llm.RoleUser {
				return nil, fmt.Errorf("catalog history: invalid boundary layout at record %d", i)
			}
			meta, ok := llm.ParseBoundaryMeta(*marker)
			if !ok || meta.MessagesSummarized != head || !slices.Equal(meta.ActiveSkills, rec.Boundary.ActiveSkills) {
				return nil, fmt.Errorf("catalog history: inconsistent boundary metadata at record %d", i)
			}
			for j, name := range rec.Boundary.ActiveSkills {
				skill := records[i+3+j].Message
				if skill == nil {
					return nil, fmt.Errorf("catalog history: missing re-injected skill at record %d", i)
				}
				if actual, ok := llm.SkillInvocationName(*skill); !ok || actual != name {
					return nil, fmt.Errorf("catalog history: displaced re-injected skill at record %d", i)
				}
			}
			start := i + 3 + skills
			for j, source := range working[head:] {
				copy := records[start+j]
				if copy.Message == nil || !catalogSameOccurrence(*source.Message, *copy.Message) {
					return nil, fmt.Errorf("catalog history: displaced boundary copy at record %d", start+j)
				}
				marks[copy.UUID] = marks[source.UUID]
			}
			working = nil
		}
		if rec.Message == nil {
			continue
		}
		if _, copied := marks[rec.UUID]; !copied {
			marks[rec.UUID] = ids[rec.ParentUUID]
			for _, use := range rec.Message.ToolUses() {
				if ids[""][use.ID] && !legacy[use.ID] {
					if marks[rec.UUID] == nil {
						marks[rec.UUID] = map[string]bool{}
					}
					marks[rec.UUID][use.ID] = true
					legacy[use.ID] = true
				}
			}
		}
		if llm.IsBoundaryMarker(*rec.Message) {
			working = nil
		} else {
			working = append(working, rec)
		}
	}
	return marks, nil
}

// Identity is assigned by the scoped UUID chain, not content comparison. This
// guard detects displacement before applying a mark. Result bodies can change
// under MicroCompact; no ordinary content is modified by this check.
func catalogSameOccurrence(source, current llm.Message) bool {
	if source.Role != current.Role || len(source.Content) != len(current.Content) {
		return false
	}
	for i, b := range source.Content {
		c := current.Content[i]
		if b.Type != c.Type || b.ID != c.ID || b.Name != c.Name || b.ToolUseID != c.ToolUseID {
			return false
		}
	}
	return true
}
