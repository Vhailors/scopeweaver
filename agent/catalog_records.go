package agent

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// Bounded legacy adapter only. New births do not create exclusion marks.
func catalogRecordMarks(records []transcript.Record, ids map[string]map[string]bool) (map[string]map[string]bool, error) {
	marks := map[string]map[string]bool{}
	var working []transcript.Record
	legacy := map[string]bool{}
	results := map[string]bool{}
	for i, rec := range records {
		if rec.ParentUUID == "" {
			working = nil // never summarize records from a previous fresh writer
			results = map[string]bool{}
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
			results = map[string]bool{}
		}
		if rec.Message == nil {
			continue
		}
		if _, copied := marks[rec.UUID]; !copied {
			marks[rec.UUID] = maps.Clone(ids[rec.ParentUUID])
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
		// Associate a result at its source occurrence, before a boundary cut or
		// later ID reuse can separate it from its preceding use. Copies inherit
		// that exact record's mark rather than re-pairing the active suffix.
		for _, block := range rec.Message.Content {
			switch block.Type {
			case llm.BlockToolUse:
				results[block.ID] = marks[rec.UUID][block.ID]
			case llm.BlockToolResult:
				if results[block.ToolUseID] && !marks[rec.UUID][block.ToolUseID] {
					marks[rec.UUID] = maps.Clone(marks[rec.UUID])
					if marks[rec.UUID] == nil {
						marks[rec.UUID] = map[string]bool{}
					}
					marks[rec.UUID][block.ToolUseID] = true
				}
			}
		}
		// A scoped ID cannot distinguish multiple births or results in one
		// occurrence. Resolve all marks before any destructive projection.
		uses, outputs := map[string]bool{}, map[string]bool{}
		for _, block := range rec.Message.Content {
			switch block.Type {
			case llm.BlockToolUse:
				if marks[rec.UUID][block.ID] && uses[block.ID] {
					return nil, fmt.Errorf("catalog history: ambiguous marked use %q at record %d", block.ID, i)
				}
				uses[block.ID] = true
			case llm.BlockToolResult:
				if marks[rec.UUID][block.ToolUseID] && outputs[block.ToolUseID] {
					return nil, fmt.Errorf("catalog history: ambiguous marked result %q at record %d", block.ToolUseID, i)
				}
				outputs[block.ToolUseID] = true
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
