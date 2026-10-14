package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func TestDeferredSystem_NoGlobal(t *testing.T) {
	// No global MCP names → plain single-segment system, no cache boundary.
	sys, boundary := deferredSystem("SYS", DeferredInfo{})
	if len(sys) != 1 || sys[0] != "SYS" || boundary != 0 {
		t.Fatalf("expected [SYS],0 — got %v,%d", sys, boundary)
	}
}

func TestDeferredSystem_WithGlobal(t *testing.T) {
	def := DeferredInfo{
		Deferred:    []string{"mcp__browser__navigate", "mcp__browser__click"},
		GlobalNames: []string{"mcp__browser__navigate", "mcp__browser__click"},
	}
	sys, boundary := deferredSystem("SYS", def)
	if len(sys) != 2 || sys[0] != "SYS" {
		t.Fatalf("expected [SYS, block], got %v", sys)
	}
	if !strings.Contains(sys[1], "<available-deferred-tools>") ||
		!strings.Contains(sys[1], "mcp__browser__navigate") {
		t.Fatalf("block missing names:\n%s", sys[1])
	}
	if boundary != len(sys) {
		t.Fatalf("boundary=%d want %d (whole prompt cached)", boundary, len(sys))
	}
}

func TestDeferredSystem_GatedNotInBlock(t *testing.T) {
	// A skill-gated server's tools are deferred but NOT in the global block.
	def := DeferredInfo{
		Deferred:    []string{"mcp__browser__navigate", "mcp__secret__do"},
		GlobalNames: []string{"mcp__browser__navigate"}, // secret gated → excluded
	}
	sys, _ := deferredSystem("SYS", def)
	if strings.Contains(sys[1], "mcp__secret__do") {
		t.Fatalf("gated tool must not appear in global block:\n%s", sys[1])
	}
	if !strings.Contains(sys[1], "mcp__browser__navigate") {
		t.Fatal("global tool should appear in block")
	}
}

func TestSeedUnlockFromHistory(t *testing.T) {
	skillCall := func(name string) llm.ContentBlock {
		return llm.ContentBlock{Type: llm.BlockToolUse, Name: "Skill", Input: json.RawMessage(`{"name":"` + name + `"}`)}
	}
	msgs := []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{skillCall("browsing")}},
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, Name: "Bash", Input: json.RawMessage(`{}`)}, // ignored
			skillCall("recon"),
		}},
	}
	var got []string
	seedUnlockFromHistory(msgs, func(name string) { got = append(got, name) })
	if strings.Join(got, ",") != "browsing,recon" {
		t.Fatalf("unlocked=%v want [browsing recon]", got)
	}
	seedUnlockFromHistory(msgs, nil) // nil → no-op, no panic
}

func TestSeedUnlockCatalogHistory(t *testing.T) {
	// Given resumed Skill output from an old tagged label and a generic server.
	msgs := []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "skill", Name: "Skill", Input: json.RawMessage(`{"name":"catalog-probe"}`)},
			{Type: llm.BlockToolUse, ID: "native", Name: "mcp__old-label__unexpected_operation", Input: json.RawMessage(`{}`)},
		}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{
			llm.ToolResultText("skill", "<available-deferred-tools>\nmcp__old-label__unexpected_operation\nmcp__generic__allowed\n</available-deferred-tools>", false),
			llm.ToolResultText("native", "fixture", true),
		}},
	}
	unlock := actool.NewUnlockSet()
	unlockSkill := func(name string) {
		if name == "catalog-probe" {
			unlock.Add("mcp__generic__allowed")
		}
	}
	// When capability filtering leaves historical Skill free text untouched.
	store, ctx, parent := deferredHistory(t, msgs)
	filter := &nativeHistoryProvider{store: store, load: func(context.Context, string) (map[string]map[string]bool, error) {
		return map[string]map[string]bool{parent: {"native": true}}, nil
	}}
	request, err := filter.request(ctx, llm.CompletionRequest{Messages: msgs})
	if err != nil {
		t.Fatal(err)
	}
	filtered := request.Messages
	for _, msg := range filtered {
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse && block.ID == "native" ||
				block.Type == llm.BlockToolResult && block.ToolUseID == "native" {
				t.Fatal("marked native pair survived Skill history filtering")
			}
		}
	}
	seedUnlockFromHistory(filtered, unlockSkill)
	raw, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	// Then free-text names survive but never grant a tagged capability/unlock.
	if !strings.Contains(string(raw), "mcp__old-label__unexpected_operation") ||
		!strings.Contains(string(raw), "mcp__generic__allowed") ||
		!unlock.Has("mcp__generic__allowed") || unlock.Has("mcp__old-label__unexpected_operation") {
		t.Fatalf("catalog resume boundary: %s", raw)
	}
	seedUnlockFromHistory(filtered, nil)
}

// TestUnlockGatingFlow mirrors what OnInvoke / seedUnlockFromHistory do: a gated
// tool starts locked and becomes callable only after its skill unlocks it.
func TestUnlockGatingFlow(t *testing.T) {
	serverTools := map[string][]string{"secret": {"mcp__secret__do"}}
	unlock := actool.NewUnlockSet("mcp__browser__navigate") // global only
	unlockSkill := func(name string) {
		if name == "unlock-secret" {
			unlock.Add(serverTools["secret"]...)
		}
	}
	if unlock.Has("mcp__secret__do") {
		t.Fatal("gated tool should start locked")
	}
	unlockSkill("unlock-secret")
	if !unlock.Has("mcp__secret__do") {
		t.Fatal("gated tool should be unlocked after skill load")
	}
}
