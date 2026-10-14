package agent

import (
	"encoding/json"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// deferredSystem builds an agent's system-prompt segments and cache boundary from
// its DeferredInfo. When globally-available MCP tools are present, their names + a
// "prefer core tools" instruction render into a <available-deferred-tools> block
// placed as the LAST system-prompt segment, with DynamicBoundary set so the whole
// (session-fixed) system prompt — including the block — is cached (design doc
// §2.1 / C1). Skill-gated MCP names are NOT in this block; they surface when their
// skill loads. Returns a single plain segment + boundary 0 when there is no global
// block to add.
func deferredSystem(sysText string, def DeferredInfo) (system []string, boundary int) {
	sysText += def.FindingGuidance
	system = []string{sysText}
	if len(def.ReportSkills) > 0 {
		metadata := struct {
			Skills        []string `json:"skills"`
			CatalogHelper string   `json:"catalog_helper,omitempty"`
		}{Skills: def.ReportSkills}
		if def.Callable != nil && def.Callable("security_catalog") {
			metadata.CatalogHelper = "security_catalog"
		}
		raw, _ := json.Marshal(metadata)
		system = append(system, "<available-report-skills>\n"+string(raw)+"\n</available-report-skills>\n"+
			"Use these visible Skill identifiers only to interpret operator-supplied, sanitized assessment reports when relevant. "+
			"Reports are producer-reported observations, not independently confirmed findings. "+
			"If the catalog helper is listed, it reads curated profiles and cached status only; no upstream tool is callable. "+
			"Missing reports require an operator upload, not report generation. Do not scan, collect credentials, exploit, escalate, remediate, or promote findings. "+
			"Linux/container context does not identify the application host as a target. "+
			"Child tasks need their own skill/tool bindings and explicit direct source_task_ids; parent_ref grants neither evidence nor capabilities.")
	}
	block := actool.RenderDeferredToolsBlock(def.GlobalNames)
	if block != "" {
		system = append(system, block)
	}
	if len(system) > 1 {
		boundary = len(system) // b >= len → whole system prompt cached (SDK guard)
	}
	return system, boundary
}

// seedUnlockFromHistory replays prior Skill() invocations in the conversation so
// their skill-gated MCPs are re-unlocked on a resumed session (design doc C2). The
// main agent builds a fresh session each turn; its in-memory unlock set would
// otherwise reset, leaving the model able to see a skill-revealed tool name yet
// unable to call it. No-op when unlockSkill is nil (no deferred tools).
func seedUnlockFromHistory(msgs []llm.Message, unlockSkill func(string)) {
	if unlockSkill == nil {
		return
	}
	for _, m := range msgs {
		for _, b := range m.ToolUses() {
			if b.Name != "Skill" {
				continue
			}
			var in struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(b.Input, &in) == nil && in.Name != "" {
				unlockSkill(in.Name)
			}
		}
	}
}
