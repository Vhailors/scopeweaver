package server

import (
	"path/filepath"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
)

// Assembly and live helper calls share the same filesystem/visibility contract.
// Directory names grant visibility; the loaded registry owns callable identifiers.
func visibleSkillRegistry(pg *db.DB, skillDir string, agentID int64) (*skill.Registry, error) {
	names, err := pg.AgentSkillNames(agentID)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	all, err := skill.LoadDir(skillDir)
	if err != nil || all == nil {
		return nil, err
	}
	reg := skill.NewRegistry()
	for _, s := range all.List() {
		if s.Dir != "" && contains(names, filepath.Base(s.Dir)) {
			reg.Add(s)
		}
	}
	if len(reg.List()) == 0 {
		return nil, nil
	}
	return reg, nil
}

func visibleReportSkills(reg *skill.Registry) []string {
	if reg == nil {
		return nil
	}
	var names []string
	for _, name := range []string{"yeepforge", "adstrike", "confirmesc"} {
		if s, ok := reg.Get(name); ok && filepath.Base(s.Dir) == name {
			names = append(names, s.Name)
		}
	}
	return names
}

type catalogLiveServer struct {
	Server   string `json:"server"`
	Skill    string `json:"skill"`
	Enabled  bool   `json:"enabled"`
	Callable bool   `json:"callable"`
	Tools    int    `json:"tools"`
}

// visibleLiveServers reports generic (non-catalog) MCP servers named by a visible
// skill's mcps field. Unlike catalog providers (Callable always false), these are
// callable by the agent once that skill is loaded, which is what unlocks them.
func visibleLiveServers(reg *skill.Registry, providers []*db.MCPServer, visible map[int64]bool) []catalogLiveServer {
	if reg == nil {
		return nil
	}
	var out []catalogLiveServer
	seen := map[string]bool{}
	for _, sk := range reg.List() {
		for _, name := range sk.MCPs {
			if name == "" || seen[sk.Name+"\x00"+name] {
				continue
			}
			seen[sk.Name+"\x00"+name] = true
			for _, m := range providers {
				if m.Name == name && m.ProviderKind == "" && visible[m.ID] {
					out = append(out, catalogLiveServer{
						Server: m.Name, Skill: sk.Name, Enabled: m.Enabled,
						Callable: true, Tools: len(m.Tools),
					})
				}
			}
		}
	}
	return out
}
