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
