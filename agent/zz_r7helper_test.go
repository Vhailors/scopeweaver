package agent

import (
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func r7Def(d *db.DB) DeferredInfo {
	return DeferredInfo{CatalogTagged: d.CatalogTaggedName, CatalogUseIDs: d.CatalogNativeUseIDs}
}

func r7Wrap(p llm.Provider, d *db.DB, store *transcript.Store) llm.Provider {
	def := r7Def(d)
	registered := map[string]bool{}
	for _, tool := range actool.DefaultTools() {
		registered[tool.Name()] = true
	}
	def.Callable = func(name string) bool { return registered[name] }
	return deferredProvider(p, def, store)
}
