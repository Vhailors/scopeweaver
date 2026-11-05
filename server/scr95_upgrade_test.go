package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/jackc/pgx/v5"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Intent: SCR-95 and SCR-107. Upgrade actual source code over persisted legacy
// snapshots and an interrupted real consumer; never rewrite source observations.
func TestSCR95ProviderUpgrade(t *testing.T) {
	if os.Getenv("SCR95_UPGRADE") != "1" {
		t.Skip("requires an explicitly prepared isolated upgrade fixture")
	}
	cfg, err := pgx.ParseConfig(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || !strings.HasPrefix(cfg.Database, "scopeweaver_provider_") {
		t.Fatal("explicit disposable provider database required")
	}
	directory := os.Getenv("SCR95_PRIVATE")
	if directory == "" {
		t.Fatal("private fixture directory required")
	}
	manager, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal("isolated upgraded manager failed")
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scratch := t.TempDir()
	app := New(ctx, manager, scratch, scratch, scratch)
	httpServer := httptest.NewTLSServer(app.Handler())
	defer httpServer.Close()
	raw, err := os.ReadFile(filepath.Join(directory, "source.json"))
	if err != nil {
		t.Fatal("prepared source configuration unavailable")
	}
	var settings map[string]any
	if json.Unmarshal(raw, &settings) != nil {
		t.Fatal("prepared source configuration invalid")
	}
	settings["base"] = httpServer.URL
	certPath := filepath.Join(directory, "source-cert.pem")
	settings["certificate"] = certPath
	if os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0600) != nil {
		t.Fatal("cannot write isolated source certificate")
	}
	raw, err = json.Marshal(settings)
	if err != nil || os.WriteFile(filepath.Join(directory, "source.json"), raw, 0600) != nil {
		t.Fatal("cannot update isolated source origin")
	}
	log, err := os.OpenFile(filepath.Join(directory, "upgrade-private.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal("cannot open private upgrade diagnostic")
	}
	defer log.Close()
	command := osexec.Command("/tmp/aisoc-scr94-tools/api/bin/python", filepath.Join(directory, "upgrade.py"))
	command.Stdout = log
	command.Stderr = log
	if command.Run() != nil {
		t.Fatal("real source upgrade journey failed; private diagnostic retained")
	}
}
