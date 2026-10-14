package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/db"
)

const catalogResponseLimit = 1 << 20

var catalogToolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var catalogInterpreter = regexp.MustCompile(`^(node|nodejs|python[0-9]*(\.[0-9]+)?|bash|sh|ruby|perl|php|lua)$`)

// A direct interpreter/script invocation measures the script, not the runtime.
// Option-bearing or otherwise ambiguous interpreter invocations stay unmeasured.
func catalogProgramDigest(path string, args []string) string {
	target := path
	if catalogInterpreter.MatchString(filepath.Base(path)) {
		if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
			return ""
		}
		target = args[0]
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return ""
	}
	f, err := os.Open(target)
	if err != nil {
		return ""
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, 256<<20+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || n > 256<<20 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// listSecurityCatalog owns a short-lived stdio process, NOT an MCP tool client.
// There is deliberately no tools/call method or CoreTool adapter in this path.
func listSecurityCatalog(ctx context.Context, m *db.MCPServer) (cache db.MCPCatalog, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	path, err := exec.LookPath(m.Command)
	if err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	args := jsonStrSlice(m.Args)
	cache.ExecutableSHA256 = catalogProgramDigest(path, args)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = os.Environ()
	for key, value := range jsonStrMap(m.Env) {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard // upstream errors/prose must never escape into server logs
	in, err := cmd.StdinPipe()
	if err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	defer out.Close()
	if err := cmd.Start(); err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	defer func() {
		if err != nil {
			cancel()
		}
		_ = in.Close() // stdio transport closes by EOF, not an upstream tool call
		if werr := cmd.Wait(); werr != nil && err == nil {
			err = &catalogError{Code: "unavailable"}
		}
		// Also reap descendants holding pipes or surviving their parent.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()
	scanner := bufio.NewScanner(io.LimitReader(out, catalogResponseLimit+1))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	encoder := json.NewEncoder(in)
	call := func(id int, method string, params any, dest any) error {
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
			return &catalogError{Code: "unavailable"}
		}
		// A bounded number of notifications is permitted between responses.
		for range 32 {
			if !scanner.Scan() {
				return &catalogError{Code: "unavailable"}
			}
			var response struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      int             `json:"id"`
				Method  string          `json:"method"`
				Result  json.RawMessage `json:"result"`
				Error   json.RawMessage `json:"error"`
			}
			if json.Unmarshal(scanner.Bytes(), &response) != nil || response.JSONRPC != "2.0" {
				return &catalogError{Code: "unavailable"}
			}
			if response.ID == 0 && response.Method != "" {
				continue
			}
			if response.ID != id || len(response.Error) > 0 && string(response.Error) != "null" ||
				len(response.Result) == 0 || string(response.Result) == "null" ||
				json.Unmarshal(response.Result, dest) != nil {
				return &catalogError{Code: "unavailable"}
			}
			return nil
		}
		return &catalogError{Code: "unavailable"}
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err = call(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "scopeweaver-catalog", "version": "1"},
	}, &init); err != nil {
		return cache, err
	}
	switch init.ProtocolVersion {
	case "2024-11-05", "2025-03-26", "2025-06-18":
	default:
		return cache, &catalogError{Code: "unavailable"}
	}
	if len(init.ServerInfo.Version) > 128 {
		return cache, &catalogError{Code: "unavailable"}
	}
	cache.ObservedRevision = init.ServerInfo.Version // producer-reported, not authenticated
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return cache, &catalogError{Code: "unavailable"}
	}
	var listed struct {
		Tools      *[]db.MCPTool `json:"tools"`
		NextCursor string        `json:"nextCursor"`
	}
	if err = call(2, "tools/list", map[string]any{}, &listed); err != nil {
		return cache, err
	}
	if listed.Tools == nil || len(*listed.Tools) > 256 || listed.NextCursor != "" {
		return cache, &catalogError{Code: "unavailable"}
	}
	seen := make(map[string]bool)
	for _, tool := range *listed.Tools {
		if !catalogToolName.MatchString(tool.Name) || len(tool.Description) > 1024 || seen[tool.Name] {
			return cache, &catalogError{Code: "unavailable"}
		}
		seen[tool.Name] = true
	}
	cache.Tools, cache.Available = *listed.Tools, true
	return cache, nil
}
