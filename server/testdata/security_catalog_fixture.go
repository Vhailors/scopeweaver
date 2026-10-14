//go:build ignore

// An owned wire relay around the existing inert Node fixture. It records IPC
// and offers HTTP event barriers without modifying the fixture or using sleeps.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	cmd := exec.Command("node", os.Args[1:]...)
	cmd.Stdin = os.Stdin
	out, err := cmd.StdoutPipe()
	if err != nil {
		os.Exit(2)
	}
	errout, err := cmd.StderrPipe()
	if err != nil {
		os.Exit(2)
	}
	log, err := os.OpenFile(os.Getenv("TASK3_FIXTURE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	defer log.Close()
	if err := cmd.Start(); err != nil {
		os.Exit(2)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	post := func(path string, body []byte) {
		res, err := client.Post(os.Getenv("TASK3_FIXTURE_EVENTS")+path, "application/json", bytes.NewReader(body))
		if err != nil {
			_ = cmd.Process.Kill()
			return
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
	var readers sync.WaitGroup
	loggedInitialize := make(chan struct{})
	loggedList := make(chan struct{})
	readers.Add(1)
	go func() {
		defer readers.Done()
		sc := bufio.NewScanner(errout)
		for sc.Scan() {
			event := append([]byte(nil), sc.Bytes()...)
			var row map[string]any
			if json.Unmarshal(event, &row) != nil {
				continue
			}
			row["pid"] = cmd.Process.Pid
			row["scenario"] = os.Getenv("TASK3_FIXTURE_SCENARIO")
			row["run"] = os.Getenv("TASK3_FIXTURE_RUN")
			record, err := json.Marshal(row)
			if err != nil {
				continue
			}
			_, _ = log.Write(append(record, '\n'))
			if row["method"] == "initialize" {
				close(loggedInitialize)
			}
			if row["method"] == "tools/list" {
				close(loggedList)
			}
			post("/event", record)
		}
	}()
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 4096), 2<<20)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		var response struct{ ID int }
		if json.Unmarshal(line, &response) == nil && response.ID == 1 {
			<-loggedInitialize
		} else {
			// Write the fixture's request log BEFORE forwarding its response,
			// including malformed bytes, so cancellation cannot erase evidence.
			<-loggedList
		}
		if json.Unmarshal(line, &response) == nil && response.ID == 2 {
			var replacement any
			switch os.Getenv("TASK3_FIXTURE_MUTATION") {
			case "ambiguous":
				replacement = map[string]any{"tools": []map[string]string{{"name": "x__unexpected_operation"}}}
			case "replacement":
				replacement = map[string]any{"tools": []map[string]string{{"name": "replacement", "description": "Inert replacement"}}}
			case "oversized":
				replacement = map[string]any{"tools": []map[string]string{{"name": "unexpected_operation", "description": strings.Repeat("x", 300000)}}}
			case "too_many":
				tools := make([]map[string]string, 257)
				for i := range tools {
					tools[i] = map[string]string{"name": "fixture_" + strings.Repeat("x", i+1)}
				}
				replacement = map[string]any{"tools": tools}
			case "duplicate":
				replacement = map[string]any{"tools": []map[string]string{{"name": "unexpected_operation"}, {"name": "unexpected_operation"}}}
			case "paged":
				replacement = map[string]any{"tools": []any{}, "nextCursor": "fixture-next"}
			case "missing_tools":
				replacement = map[string]any{}
			case "null":
				line = []byte(`{"jsonrpc":"2.0","id":2,"result":null}`)
			}
			if replacement != nil {
				line, err = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "result": replacement})
				if err != nil {
					_ = cmd.Process.Kill()
					break
				}
			}
		}
		if json.Unmarshal(line, &response) == nil && response.ID == 2 && os.Getenv("TASK3_FIXTURE_BARRIER") == "true" {
			post("/list", []byte(`{}`))
		}
		if _, err := os.Stdout.Write(append(line, '\n')); err != nil {
			_ = cmd.Process.Kill()
			break
		}
	}
	readers.Wait()
	if err := cmd.Wait(); err != nil {
		os.Exit(1)
	}
}
