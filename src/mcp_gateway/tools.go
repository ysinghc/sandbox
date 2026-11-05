// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// toolHandler runs one tool: text is the model's content, isErr marks a failed
// execution (still a result, so the model sees it), perr is a protocol-level
// refusal (bad arguments) answered as a JSON-RPC error instead.
type toolHandler func(ctx context.Context, s *Server, args map[string]any) (text string, isErr bool, perr *rpcError)

type toolDef struct {
	name        string
	title       string
	description string
	scope       string
	schema      map[string]any
	annotations map[string]any
	run         toolHandler
}

// --- schema DSL: small builders so the twelve schemas stay readable ---

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func strEnumProp(desc string, enum ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": enum}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func strListProp(desc string) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "string"}}
}

func strMapProp(desc string) map[string]any {
	return map[string]any{"type": "object", "description": desc, "additionalProperties": map[string]any{"type": "string"}}
}

func objSchema(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func readOnlyAnno() map[string]any {
	return map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
}

func writeAnno(destructive, idempotent bool) map[string]any {
	return map[string]any{"readOnlyHint": false, "destructiveHint": destructive, "idempotentHint": idempotent, "openWorldHint": false}
}

// toolTable is the whole 1:1 map onto the #27 API: the nine tools the issue
// names plus stat, mkdir and file delete, which complete the endpoint cover.
var toolTable = []toolDef{
	{
		name: "create_session", title: "Create session", scope: ScopeWrite,
		description: "Create a sandbox session (or reattach to the key's session). The session id is deterministic per key.",
		schema: objSchema([]string{}, map[string]any{
			"key":             strProp("Session key; omit for a random one."),
			"template":        strProp("Template name (default from the server)."),
			"memory_mib":      intProp("Guest memory in MiB."),
			"vcpus":           intProp("Guest vCPU count."),
			"ttl_seconds":     intProp("Workspace lifetime in seconds (default 7 days, max 30)."),
			"env":             strMapProp("Environment for commands, KEY to value."),
			"egress_allow":    strListProp("Hosts this session may reach (max 16)."),
			"egress_deny_all": boolProp("True to allow no egress at all."),
		}),
		annotations: writeAnno(false, true),
		run:         toolCreateSession,
	},
	{
		name: "list_sessions", title: "List sessions", scope: ScopeRead,
		description: "List your sessions with their state and expiry.",
		schema:      objSchema([]string{}, map[string]any{}),
		annotations: readOnlyAnno(),
		run:         toolListSessions,
	},
	{
		name: "get_status", title: "Session status", scope: ScopeRead,
		description: "Show one session's state, resources and expiry.",
		schema: objSchema([]string{"session_id"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
		}),
		annotations: readOnlyAnno(),
		run:         toolGetStatus,
	},
	{
		name: "run", title: "Run command", scope: ScopeWrite,
		description: "Run a shell command or argv in the session. Output arrives when the command finishes.",
		schema: objSchema([]string{"session_id"}, map[string]any{
			"session_id":      strProp("Session id (ses_...)."),
			"command":         strProp("Shell script for /bin/sh -c (give command or argv, not both)."),
			"argv":            strListProp("Argument vector (give command or argv, not both)."),
			"cwd":             strProp("Working directory (default /workspace)."),
			"env":             strMapProp("Extra environment for this command."),
			"timeout_ms":      intProp("Kill the command after this long (0-3600000, default 60000)."),
			"max_output":      intProp("Kill past this many output bytes (0-4194304)."),
			"stdin":           strProp("Text on the command's stdin (or stdin_base64)."),
			"stdin_base64":    strProp("Base64 bytes on the command's stdin (or stdin)."),
			"output_encoding": strEnumProp("How to return output with invalid UTF-8.", "utf8", "base64"),
			"idempotency_key": strProp("Safe-retry key: a replay returns the first answer."),
		}),
		annotations: writeAnno(true, false),
		run:         toolRun,
	},
	{
		name: "read_file", title: "Read file", scope: ScopeRead,
		description: "Read a file from /workspace (max 4 MiB).",
		schema: objSchema([]string{"session_id", "path"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
			"path":       strProp("Absolute path under /workspace."),
			"encoding":   strEnumProp("Return text or base64 (for non-UTF-8).", "text", "base64"),
		}),
		annotations: readOnlyAnno(),
		run:         toolReadFile,
	},
	{
		name: "write_file", title: "Write file", scope: ScopeWrite,
		description: "Write a file under /workspace (max 4 MiB).",
		schema: objSchema([]string{"session_id", "path"}, map[string]any{
			"session_id":     strProp("Session id (ses_...)."),
			"path":           strProp("Absolute path under /workspace."),
			"content":        strProp("Text content (or content_base64)."),
			"content_base64": strProp("Base64 content (or content)."),
			"append":         boolProp("Append instead of replacing."),
			"exclusive":      boolProp("Fail if the path already exists."),
		}),
		annotations: writeAnno(true, false),
		run:         toolWriteFile,
	},
	{
		name: "list_files", title: "List files", scope: ScopeRead,
		description: "List a directory under /workspace.",
		schema: objSchema([]string{"session_id"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
			"path":       strProp("Absolute path under /workspace (default /workspace)."),
		}),
		annotations: readOnlyAnno(),
		run:         toolListFiles,
	},
	{
		name: "get_file_stat", title: "File metadata", scope: ScopeRead,
		description: "Stat a path under /workspace (type, size, mode, mtime).",
		schema: objSchema([]string{"session_id", "path"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
			"path":       strProp("Absolute path under /workspace."),
		}),
		annotations: readOnlyAnno(),
		run:         toolFileStat,
	},
	{
		name: "make_directory", title: "Make directory", scope: ScopeWrite,
		description: "Create a directory under /workspace.",
		schema: objSchema([]string{"session_id", "path"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
			"path":       strProp("Absolute path under /workspace."),
			"parents":    boolProp("Create parents as needed (mkdir -p)."),
			"mode":       intProp("Permission bits, e.g. 493 for 0755."),
		}),
		annotations: writeAnno(false, false),
		run:         toolMkdir,
	},
	{
		name: "delete_file", title: "Delete path", scope: ScopeWrite,
		description: "Remove a file or directory under /workspace. Directories need recursive.",
		schema: objSchema([]string{"session_id", "path"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
			"path":       strProp("Absolute path under /workspace (never / or /workspace itself)."),
			"recursive":  boolProp("Remove directories and their contents."),
		}),
		annotations: writeAnno(true, false),
		run:         toolDeleteFile,
	},
	{
		name: "renew", title: "Renew session", scope: ScopeWrite,
		description: "Extend a session's workspace deadline.",
		schema: objSchema([]string{"session_id"}, map[string]any{
			"session_id":  strProp("Session id (ses_...)."),
			"ttl_seconds": intProp("Seconds to add from now (default platform policy)."),
		}),
		annotations: writeAnno(false, false),
		run:         toolRenew,
	},
	{
		name: "destroy_session", title: "Destroy session", scope: ScopeWrite,
		description: "Release a session's VM and forget it. The workspace is kept until its TTL.",
		schema: objSchema([]string{"session_id"}, map[string]any{
			"session_id": strProp("Session id (ses_...)."),
		}),
		annotations: writeAnno(true, true),
		run:         toolDestroySession,
	},
}

// toolDefs is the tools/list payload, derived from the table so the listing
// and the dispatch can never disagree.
var toolDefs = func() []map[string]any {
	var out []map[string]any
	for _, t := range toolTable {
		out = append(out, map[string]any{
			"name": t.name, "title": t.title, "description": t.description,
			"inputSchema": t.schema, "annotations": t.annotations,
		})
	}
	return out
}()

func findTool(name string) *toolDef {
	for i := range toolTable {
		if toolTable[i].name == name {
			return &toolTable[i]
		}
	}
	return nil
}

// rpcToolCall validates a tools/call request, enforces the token's scopes and
// runs the tool. Argument problems are JSON-RPC errors; API failures come back
// as failed results so the model reads them.
func (s *Server) rpcToolCall(ctx context.Context, id *json.RawMessage, tok *AccessToken, params json.RawMessage) *rpcResponse {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return rpcErr(id, rpcInvalidParams, "tools/call params are not an object")
		}
	}
	if p.Name == "" {
		return rpcErr(id, rpcInvalidParams, "tool name is required")
	}
	tool := findTool(p.Name)
	if tool == nil {
		return rpcErr(id, rpcInvalidParams, fmt.Sprintf("unknown tool %q", p.Name))
	}
	args := map[string]any{}
	if len(p.Arguments) > 0 {
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return rpcErr(id, rpcInvalidParams, "arguments are not an object")
		}
	}
	if !contains(tok.Scopes, tool.scope) {
		return rpcErr(id, rpcNoScope, fmt.Sprintf("token lacks scope %q", tool.scope))
	}
	text, isErr, perr := tool.run(ctx, s, args)
	if perr != nil {
		return rpcErr(id, perr.Code, perr.Message)
	}
	result := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
	if isErr {
		result["isError"] = true
	}
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// --- argument helpers: missing or mistyped arguments are -32602 ---

func argErr(format string, a ...any) *rpcError {
	return &rpcError{Code: rpcInvalidParams, Message: fmt.Sprintf(format, a...)}
}

func needStr(args map[string]any, key string) (string, *rpcError) {
	v, ok := args[key]
	if !ok {
		return "", argErr("argument %q is required", key)
	}
	str, ok := v.(string)
	if !ok || str == "" {
		return "", argErr("argument %q must be a non-empty string", key)
	}
	return str, nil
}

func optStr(args map[string]any, key string) (string, *rpcError) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", nil
	}
	str, ok := v.(string)
	if !ok {
		return "", argErr("argument %q must be a string", key)
	}
	return str, nil
}

func optBool(args map[string]any, key string) (bool, *rpcError) {
	v, ok := args[key]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, argErr("argument %q must be a boolean", key)
	}
	return b, nil
}

func optNum(args map[string]any, key string) (float64, bool, *rpcError) {
	v, ok := args[key]
	if !ok || v == nil {
		return 0, false, nil
	}
	n, ok := v.(float64)
	if !ok {
		return 0, false, argErr("argument %q must be a number", key)
	}
	return n, true, nil
}

func optStrList(args map[string]any, key string) ([]string, *rpcError) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, argErr("argument %q must be an array of strings", key)
	}
	var out []string
	for _, e := range arr {
		str, ok := e.(string)
		if !ok {
			return nil, argErr("argument %q must be an array of strings", key)
		}
		out = append(out, str)
	}
	return out, nil
}

func optStrMap(args map[string]any, key string) (map[string]string, *rpcError) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, argErr("argument %q must be an object of strings", key)
	}
	out := map[string]string{}
	for k, e := range obj {
		str, ok := e.(string)
		if !ok {
			return nil, argErr("argument %q must be an object of strings", key)
		}
		out[k] = str
	}
	return out, nil
}

// --- handlers: one per tool, each a single #27 call plus formatting ---

func toolCreateSession(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	fields := map[string]any{}
	for _, k := range []string{"key", "template"} {
		if v, err := optStr(args, k); err != nil {
			return "", false, err
		} else if v != "" {
			fields[k] = v
		}
	}
	for _, k := range []string{"memory_mib", "vcpus", "ttl_seconds"} {
		if n, present, err := optNum(args, k); err != nil {
			return "", false, err
		} else if present {
			if n < 0 || n != float64(int64(n)) {
				return "", false, argErr("argument %q must be a non-negative integer", k)
			}
			fields[k] = int64(n)
		}
	}
	if env, err := optStrMap(args, "env"); err != nil {
		return "", false, err
	} else if env != nil {
		fields["env"] = env
	}
	if allow, err := optStrList(args, "egress_allow"); err != nil {
		return "", false, err
	} else if allow != nil {
		fields["egress_allow"] = allow
	}
	if deny, err := optBool(args, "egress_deny_all"); err != nil {
		return "", false, err
	} else if deny {
		fields["egress_deny_all"] = true
	}
	res, err := s.api.CreateSession(ctx, s.apiToken, fields)
	if err != nil {
		return "engine unreachable: " + err.Error(), true, nil
	}
	if res.Status != http.StatusCreated && res.Status != http.StatusOK {
		return "create_session failed: " + res.errText(), true, nil
	}
	return formatSession(res.json()), false, nil
}

func toolListSessions(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	res, err := s.api.ListSessions(ctx, s.apiToken)
	if err != nil {
		return "engine unreachable: " + err.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "list_sessions failed: " + res.errText(), true, nil
	}
	m := res.json()
	raw, _ := m["sessions"].([]any)
	if len(raw) == 0 {
		return "no sessions", false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d session(s):\n", len(raw))
	for _, e := range raw {
		sm, _ := e.(map[string]any)
		fmt.Fprintf(&b, "- %s (%s, expires %v)\n", strOf(sm, "id"), strOf(sm, "state"), numOf(sm, "expires_at"))
	}
	return strings.TrimSuffix(b.String(), "\n"), false, nil
}

func toolGetStatus(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	res, err := s.api.GetSession(ctx, s.apiToken, id)
	if err != nil {
		return "engine unreachable: " + err.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "get_status failed: " + res.errText(), true, nil
	}
	return formatSession(res.json()), false, nil
}

func toolRun(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	command, err := optStr(args, "command")
	if err != nil {
		return "", false, err
	}
	argv, err := optStrList(args, "argv")
	if err != nil {
		return "", false, err
	}
	if (command == "") == (len(argv) == 0) {
		return "", false, argErr("give command or argv, not both and not neither")
	}
	fields := map[string]any{}
	if command != "" {
		fields["command"] = command
	} else {
		fields["argv"] = argv
	}
	if cwd, err := optStr(args, "cwd"); err != nil {
		return "", false, err
	} else if cwd != "" {
		fields["cwd"] = cwd
	}
	if env, err := optStrMap(args, "env"); err != nil {
		return "", false, err
	} else if env != nil {
		fields["env"] = env
	}
	for _, k := range []string{"timeout_ms", "max_output"} {
		if n, present, err := optNum(args, k); err != nil {
			return "", false, err
		} else if present {
			if n < 0 || n != float64(int64(n)) {
				return "", false, argErr("argument %q must be a non-negative integer", k)
			}
			fields[k] = int64(n)
		}
	}
	stdin, err := optStr(args, "stdin")
	if err != nil {
		return "", false, err
	}
	stdinB64, err := optStr(args, "stdin_base64")
	if err != nil {
		return "", false, err
	}
	if stdin != "" && stdinB64 != "" {
		return "", false, argErr("give stdin or stdin_base64, not both")
	}
	if stdin != "" {
		fields["stdin"] = stdin
	}
	if stdinB64 != "" {
		fields["stdin_base64"] = stdinB64
	}
	if enc, err := optStr(args, "output_encoding"); err != nil {
		return "", false, err
	} else if enc != "" {
		if enc != "utf8" && enc != "base64" {
			return "", false, argErr("output_encoding must be utf8 or base64")
		}
		fields["output_encoding"] = enc
	}
	idem, err := optStr(args, "idempotency_key")
	if err != nil {
		return "", false, err
	}
	res, aerr := s.api.Exec(ctx, s.apiToken, id, fields, idem)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "run failed: " + res.errText(), true, nil
	}
	return formatExec(res.json()), false, nil
}

func toolReadFile(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, perr := needStr(args, "path")
	if perr != nil {
		return "", false, perr
	}
	enc, err := optStr(args, "encoding")
	if err != nil {
		return "", false, err
	}
	if enc == "" {
		enc = "text"
	}
	if enc != "text" && enc != "base64" {
		return "", false, argErr("encoding must be text or base64")
	}
	res, aerr := s.api.GetFile(ctx, s.apiToken, id, path)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "read_file failed: " + res.errText(), true, nil
	}
	if enc == "base64" {
		return base64.StdEncoding.EncodeToString(res.Body), false, nil
	}
	return string(res.Body), false, nil
}

func toolWriteFile(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, perr := needStr(args, "path")
	if perr != nil {
		return "", false, perr
	}
	content, err := optStr(args, "content")
	if err != nil {
		return "", false, err
	}
	contentB64, err := optStr(args, "content_base64")
	if err != nil {
		return "", false, err
	}
	if (content == "") == (contentB64 == "") {
		return "", false, argErr("give content or content_base64, not both and not neither")
	}
	var data []byte
	if contentB64 != "" {
		var derr error
		if data, derr = base64.StdEncoding.DecodeString(contentB64); derr != nil {
			return "", false, argErr("content_base64 is not valid base64")
		}
	} else {
		data = []byte(content)
	}
	appendMode, err := optBool(args, "append")
	if err != nil {
		return "", false, err
	}
	exclusive, err := optBool(args, "exclusive")
	if err != nil {
		return "", false, err
	}
	res, aerr := s.api.PutFile(ctx, s.apiToken, id, path, data, appendMode, exclusive)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "write_file failed: " + res.errText(), true, nil
	}
	verb := "wrote"
	if appendMode {
		verb = "appended"
	}
	return fmt.Sprintf("%s %d bytes to %s", verb, len(data), path), false, nil
}

func toolListFiles(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, err := optStr(args, "path")
	if err != nil {
		return "", false, err
	}
	if path == "" {
		path = "/workspace"
	}
	res, aerr := s.api.ListPath(ctx, s.apiToken, id, path)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "list_files failed: " + res.errText(), true, nil
	}
	m := res.json()
	raw, _ := m["entries"].([]any)
	if len(raw) == 0 {
		return path + ": empty", false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d entries):\n", path, len(raw))
	for _, e := range raw {
		em, _ := e.(map[string]any)
		fmt.Fprintf(&b, "- %s (%s, %v bytes)\n", strOf(em, "name"), strOf(em, "type"), numOf(em, "size"))
	}
	out := strings.TrimSuffix(b.String(), "\n")
	if trunc, _ := m["truncated"].(bool); trunc {
		out += "\n(listing truncated)"
	}
	return out, false, nil
}

func toolFileStat(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, perr := needStr(args, "path")
	if perr != nil {
		return "", false, perr
	}
	res, aerr := s.api.StatPath(ctx, s.apiToken, id, path)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "get_file_stat failed: " + res.errText(), true, nil
	}
	m := res.json()
	return fmt.Sprintf("%s: %s, %v bytes, mode %s, mtime %v",
		strOf(m, "path"), strOf(m, "type"), numOf(m, "size"), strOf(m, "mode"), numOf(m, "mtime")), false, nil
}

func toolMkdir(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, perr := needStr(args, "path")
	if perr != nil {
		return "", false, perr
	}
	parents, err := optBool(args, "parents")
	if err != nil {
		return "", false, err
	}
	fields := map[string]any{"path": path, "parents": parents}
	if n, present, err := optNum(args, "mode"); err != nil {
		return "", false, err
	} else if present {
		if n < 0 || n > 0777 || n != float64(int64(n)) {
			return "", false, argErr("mode must be permission bits 0-511")
		}
		fields["mode"] = int64(n)
	}
	res, aerr := s.api.Mkdir(ctx, s.apiToken, id, fields)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusNoContent && res.Status != http.StatusOK {
		return "make_directory failed: " + res.errText(), true, nil
	}
	return "created " + path, false, nil
}

func toolDeleteFile(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	path, perr := needStr(args, "path")
	if perr != nil {
		return "", false, perr
	}
	recursive, err := optBool(args, "recursive")
	if err != nil {
		return "", false, err
	}
	res, aerr := s.api.DeleteFile(ctx, s.apiToken, id, path, recursive)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusNoContent && res.Status != http.StatusOK {
		return "delete_file failed: " + res.errText(), true, nil
	}
	return "removed " + path, false, nil
}

func toolRenew(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	fields := map[string]any{}
	if n, present, err := optNum(args, "ttl_seconds"); err != nil {
		return "", false, err
	} else if present {
		if n < 0 || n != float64(int64(n)) {
			return "", false, argErr("ttl_seconds must be a non-negative integer")
		}
		fields["ttl_seconds"] = int64(n)
	}
	res, aerr := s.api.RenewSession(ctx, s.apiToken, id, fields)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusOK {
		return "renew failed: " + res.errText(), true, nil
	}
	return fmt.Sprintf("session %s now expires at %v", id, numOf(res.json(), "expires_at")), false, nil
}

func toolDestroySession(ctx context.Context, s *Server, args map[string]any) (string, bool, *rpcError) {
	id, perr := needStr(args, "session_id")
	if perr != nil {
		return "", false, perr
	}
	res, aerr := s.api.DeleteSession(ctx, s.apiToken, id)
	if aerr != nil {
		return "engine unreachable: " + aerr.Error(), true, nil
	}
	if res.Status != http.StatusNoContent && res.Status != http.StatusOK {
		return "destroy_session failed: " + res.errText(), true, nil
	}
	return "session " + id + " deleted (its workspace is kept until its TTL)", false, nil
}

// --- formatters: API JSON in, model-readable text out ---

func strOf(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func numOf(m map[string]any, key string) int64 {
	switch n := m[key].(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func boolOf(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

func formatSession(m map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "session %s (%s)\n", strOf(m, "id"), strOf(m, "state"))
	fmt.Fprintf(&b, "template: %s, memory: %d MiB, vcpus: %d\n",
		strOf(m, "template"), numOf(m, "memory_mib"), numOf(m, "vcpus"))
	fmt.Fprintf(&b, "expires_at: %d", numOf(m, "expires_at"))
	return b.String()
}

func formatExec(m map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit %d, %d ms", numOf(m, "exit_code"), numOf(m, "duration_ms"))
	var notes []string
	if sig := numOf(m, "term_signal"); sig != 0 {
		notes = append(notes, fmt.Sprintf("killed by signal %d", sig))
	}
	if boolOf(m, "timed_out") {
		notes = append(notes, "timed out")
	}
	if boolOf(m, "output_truncated") {
		notes = append(notes, "output truncated by the cap")
	}
	if len(notes) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(notes, ", "))
	}
	stdout, stderr := strOf(m, "stdout"), strOf(m, "stderr")
	fmt.Fprintf(&b, "\n--- stdout (%d of %d bytes) ---\n%s",
		numOf(m, "stdout_returned"), numOf(m, "stdout_bytes"), stdout)
	if stderr != "" {
		fmt.Fprintf(&b, "\n--- stderr (%d of %d bytes) ---\n%s",
			numOf(m, "stderr_returned"), numOf(m, "stderr_bytes"), stderr)
	}
	return b.String()
}
