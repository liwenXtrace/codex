# Read-only paths for local subprocesses

On macOS, the top-level `process_read_only_paths` setting adds read-only filesystem restrictions to trusted command hooks, legacy `notify` commands and local stdio MCP servers. It lets a client fork a session into a disposable checkout while retaining its configured integrations.

```toml
process_read_only_paths = ["/work/original", "/work/shared.git", "/history/original.jsonl"]
```

The native launchers apply the existing Seatbelt sandbox transformation before spawning each process. Descendants inherit the restriction. Hook trust checks, stdin payloads, output parsing, environment overrides, timeouts and asynchronous scheduling use their existing paths. Notifications retain their JSON argument and MCP servers retain their transport. Protected sessions start private MCP processes instead of reusing a shared process that might lack these restrictions. The main Codex process is not wrapped, so model tools can still start their own sandbox.

The subprocess filesystem policy permits writes outside the listed paths and retains network access. This setting does not snapshot external state, restrict tools invoked through remote services, or undo remote effects. Clients must separately enforce their tool sandbox and replay contract. Remote-environment command hooks, remote stdio servers and HTTP header-helper subprocesses refuse execution when these restrictions are requested. Nonempty restrictions fail closed on unsupported operating systems.

Restrictions are retained across hook configuration refreshes and saved in session metadata when the thread is created. Fork and resume restore persisted restrictions before startup hooks and MCP initialization. A client adding restrictions to an existing thread should fork a new thread to persist them; refresh only adds restrictions for the current process. The `thread/fork` response includes `processReadOnlyPaths` when effective restrictions are present, allowing clients to verify them before submitting input. Clients must not infer support merely because an older runtime accepted a config override.

Run `cargo test -p codex-hooks` on macOS for direct, asynchronous and notification child-process checks. The MemHub native fixture additionally verifies stdio MCP, fork, process restart/resume, original checkout and Git protection, and independent native tool sandbox execution. Passing these tests does not release this feature into an installed desktop application; the client must select a binary containing this implementation.
