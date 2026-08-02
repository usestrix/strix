# Strix TUI protocol v3

The Python parent and Go TUI communicate through a private connected socket.
POSIX uses an inherited `STRIX_TUI_FD`. Windows uses an authenticated one-use
loopback connection because inherited descriptors are unavailable. The Windows
address and token are removed from the child environment immediately after use.

Every frame starts with a four-byte unsigned big-endian JSON length. Command and
control frames are limited to 64 KiB. Collection frames are limited to 4 MiB.
Lengths are rejected before payload allocation. There is no v2 compatibility
mode.

## Activation handshake

Python sends exactly one `hello` immediately after transport connection:

```json
{"version":3,"type":"hello","payload":{"capabilities":["state-revisions","collection-deltas","structured-command-errors","paged-models","agents-collection","setup-run-controls"]}}
```

Go validates the version, message type, and exact ordered capability list. It
then sends the corresponding `ready` before creating the Bubble Tea program or
entering the terminal alternate screen:

```json
{"version":3,"type":"ready","payload":{"capabilities":["state-revisions","collection-deltas","structured-command-errors","paged-models","agents-collection","setup-run-controls"]}}
```

Python does not initialize report/run state or start a scan until it validates
`ready`. A version/capability mismatch makes the Go sidecar exit nonzero and
the launch fails with guidance. Failures after `ready` are surfaced and never
start a second UI.

## State and collections

Small mutable state is sent only when it changes:

```json
{"version":3,"type":"state","payload":{"revision":4,"state":{"scan_state":"running","messages":[]}}}
```

Agents, events, and vulnerabilities are separate revisioned collections. Initial or
resynchronized history is split into bounded frames. `cursor` is the item offset
for that frame and must equal the receiver's expected cursor.

```json
{"version":3,"type":"collection_bootstrap","payload":{"collection":"events","revision":1,"cursor":0,"next_cursor":2,"done":false,"items":[{},{}]}}
```

After bootstrap, only changed/new items and deletes are sent. `base_revision`
must match the receiver's installed revision. Agent IDs are stable and the
agents collection is not capped. Event IDs are stable and an update must carry
a higher event `version`.

```json
{"version":3,"type":"collection_delta","payload":{"collection":"events","base_revision":1,"revision":2,"cursor":0,"next_cursor":1,"done":true,"operations":[{"op":"upsert","item":{"id":"tool_9","version":2}}]}}
```

Agents never appear in `state`. This allows arbitrarily large graphs to bootstrap
and update without exceeding the 64 KiB control-frame limit. The Go client keeps
the selected agent ID across agent bootstraps and deltas, falling back to the
first remaining agent only when that ID is deleted.

Idle polls produce no frames. A cursor, revision, duplicate-ID, or event-version
mismatch causes the Go client to submit one `collection.resync` command for that
collection. The replacement bootstrap may contain any number of frames, so
histories larger than 64 MiB can resume without increasing a frame limit.
Terminal projections may truncate pathological individual fields or nested tool
output. The terminal projection retains at most 5,000 recent events and 1,000
findings; older terminal rows are evicted with `delete` operations while durable
SDK session and report history remains unchanged.

## Commands

Every command has a non-empty `request_id`. The Go client keeps one pending
request per command (and per collection for resync), rejects duplicate
submissions, and applies results only when both request ID and command match.

Client commands are:

- `providers.list`, `models.list`
- `setup.select_provider`, `setup.save_api_key`, `setup.disconnect_provider`
- `setup.add_custom_provider`, `setup.select_model`
- `setup.add_target`, `setup.add_mount`, `setup.load_target_list`, `setup.clear_targets`
- `setup.set_instruction`, `setup.load_instruction_file`, `setup.set_mode`
- `setup.set_budget`, `setup.set_max_turns`, `setup.set_scope`, `setup.start`
- `agent.send_message`, `agent.stop`
- `viewer.open`, `collection.resync`, `app.quit`

A success is correlated as follows:

```json
{"version":3,"type":"command_result","request_id":"go-1","payload":{"ok":true,"command":"providers.list","result":{}}}
```

Errors are structured and do not stop the command reader:

```json
{"version":3,"type":"command_result","request_id":"go-2","payload":{"ok":false,"command":"setup.select_model","error":{"code":"persistence_error","message":"disk is read-only","retryable":true}}}
```

Malformed commands, persistence `OSError`s, and unexpected command exceptions
are isolated to their request. EOF, invalid frame lengths, and socket I/O errors
are fatal transport failures and close the connection.

API keys appear only in `setup.save_api_key` and `setup.add_custom_provider`
payloads. They are cleared from Go input fields after submission and are never
echoed in state, results, logs, process arguments, or the child environment.

### Paged model listings

`models.list` is always paged. A request without a cursor creates an immutable,
short-lived server snapshot:

```json
{"version":3,"type":"models.list","request_id":"go-3","payload":{}}
```

The result identifies the snapshot and page. Every command result, including a
page containing part of one unusually large provider group, remains below the
64 KiB control-frame limit:

```json
{"listing_id":"R4nd0m","cursor":0,"next_cursor":1,"done":false,"groups":[{"provider":"openai","label":"OpenAI","models":["openai/gpt-5"],"allow_manual":false,"error":""}],"providers":[]}
```

The next request must echo both values:

```json
{"version":3,"type":"models.list","request_id":"go-4","payload":{"listing_id":"R4nd0m","cursor":1}}
```

The listing ID expires after 60 seconds. Unknown, expired, or out-of-range
cursors are rejected as structured `invalid_request` results. Provider groups
may span pages; Go merges fragments by provider and opens the model picker only
after receiving `done:true`. If no provider is connected, the same paging shape
uses `providers` instead of `groups`.

## Protocol smoke

`--tui-protocol-smoke` does not stop at negotiation. The sidecar sends a
correlated `setup.set_instruction` command containing a random nonce, observes
its successful result and a state revision containing that nonce, and consumes
complete agents, events, and vulnerabilities bootstraps. It exits successfully
only after all checks pass and never enters the terminal alternate screen.
