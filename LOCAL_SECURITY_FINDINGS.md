# Local-Run Security Findings

This note records security risks found during a read-only scan of the repository
for local execution. The scan focused on build scripts, downloader scripts, local
server exposure, shell execution, filesystem writes, caches, traces, and network
use.

## Findings

### High: `ds4-agent` Runs Unsandboxed Tool Calls

`ds4-agent` gives the model native tools including `bash`, `read`, `write`,
`edit`, `search`, and `list`. The `bash` tool executes commands through
`/bin/sh -c`, and the file tools are not confined to the repository.

References:

- `ds4_agent.c:572` defines the model-visible tool prompt and tool schemas.
- `ds4_agent.c:4772` starts shell commands via `fork()` and `execl("/bin/sh", "sh", "-c", ...)`.
- `ds4_agent.c:5093` dispatches parsed model tool calls to side-effecting tools.
- `ds4_agent.c:5456` continues assistant/tool rounds automatically.

Risk: prompt injection or bad model output can execute commands, read secrets, or
overwrite files as the current user.

Mitigation: run `ds4-agent` only in a disposable workspace, container, VM, or
dedicated low-privilege user account. Avoid running it in directories containing
secrets.

### Medium-High: `ds4-server` Has No Authentication

`ds4-server` binds to `127.0.0.1` by default, but accepts `--host 0.0.0.0`.
`--cors` adds permissive browser CORS headers and does not add authentication.

References:

- `ds4_server.c:4757` emits `Access-Control-Allow-Origin: *` when CORS is enabled.
- `ds4_server.c:11158` binds the configured host and port.
- `ds4_server.c:11324` documents default bind address and CORS behavior.
- `ds4_server.c:11407` defaults to host `127.0.0.1` and port `8000`.

Risk: anyone who can reach the server can submit prompts and consume local
GPU/RAM resources. If exposed with CORS enabled, browser-origin requests become
easier to trigger.

Mitigation: keep the server bound to loopback. Do not use `--host 0.0.0.0`
unless it is behind a firewall or authenticated reverse proxy. Use `--cors` only
for trusted local browser clients.

### Medium: Model Downloader Lacks Integrity Verification

`download_model.sh` downloads large model artifacts from Hugging Face and updates
`ds4flash.gguf`, but does not verify a pinned revision, checksum, or signature.
It also uses `HF_TOKEN` or the local Hugging Face token cache if present.

References:

- `download_model.sh:119` reads `$HOME/.cache/huggingface/token`.
- `download_model.sh:148` passes the token to `curl` as an authorization header.
- `download_model.sh:150` downloads public files without any checksum check.

Risk: a replaced, corrupted, or compromised model artifact becomes native
parser/GPU input. Local Hugging Face tokens may be exposed to local process
inspection while `curl` is running.

Mitigation: pin model revisions and verify SHA256 checksums after download.
Unset `HF_TOKEN` for public downloads when authentication is unnecessary.

### Medium: Traces, KV Caches, And Sessions May Store Sensitive Data

Server traces can include raw request JSON, rendered prompts, generated text,
and tool calls. KV cache files and agent sessions can persist prompt-derived
state and exact replay data.

References:

- `ds4_server.c:9114` writes raw request JSON and rendered prompts to trace files.
- `ds4_server.c:11555` opens the server trace path.
- `ds4_kvstore.c:347` creates KV cache directories with mode `0700`.
- `ds4_agent.c:2196` stores agent sessions under `~/.ds4/kvcache`.

Risk: local disclosure if traces or cache directories are placed in shared,
world-readable, synced, or backed-up locations.

Mitigation: avoid `--trace` for sensitive prompts. Put `--kv-disk-dir` in a
private `0700` directory. Clean traces and KV caches intentionally.

### Medium-Low: Local HTTP Resource Exhaustion Is Possible

The server has a 64 MiB request body cap, creates a thread per accepted client,
serializes inference through one worker, and has a very large default output
token budget.

References:

- `ds4_server.c:10955` sets a 64 KiB header cap and 64 MiB body cap.
- `ds4_server.c:11585` accepts clients in a loop and spawns client handling.
- `ds4_server.c:11408` defaults `--tokens` to `393216`.

Risk: a local process or exposed remote client can tie up memory, threads, or
the single inference worker.

Mitigation: keep loopback-only, lower `--tokens` for routine use, and put an
authenticating/rate-limiting proxy in front of any remote deployment.

## Clean Signals

- No hidden install hooks or post-build network steps were found in the main
  Makefile.
- No embedded real API keys or private keys were found by pattern scan.
- The main CLI/server path did not show arbitrary shell execution; shell
  execution is concentrated in `ds4-agent`.
- Network access appears limited to explicit downloader and API utility scripts.
