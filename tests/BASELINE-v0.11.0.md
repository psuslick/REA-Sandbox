# v0.11.0 validation record

## Inherited repairs from the v0.9.1 audit

- Tunnel ZIP recognition is no longer dependent on matching the filename variant to the inner executable name. Candidate entries are inspected, staged singly into the guest, PE x64 checked, and checked for the actual run CLI flags before large copies or npm. Invalid candidates fall through to the next one. Archive contents and reasons are logged. No Cloudflare companion is started.
- Node is copied to guest storage and used consistently for npm, firewall and the MCP launcher; the fixed nested host Node path is removed. Robocopy retains console QuickEdit protection and reports copy activity and errors.
- Readiness is now gated on scoped doctor JSON, local MCP protocol smoke, and shared effective firewall verification. The guest readiness record captures staged guard/client hashes. Credentials are read only after readiness and current firewall checks. The cleanup scope now covers the entire credential acquisition and launch sequence.
- The MCP gateway starts REA's package-declared, pinned-version entrypoint directly through Node instead of a shell, verifies sample identity, filters the tool list, blocks additional session/path arguments and unsupported methods, rejects duplicate pending requests and strips runtime credentials from its own environment and its child environment. Direct native image/API tools are removed to keep this gateway focused on active binary sessions.

## v0.11.0 startup regressions repaired

- Clipboard redirection is enabled in the versioned WSB. ProtectedClient and all other forwarding restrictions remain unchanged.
- The versioned launcher explicitly starts Windows PowerShell in STA mode and rejects legacy launcher use. The legacy CMD is a safe instruction-only stub.
- The tunnel starts automatically after the readiness record and successful transcript shutdown. There is no manual PowerShell command. Connection failures offer an explicit retry without repeating provisioning.
- A local WinForms dialog accepts pasted ID and masked key, checks syntax, offers cancellation and clears input on exit. The API key is never passed as a command-line argument or saved to a file. The launcher no longer consumes the legacy plaintext handoff.
- Effective firewall policy is rechecked after credential entry. Existing guest-only installation, read-only source map, limited diagnostics map, sample hash, and MCP guard remain in place.

## Completed in the build container

| Check | Result |
|---|---|
| Node JavaScript syntax (`node --check` on guard and smoke) | PASS |
| Mock MCP subprocess: initialize, tools/list filtering, pinned open/session/close | PASS |
| Mock MCP: wrong file, wrong provider, disallowed tool, snapshot write, session-path argument, resource method denied | PASS |
| Mock MCP: dummy control-plane, OpenAI and Cloudflare credentials absent in REA child | PASS |
| Static package invariants: clipboard enabled, remaining isolation flags and exact mapped folders | PASS |
| Static regression checks: versioned launcher, STA, automatic start after transcript stops, masked input, no legacy plaintext handoff | PASS |
| Static bootstrap ordering: tunnel preflight before copies/npm; firewall and MCP check before checkpoint and credentials | PASS |
| Sample SHA-256 unchanged, no sample execution | PASS |
| ZIP integrity | PASS (verified after packaging) |

The mock is not the real REA package. No npm commands or package downloads were performed in the build container or on the user's host. No executable supplied in the original package was run here.

## Not verified here

- Windows PowerShell 5.1 parser or runtime execution (not installed in this Linux container), actual WinForms rendering, clipboard paste or retry behavior.
- User's actual tunnel archive bytes, signatures, PE architecture or run-help output (not supplied with the original ZIP).
- Windows Sandbox startup, copy performance, actual npm installation, Ghidra native provider or real MCP startup/analysis.
- Effective Windows firewall behavior or authenticated OpenAI polling/ChatGPT connector operation.

The new bootstrap performs several of those checks on first launch and refuses readiness on failure. It does not test actual remote credentials or guarantee an air gap. The first connection is a Windows integration test, not a certified deployment.

## Reproduce build-side tests (optional; not a host installation instruction)

    python tests/check_package.py
    node --check rea-mcp-guard.js
    node --check rea-smoke.js
    REA_GUARD_TEST=1 REA_GUARD_REA="$PWD/tests/mock-rea.js" CONTROL_PLANE_API_KEY=mock OPENAI_API_KEY=mock CLOUDFLARED_TOKEN=mock node rea-smoke.js

The final command is for a non-Windows build/test environment only. Windows users should launch the WSB; no npm command on the host.
