# v0.12.0 validation record

Source baseline: supplied REA-MCP-v0.11.0(1).zip. The earlier separately documented tunnel hotfix is restored by serializing the MCP command with forward slashes. The original binary guard and firewall policy code are unchanged. The original Intel sample is excluded from the Git tree, but its path and expected SHA-256 remain fixed. See `tests/BASELINE-v0.11.0.md` for historical validation, not evidence of this release's Windows behavior.

## Completed in the Linux build environment

| Check | Result |
|---|---|
| Static tree / WSB XML / guest mapping / launch ordering / inherited security markers | PASS |
| Node syntax checks, guard and smoke | PASS |
| Mock MCP initialize, filtered tool list, pinned open/session/close | PASS |
| Mock MCP denies wrong path/provider, shell tool, snapshot, session path and resource method | PASS |
| Mock child checks dummy runtime secrets absent | PASS |
| Local synthetic Git repository: no-checkout clone, ancestor check, detached checkout, symlink detection predicate | PASS |
| Repo tree omits binary payloads, local configuration and credentials | PASS (static tree check; not a full secret scan) |

No npm commands, downloads of npm packages, supplied Windows executables or game code were executed. The Git fixture used only a synthetic local repository, not the user's remote. The CI workflow is included but not run on GitHub here.

## Pending real Windows verification

- PowerShell 5.1 parsing and execution of the new bootstrap; existing shared portable Git staging and GitHub HTTPS clone from the user's actual repo.
- WSB startup, approval interaction and correct checkout on Windows; a rejected/mismatched commit must not launch provisioning or prompt for credentials.
- Actual tool copying, npm provisioning, Ghidra doctor, MCP smoke, effective firewall and authenticated tunnel, including tunnel-hotfix behavior.
- Confirm the host source mapping is read-only, Git writes are guest-only, and the original Intel target pin is unchanged.

This package is a candidate, not a validated Windows release. Use a fresh VM, verify the clone SHA and hardening checkpoint, and close on any error. No credentials are needed to test clone failures or source approval.

## Repeatable source-only tests

    python3 tests/check_package.py
    node --check sandbox/rea-mcp-guard.js
    node --check sandbox/rea-smoke.js
    REA_GUARD_TEST=1 REA_GUARD_REA="$PWD/tests/mock-rea.js" CONTROL_PLANE_API_KEY=mock OPENAI_API_KEY=mock CLOUDFLARED_TOKEN=mock node sandbox/rea-smoke.js

The mock harness is for Linux/non-Windows test runners. No host npm installation is required.

## Repository-specific configuration update

The bundled default is `https://github.com/psuslick/REA-Sandbox.git`, branch `main`, mode `confirm-latest`. The bootstrap uses `repo.json` unless a local `repo.local.json` override exists. The source-only package check was rerun for this change. The actual remote, branch and public visibility could not be independently verified; live Windows and GitHub tests remain pending. The original Intel-only guard and all other sandbox scripts are unchanged.

## v0.12.1 shared dependency correction

The local bootstrap now reads the previously confirmed shared Git location `C:\SandboxBootstrap\git\cmd\git.exe`. No other shared dependency paths, WSB mappings, or sandbox provisioning/guard code changed. The CMD launcher checks for its sibling PowerShell bootstrap and reports the missing path explicitly. Source checks and mock tests are rerun below; live Windows validation remains pending.

## v0.12.2 automatic Git launch

Default mode is `latest`; legacy `confirm-latest` also launches without a prompt. Optional pinned mode remains. The user's live v0.12.1 output confirmed portable Git copying and GitHub cloning worked. This revision removes only the interactive approval, updates documentation and checks, and keeps the existing commit identity, tree validation, detached checkout, guest paths, WSB and provisioning/guard scripts. The source-only checks and mock MCP tests passed for v0.12.2. Windows execution of the changed bootstrap remains untested here. Automatic latest mode trusts the repository branch, including future changes.

## v0.12.3 visible copy progress

The Git copy was the only Robocopy call suppressing both filenames and progress. Removed `/NP` and `/NFL`, added `/ETA`, and added a copy start/completion message with elapsed time. The preexisting QuickEdit adjustment is also applied before Git copying, using a distinct class name to avoid collisions with the later provisioning script. All later Robocopy invocations already expose progress and remain unchanged. Added regression assertions covering all Robocopy calls and QuickEdit ordering. The source-only checks and mock MCP tests are run below; live Windows console rendering and QuickEdit behavior remain unverified. No dependency layout, repository mode, WSB, security policy or provisioning scripts changed.

## v0.12.4 scoped source inspection

- Source package static checks and all previous mock MCP policy checks passed; source scope module and all gateway JavaScript passed `node --check`. No npm commands or downloads. No inspected executable was run.
- Mock MCP end-to-end tests additionally verified directory pagination, UTF-8 source line paging, SHA-256, symlink and hardlink rejection, traversal/absolute/UNC/ADS/device-name rejection, unexpected arguments, document override rejection, malformed binary header rejection, and staged PE forwarding (synthetic fixture only).
- Existing launcher files, WSB, shared dependency paths, QuickEdit setup, copy progress, firewall helper and credential helper are unchanged. Existing Intel pin remains optional. New source module is copied to guest-local MCP directory and hash-bound to readiness before tunnel startup.
- Pending: actual Windows PowerShell and mapped-folder canonicalization/reparse behavior, real Ghidra opening of scoped binaries, authenticated tunnel exposure and client discovery of the three new source tools. The Linux mock test does not establish Windows isolation or real Ghidra behavior. No remote repository push or live permission change was performed.

## v0.12.5 full discovery and scoped invocation

- Live v0.12.4 REA `binary_session` reported all 263 upstream names; the full named inventory is recorded in CAPABILITIES.json. The updated gateway has not been deployed to that session.
- Source-only tests and mock RPC tests exercise paginated discovery of the 263 names plus 3 local tools, blocked operations still advertised, scoped PE/managed/package forwarding, retained evidence comparison, rejected arbitrary paths, and earlier regression checks. Mock provider schemas and responses are fixtures, not the actual upstream implementation.
- The release retains the same launcher, source mapping, shared dependency paths, firewall and credential helpers, Git mode and progress behavior. No npm commands, target execution, GitHub pushes or live Windows validation were performed in preparing it.
- Pending: live upstream catalog negotiation (including client limits), real parser schemas and results, Windows filesystem behavior, Ghidra analysis, and authenticated remote tool discovery. Not all static tools are enabled: unreviewed contracts fail closed.
