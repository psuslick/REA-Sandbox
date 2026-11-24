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

- PowerShell 5.1 parsing and execution of the new bootstrap; MinGit staging and GitHub HTTPS clone from the user's actual repo.
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
