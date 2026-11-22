# REA Windows Sandbox — source-only bootstrap (v0.1)

A Git-ready project modeled on the existing HereSphere/video-link Windows Sandbox design.

**Trust model:** one read-only host share at `C:\SandboxBootstrap`, a manually reviewed trusted bootstrap snapshot, pre-staged portable tools, a fresh public Git clone to writable `C:\App`, a disposable session, no host writes from Sandbox, no automatic dependency installs, no automatic execution of any target binary.

This repository contains **no Intel scanner executable**, account credentials, private analysis files, third-party executables, npm packages or binaries. Copy your analysis target to the *private host folder*, never to this repository.

## Repo layout

```text
BOOTSTRAP/
  run-bootstrap.cmd         Trusted entrypoint copied to host manually
  bootstrap.ps1            Preflight, LAN guard, public Git clone, outbound lockdown, target staging
  rea.cmd                  Short REA CLI wrapper
LAUNCHER/
  REA-Sandbox.wsb          Windows Sandbox configuration, one read-only mapping
config/
  repo-config.psd1.example Local-only Git source configuration template
DOCS/
  01-HOST-SETUP.md         One-time manual staging and deployment
  02-RUN-AND-ANALYZE.md    Start, inspect, copy selected results
  SECURITY.md             Threat model, limits and network behavior
  TROUBLESHOOTING.md      Single-step diagnostics
.gitignore
```

## The exact startup sequence

1. Double-click `LAUNCHER/REA-Sandbox.wsb` (after placing it at any location on host).
2. Windows maps **only** `C:\SandboxBootstrap` as read-only and invokes its **trusted local copy** of `BOOTSTRAP/run-bootstrap.cmd`.
3. The trusted script verifies Git/Node/Java/Ghidra/REA and applies a local-network guard **before** the networked Git operation.
4. It clones the public Git repository configured in private `repo-config.psd1` into the writable, ephemeral `C:\App` directory (never syncs the repo back to host).
5. In a `finally` block, Windows Sandbox outbound firewall policy is set to **Block** across profiles. Then pre-staged target EXEs are copied to `C:\App\Targets` *without execution*, and a guest shell is provided.

**Nothing is downloaded or installed by bootstrap except the requested public Git source clone.** REA, Ghidra, Java, Node and Git are staged once by the user.

## Read first

See [DOCS/01-HOST-SETUP.md](DOCS/01-HOST-SETUP.md) for exact manual setup and source publishing. The scripts are intentionally short and reviewable: do not use the older auto-installer kit.

### Compatibility notes (verified 2026-11-21)

- Official REA: https://github.com/morluto/rea
- Current REA Ghidra provider accepts **Ghidra >=12.2** and matching full JDK; **Ghidra 12.2 needs JDK 25**. Earlier 12.1.x advice is obsolete for current REA.
- Windows x64 Ghidra provider remains **experimental**. A working static Python/Go inspection does not imply REA native addon succeeds in Windows Sandbox.
- For a first CLI test, use `rea doctor --provider ghidra --json` after the guest starts. Only then run `rea analyze ... --provider ghidra --json`.
- A successful local analysis cannot establish private Intel backend redemption rules. This project does not intercept Intel services or alter identity markers.

## Changes and updates

**App/source changes**: review and commit changes, push public repo, restart `.wsb`; next startup clones the current ref. **Bootstrap/security changes**: consciously review and copy the new `BOOTSTRAP/` snapshot to host. **Third-party tool changes**: manually stage and verify new versions outside the bootstrap; do not auto-update inside the Sandbox.

## State

Created as a source-only prototype; **not executed on a Windows Sandbox instance**. File layout and XML have been statically checked. Validate your local tool layout before attempting first launch.
