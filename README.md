# REA MCP Windows Sandbox

**v0.12.4 — Scoped source inspection.** This is a disposable, static-analysis-focused REA/Ghidra environment, not an air gap or a malware detonation platform. The existing launcher and shared dependency cache are unchanged. New read-only source access is limited to `C:\SandboxBootstrap\reaSourceInspection`; the legacy Intel sample is optional and retains its SHA-256 pin.

## One-time migration

1. Review this source tree and commit its contents to the root of your existing public launcher repository (not either Galactic Racer repository). Do not commit the old flat package, Intel binary, vendor tools, credentials, or diagnostics. The `.gitignore` is defense in depth, not secret scanning; it does not untrack already committed files.
2. Keep the existing `C:\SandboxBootstrap` tool cache. From this source tree, copy the **launcher** directory into `C:\SandboxBootstrap\launcher`. This is the small, locally trusted launch anchor, not a second working copy of the application. The WSB maps the same read-only host root and separate writable `REA-Exchange` directory as before. Create `REA-Exchange` if missing. Do not put private files in either mapping.
3. The launcher is preconfigured for `https://github.com/psuslick/REA-Sandbox.git`, branch `main`, in `latest` mode. No local JSON file is required. The guest automatically clones and runs the branch tip without a commit approval prompt. Legacy `confirm-latest` settings behave identically. For optional pinned mode, copy `launcher\repo.json` to `C:\SandboxBootstrap\launcher\repo.local.json`, set `mode` to `pinned`, and set `commit` to the exact reviewed 40-character lowercase commit SHA. A local override takes precedence over the bundled default. Use pinned mode for repeatable validated runs. A Git commit is an identity, not proof of trust.
4. Reuse the existing portable Git installation at `C:\SandboxBootstrap\git\cmd\git.exe`. Do not download MinGit, move, rename, or replace any shared dependency. The bootstrap copies the existing `git` directory into disposable `C:\App\tools\git` before invoking Git. Git copying displays file names, per-file progress and ETA, plus a completion time. Console QuickEdit is disabled on a best-effort basis before the first copy. The existing Node, Java and Ghidra copy progress remains enabled. All Git writes and npm operations remain guest-local.
5. Double-click `C:\SandboxBootstrap\launcher\REA-MCP.wsb`. Do not run the guest scripts on the host. The guest clones into `C:\App\repo`, checks the selected commit, checks out detached HEAD, and starts the repository's `sandbox\Start-REA-Quick.ps1`. The protocol argument `git-v1` stays stable across compatible application releases. No source ZIP extraction or script replacement is necessary for future compatible repo updates.
6. After the hardening checkpoint, enter your existing REA-VM tunnel ID and restricted runtime API key in the local masked dialog. Never commit or send either credential to an assistant. An optional non-secret `rea-vm-tunnel-id.txt` in the read-only local cache can prefill the ID; keep it out of Git.

## Subsequent launches

Commit and push reviewed changes to the configured branch. Close the old VM and reopen the same WSB. `latest` fetches and runs the branch tip automatically; `pinned` runs exactly the configured commit (edit the local pin only when deliberately promoting a new revision). A fresh clone occurs on each launch; no guest Git checkout survives closure. Changing the trust anchor or bootstrap protocol itself still requires a deliberate one-time local replacement of the launcher files. Never point this launcher at untrusted code you want to audit.

## Layout

- `launcher/`: stable local WSB, CMD, Git bootstrap and default repository configuration.
- `sandbox/`: versioned provisioning, firewall checks, credential dialog, tunnel startup, MCP guard and smoke test.
- `tests/`: static package checks, mock MCP fixture and historical validation record.
- `.github/workflows/`: source-only static checks on a GitHub-hosted Linux runner; no npm install, sample execution or Windows deployment.

## Required existing local tools and analysis input

Retain the existing `git`, `node-v24.22.3-win-x64`, `jdk25`, `ghidra_12.2_PUBLIC` directories and official tunnel-client Windows AMD64 archive (v0.0.21 was used in the earlier workflow; verify official release provenance independently). Optionally retain the Intel file `Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe` in the read-only host root. Expected SHA-256: `dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b`. The binary is deliberately **not** included in or published to this repository. The Intel sample is no longer required to start REA. Source archives must be extracted by the operator into the designated inspection directory; the gateway does not unpack or execute archives.

## Inspect a repository (existing launcher users)

1. On the host, create `C:\SandboxBootstrap\reaSourceInspection` and place the extracted public repository folders inside it. Do not put credentials, personal files, or private repositories there. No other shared directory moves, downloads, or launcher updates are required.
2. Commit this version to the existing `psuslick/REA-Sandbox` infrastructure repository; do not commit inspection inputs. Close the old Sandbox and reopen the existing WSB. The normal noninteractive latest-mode clone, visible copy progress, dependency paths, credentials, and firewall remain unchanged.
3. Enter the existing tunnel credentials in the local dialog. The smoke test verifies the new source tools and denies outside paths before accepting credentials. Refresh the MCP tool registration if the client continues to show only the old tool list.

| Tool | Example arguments |
|---|---|
| `list_source_files` | `{"path":"","offset":0,"limit":100}` |
| `read_source_file` | `{"path":"repo/main.go","start_line":1,"line_count":100}` |
| `hash_source_file` | `{"path":"repo/main.go"}` |
| `open_binary` | `{"path":"repo/build/app.exe","provider_id":"ghidra"}` |

Paths use names relative to `reaSourceInspection`. Directory entries are paginated, UTF-8 source text is returned with line ranges and hashes, and binaries are copied into a fresh guest-local directory under `C:\App\source-samples` before Ghidra opens them. No file writing, arbitrary file access, source execution, shell, network download, archive extraction, alternate provider, or document-path override is exposed. Absolute paths, traversal, device names, ADS, symbolic links, detected redirections and detected hardlinks are rejected. Legacy Intel analysis still works through the existing pin when present. Limits: 20,000 entries per directory, 200 entries per page, 2 MiB source text, 400 lines/64 KB per response, 128 MiB per binary or hashed file, 64 binary stages/1 GiB per gateway process. Files are live reads of the mapped host directory, not a filesystem snapshot: do not change the inspection tree during analysis. Canonical paths and file identities are checked, but mapped-filesystem reparse behavior and concurrent modifications are not a proven security boundary. Real Windows behavior remains to be validated. The wider WSB mapping is still guest-readable as before; the scope is enforced by the MCP gateway, not a new host filesystem ACL.

## Security boundaries

Git clone is a new provisioning-time network operation, before the existing guest firewall lockdown. Public source is not inherently trustworthy. Only clone this trusted infrastructure repo. Automatic latest mode trusts every new commit to the configured branch; a compromised repository could execute untrusted launcher code before guest firewall lockdown. Optional pinned mode remains available. Git uses HTTPS with certificate checking, no credential helper, no submodule recursion, no checkout until commit resolution and tree validation, no hooks and no system/global configuration. Symlink and submodule entries are rejected. The clone is disposable and not mapped to the host. No Git or npm network permissions are added to the post-provision firewall. The existing REA 6.10.1 pin, scoped doctor, MCP smoke, optional legacy SHA-256 pin and scoped binary staging, effective firewall check, guest-only npm, and local credential flow are retained. The prior tunnel command hotfix (forward slashes) is included.

The source root is read-only from the guest, not unreadable. Clipboard sharing is enabled as before for credentials; avoid unrelated clipboard secrets and disable sharing after use if supported. The diagnostic exchange is writable by the guest; its contents are untrusted. The guest firewall is not host-enforced. Neither the guard nor a Git pin is a guarantee against malicious code or VM escape. No target execution is intended. Do not put any unrelated data in the mapped root. If provisioning fails, close the VM and start a fresh one. No credentials should be entered after failure.

## Tests and diagnostics

See `VALIDATION.md`. Git failures appear in the guest console; provisioning logs are in `C:\SandboxBootstrap\REA-Exchange\bootstrap.log` once provisioning starts. The log records the selected Git commit and the guest readiness record binds the tunnel startup to it. The tunnel status file contains no credentials. No real Windows Sandbox, firewall or tunnel execution was performed in the build environment for this revision.
