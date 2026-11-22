# One-time manual host setup

This is **NOT an installer**. Review every command before using it. The main Windows host is the administrator-controlled *staging store*; startup scripts are executed **only inside the Windows Sandbox**. Windows Sandbox must be enabled through Windows Features in Windows 11 Pro.

## A. Create a public source repository

Create your own public `rea-sandbox` repository on GitHub. Use the **source-only files in this ZIP** as the initial Git commit (do not publish staged third-party binaries, target samples, private configuration, report outputs or downloaded packages). The bootstrap is a deliberately frozen, trusted host snapshot and is **not** run from the freshly cloned repo.

## B. Prepare the trusted staging tree manually

```text
C:\SandboxBootstrap\                       existing read-only host mapping root
  git\cmd\git.exe                         reuse your existing portable Git
  REA\
    BOOTSTRAP\run-bootstrap.cmd            copy manually from this repository
    BOOTSTRAP\bootstrap.ps1                copy manually from this repository
    BOOTSTRAP\rea.cmd                      copy manually from this repository
    repo-config.psd1                       private; copied from example and edited
    Tools\node\node.exe                   portable 64-bit Node.js 24.x ZIP tree
    Tools\jdk25\bin\java.exe             full x64 JDK 25 ZIP tree, includes javac.exe
    Tools\ghidra_12.2_PUBLIC\            Ghidra 12.2 ZIP tree
      support\analyzeHeadless.bat
    Tools\rea\node_modules\rea-agents\   complete REA npm package and dependencies
      scripts\rea.mjs
    Targets\                               privately staged read-only samples
      Intel_HST_...exe                     your personal original, never publish
```

Use existing `C:\SandboxBootstrap\git` if it works in your other Sandbox app. Download and inspect third-party dependencies manually from the publishers listed below; verify SHA-256 hashes against publisher release manifests when available. *Do not* rename extracted internal Ghidra folders inconsistently with their actual version. If upgrading REA, reconfirm provider compatibility first.

- REA canonical: https://github.com/morluto/rea (npm package **rea-agents**, not similarly named third-party repos)
- Ghidra official release: https://github.com/NationalSecurityAgency/ghidra/releases
- JDK: https://adoptium.net/temurin/releases/?version=25
- Node.js official: https://nodejs.org/en/download
- Portable Git (if needed): https://git-scm.com/downloads/win

REA 12.2 Ghidra requires full JDK 25. Node 24.x is the upstream project's current `.nvmrc` family. REA's Windows Ghidra provider is experimental and needs its **complete installed npm dependencies and native Windows support**. Simply extracting the top-level REA tarball will usually not be enough.

### REA package: one-time controlled provisioning, not a startup installer

Stage an installed **Windows x64** `rea-agents` npm package tree into `Tools\rea` using a deliberately selected, reviewed environment. One-time setup with npm might run third-party install-time code, so do **not** run it automatically on your main Windows machine if that conflicts with your threat model; use a separate temporary provisioning VM/Sandbox and manually transfer the prepared directory after review. If you deliberately use npm on the host, confine it to the specified `Tools\rea` prefix and review the package scripts first. This project intentionally provides **no automatic npm install, curl or bootstrap dependency installation commands**.

## C. Configure repository reference privately

Copy `config/repo-config.psd1.example` into `C:\SandboxBootstrap\REA\repo-config.psd1` and change `YOURNAME` to the owner of your actually published public repository. Keep the data-only `.psd1` *outside Git*. Default `Ref = 'main'`. Startup fails rather than pulling an unconfigured repository.

Copy your Intel HST executable **only** to `C:\SandboxBootstrap\REA\Targets`. Only this user-supplied private staging area contains it. For review, get its original SHA-256 separately and compare with the copied guest file.

## D. Launch

Keep the actual `.wsb` on the host; double-click `LAUNCHER\REA-Sandbox.wsb`. It maps one host folder (`C:\SandboxBootstrap`) with `<ReadOnly>true</ReadOnly>`, launches trusted `run-bootstrap.cmd`, performs restricted Git clone and disables guest outbound networking, then copies the target inside the VM (without running it).

A full successful run displays five numbered stages. No additional host-side scripts/services/port forwarding are required.

## E. Important constraints

- REA inside Sandbox does **not** use physical host Intel CPU/motherboard identifiers. This environment is for static analysis, not real device eligibility testing.
- Startup must **not** execute a cloned script; clone is only for source content and investigation notes.
- Clipboard is enabled for deliberate manual export. It is a bidirectional exposure; never copy tokens/secrets or confidential data unintentionally.
- Windows Firewall block after Git clone is not equivalent to `Networking=Disable` from power-on; the short Git-clone phase has networking, including the Sandbox NAT gateway. See `SECURITY.md`.
