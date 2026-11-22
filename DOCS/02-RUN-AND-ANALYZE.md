# Running the guest and collecting results

Launch `REA-Sandbox.wsb` from the host. The `cmd` window should display `[1/5]` through `[5/5]`, then remain interactive in `C:\App`.

## Verify everything manually

```cmd
node --version
java -version
rea --help
rea doctor --provider ghidra --json
rea providers --json
```

There are no automatic REA analysis queries. The scanner is **not executed**.

## Static inspection example

After the scanner has been copied to `C:\App\Targets` (its name will be printed by bootstrap), type:

```cmd
rea analyze "C:\App\Targets\YOUR_ACTUAL_FILENAME.exe" --provider ghidra --json
```

Use `rea search ... --provider ghidra --json` to find functions and `rea function ...` or `rea decompile ...` once REA shows supported selectors; confirm syntax using `rea --help`. The first Ghidra import can take longer. Read-only analysis does not execute the target.

For durable observations, generate short results and **manually copy selected non-sensitive text through clipboard** into a host-local notebook. Do not enable a writable host mapping to export results; avoid copying raw system identifiers or account data. All guest files disappear on Sandbox close.

This workflow cannot determine Intel's private backend deduplication rules on its own. It must not be used to modify identifiers or intercept live redemption traffic.

## Updates

- Public project source: review, commit/push, relaunch guest to clone new `main`.
- Trusted bootstrap: after code review, manually replace the three files in host `C:\SandboxBootstrap\REA\BOOTSTRAP`.
- Toolchain: manually update in private staging when versions are compatible; update expected paths in both trusted `run-bootstrap.cmd` and `bootstrap.ps1` if needed.
