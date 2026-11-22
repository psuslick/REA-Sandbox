# Test results — v0.1

- Project generated as plain text only; **no binaries or private samples included**.
- Checked Windows Sandbox `.wsb` as well-formed XML with one read-only mapped folder.
- Checked `BOOTSTRAP/` trusted script references match the intended host staging paths.
- Verified the zip has no `.exe`, `.dll`, `.msi`, packages or user Intel HST file.
- **NOT tested:** real Windows Sandbox startup, firewall cmdlets, local Git cloning, pre-staged REA npm package, or Ghidra analysis. Windows REA support is experimental; runtime validation is required.
