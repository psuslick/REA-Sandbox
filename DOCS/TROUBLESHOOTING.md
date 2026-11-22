# First failure diagnostics (one step at a time)

1. If `Windows Sandbox` isn't available, enable the Windows feature, restart, and confirm CPU virtualization is enabled.
2. If `[1/5]` fails, read the exact missing-file path: it identifies which tool has not been staged in the expected layout.
3. If `[2/5]` fails, copy only the firewall error text (without personal identifiers).
4. If Git clone fails at `[3/5]`, confirm your public GitHub repo exists, `repo-config.psd1` points to it, and the declared `main` branch has commits. A failed clone locks down network anyway.
5. If `[4/5]` fails, do not proceed with private samples; close Sandbox and review privilege/security policy.
6. If REA `doctor` fails after Ready, confirm the actual Ghidra `application.version`, JDK `java -version` and `javac -version`, Node version, and the complete installed REA npm tree before changing anything.
7. If Ghidra rejects a PE executable, retain error text and the *tool versions* but avoid sharing private sample paths, identifiers, or raw runtime dumps.

Official references:
- https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
- https://github.com/morluto/rea/blob/main/docs/getting-started/installation.md
- https://github.com/morluto/rea/blob/main/docs/getting-started/cli.md
