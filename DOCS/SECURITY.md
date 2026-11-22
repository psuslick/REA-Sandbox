# Security architecture and limitations

## Preserved invariants

- `C:\SandboxBootstrap` is the **only** host mapped folder, and it is read-only to Windows Sandbox.
- Private target files and `repo-config.psd1` never belong in public Git.
- Portable programs, Ghidra and REA are staged manually and never auto-updated on launch.
- Public repo is cloned into a fresh writable `C:\App`; no fresh-cloned code is auto-executed.
- No host services, port forwarding, mapped writable outputs, or code execution outside Windows Sandbox.
- Intel HST is only copied/hashes; **the bootstrap never runs it**.
- At end of cloning (even on error), the trusted script sets all Windows Sandbox firewall profiles to **DefaultOutboundAction Block**.

## Important limitation during Git clone

The `.wsb` config has `<Networking>Enable</Networking>` solely so the guest can clone your public repo at startup, mirroring the previous video-link architecture. Before that clone, guest firewall blocks outbound connections to 10.0.0.0/8 and 192.168.0.0/16 and 169.254.0.0/16. Those blocks are **not a complete LAN/network isolation guarantee**: the 172.16.0.0/12 range may include the Sandbox NAT gateway/DNS and is intentionally not blocked before the clone. Other network destinations are not allowlisted by hostname. Do not use this as a malware dynamic-analysis containment design or for secrets.

The script verifies the guest firewall profile is enabled with outbound default Block before copying target files into `C:\App\Targets`. That is a best-effort guest firewall control, not a hypervisor egress policy. For *strict no-network-at-all isolation*, use a separately reviewed WSB with `<Networking>Disable</Networking>` and manually stage a source snapshot, foregoing startup Git clone.

## Clipboard and ProtectedClient

`<ProtectedClient>Enable</ProtectedClient>` adds RDP-session protections. `<ClipboardRedirection>Enable</ClipboardRedirection>` provides a deliberate user-controlled manual export path, and therefore breaks a strict one-way data boundary. Copy only results you intend to retain.

## Windows x64 experimental status

REA's Ghidra bridge is experimental on Windows. Official docs currently require Ghidra >=12.2 and matching full JDK; Ghidra 12.1 is rejected. Windows native packaging is required. This source-only project was not run on a Windows host.

## Research boundaries

Use static analysis on binaries you're authorized to inspect. Do not submit altered identifiers or falsified hardware claims to third-party services. The goal is understanding client-side data flow; backend enforcement remains a separate unknown.
