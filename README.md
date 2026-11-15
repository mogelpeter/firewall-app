<p align="center"><img src="assets/icon.png" width="96" alt="Firewall Manager icon"></p>

# Firewall Manager

A small native Windows app (Rust + egui) to block programs in Windows Firewall: pick a folder or `.exe` files and it creates inbound and outbound block rules for every program.

> **Portable program.** There is no installer: download `FirewallManager.exe` from the [latest release](../../releases/latest) and run it from anywhere. It asks for administrator rights once at start (UAC), which Windows requires to change firewall rules.

## Features

- Block every `.exe` in a folder (recursive) after a preview that shows how many are new and how many are already blocked
- Block single or multiple `.exe` files; drag and drop folders or files onto the window
- One searchable list of everything blocked, with inbound / outbound / active state; remove selected, only entries whose file no longer exists, or everything
- Blocking is idempotent: re-blocking a folder never creates duplicate rules
- Fast: uses the Windows Firewall COM API (`INetFwPolicy2`) directly, no PowerShell; listing takes milliseconds

## Where data is kept

- The rules live in Windows Firewall itself and are named `PSFirewallBlock_<program>_<hash>_Inbound|Outbound`.
- Every blocked program is also remembered in `%ProgramFiles%\FirewallManager\blocked.txt` (plus a `blocked.bak` copy). That folder is only writable by administrators, so it is not removed or changed by accident, and it survives updates of the portable exe. If rules ever disappear from the firewall, the list shows them as "Not in firewall" and **Restore missing rules** re-creates them. Removing an entry in the app also forgets it.
- To uninstall completely: remove all rules in the app, then delete `%ProgramFiles%\FirewallManager`.

## Build

Needs the Rust toolchain (MSVC) on Windows.

```
cargo build --release          # target\release\firewall-manager.exe
cargo test                     # unit tests
cargo test -- --ignored        # firewall round trip, needs an elevated shell
```

`assets/make_icon.py` regenerates the icon (needs Pillow).

## License

[MIT](LICENSE)
