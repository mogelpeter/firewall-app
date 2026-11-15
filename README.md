<p align="center"><img src="assets/icon.png" width="96" alt="Firewall Manager icon"></p>

# Firewall Manager

A small native Windows app (Rust + egui) to block programs in Windows Firewall: pick a folder or `.exe` files and it creates inbound and outbound block rules for every program.

## Install

Download `FirewallManager-Setup.exe` from the [latest release](../../releases/latest) and run it. It installs to `%ProgramFiles%\FirewallManager`, adds a Start menu entry and an uninstaller, and asks after installing whether to create a desktop shortcut.

The app asks for administrator rights once when it starts (UAC), which Windows requires to change firewall rules.

### Updates

On start the app checks the GitHub releases of this project. If a newer version exists, a banner offers **Update now**: the installer is downloaded, its SHA-256 is verified against the checksum GitHub publishes for the release asset, and it is run silently; the app restarts afterwards. Your blocked list is kept. The only network request the app makes is this check (to `api.github.com`), and nothing about you is sent.

## Features

- **Block Folder:** scans a folder and all subfolders for `.exe` files, shows how many are new and how many are already blocked, then creates an inbound and an outbound block rule per program
- **Block EXE:** the same for single or multiple `.exe` files; folders and files can also be dropped onto the window
- **Blocked Programs:** one searchable list with direction and state; remove selected entries, entries whose file was deleted, or everything
- Blocking is idempotent: re-blocking a folder never creates duplicate rules
- Fast: talks to Windows Firewall through the COM API (`INetFwPolicy2`), no PowerShell

## Where data is kept

- The rules live in Windows Firewall itself and are named `PSFirewallBlock_<program>_<hash>_Inbound|Outbound`.
- Every blocked program is also remembered in `%ProgramFiles%\FirewallManager\blocked.txt` (plus a `blocked.bak` copy). Only administrators can change that folder, and updates and the uninstaller leave the list alone. If rules ever disappear from the firewall, the list shows them as "Not in firewall" and **Restore missing rules** re-creates them. Removing an entry in the app also forgets it.
- To remove everything: remove all rules in the app, uninstall, then delete `%ProgramFiles%\FirewallManager`.

## Build

Needs the Rust toolchain (MSVC) on Windows, and [Inno Setup 6](https://jrsoftware.org/isinfo.php) for the installer.

```
cargo build --release                                   # target\release\firewall-manager.exe
cargo test                                              # unit tests
cargo test -- --ignored                                 # firewall round trip, needs an elevated shell
ISCC /DAppVersion=<version> installer\FirewallManager.iss   # target\installer\FirewallManager-Setup.exe
```

`assets/make_icon.py` regenerates the icon (needs Pillow). The UI font is JetBrains Mono (SIL Open Font License, `assets/fonts/LICENSE-JetBrainsMono.txt`). Releases must contain an asset named `FirewallManager-Setup.exe`, which is what the updater looks for.

## License

[MIT](LICENSE)
