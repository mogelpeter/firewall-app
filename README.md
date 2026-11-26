<div align="center">

<img src="assets/icon.png" width="96" alt="Firewall Manager icon">

# Firewall Manager

**Block programs and whole folders in Windows Firewall.**

[![Release](https://img.shields.io/github/v/release/mogelpeter/firewall-app?style=flat-square&color=2b6cb0)](https://github.com/mogelpeter/firewall-app/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/mogelpeter/firewall-app/total?style=flat-square&color=2f855a)](https://github.com/mogelpeter/firewall-app/releases)
[![License: MIT](https://img.shields.io/github/license/mogelpeter/firewall-app?style=flat-square&color=718096)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-4a5568?style=flat-square)](#install)
[![Last commit](https://img.shields.io/github/last-commit/mogelpeter/firewall-app?style=flat-square&color=718096)](https://github.com/mogelpeter/firewall-app/commits/main)
[![Built with](https://img.shields.io/badge/built%20with-Rust-b7791f?style=flat-square)](#build)

[Download](https://github.com/mogelpeter/firewall-app/releases/latest) &nbsp;|&nbsp; [Install](#install) &nbsp;|&nbsp; [Features](#features) &nbsp;|&nbsp; [Build](#build)

</div>

---

A small native Windows app (Rust + egui): pick a folder or `.exe` files and it creates inbound and outbound block rules for every program.

## Install

Download `FirewallManager-Setup.exe` from the [latest release](../../releases/latest) and run it. It installs to `%ProgramFiles%\FirewallManager`, adds a Start menu entry and an uninstaller, and asks after installing whether to create a desktop shortcut.

The app asks for administrator rights once when it starts (UAC), which Windows requires to change firewall rules.

### Updates

On start the app checks the GitHub releases of this project. If a newer version exists, a banner offers **Update now**: the installer is downloaded, its SHA-256 is verified against the checksum GitHub publishes for the release asset, and it is run silently; the app restarts afterwards. Your blocked list is kept. The only network request the app makes is this check (to `api.github.com`), and nothing about you is sent.

## Features

- **Block Folder:** scans a folder and all subfolders for `.exe` files, shows how many are new and how many are already blocked, then creates an inbound and an outbound block rule per program
- **Block EXE:** the same for single or multiple `.exe` files; folders and files can also be dropped onto the window
- **Blocked Programs:** searchable list, grouped by program folder, with direction and state; select single files or whole groups, then remove selected entries, entries whose file was deleted, or everything
- No duplicate rules: the firewall is re-scanned in the background, and a program that already has a block rule (from this app, or a complete block rule from another source) gets no second one. Rules from other sources are never changed or removed
- **Settings:** optionally close to tray, so the app keeps running next to the clock; starting it again opens the running window
- Fast: talks to Windows Firewall through the COM API (`INetFwPolicy2`), no PowerShell

## Where data is kept

- The rules live in Windows Firewall itself and are named `PSFirewallBlock_<program>_<hash>_Inbound|Outbound`.
- The close-to-tray setting is stored in `%ProgramFiles%\FirewallManager\settings.txt`.
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
