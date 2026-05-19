# Firewall Manager — Electron App Design

**Date:** 2026-05-19  
**Status:** Approved  
**Source:** Rewrite of `firewall_manager.ps1` as a desktop GUI application

---

## Overview

A minimal Electron desktop app that replaces the PowerShell firewall manager script. Users can block `.exe` files' network access via Windows Firewall, view created rules, and remove them. All firewall operations are executed by spawning PowerShell child processes from the Electron main process.

---

## Architecture

```
firewall-app/
├── main.js          ← Electron main process, IPC handlers, PowerShell bridge
├── preload.js       ← contextBridge exposes safe IPC API to renderer
├── package.json     ← Electron dep, start/build scripts
└── renderer/
    ├── index.html   ← single page shell, sidebar + content area
    ├── app.js       ← view switching, IPC calls, DOM updates
    └── styles.css   ← dark utility theme
```

**Constraints:**
- No bundler (Vite/webpack) — plain Electron
- No frontend framework — vanilla JS/HTML/CSS
- `contextIsolation: true`, `nodeIntegration: false` — renderer talks to main only via contextBridge
- Windows 11 target

---

## Admin Elevation

- On startup, main process checks if running as administrator (via `net session` or `whoami /groups` PowerShell call)
- If not elevated: show a dialog — "This app requires administrator privileges. Please run as administrator." — then quit
- When packaged with electron-builder, embed an `app.manifest` requesting `requireAdministrator` so UAC fires automatically on launch

---

## IPC Bridge

`preload.js` exposes a `window.fw` API via `contextBridge.exposeInMainWorld`.

### Channels

| Renderer calls | Main does | Returns |
|---|---|---|
| `fw.pickFolder()` | `dialog.showOpenDialog({ properties: ['openDirectory'] })` | `string \| null` — selected path |
| `fw.pickExe()` | `dialog.showOpenDialog({ filters: [{ name: 'Executables', extensions: ['exe'] }] })` | `string \| null` — selected file path |
| `fw.blockFolder(path)` | Runs PS: find all `.exe` files recursively, create inbound+outbound rule per exe | `{ blocked: number, errors: string[] }` |
| `fw.blockExe(path)` | Runs PS: create inbound+outbound rule for one exe | `{ success: boolean, error?: string }` |
| `fw.listRules()` | Runs PS: get all `PSFirewallBlock_*` rules, group by program path | `RuleGroup[]` |
| `fw.removeRules(paths)` | Runs PS: remove all rules for each path in array | `{ removed: number, errors: string[] }` |
| `fw.removeAllRules()` | Runs PS: remove all `PSFirewallBlock_*` rules | `{ removed: number, errors: string[] }` |

### RuleGroup type
```
{
  programPath: string,
  programName: string,    // basename of path
  inbound: boolean,
  outbound: boolean,
  enabled: boolean
}
```

### PowerShell execution pattern
Main process uses `child_process.spawn('powershell.exe', ['-NoProfile', '-Command', cmd])` for each operation. Output is collected from stdout, errors from stderr. Commands are constructed as safe string literals — no user input interpolated directly into PS strings (paths are passed via `-LiteralPath` or escaped).

**Rule naming:** `PSFirewallBlock_<basename>_Inbound` and `PSFirewallBlock_<basename>_Outbound` — identical to the original script.

---

## UI

### Layout

```
┌─────────────────────────────────────────────────┐
│  FIREWALL MANAGER                      [─][□][×] │
├───────────────┬─────────────────────────────────┤
│               │                                 │
│  Block Folder │         Content Area            │
│  Block EXE    │                                 │
│  View Rules   │                                 │
│  Remove Rules │                                 │
│               │                                 │
└───────────────┴─────────────────────────────────┘
```

- Fixed-width left sidebar (180px), content area fills remainder
- Active nav item highlighted
- Window size: 900×600, not resizable (utility app, fixed layout is fine)

### Theme
Dark utility — no gradients, no animations.
- Background: `#141414`
- Sidebar: `#1c1c1c`
- Accent: `#6c63ff` (buttons, active nav)
- Text: `#e0e0e0`
- Danger: `#e05555` (remove actions)
- Success: `#4caf50` (status badges)
- Font: system-ui

### Views

**Block Folder**
1. "Browse Folder" button → opens native folder picker
2. Selected path displayed
3. "Scan" button → shows count of `.exe` files found
4. "Block All (N files)" confirm button
5. Progress: inline status messages per file (scrollable log area)
6. Summary on completion: X blocked, Y errors

**Block EXE**
1. "Browse EXE" button → opens native file picker filtered to `.exe`
2. Selected file path displayed
3. "Block" button
4. Inline result: success or error message

**View Rules**
- Table: Program Name | Full Path | Inbound | Outbound | Status
- Status badge: Active / Inactive
- "Refresh" button
- Empty state: "No rules created by this tool."

**Remove Rules**
- Same list as View Rules but with checkboxes per row
- "Remove Selected" button (disabled when nothing checked)
- "Remove All" button (red, triggers confirmation dialog)
- Confirmation: native `dialog.showMessageBox` before destructive actions

---

## Error Handling

- PowerShell spawn failures surface as error messages inline in the relevant view — no unhandled crashes
- Invalid/nonexistent paths: PowerShell returns an error which main process serializes and sends back to renderer for display — no extra IPC channel needed
- All PS operations wrapped in try/catch in main process; errors serialized and returned to renderer

---

## Packaging (post-scope, noted for reference)

- electron-builder with `win` target, embedded manifest for admin elevation
- Single NSIS installer or portable `.exe`
- Not in scope for initial implementation — `npm start` is sufficient

---

## Out of Scope

- Rule toggling (enable/disable without removing)
- Scheduling or automated blocking
- Non-Windows platforms
- Auto-updates
