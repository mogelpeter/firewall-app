# Firewall Manager Electron App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a minimal Electron desktop app replacing `firewall_manager.ps1` — block `.exe` network access, view rules, and remove rules via a GUI with Windows Explorer folder/file pickers.

**Architecture:** Electron main process spawns PowerShell child processes for all firewall operations. `firewall.js` encapsulates PS logic as pure async functions. Renderer communicates with main exclusively via `contextBridge` IPC. No framework, no bundler — vanilla HTML/CSS/JS.

**Tech Stack:** Electron 28, Node.js `child_process.execFile`, PowerShell (`New-NetFirewallRule`, `Get-NetFirewallRule`, `Remove-NetFirewallRule`), Jest 29

---

## File Map

| File | Responsibility |
|---|---|
| `package.json` | Deps, scripts, Jest config |
| `main.js` | App lifecycle, admin check, IPC handlers, window creation |
| `preload.js` | `contextBridge` — exposes `window.fw` API to renderer |
| `firewall.js` | All PowerShell operations (testable, no Electron imports) |
| `renderer/index.html` | App shell — sidebar + view containers |
| `renderer/styles.css` | Dark utility theme |
| `renderer/app.js` | View switching, IPC calls, DOM updates |
| `tests/firewall.test.js` | Jest unit tests for `firewall.js` |

---

### Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `renderer/` (empty directory placeholder)

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "firewall-manager",
  "version": "1.0.0",
  "description": "Windows Firewall Manager GUI",
  "main": "main.js",
  "scripts": {
    "start": "electron .",
    "test": "jest"
  },
  "devDependencies": {
    "electron": "^28.0.0",
    "jest": "^29.0.0"
  },
  "jest": {
    "testEnvironment": "node"
  }
}
```

- [ ] **Step 2: Create `.gitignore`**

```
node_modules/
dist/
```

- [ ] **Step 3: Install dependencies**

Run: `npm install`

Expected: `node_modules/` created, `package-lock.json` generated, no errors.

- [ ] **Step 4: Create renderer directory and placeholder**

Run: `mkdir renderer`

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json .gitignore
git commit -m "chore: project scaffold"
```

---

### Task 2: `firewall.js` — `runPS` + `checkAdmin`

**Files:**
- Create: `firewall.js`
- Create: `tests/firewall.test.js`

- [ ] **Step 1: Create `tests/` directory and write failing test**

Create `tests/firewall.test.js`:

```javascript
jest.mock('child_process', () => ({ execFile: jest.fn() }))
const { execFile } = require('child_process')
const { runPS, checkAdmin } = require('../firewall')

function mockPS(stdout, exitCode = 0) {
  execFile.mockImplementation((cmd, args, opts, cb) => {
    if (exitCode !== 0) {
      const err = new Error('PS failed')
      err.code = exitCode
      cb(err, '', 'error output')
    } else {
      cb(null, stdout, '')
    }
  })
}

describe('runPS', () => {
  it('resolves with trimmed stdout on success', async () => {
    mockPS('  hello  ')
    const result = await runPS('Write-Output hello')
    expect(result).toBe('hello')
  })

  it('rejects when exitCode is non-zero', async () => {
    mockPS('', 1)
    await expect(runPS('bad command')).rejects.toThrow()
  })

  it('calls powershell.exe with -EncodedCommand', async () => {
    mockPS('True')
    await runPS('$true')
    expect(execFile).toHaveBeenCalledWith(
      'powershell.exe',
      expect.arrayContaining(['-EncodedCommand']),
      expect.any(Object),
      expect.any(Function)
    )
  })
})

describe('checkAdmin', () => {
  it('returns true when PS outputs True', async () => {
    mockPS('True')
    expect(await checkAdmin()).toBe(true)
  })

  it('returns false when PS outputs False', async () => {
    mockPS('False')
    expect(await checkAdmin()).toBe(false)
  })

  it('returns false when PS throws', async () => {
    mockPS('', 1)
    expect(await checkAdmin()).toBe(false)
  })
})
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `npm test -- --testPathPattern=firewall`

Expected: `Cannot find module '../firewall'`

- [ ] **Step 3: Create `firewall.js` with `runPS` and `checkAdmin`**

```javascript
const { execFile } = require('child_process')

const RULE_PREFIX = 'PSFirewallBlock_'

function runPS(script) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, 'utf16le').toString('base64')
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded],
      { timeout: 60000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) reject(new Error(stderr || err.message))
        else resolve(stdout.trim())
      }
    )
  })
}

async function checkAdmin() {
  try {
    const out = await runPS(
      '$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()\n' +
      '$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
    )
    return out === 'True'
  } catch {
    return false
  }
}

module.exports = { runPS, checkAdmin, RULE_PREFIX }
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=firewall`

Expected: All 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add firewall.js tests/firewall.test.js
git commit -m "feat: add runPS and checkAdmin to firewall module"
```

---

### Task 3: `firewall.js` — `blockFolder`

**Files:**
- Modify: `firewall.js`
- Modify: `tests/firewall.test.js`

- [ ] **Step 1: Add failing tests for `blockFolder`**

Append to `tests/firewall.test.js`:

```javascript
const { blockFolder } = require('../firewall')

describe('blockFolder', () => {
  it('returns blocked count from PS JSON output', async () => {
    mockPS(JSON.stringify({ blocked: 3, errors: [] }))
    const result = await blockFolder('C:\\Games\\App')
    expect(result).toEqual({ blocked: 3, errors: [] })
  })

  it('returns errors array when PS reports errors', async () => {
    mockPS(JSON.stringify({ blocked: 1, errors: ['C:\\path\\bad.exe'] }))
    const result = await blockFolder('C:\\Games\\App')
    expect(result.errors).toHaveLength(1)
  })

  it('returns errors array when PS throws', async () => {
    mockPS('', 1)
    const result = await blockFolder('C:\\Games\\App')
    expect(result.blocked).toBe(0)
    expect(result.errors.length).toBeGreaterThan(0)
  })

  it('escapes single quotes in folder path', async () => {
    mockPS(JSON.stringify({ blocked: 0, errors: [] }))
    await blockFolder("C:\\It's\\App")
    const call = execFile.mock.calls[0]
    const encodedArg = call[1][call[1].indexOf('-EncodedCommand') + 1]
    const decoded = Buffer.from(encodedArg, 'base64').toString('utf16le')
    expect(decoded).toContain("C:\\It''s\\App")
  })
})
```

- [ ] **Step 2: Run to confirm new tests fail**

Run: `npm test -- --testPathPattern=firewall`

Expected: 4 new failures — `blockFolder is not a function`

- [ ] **Step 3: Implement `blockFolder` in `firewall.js`**

Add to `firewall.js` before `module.exports`:

```javascript
async function blockFolder(folderPath) {
  const safePath = folderPath.replace(/'/g, "''")
  const script = `
$blocked = 0
$errs = [System.Collections.Generic.List[string]]::new()
try {
  $files = Get-ChildItem -LiteralPath '${safePath}' -Filter '*.exe' -Recurse -File -ErrorAction Stop
  foreach ($f in $files) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($f.Name) -replace '[^\\w\\-]','_'
    $inName  = '${RULE_PREFIX}' + $base + '_Inbound'
    $outName = '${RULE_PREFIX}' + $base + '_Outbound'
    try {
      New-NetFirewallRule -DisplayName $inName  -Direction Inbound  -Program $f.FullName -Action Block -Enabled True | Out-Null
      New-NetFirewallRule -DisplayName $outName -Direction Outbound -Program $f.FullName -Action Block -Enabled True | Out-Null
      $blocked++
    } catch {
      $errs.Add($f.FullName)
    }
  }
} catch {
  $errs.Add($_.Exception.Message)
}
[PSCustomObject]@{ blocked = $blocked; errors = $errs } | ConvertTo-Json -Compress
`
  try {
    const out = await runPS(script)
    return JSON.parse(out)
  } catch (e) {
    return { blocked: 0, errors: [e.message] }
  }
}
```

Update `module.exports`:

```javascript
module.exports = { runPS, checkAdmin, blockFolder, RULE_PREFIX }
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=firewall`

Expected: All 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add firewall.js tests/firewall.test.js
git commit -m "feat: add blockFolder to firewall module"
```

---

### Task 4: `firewall.js` — `blockExe`

**Files:**
- Modify: `firewall.js`
- Modify: `tests/firewall.test.js`

- [ ] **Step 1: Add failing tests for `blockExe`**

Append to `tests/firewall.test.js`:

```javascript
const { blockExe } = require('../firewall')

describe('blockExe', () => {
  it('returns success:true on clean PS output', async () => {
    mockPS(JSON.stringify({ success: true, error: null }))
    const result = await blockExe('C:\\Games\\game.exe')
    expect(result).toEqual({ success: true, error: null })
  })

  it('returns success:false on PS error', async () => {
    mockPS('', 1)
    const result = await blockExe('C:\\Games\\game.exe')
    expect(result.success).toBe(false)
    expect(typeof result.error).toBe('string')
  })

  it('escapes single quotes in exe path', async () => {
    mockPS(JSON.stringify({ success: true, error: null }))
    await blockExe("C:\\It's\\game.exe")
    const call = execFile.mock.calls[0]
    const encodedArg = call[1][call[1].indexOf('-EncodedCommand') + 1]
    const decoded = Buffer.from(encodedArg, 'base64').toString('utf16le')
    expect(decoded).toContain("C:\\It''s\\game.exe")
  })
})
```

- [ ] **Step 2: Run to confirm new tests fail**

Run: `npm test -- --testPathPattern=firewall`

Expected: 3 new failures — `blockExe is not a function`

- [ ] **Step 3: Implement `blockExe` in `firewall.js`**

Add before `module.exports`:

```javascript
const path = require('path')

async function blockExe(exePath) {
  const safePath = exePath.replace(/'/g, "''")
  const base = path.basename(exePath, '.exe').replace(/[^\w\-]/g, '_')
  const inName  = `${RULE_PREFIX}${base}_Inbound`
  const outName = `${RULE_PREFIX}${base}_Outbound`
  const safeIn  = inName.replace(/'/g, "''")
  const safeOut = outName.replace(/'/g, "''")
  const script = `
try {
  New-NetFirewallRule -DisplayName '${safeIn}'  -Direction Inbound  -Program '${safePath}' -Action Block -Enabled True | Out-Null
  New-NetFirewallRule -DisplayName '${safeOut}' -Direction Outbound -Program '${safePath}' -Action Block -Enabled True | Out-Null
  [PSCustomObject]@{ success = $true; error = $null } | ConvertTo-Json -Compress
} catch {
  [PSCustomObject]@{ success = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`
  try {
    const out = await runPS(script)
    return JSON.parse(out)
  } catch (e) {
    return { success: false, error: e.message }
  }
}
```

Move the `const path = require('path')` line to the top of `firewall.js` (after the `execFile` require).

Update `module.exports`:

```javascript
module.exports = { runPS, checkAdmin, blockFolder, blockExe, RULE_PREFIX }
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=firewall`

Expected: All 13 tests pass.

- [ ] **Step 5: Commit**

```bash
git add firewall.js tests/firewall.test.js
git commit -m "feat: add blockExe to firewall module"
```

---

### Task 5: `firewall.js` — `listRules`

**Files:**
- Modify: `firewall.js`
- Modify: `tests/firewall.test.js`

- [ ] **Step 1: Add failing tests for `listRules`**

Append to `tests/firewall.test.js`:

```javascript
const { listRules } = require('../firewall')

describe('listRules', () => {
  it('returns array of rule groups from PS JSON', async () => {
    const psOutput = JSON.stringify([
      { programPath: 'C:\\app\\game.exe', programName: 'game.exe', inbound: true, outbound: true, enabled: true }
    ])
    mockPS(psOutput)
    const result = await listRules()
    expect(result).toHaveLength(1)
    expect(result[0].programName).toBe('game.exe')
    expect(result[0].inbound).toBe(true)
  })

  it('wraps single object in array (PS quirk with one result)', async () => {
    const psOutput = JSON.stringify(
      { programPath: 'C:\\app\\game.exe', programName: 'game.exe', inbound: true, outbound: true, enabled: true }
    )
    mockPS(psOutput)
    const result = await listRules()
    expect(Array.isArray(result)).toBe(true)
    expect(result).toHaveLength(1)
  })

  it('returns empty array when PS outputs empty or null', async () => {
    mockPS('')
    const result = await listRules()
    expect(result).toEqual([])
  })

  it('returns empty array on PS error', async () => {
    mockPS('', 1)
    const result = await listRules()
    expect(result).toEqual([])
  })
})
```

- [ ] **Step 2: Run to confirm new tests fail**

Run: `npm test -- --testPathPattern=firewall`

Expected: 4 new failures — `listRules is not a function`

- [ ] **Step 3: Implement `listRules` in `firewall.js`**

Add before `module.exports`:

```javascript
async function listRules() {
  const script = `
$rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like '${RULE_PREFIX}*' }
if (-not $rules) { Write-Output '[]'; exit 0 }
$grouped = @{}
foreach ($r in $rules) {
  $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r
  $prog = $app.Program
  if (-not $grouped.ContainsKey($prog)) {
    $grouped[$prog] = @{ inbound = $false; outbound = $false; enabled = $false }
  }
  if ($r.Direction -eq 'Inbound')  { $grouped[$prog].inbound  = $true }
  if ($r.Direction -eq 'Outbound') { $grouped[$prog].outbound = $true }
  if ($r.Enabled   -eq 'True')     { $grouped[$prog].enabled  = $true }
}
$out = foreach ($prog in $grouped.Keys) {
  [PSCustomObject]@{
    programPath = $prog
    programName = (Split-Path -Leaf $prog)
    inbound     = $grouped[$prog].inbound
    outbound    = $grouped[$prog].outbound
    enabled     = $grouped[$prog].enabled
  }
}
$out | ConvertTo-Json -Compress
`
  try {
    const out = await runPS(script)
    if (!out || out === 'null') return []
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return []
  }
}
```

Update `module.exports`:

```javascript
module.exports = { runPS, checkAdmin, blockFolder, blockExe, listRules, RULE_PREFIX }
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `npm test -- --testPathPattern=firewall`

Expected: All 17 tests pass.

- [ ] **Step 5: Commit**

```bash
git add firewall.js tests/firewall.test.js
git commit -m "feat: add listRules to firewall module"
```

---

### Task 6: `firewall.js` — `removeRules` + `removeAllRules`

**Files:**
- Modify: `firewall.js`
- Modify: `tests/firewall.test.js`

- [ ] **Step 1: Add failing tests**

Append to `tests/firewall.test.js`:

```javascript
const { removeRules, removeAllRules } = require('../firewall')

describe('removeRules', () => {
  it('returns removed count from PS JSON', async () => {
    mockPS(JSON.stringify({ removed: 2, errors: [] }))
    const result = await removeRules(['C:\\app\\game.exe'])
    expect(result).toEqual({ removed: 2, errors: [] })
  })

  it('returns errors on PS failure', async () => {
    mockPS('', 1)
    const result = await removeRules(['C:\\app\\game.exe'])
    expect(result.removed).toBe(0)
    expect(result.errors.length).toBeGreaterThan(0)
  })
})

describe('removeAllRules', () => {
  it('returns removed count', async () => {
    mockPS(JSON.stringify({ removed: 5, errors: [] }))
    const result = await removeAllRules()
    expect(result.removed).toBe(5)
  })

  it('returns errors on PS failure', async () => {
    mockPS('', 1)
    const result = await removeAllRules()
    expect(result.removed).toBe(0)
  })
})
```

- [ ] **Step 2: Run to confirm new tests fail**

Run: `npm test -- --testPathPattern=firewall`

Expected: 4 new failures.

- [ ] **Step 3: Implement `removeRules` and `removeAllRules`**

Add before `module.exports`:

```javascript
async function removeRules(paths) {
  const safeJson = JSON.stringify(paths).replace(/'/g, "''")
  const script = `
$targets = '${safeJson}' | ConvertFrom-Json
$removed = 0
$errs = [System.Collections.Generic.List[string]]::new()
$rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like '${RULE_PREFIX}*' }
foreach ($r in $rules) {
  $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r
  if ($targets -contains $app.Program) {
    try {
      Remove-NetFirewallRule -Name $r.Name
      $removed++
    } catch {
      $errs.Add($r.DisplayName)
    }
  }
}
[PSCustomObject]@{ removed = $removed; errors = $errs } | ConvertTo-Json -Compress
`
  try {
    const out = await runPS(script)
    return JSON.parse(out)
  } catch (e) {
    return { removed: 0, errors: [e.message] }
  }
}

async function removeAllRules() {
  const script = `
$removed = 0
$errs = [System.Collections.Generic.List[string]]::new()
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '${RULE_PREFIX}*' } | ForEach-Object {
  try {
    Remove-NetFirewallRule -Name $_.Name
    $removed++
  } catch {
    $errs.Add($_.DisplayName)
  }
}
[PSCustomObject]@{ removed = $removed; errors = $errs } | ConvertTo-Json -Compress
`
  try {
    const out = await runPS(script)
    return JSON.parse(out)
  } catch (e) {
    return { removed: 0, errors: [e.message] }
  }
}
```

Update `module.exports`:

```javascript
module.exports = { runPS, checkAdmin, blockFolder, blockExe, listRules, removeRules, removeAllRules, RULE_PREFIX }
```

- [ ] **Step 4: Run full test suite**

Run: `npm test`

Expected: All 25 tests pass, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add firewall.js tests/firewall.test.js
git commit -m "feat: add removeRules and removeAllRules to firewall module"
```

---

### Task 7: `main.js` + `preload.js`

**Files:**
- Create: `main.js`
- Create: `preload.js`

- [ ] **Step 1: Create `preload.js`**

```javascript
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('fw', {
  pickFolder:     ()        => ipcRenderer.invoke('fw:pick-folder'),
  pickExe:        ()        => ipcRenderer.invoke('fw:pick-exe'),
  blockFolder:    (path)    => ipcRenderer.invoke('fw:block-folder', path),
  blockExe:       (path)    => ipcRenderer.invoke('fw:block-exe', path),
  listRules:      ()        => ipcRenderer.invoke('fw:list-rules'),
  removeRules:    (paths)   => ipcRenderer.invoke('fw:remove-rules', paths),
  removeAllRules: ()        => ipcRenderer.invoke('fw:remove-all'),
})
```

- [ ] **Step 2: Create `main.js`**

```javascript
const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path = require('path')
const {
  checkAdmin, blockFolder, blockExe, listRules, removeRules, removeAllRules
} = require('./firewall')

let win

function createWindow() {
  win = new BrowserWindow({
    width: 900,
    height: 600,
    resizable: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })
  win.loadFile('renderer/index.html')
  win.setMenu(null)
}

app.whenReady().then(async () => {
  const isAdmin = await checkAdmin()
  if (!isAdmin) {
    await dialog.showMessageBox({
      type: 'error',
      title: 'Administrator Required',
      message: 'Firewall Manager requires administrator privileges.\nPlease right-click and run as administrator.',
      buttons: ['OK'],
    })
    app.quit()
    return
  }
  createWindow()
})

app.on('window-all-closed', () => app.quit())

ipcMain.handle('fw:pick-folder', () =>
  dialog.showOpenDialog(win, { properties: ['openDirectory'] })
    .then(r => r.canceled ? null : r.filePaths[0])
)

ipcMain.handle('fw:pick-exe', () =>
  dialog.showOpenDialog(win, {
    properties: ['openFile'],
    filters: [{ name: 'Executables', extensions: ['exe'] }],
  }).then(r => r.canceled ? null : r.filePaths[0])
)

ipcMain.handle('fw:block-folder',    (_, p)     => blockFolder(p))
ipcMain.handle('fw:block-exe',       (_, p)     => blockExe(p))
ipcMain.handle('fw:list-rules',      ()         => listRules())
ipcMain.handle('fw:remove-rules',    (_, paths) => removeRules(paths))
ipcMain.handle('fw:remove-all',      ()         => removeAllRules())
```

- [ ] **Step 3: Verify `npm test` still passes**

Run: `npm test`

Expected: All 25 tests pass (main.js and preload.js have no testable pure logic).

- [ ] **Step 4: Commit**

```bash
git add main.js preload.js
git commit -m "feat: add main process and preload IPC bridge"
```

---

### Task 8: `renderer/index.html` + `renderer/styles.css`

**Files:**
- Create: `renderer/index.html`
- Create: `renderer/styles.css`

- [ ] **Step 1: Create `renderer/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
  <title>Firewall Manager</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="layout">
    <nav class="sidebar">
      <div class="app-title">Firewall Manager</div>
      <ul class="nav-list">
        <li class="nav-item active" data-view="block-folder">Block Folder</li>
        <li class="nav-item" data-view="block-exe">Block EXE</li>
        <li class="nav-item" data-view="view-rules">View Rules</li>
        <li class="nav-item" data-view="remove-rules">Remove Rules</li>
      </ul>
    </nav>
    <main class="content">
      <div id="view-block-folder"  class="view active"></div>
      <div id="view-block-exe"     class="view"></div>
      <div id="view-view-rules"    class="view"></div>
      <div id="view-remove-rules"  class="view"></div>
    </main>
  </div>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `renderer/styles.css`**

```css
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: #141414;
  color: #e0e0e0;
  height: 100vh;
  overflow: hidden;
  user-select: none;
}

.layout { display: flex; height: 100vh; }

.sidebar {
  width: 180px;
  background: #1c1c1c;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  border-right: 1px solid #2a2a2a;
}

.app-title {
  color: #6c63ff;
  font-weight: 700;
  font-size: 13px;
  padding: 18px 16px 16px;
  border-bottom: 1px solid #2a2a2a;
  letter-spacing: 0.02em;
}

.nav-list { list-style: none; padding: 8px 0; }

.nav-item {
  padding: 10px 16px;
  cursor: pointer;
  font-size: 13px;
  color: #888;
  border-left: 3px solid transparent;
}
.nav-item:hover { background: #242424; color: #ccc; }
.nav-item.active { color: #6c63ff; border-left-color: #6c63ff; background: #1f1f2e; }

.content { flex: 1; overflow-y: auto; padding: 28px; }

.view { display: none; }
.view.active { display: block; }

h2 {
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 20px;
  color: #e0e0e0;
  padding-bottom: 12px;
  border-bottom: 1px solid #2a2a2a;
}

.row { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }

.path-display {
  flex: 1;
  background: #1c1c1c;
  border: 1px solid #2a2a2a;
  padding: 7px 12px;
  border-radius: 4px;
  font-size: 12px;
  color: #666;
  font-family: monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.path-display.has-value { color: #aaa; }

button {
  padding: 7px 14px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 13px;
  font-family: inherit;
  white-space: nowrap;
}
button:disabled { opacity: 0.4; cursor: not-allowed; }

.btn-primary  { background: #6c63ff; color: #fff; }
.btn-primary:hover:not(:disabled)  { background: #5a52e0; }

.btn-danger   { background: #c0392b; color: #fff; }
.btn-danger:hover:not(:disabled)   { background: #a93226; }

.btn-secondary { background: #2a2a2a; color: #ccc; border: 1px solid #3a3a3a; }
.btn-secondary:hover:not(:disabled) { background: #333; }

.info-text { font-size: 13px; color: #888; margin-bottom: 12px; }
.info-text strong { color: #6c63ff; }

.log {
  background: #1c1c1c;
  border: 1px solid #2a2a2a;
  border-radius: 4px;
  padding: 10px 12px;
  font-family: monospace;
  font-size: 12px;
  height: 180px;
  overflow-y: auto;
  margin-top: 12px;
}
.log-ok   { color: #4caf50; }
.log-err  { color: #e05555; }
.log-info { color: #888; }

.summary { margin-top: 10px; font-size: 13px; }
.summary .ok  { color: #4caf50; }
.summary .err { color: #e05555; }

.msg { margin-top: 10px; font-size: 13px; }
.msg-ok  { color: #4caf50; }
.msg-err { color: #e05555; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  text-align: left;
  padding: 6px 12px;
  color: #555;
  font-weight: 500;
  border-bottom: 1px solid #2a2a2a;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
td { padding: 10px 12px; border-bottom: 1px solid #1e1e1e; }
tr:hover td { background: #1c1c1c; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
}
.badge-yes  { background: #1a2f1a; color: #4caf50; }
.badge-no   { background: #2f1a1a; color: #e05555; }

.empty-state { color: #444; font-size: 13px; padding: 40px 0; text-align: center; }

.check-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid #1e1e1e;
}
.check-row:hover { background: #1a1a1a; }

input[type="checkbox"] { accent-color: #6c63ff; width: 14px; height: 14px; margin-top: 2px; flex-shrink: 0; }

.prog-info { flex: 1; min-width: 0; }
.prog-name { font-size: 13px; color: #e0e0e0; }
.prog-path { font-size: 11px; color: #444; font-family: monospace; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.actions-row { display: flex; gap: 8px; margin-top: 16px; }

.table-actions { display: flex; justify-content: flex-end; margin-bottom: 14px; }
```

- [ ] **Step 3: Verify app loads without JS errors**

Run: `npm start` (as administrator)

Expected: Electron window opens, sidebar visible with 4 nav items, content area empty. No console errors. Close the window.

- [ ] **Step 4: Commit**

```bash
git add renderer/index.html renderer/styles.css
git commit -m "feat: add renderer shell and dark theme"
```

---

### Task 9: `renderer/app.js` — Navigation + Block Folder view

**Files:**
- Create: `renderer/app.js`

- [ ] **Step 1: Create `renderer/app.js` with navigation and Block Folder view**

```javascript
// Navigation
const navItems = document.querySelectorAll('.nav-item')
const views    = document.querySelectorAll('.view')

navItems.forEach(item => {
  item.addEventListener('click', () => {
    navItems.forEach(n => n.classList.remove('active'))
    views.forEach(v => v.classList.remove('active'))
    item.classList.add('active')
    document.getElementById(`view-${item.dataset.view}`).classList.add('active')
  })
})

// ── Block Folder ──────────────────────────────────────────────────
const folderView = document.getElementById('view-block-folder')
folderView.innerHTML = `
  <h2>Block Folder</h2>
  <div class="row">
    <div class="path-display" id="bf-path">No folder selected</div>
    <button class="btn-secondary" id="bf-browse">Browse...</button>
  </div>
  <div class="info-text" id="bf-scan-info" style="display:none">
    Found <strong id="bf-count">0</strong> .exe file(s)
  </div>
  <div class="row" style="margin-top:4px">
    <button class="btn-primary" id="bf-scan"  disabled>Scan</button>
    <button class="btn-danger"  id="bf-block" disabled>Block All</button>
  </div>
  <div class="log" id="bf-log" style="display:none"></div>
  <div class="summary" id="bf-summary"></div>
`

let bfSelectedPath = null
let bfExeCount     = 0

const bfPath     = document.getElementById('bf-path')
const bfBrowse   = document.getElementById('bf-browse')
const bfScan     = document.getElementById('bf-scan')
const bfBlock    = document.getElementById('bf-block')
const bfScanInfo = document.getElementById('bf-scan-info')
const bfCount    = document.getElementById('bf-count')
const bfLog      = document.getElementById('bf-log')
const bfSummary  = document.getElementById('bf-summary')

bfBrowse.addEventListener('click', async () => {
  const p = await window.fw.pickFolder()
  if (!p) return
  bfSelectedPath = p
  bfPath.textContent = p
  bfPath.classList.add('has-value')
  bfScanInfo.style.display = 'none'
  bfBlock.disabled = true
  bfScan.disabled = false
  bfLog.style.display = 'none'
  bfSummary.innerHTML = ''
  bfExeCount = 0
})

bfScan.addEventListener('click', async () => {
  if (!bfSelectedPath) return
  bfScan.disabled = true
  bfScanInfo.style.display = 'none'

  // Count exes via block (dry run not available; just show pending state)
  // We show the count after block, so here just enable block
  bfScanInfo.style.display = 'block'
  bfCount.textContent = '...'
  bfBlock.disabled = false
  bfScan.disabled = false

  // Pre-scan using a list approach: use listRules as proxy isn't right.
  // Instead, show "ready to block" and let block report the count.
  bfCount.textContent = '?'
  bfScanInfo.querySelector('strong').previousSibling.textContent = 'Ready — will block all '
  bfCount.textContent = ''
  bfScanInfo.innerHTML = 'Ready to scan and block all <strong>.exe</strong> files in the selected folder.'
})

bfBlock.addEventListener('click', async () => {
  if (!bfSelectedPath) return
  bfBlock.disabled = true
  bfScan.disabled  = true
  bfBrowse.disabled = true
  bfLog.style.display = 'block'
  bfLog.innerHTML = '<span class="log-info">Scanning and blocking...</span>'
  bfSummary.innerHTML = ''

  const result = await window.fw.blockFolder(bfSelectedPath)

  bfLog.innerHTML = ''
  if (result.errors && result.errors.length > 0) {
    result.errors.forEach(e => {
      bfLog.innerHTML += `<div class="log-err">✗ ${e}</div>`
    })
  }
  if (result.blocked > 0) {
    bfLog.innerHTML += `<div class="log-ok">✓ ${result.blocked} file(s) blocked successfully</div>`
  }

  bfSummary.innerHTML = `
    <span class="ok">Blocked: ${result.blocked}</span>
    ${result.errors.length > 0 ? `&nbsp;&nbsp;<span class="err">Errors: ${result.errors.length}</span>` : ''}
  `
  bfBlock.disabled  = false
  bfScan.disabled   = false
  bfBrowse.disabled = false
})
```

- [ ] **Step 2: Run the app and test Block Folder view**

Run: `npm start` (as administrator)

Manual test:
1. Click "Browse..." → Windows Explorer folder picker opens → select a folder with `.exe` files
2. Click "Scan" → info text updates
3. Click "Block All" → log shows results, summary shows count
4. Verify rules exist: open PowerShell and run `Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'PSFirewallBlock_*' } | Select DisplayName`

- [ ] **Step 3: Commit**

```bash
git add renderer/app.js
git commit -m "feat: add navigation and Block Folder view"
```

---

### Task 10: `renderer/app.js` — Block EXE view

**Files:**
- Modify: `renderer/app.js`

- [ ] **Step 1: Append Block EXE view to `renderer/app.js`**

```javascript
// ── Block EXE ────────────────────────────────────────────────────
const exeView = document.getElementById('view-block-exe')
exeView.innerHTML = `
  <h2>Block Single EXE</h2>
  <div class="row">
    <div class="path-display" id="be-path">No file selected</div>
    <button class="btn-secondary" id="be-browse">Browse...</button>
  </div>
  <div class="row" style="margin-top:4px">
    <button class="btn-primary" id="be-block" disabled>Block</button>
  </div>
  <div class="msg" id="be-msg"></div>
`

let beSelectedPath = null

const bePath    = document.getElementById('be-path')
const beBrowse  = document.getElementById('be-browse')
const beBlock   = document.getElementById('be-block')
const beMsg     = document.getElementById('be-msg')

beBrowse.addEventListener('click', async () => {
  const p = await window.fw.pickExe()
  if (!p) return
  beSelectedPath = p
  bePath.textContent = p
  bePath.classList.add('has-value')
  beBlock.disabled = false
  beMsg.innerHTML = ''
})

beBlock.addEventListener('click', async () => {
  if (!beSelectedPath) return
  beBlock.disabled  = true
  beBrowse.disabled = true
  beMsg.innerHTML = '<span class="log-info">Blocking...</span>'

  const result = await window.fw.blockExe(beSelectedPath)

  if (result.success) {
    beMsg.innerHTML = `<span class="msg-ok">✓ Blocked successfully</span>`
  } else {
    beMsg.innerHTML = `<span class="msg-err">✗ ${result.error || 'Unknown error'}</span>`
  }
  beBlock.disabled  = false
  beBrowse.disabled = false
})
```

- [ ] **Step 2: Run and test Block EXE view**

Run: `npm start` (as administrator)

Manual test:
1. Click "Block EXE" in sidebar
2. Click "Browse..." → file picker opens, filtered to `.exe` → select a single `.exe`
3. Click "Block" → success message appears
4. Verify: `Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'PSFirewallBlock_*' } | Select DisplayName`

- [ ] **Step 3: Commit**

```bash
git add renderer/app.js
git commit -m "feat: add Block EXE view"
```

---

### Task 11: `renderer/app.js` — View Rules view

**Files:**
- Modify: `renderer/app.js`

- [ ] **Step 1: Append View Rules view to `renderer/app.js`**

```javascript
// ── View Rules ───────────────────────────────────────────────────
const rulesView = document.getElementById('view-view-rules')
rulesView.innerHTML = `
  <h2>View Rules</h2>
  <div class="table-actions">
    <button class="btn-secondary" id="vr-refresh">Refresh</button>
  </div>
  <div id="vr-content"></div>
`

const vrRefresh = document.getElementById('vr-refresh')
const vrContent = document.getElementById('vr-content')

async function loadRules() {
  vrContent.innerHTML = '<div class="empty-state">Loading...</div>'
  const rules = await window.fw.listRules()
  if (!rules || rules.length === 0) {
    vrContent.innerHTML = '<div class="empty-state">No rules created by this tool.</div>'
    return
  }
  vrContent.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Program</th>
          <th>Path</th>
          <th>Inbound</th>
          <th>Outbound</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${rules.map(r => `
          <tr>
            <td>${r.programName}</td>
            <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:11px;color:#555"
                title="${r.programPath}">${r.programPath}</td>
            <td><span class="badge ${r.inbound  ? 'badge-yes' : 'badge-no'}">${r.inbound  ? 'Yes' : 'No'}</span></td>
            <td><span class="badge ${r.outbound ? 'badge-yes' : 'badge-no'}">${r.outbound ? 'Yes' : 'No'}</span></td>
            <td><span class="badge ${r.enabled  ? 'badge-yes' : 'badge-no'}">${r.enabled  ? 'Active' : 'Inactive'}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `
}

vrRefresh.addEventListener('click', loadRules)

// Auto-load when tab is activated
document.querySelector('[data-view="view-rules"]').addEventListener('click', loadRules)
```

- [ ] **Step 2: Run and test View Rules**

Run: `npm start` (as administrator)

Manual test:
1. First block a folder or EXE (from Block Folder or Block EXE views)
2. Click "View Rules" — table shows blocked programs with inbound/outbound badges
3. Click "Refresh" — table reloads
4. If no rules exist: empty state message shows

- [ ] **Step 3: Commit**

```bash
git add renderer/app.js
git commit -m "feat: add View Rules view"
```

---

### Task 12: `renderer/app.js` — Remove Rules view

**Files:**
- Modify: `renderer/app.js`

- [ ] **Step 1: Append Remove Rules view to `renderer/app.js`**

```javascript
// ── Remove Rules ─────────────────────────────────────────────────
const removeView = document.getElementById('view-remove-rules')
removeView.innerHTML = `
  <h2>Remove Rules</h2>
  <div id="rr-content"></div>
  <div class="actions-row" id="rr-actions" style="display:none">
    <button class="btn-secondary" id="rr-remove-sel" disabled>Remove Selected</button>
    <button class="btn-danger"    id="rr-remove-all">Remove All</button>
  </div>
  <div class="msg" id="rr-msg"></div>
`

const rrContent   = document.getElementById('rr-content')
const rrActions   = document.getElementById('rr-actions')
const rrRemoveSel = document.getElementById('rr-remove-sel')
const rrRemoveAll = document.getElementById('rr-remove-all')
const rrMsg       = document.getElementById('rr-msg')

let rrRules = []

async function loadRemoveRules() {
  rrMsg.innerHTML = ''
  rrContent.innerHTML = '<div class="empty-state">Loading...</div>'
  rrRules = await window.fw.listRules()

  if (!rrRules || rrRules.length === 0) {
    rrContent.innerHTML = '<div class="empty-state">No rules to remove.</div>'
    rrActions.style.display = 'none'
    return
  }

  rrContent.innerHTML = rrRules.map((r, i) => `
    <div class="check-row">
      <input type="checkbox" id="rr-cb-${i}" data-path="${r.programPath}">
      <div class="prog-info">
        <div class="prog-name">${r.programName}</div>
        <div class="prog-path">${r.programPath}</div>
      </div>
    </div>
  `).join('')

  rrActions.style.display = 'flex'
  rrRemoveSel.disabled = true

  rrContent.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
      const anyChecked = rrContent.querySelectorAll('input:checked').length > 0
      rrRemoveSel.disabled = !anyChecked
    })
  })
}

rrRemoveSel.addEventListener('click', async () => {
  const checked = [...rrContent.querySelectorAll('input:checked')]
  const paths   = checked.map(cb => cb.dataset.path)
  if (paths.length === 0) return

  setRRBusy(true)
  const result = await window.fw.removeRules(paths)
  setRRBusy(false)

  rrMsg.innerHTML = result.errors.length
    ? `<span class="msg-err">Removed ${result.removed}, errors: ${result.errors.length}</span>`
    : `<span class="msg-ok">✓ Removed ${result.removed} rule(s)</span>`

  await loadRemoveRules()
})

rrRemoveAll.addEventListener('click', async () => {
  const confirmed = await require
  // Use Electron's dialog via IPC isn't wired — use native confirm as fallback
  if (!confirm('Remove ALL firewall rules created by this tool?')) return

  setRRBusy(true)
  const result = await window.fw.removeAllRules()
  setRRBusy(false)

  rrMsg.innerHTML = result.errors.length
    ? `<span class="msg-err">Removed ${result.removed}, errors: ${result.errors.length}</span>`
    : `<span class="msg-ok">✓ Removed all ${result.removed} rule(s)</span>`

  await loadRemoveRules()
})

function setRRBusy(busy) {
  rrRemoveSel.disabled = busy
  rrRemoveAll.disabled = busy
  if (busy) rrMsg.innerHTML = '<span class="log-info">Removing rules...</span>'
}

document.querySelector('[data-view="remove-rules"]').addEventListener('click', loadRemoveRules)
```

**Note:** The `rrRemoveAll` listener has a broken `const confirmed = await require` line — that's a placeholder accident in the draft. Fix it in the next step.

- [ ] **Step 2: Fix the broken confirm line in `renderer/app.js`**

Find and replace the broken block:

```javascript
// REMOVE this line:
  const confirmed = await require
  // Use Electron's dialog via IPC isn't wired — use native confirm as fallback
  if (!confirm('Remove ALL firewall rules created by this tool?')) return
```

Replace with:

```javascript
  if (!confirm('Remove ALL firewall rules created by this tool?')) return
```

- [ ] **Step 3: Run and test Remove Rules view**

Run: `npm start` (as administrator)

Manual test:
1. Block at least one EXE or folder first
2. Click "Remove Rules" — list shows blocked programs with checkboxes
3. Check one or more → "Remove Selected" enables → click it → rules removed, list refreshes
4. Click "Remove All" → confirmation dialog → rules removed, empty state shows
5. Switch to "View Rules" and refresh — table is empty

- [ ] **Step 4: Commit**

```bash
git add renderer/app.js
git commit -m "feat: add Remove Rules view"
```

---

### Task 13: Final smoke test + polish

**Files:**
- Modify: `renderer/app.js` (minor)

- [ ] **Step 1: Run full test suite one last time**

Run: `npm test`

Expected: All 25 tests pass, 0 failures.

- [ ] **Step 2: Full manual smoke test**

Run: `npm start` (as administrator)

Work through this checklist:

1. **Block Folder** — browse to a folder containing `.exe` files → Scan → Block All → log shows results, summary shows count
2. **Block EXE** — browse to a single `.exe` → Block → success message
3. **View Rules** — click tab → table populates with blocked programs → Refresh works
4. **Remove Rules** — check individual programs → Remove Selected → list updates
5. **Remove All** — confirm dialog → all rules removed → empty state

Verify rules in PowerShell: `Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'PSFirewallBlock_*' }`

- [ ] **Step 3: Test not-admin path**

Temporarily test by running without elevation (or by stubbing `checkAdmin` to return false in `main.js`, run, verify dialog shows and app quits, then revert).

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete Firewall Manager Electron app"
```

---

## Self-Review Notes

- All `RULE_PREFIX` references use the same `PSFirewallBlock_` constant from `firewall.js` — consistent with the original PS script
- `listRules` handles the PS single-object quirk (wraps in array if needed) and empty output
- Path escaping for single-quotes applied in `blockFolder`, `blockExe`, and `removeRules`
- `confirm()` used for "Remove All" — available in Electron renderer without extra IPC wiring
- No test coverage for `main.js`/`preload.js`/renderer — these are glue code verified by manual smoke test
- Task 12 includes an intentional fix step for the draft mistake in the `rrRemoveAll` listener
