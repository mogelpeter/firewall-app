const { execFile } = require('child_process')
const path = require('path')

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

async function listRules() {
  const script = `
$rules = Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue
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

async function removeRules(paths) {
  const safeJson = JSON.stringify(paths).replace(/'/g, "''")
  const script = `
$targets = '${safeJson}' | ConvertFrom-Json
$removed = 0
$errs = [System.Collections.Generic.List[string]]::new()
$rules = Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue
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
Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | ForEach-Object {
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

module.exports = { runPS, checkAdmin, blockFolder, blockExe, listRules, removeRules, removeAllRules, RULE_PREFIX }
