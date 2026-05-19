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
