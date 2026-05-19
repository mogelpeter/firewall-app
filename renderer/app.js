// ── Rules cache ──────────────────────────────────────────────────
// Avoids re-querying PowerShell on every tab switch.
// Invalidated after any mutation (block/remove). Refresh button forces a fresh fetch.
let rulesCache = null

function invalidateRulesCache() { rulesCache = null }

async function fetchRules(force = false) {
  if (!force && rulesCache !== null) return rulesCache
  rulesCache = await window.fw.listRules()
  return rulesCache
}

// Prefetch in background so first tab click is instant
window.fw.listRules().then(r => { rulesCache = r })

// ── Navigation ───────────────────────────────────────────────────
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
  <div class="info-text" id="bf-info" style="display:none">
    Ready to scan and block all <strong>.exe</strong> files in the selected folder.
  </div>
  <div class="row">
    <button class="btn-secondary" id="bf-scan"  disabled>Scan Folder</button>
    <button class="btn-danger"    id="bf-block" disabled>Block All</button>
  </div>
  <div class="log" id="bf-log" style="display:none"></div>
  <div class="summary" id="bf-summary"></div>
`

let bfSelectedPath = null

const bfPath    = document.getElementById('bf-path')
const bfBrowse  = document.getElementById('bf-browse')
const bfScan    = document.getElementById('bf-scan')
const bfBlock   = document.getElementById('bf-block')
const bfInfo    = document.getElementById('bf-info')
const bfLog     = document.getElementById('bf-log')
const bfSummary = document.getElementById('bf-summary')

bfBrowse.addEventListener('click', async () => {
  const p = await window.fw.pickFolder()
  if (!p) return
  bfSelectedPath = p
  bfPath.textContent = p
  bfPath.classList.add('has-value')
  bfInfo.style.display = 'none'
  bfBlock.disabled = true
  bfScan.disabled = false
  bfLog.style.display = 'none'
  bfSummary.innerHTML = ''
})

bfScan.addEventListener('click', () => {
  if (!bfSelectedPath) return
  bfInfo.style.display = 'block'
  bfBlock.disabled = false
})

bfBlock.addEventListener('click', async () => {
  if (!bfSelectedPath) return
  bfBlock.disabled = true
  bfScan.disabled  = true
  bfBrowse.disabled = true
  bfLog.style.display = 'block'
  bfLog.innerHTML = '<div class="log-info">Scanning and blocking .exe files...</div>'
  bfSummary.innerHTML = ''

  const result = await window.fw.blockFolder(bfSelectedPath)
  if (result.blocked > 0) invalidateRulesCache()

  bfLog.innerHTML = ''
  if (result.errors && result.errors.length > 0) {
    result.errors.forEach(e => {
      bfLog.innerHTML += `<div class="log-err">✗ ${e}</div>`
    })
  }
  if (result.blocked > 0) {
    bfLog.innerHTML += `<div class="log-ok">✓ ${result.blocked} file(s) blocked successfully</div>`
  }
  if (result.blocked === 0 && (!result.errors || result.errors.length === 0)) {
    bfLog.innerHTML = '<div class="log-info">No .exe files found in the selected folder.</div>'
  }

  bfSummary.innerHTML = `
    <span class="ok">Blocked: ${result.blocked}</span>
    ${result.errors && result.errors.length > 0 ? `&nbsp;&nbsp;<span class="err">Errors: ${result.errors.length}</span>` : ''}
  `
  bfBlock.disabled  = false
  bfScan.disabled   = false
  bfBrowse.disabled = false
})

// ── Block EXE ────────────────────────────────────────────────────
const exeView = document.getElementById('view-block-exe')
exeView.innerHTML = `
  <h2>Block Single EXE</h2>
  <div class="row">
    <div class="path-display" id="be-path">No file selected</div>
    <button class="btn-secondary" id="be-browse">Browse...</button>
  </div>
  <div class="row">
    <button class="btn-primary" id="be-block" disabled>Block</button>
  </div>
  <div class="msg" id="be-msg"></div>
`

let beSelectedPath = null

const bePath   = document.getElementById('be-path')
const beBrowse = document.getElementById('be-browse')
const beBlock  = document.getElementById('be-block')
const beMsg    = document.getElementById('be-msg')

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
  if (result.success) invalidateRulesCache()

  beMsg.innerHTML = result.success
    ? '<span class="msg-ok">✓ Blocked successfully</span>'
    : `<span class="msg-err">✗ ${result.error || 'Unknown error'}</span>`

  beBlock.disabled  = false
  beBrowse.disabled = false
})

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

async function loadRules(force = false) {
  if (force || rulesCache === null) vrContent.innerHTML = '<div class="empty-state">Loading...</div>'
  const rules = await fetchRules(force)
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

vrRefresh.addEventListener('click', () => loadRules(true))
document.querySelector('[data-view="view-rules"]').addEventListener('click', () => loadRules())

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

async function loadRemoveRules(force = false) {
  rrMsg.innerHTML = ''
  if (force || rulesCache === null) rrContent.innerHTML = '<div class="empty-state">Loading...</div>'
  const rules = await fetchRules(force)

  if (!rules || rules.length === 0) {
    rrContent.innerHTML = '<div class="empty-state">No rules to remove.</div>'
    rrActions.style.display = 'none'
    return
  }

  rrContent.innerHTML = rules.map((r, i) => `
    <div class="check-row">
      <input type="checkbox" id="rr-cb-${i}" data-path="${r.programPath}">
      <div class="prog-info">
        <div class="prog-name">${r.programName}</div>
        <div class="prog-path" title="${r.programPath}">${r.programPath}</div>
      </div>
    </div>
  `).join('')

  rrActions.style.display = 'flex'
  rrRemoveSel.disabled = true

  rrContent.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
      rrRemoveSel.disabled = rrContent.querySelectorAll('input:checked').length === 0
    })
  })
}

function setRRBusy(busy) {
  rrRemoveSel.disabled = busy
  rrRemoveAll.disabled = busy
  if (busy) rrMsg.innerHTML = '<span class="log-info">Removing rules...</span>'
}

rrRemoveSel.addEventListener('click', async () => {
  const paths = [...rrContent.querySelectorAll('input:checked')].map(cb => cb.dataset.path)
  if (paths.length === 0) return
  setRRBusy(true)
  const result = await window.fw.removeRules(paths)
  invalidateRulesCache()
  setRRBusy(false)
  rrMsg.innerHTML = result.errors.length
    ? `<span class="msg-err">Removed ${result.removed}, errors: ${result.errors.length}</span>`
    : `<span class="msg-ok">✓ Removed ${result.removed} rule(s)</span>`
  await loadRemoveRules()
})

rrRemoveAll.addEventListener('click', async () => {
  if (!confirm('Remove ALL firewall rules created by this tool?')) return
  setRRBusy(true)
  const result = await window.fw.removeAllRules()
  invalidateRulesCache()
  setRRBusy(false)
  rrMsg.innerHTML = result.errors.length
    ? `<span class="msg-err">Removed ${result.removed}, errors: ${result.errors.length}</span>`
    : `<span class="msg-ok">✓ Removed all ${result.removed} rule(s)</span>`
  await loadRemoveRules()
})

document.querySelector('[data-view="remove-rules"]').addEventListener('click', () => loadRemoveRules())
