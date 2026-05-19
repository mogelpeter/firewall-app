const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path = require('path')
const { execFileSync } = require('child_process')
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
    try {
      // Re-launch the current process with UAC elevation via PowerShell Start-Process -Verb RunAs
      const safePath = process.execPath.replace(/'/g, "''")
      const extraArgs = process.argv.slice(1)
      const safeArgs = extraArgs.map(a => `'${a.replace(/'/g, "''")}'`).join(', ')
      const psCmd = extraArgs.length > 0
        ? `Start-Process -FilePath '${safePath}' -ArgumentList @(${safeArgs}) -Verb RunAs`
        : `Start-Process -FilePath '${safePath}' -Verb RunAs`
      execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', psCmd])
    } catch {
      // UAC was declined by user — show a brief notice
      await dialog.showMessageBox({
        type: 'warning',
        title: 'Administrator Required',
        message: 'Firewall Manager needs administrator privileges to manage Windows Firewall rules.',
        buttons: ['OK'],
      })
    }
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
