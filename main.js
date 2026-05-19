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
