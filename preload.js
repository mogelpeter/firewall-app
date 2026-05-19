const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('fw', {
  pickFolder:     ()        => ipcRenderer.invoke('fw:pick-folder'),
  pickExe:        ()        => ipcRenderer.invoke('fw:pick-exe'),
  blockFolder:    (p)       => ipcRenderer.invoke('fw:block-folder', p),
  blockExe:       (p)       => ipcRenderer.invoke('fw:block-exe', p),
  listRules:      ()        => ipcRenderer.invoke('fw:list-rules'),
  removeRules:    (paths)   => ipcRenderer.invoke('fw:remove-rules', paths),
  removeAllRules: ()        => ipcRenderer.invoke('fw:remove-all'),
})
