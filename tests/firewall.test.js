jest.mock('child_process', () => ({ execFile: jest.fn() }))
const { execFile } = require('child_process')
const { runPS, checkAdmin, blockFolder, blockExe, listRules, removeRules, removeAllRules } = require('../firewall')

beforeEach(() => execFile.mockClear())

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
