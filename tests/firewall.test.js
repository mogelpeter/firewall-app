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
