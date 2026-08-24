import { createHash, webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getGameDataFile, getGameDataIndex, getGameDataMetadata } from './data'
import type { GameDataFileDescriptor, GameDataIndex } from './types'

function reference(bytes: Uint8Array, url: string) {
  return {
    url,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: bytes.byteLength,
  }
}

const payloadBytes = Buffer.from('{\n  "Sym": {"windows": "NEW"}\n}\n', 'utf8')
const payloadReference = reference(payloadBytes, `payloads/${createHash('sha256').update(payloadBytes).digest('hex')}.jsonc`)
const metadataDocument = {
  schema_version: 2 as const,
  gamever: '14176',
  file: 'Plugin/data.jsonc',
  summary: { total: 1, covered: 1, updated: 1 },
  entries: [{
    name: 'Sym',
    covered: true,
    covered_lines: [2],
    updated: true,
    changes: [{ path: ['Sym', 'windows'], before: 'OLD', after: 'NEW', line: 2 }],
  }],
}
const metadataBytes = Buffer.from(JSON.stringify(metadataDocument), 'utf8')
const metadataReference = {
  ...reference(metadataBytes, `metadata/${createHash('sha256').update(metadataBytes).digest('hex')}.json`),
  schemaVersion: 2,
  summary: metadataDocument.summary,
}
const file: GameDataFileDescriptor = {
  id: 'Plugin/data.jsonc',
  plugin: 'Plugin',
  fileName: 'data.jsonc',
  language: 'jsonc',
  content: payloadReference,
  metadata: metadataReference,
}
const index: GameDataIndex = {
  schemaVersion: 1,
  versions: [{ gameVersion: '14176', fileCount: 1, metadataFileCount: 1, files: [file] }],
}

describe('gamedata asset loading', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('validates the index and verifies payload bytes before decoding text', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(index)))
      .mockResolvedValueOnce(new Response(payloadBytes))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getGameDataIndex()).resolves.toEqual(index)
    await expect(getGameDataFile(file)).resolves.toContain('"Sym"')
    expect(fetchMock).toHaveBeenLastCalledWith(expect.stringContaining(file.content.url), { signal: undefined })
  })

  it('validates metadata identity, line ranges, and the index summary binding', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(metadataBytes)))

    await expect(getGameDataMetadata(file, 4, '14176')).resolves.toEqual(metadataDocument)
    await expect(getGameDataMetadata(file, 1, '14176')).rejects.toThrow(/covered_lines/)
  })

  it('rejects payload byte tampering', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(Buffer.from('tampered', 'utf8'))))

    await expect(getGameDataFile(file)).rejects.toThrow(/size mismatch/)
  })
})
