import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { loadGameDataAssets } from './gameDataPlugin'

const temporaryRoots: string[] = []

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'gamedata-plugin-'))
  temporaryRoots.push(root)
  return root
}

async function writePayload(root: string, version: string, file: string, text: string): Promise<void> {
  const path = join(root, version, ...file.split('/'))
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, text, 'utf8')
}

async function writeMetadata(root: string, version: string, file: string, line: number): Promise<void> {
  const metadata = {
    schema_version: 2,
    gamever: version,
    file,
    summary: { total: 1, covered: 1, updated: 1 },
    entries: [{
      name: 'Sym',
      covered: true,
      covered_lines: [line],
      updated: true,
      changes: [{ path: ['Sym', 'windows'], before: 'OLD', after: 'NEW', line }],
    }],
  }
  await writeFile(join(root, version, ...`${file}.metadata.json`.split('/')), `${JSON.stringify(metadata)}\n`, 'utf8')
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('gameDataPlugin asset loading', () => {
  it('sorts versions, detects languages, binds metadata, and deduplicates payload bytes', async () => {
    const root = await temporaryRoot()
    const jsonc = '{\n  "Sym": {"windows": "NEW"}\n}\n'
    await writePayload(root, '14175', 'Plugin/data.jsonc', jsonc)
    await writePayload(root, '14176', 'Plugin/data.jsonc', jsonc)
    await writeMetadata(root, '14176', 'Plugin/data.jsonc', 2)
    await writePayload(root, '14176', 'Vdf/core.games.txt', '"Games"\n{\n}\n')
    await writePayload(root, '14176', 'Flat/settings.txt', 'value=1\n')

    const loaded = await loadGameDataAssets(root)

    expect(loaded.index.versions.map((version) => version.gameVersion)).toEqual(['14176', '14175'])
    const latest = loaded.index.versions[0]
    expect(latest.metadataFileCount).toBe(1)
    expect(latest.files.map((file) => [file.plugin, file.fileName, file.language])).toEqual([
      ['Flat', 'settings.txt', 'flat'],
      ['Plugin', 'data.jsonc', 'jsonc'],
      ['Vdf', 'core.games.txt', 'vdf'],
    ])
    expect(latest.files.find((file) => file.id === 'Plugin/data.jsonc')?.metadata).toEqual(expect.objectContaining({
      schemaVersion: 2,
      summary: { total: 1, covered: 1, updated: 1 },
    }))
    const olderUrl = loaded.index.versions[1].files[0].content.url
    const latestUrl = latest.files.find((file) => file.id === 'Plugin/data.jsonc')?.content.url
    expect(latestUrl).toBe(olderUrl)
    expect(loaded.assets.has(olderUrl)).toBe(true)
  })

  it('rejects orphan companions and metadata whose identity does not match the payload', async () => {
    const root = await temporaryRoot()
    await writePayload(root, '14176', 'Plugin/orphan.json.metadata.json', '{}\n')
    await expect(loadGameDataAssets(root)).rejects.toThrow(/orphan metadata companion/)

    await rm(root, { recursive: true, force: true })
    const second = await temporaryRoot()
    await writePayload(second, '14176', 'Plugin/data.jsonc', '{\n  "Sym": "NEW"\n}\n')
    await writeMetadata(second, '14176', 'Plugin/data.jsonc', 2)
    const path = join(second, '14176', 'Plugin', 'data.jsonc.metadata.json')
    const mismatched = JSON.parse(await readFile(path, 'utf8'))
    mismatched.file = 'Plugin/other.jsonc'
    await writeFile(path, JSON.stringify(mismatched), 'utf8')

    await expect(loadGameDataAssets(second)).rejects.toThrow(/invalid metadata identity/)
  })
})
