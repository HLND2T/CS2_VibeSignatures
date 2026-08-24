import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  verifyGameDataAssetDirectory,
  verifyRemoteGameDataAssets,
  writeGameDataVerificationManifest,
} from './verifyGameDataAssets.mjs'

const temporaryRoots = []

async function temporaryRoot() {
  const root = await mkdtemp(join(tmpdir(), 'gamedata-pages-'))
  temporaryRoots.push(root)
  return root
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function writeAssets(root) {
  await mkdir(join(root, 'payloads'), { recursive: true })
  await mkdir(join(root, 'metadata'), { recursive: true })
  const payload = Buffer.from('{\n  "Sym": "NEW"\n}\n', 'utf8')
  const payloadUrl = `payloads/${digest(payload)}.jsonc`
  const metadataDocument = {
    schema_version: 2,
    gamever: '14176',
    file: 'Plugin/data.jsonc',
    summary: { total: 1, covered: 1, updated: 1 },
    entries: [{
      name: 'Sym', covered: true, covered_lines: [2], updated: true,
      changes: [{ path: ['Sym'], before: 'OLD', after: 'NEW', line: 2 }],
    }],
  }
  const metadata = Buffer.from(JSON.stringify(metadataDocument), 'utf8')
  const metadataUrl = `metadata/${digest(metadata)}.json`
  const index = {
    schemaVersion: 1,
    versions: [{
      gameVersion: '14176',
      fileCount: 1,
      metadataFileCount: 1,
      files: [{
        id: 'Plugin/data.jsonc', plugin: 'Plugin', fileName: 'data.jsonc', language: 'jsonc',
        content: { url: payloadUrl, sha256: digest(payload), size: payload.byteLength },
        metadata: {
          url: metadataUrl, sha256: digest(metadata), size: metadata.byteLength,
          schemaVersion: 2, summary: metadataDocument.summary,
        },
      }],
    }],
  }
  await writeFile(join(root, ...payloadUrl.split('/')), payload)
  await writeFile(join(root, ...metadataUrl.split('/')), metadata)
  await writeFile(join(root, 'index.json'), JSON.stringify(index))
  return { payload, payloadUrl, metadata, metadataUrl }
}

afterEach(async () => {
  vi.unstubAllGlobals()
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('gamedata asset verification', () => {
  it('verifies the exact indexed payload and metadata inventory', async () => {
    const root = await temporaryRoot()
    const assets = await writeAssets(root)

    await expect(verifyGameDataAssetDirectory(root)).resolves.toEqual(expect.objectContaining({
      assets: expect.arrayContaining([expect.objectContaining({ url: assets.payloadUrl }), expect.objectContaining({ url: assets.metadataUrl })]),
    }))
    await writeFile(join(root, ...assets.payloadUrl.split('/')), Buffer.from('tampered', 'utf8'))
    await expect(verifyGameDataAssetDirectory(root)).rejects.toThrow(/size does not match index/)
  })

  it('rejects files that are not declared by the index', async () => {
    const root = await temporaryRoot()
    await writeAssets(root)
    await writeFile(join(root, 'payloads', 'extra.txt'), 'extra', 'utf8')

    await expect(verifyGameDataAssetDirectory(root)).rejects.toThrow(/inventory does not match index/)
  })

  it('waits for the current index and verifies every CDN body', async () => {
    const root = await temporaryRoot()
    await writeAssets(root)
    const staleIndex = Buffer.from('{}', 'utf8')
    const currentIndex = await readFile(join(root, 'index.json'))
    const manifest = await writeGameDataVerificationManifest(root, join(root, 'verification.json'))
    let indexRequests = 0
    vi.stubGlobal('fetch', vi.fn(async (input) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/index.json')) {
        indexRequests += 1
        return new Response(indexRequests === 1 ? staleIndex : currentIndex)
      }
      const marker = '/gamedata/'
      const relativeUrl = url.pathname.slice(url.pathname.indexOf(marker) + marker.length)
      return new Response(await readFile(join(root, ...relativeUrl.split('/'))))
    }))

    await expect(verifyRemoteGameDataAssets('https://example.test/gamedata/', manifest, {
      attempts: 2,
      delayMs: 0,
      batchSize: 2,
    })).resolves.toEqual(expect.objectContaining({ verified: 2 }))
    expect(indexRequests).toBe(2)
  })
})
