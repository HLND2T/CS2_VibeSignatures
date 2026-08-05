import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  mergeImmutableArchive,
  verifyGameSymbolAssetDirectory,
  verifyRemoteGameSymbolAssets,
  writeGameSymbolVerificationManifest,
} from './verifyGameSymbolAssets.mjs'

const temporaryRoots = []

async function temporaryRoot() {
  const root = await mkdtemp(join(tmpdir(), 'gamesymbol-pages-'))
  temporaryRoots.push(root)
  return root
}

async function writeCurrentAssets(directory, gameVersion, marker) {
  await mkdir(directory, { recursive: true })
  const dataset = {
    schemaVersion: 3,
    source: { gameVersion },
    binaries: {
      server: {
        windows: {
          path: 'game/bin/win64/server.dll',
          sha256: '1'.repeat(64),
          md5: '2'.repeat(32),
          crc32: '3'.repeat(8),
          crc64: '4'.repeat(16),
          size: 123,
        },
      },
    },
    records: [{ marker }],
  }
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const digest = createHash('sha256').update(bytes).digest('hex')
  const url = `${gameVersion}.${digest}.json`
  await writeFile(join(directory, url), bytes)
  await writeFile(join(directory, 'index.json'), JSON.stringify({
    schemaVersion: 4,
    versions: [{
      gameVersion,
      url,
      sha256: digest,
      size: bytes.byteLength,
      snapshotSchemaVersion: 5,
      fileCount: 1,
      lastPublishTime: '2026-07-28T00:00:00Z',
    }],
  }))
  return { bytes, digest, url }
}

async function writeLegacySnapshot(directory, gameVersion, marker) {
  await mkdir(directory, { recursive: true })
  const dataset = {
    schemaVersion: 2,
    source: { gameVersion },
    records: [{ marker }],
  }
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const digest = createHash('sha256').update(bytes).digest('hex')
  const url = `${gameVersion}.${digest}.json`
  await writeFile(join(directory, url), bytes)
  return { bytes, digest, url }
}

async function writeIndex(directory, gameVersion, asset) {
  await writeFile(join(directory, 'index.json'), JSON.stringify({
    schemaVersion: 4,
    versions: [{
      gameVersion,
      url: asset.url,
      sha256: asset.digest,
      size: asset.bytes.byteLength,
      snapshotSchemaVersion: 4,
      fileCount: 1,
      lastPublishTime: '2026-07-28T00:00:00Z',
    }],
  }))
}

afterEach(async () => {
  vi.unstubAllGlobals()
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('immutable game-symbol asset verification', () => {
  it('verifies index v4 metadata against the exact snapshot bytes', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const asset = await writeCurrentAssets(current, '14172', '最终字节')

    await expect(verifyGameSymbolAssetDirectory(current)).resolves.toEqual(expect.objectContaining({ snapshotCount: 1 }))
    await writeFile(join(current, asset.url), Buffer.concat([asset.bytes, Buffer.from('\n')]))
    await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/filename SHA-256/)
  })

  it('keeps old digests and adds a new file when the same game version changes', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const first = await writeCurrentAssets(current, '14172', 'first')
    await mergeImmutableArchive(current, archive)

    await rm(current, { recursive: true, force: true })
    const second = await writeCurrentAssets(current, '14172', 'second')
    const result = await mergeImmutableArchive(current, archive)

    expect(first.url).not.toBe(second.url)
    expect(result.added).toBe(1)
    expect(result.archived).toBe(2)
    expect(await readdir(archive)).toEqual(expect.arrayContaining([first.url, second.url]))
    expect(await readFile(join(current, first.url))).toEqual(first.bytes)
    expect(await readFile(join(current, second.url))).toEqual(second.bytes)
  })

  it('preserves legacy schema v2 snapshots as immutable archive history', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const legacy = await writeLegacySnapshot(archive, '14172', 'legacy')
    const latest = await writeCurrentAssets(current, '14172', 'latest')

    const result = await mergeImmutableArchive(current, archive)

    expect(result.added).toBe(1)
    expect(result.archived).toBe(2)
    expect(await readFile(join(archive, latest.url))).toEqual(latest.bytes)
    expect(await readFile(join(current, legacy.url))).toEqual(legacy.bytes)
  })

  it('rejects legacy schema v2 snapshots when the current index points to them', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const legacy = await writeLegacySnapshot(current, '14172', 'legacy')
    await writeIndex(current, '14172', legacy)

    await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/snapshot body game version or schema/)
  })

  it('rejects any modification of an archived content-addressed snapshot', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const asset = await writeCurrentAssets(current, '14172', 'first')
    await mergeImmutableArchive(current, archive)
    await writeFile(join(archive, asset.url), Buffer.from('tampered', 'utf8'))

    await expect(mergeImmutableArchive(current, archive)).rejects.toThrow(/filename SHA-256/)
  })

  it('waits for this build index and verifies every current and historical CDN body', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const manifestPath = join(root, 'verification.json')
    const legacy = await writeLegacySnapshot(archive, '14172', 'legacy')
    const first = await writeCurrentAssets(current, '14172', 'first')
    const staleIndex = await readFile(join(current, 'index.json'))
    await mergeImmutableArchive(current, archive)
    await rm(current, { recursive: true, force: true })
    const second = await writeCurrentAssets(current, '14172', 'second')
    await mergeImmutableArchive(current, archive)
    const manifest = await writeGameSymbolVerificationManifest(current, manifestPath)
    const currentIndex = await readFile(join(current, 'index.json'))

    let indexRequests = 0
    const fetchMock = vi.fn(async (input) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/index.json')) {
        indexRequests += 1
        return new Response(indexRequests === 1 ? staleIndex : currentIndex)
      }
      return new Response(await readFile(join(current, url.pathname.split('/').at(-1))))
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(verifyRemoteGameSymbolAssets('https://example.test/gamesymbols/', manifest, {
      attempts: 2,
      delayMs: 0,
      batchSize: 2,
    })).resolves.toEqual(expect.objectContaining({ verified: 3 }))
    expect(indexRequests).toBe(2)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(legacy.url))).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(first.url))).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(second.url))).toBe(true)
  })

  it('fails CDN verification when an archived digest is no longer reachable', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const first = await writeCurrentAssets(current, '14172', 'first')
    await mergeImmutableArchive(current, archive)
    await rm(current, { recursive: true, force: true })
    await writeCurrentAssets(current, '14172', 'second')
    await mergeImmutableArchive(current, archive)
    const manifest = await writeGameSymbolVerificationManifest(current, join(root, 'verification.json'))
    const currentIndex = await readFile(join(current, 'index.json'))

    vi.stubGlobal('fetch', vi.fn(async (input) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/index.json')) return new Response(currentIndex)
      if (url.pathname.endsWith(first.url)) return new Response(null, { status: 404 })
      return new Response(await readFile(join(current, url.pathname.split('/').at(-1))))
    }))

    await expect(verifyRemoteGameSymbolAssets('https://example.test/gamesymbols/', manifest, {
      attempts: 1,
      delayMs: 0,
    })).rejects.toThrow(/failed after 1 attempts/)
  })
})
