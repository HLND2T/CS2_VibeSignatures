import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { canonicalJsonBytes } from './legacyInputs.mjs'
import { mergeLegacyGameSymbols, validateLegacyArchive } from './mergeLegacyGameSymbols.mjs'

const temporaryRoots = []

async function temporaryRoot() {
  const root = await mkdtemp(join(tmpdir(), 'legacy-merge-'))
  temporaryRoots.push(root)
  return root
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function dataset(gameVersion, marker, schemaVersion) {
  if (schemaVersion === 2) return { schemaVersion: 2, source: { gameVersion }, records: [{ marker }] }
  return {
    schemaVersion: 3,
    source: { gameVersion, snapshotSchemaVersion: 5, fileCount: 1, lastPublishTime: '2026-08-31T10:18:36Z' },
    binaries: {},
    modules: [],
    records: [{ marker }],
  }
}

async function writeSnapshot(directory, gameVersion, marker, schemaVersion = 3) {
  const bytes = Buffer.from(JSON.stringify(dataset(gameVersion, marker, schemaVersion)), 'utf8')
  const digest = sha256(bytes)
  const url = `${gameVersion}.${digest}.json`
  await writeFile(join(directory, url), bytes)
  return { gameVersion, url, bytes, size: bytes.byteLength, sha256: digest }
}

async function writeIndex(directory, assets) {
  const versions = assets.map((asset) => ({
    gameVersion: asset.gameVersion,
    url: asset.url,
    sha256: asset.sha256,
    size: asset.size,
    snapshotSchemaVersion: 5,
    fileCount: 1,
    lastPublishTime: '2026-08-31T10:18:36Z',
  }))
  await writeFile(join(directory, 'index.json'), JSON.stringify({ schemaVersion: 4, versions }))
}

function fileRecord(asset) {
  return { path: `gamesymbols/${asset.url}`, size: asset.size, sha256: asset.sha256 }
}

function selectedRecord(asset, overrides = {}) {
  return {
    gameVersion: asset.gameVersion,
    url: asset.url,
    sha256: asset.sha256,
    size: asset.size,
    fileCount: 1,
    snapshotSchemaVersion: 5,
    lastPublishTime: '2026-08-31T10:18:36Z',
    ...overrides,
  }
}

function buildManifest({ files, selected, gamedataVersions }) {
  return {
    schemaVersion: 1,
    repository: 'HLND2T/CS2_VibeSignatures',
    archiveCommit: 'f'.repeat(40),
    gamesymbols: { files, selected },
    gamedata: {
      versions: gamedataVersions.map((gameVersion) => ({
        gameVersion,
        files: [{ path: `gamedata/${gameVersion}/Plugin/data.jsonc`, size: 10, sha256: 'd'.repeat(64) }],
      })),
    },
    excluded: [],
    importProvenance: {
      sourceArchiveCommit: '1'.repeat(40),
      importBaseCommit: '2'.repeat(40),
      selectedBasis: {
        kind: 'pre-switch-source-reproduction',
        sourceCommit: '3'.repeat(40),
        indexSha256: 'e'.repeat(64),
        indexSize: 10,
      },
      gamedataSource: {
        kind: 'release-assets',
        commit: null,
        subtree: 'gamedata',
        inventorySha256: 'c'.repeat(64),
        selectionReason: 'release-assets',
        differences: [],
      },
      releases: gamedataVersions.map((tag) => ({
        tag,
        releaseId: 1,
        assetId: 2,
        assetName: `gamedata-${tag}.7z`,
        assetSize: 3,
        sha256: '9'.repeat(64),
        apiDigest: null,
      })),
    },
  }
}

async function readTree(directory) {
  const names = (await readdir(directory)).sort()
  const entries = {}
  for (const name of names) entries[name] = (await readFile(join(directory, name))).toString('base64')
  return entries
}

describe('legacy archive validation', () => {
  it('accepts an archive whose bytes match the manifest', async () => {
    const { mkdir } = await import('node:fs/promises')
    const root = await temporaryRoot()
    const archive = join(root, 'archive', 'gamesymbols')
    await mkdir(archive, { recursive: true })
    const asset = await writeSnapshot(archive, '14178b', 'historical')
    const manifest = buildManifest({
      files: [fileRecord(asset)],
      selected: [selectedRecord(asset)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))
    await expect(validateLegacyArchive({ manifestPath, archiveDirectory: archive })).resolves.toEqual({
      historicalFileCount: 1,
      selectedCount: 1,
    })
  })

  it('rejects a selected snapshot whose body is not indexable', async () => {
    const { mkdir } = await import('node:fs/promises')
    const root = await temporaryRoot()
    const archive = join(root, 'archive', 'gamesymbols')
    await mkdir(archive, { recursive: true })
    const legacy = await writeSnapshot(archive, '14172', 'legacy', 2)
    const manifest = buildManifest({
      files: [fileRecord(legacy)],
      selected: [selectedRecord(legacy)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))
    await expect(validateLegacyArchive({ manifestPath, archiveDirectory: archive })).rejects.toThrow(
      /snapshot body game version or schema/,
    )
  })
})

describe('historical game-symbol merge', () => {
  it('copies every archived digest and adds missing index versions without overriding current ones', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })

    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const archivedNew = await writeSnapshot(archive, '14178b', 'historical-new')
    const archivedLegacy = await writeSnapshot(archive, '14172', 'historical-legacy', 2)
    const archivedSameVersion = await writeSnapshot(archive, '14179', 'archived-14179')

    const manifest = buildManifest({
      files: [fileRecord(archivedNew), fileRecord(archivedLegacy), fileRecord(archivedSameVersion)].sort((left, right) =>
        left.path.localeCompare(right.path),
      ),
      selected: [selectedRecord(archivedNew), selectedRecord(archivedSameVersion)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))

    const receiptPath = join(root, 'receipt.json')
    await mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath })

    expect(await readFile(join(directory, archivedNew.url))).toEqual(archivedNew.bytes)
    expect(await readFile(join(directory, archivedLegacy.url))).toEqual(archivedLegacy.bytes)
    expect(await readFile(join(directory, archivedSameVersion.url))).toEqual(archivedSameVersion.bytes)
    const index = JSON.parse((await readFile(join(directory, 'index.json'))).toString('utf8'))
    const versions = index.versions.map((entry) => entry.gameVersion).sort()
    expect(versions).toEqual(['14178b', '14179'])
    expect(index.versions.find((entry) => entry.gameVersion === '14179').url).toBe(currentAsset.url)
    expect(index.versions.find((entry) => entry.gameVersion === '14178b').url).toBe(archivedNew.url)
    expect(JSON.parse((await readFile(receiptPath)).toString('utf8')).added_index_entries).toEqual([archivedNew.url])
  })

  it('is idempotent across repeated merges', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })
    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const archivedNew = await writeSnapshot(archive, '14178b', 'historical-new')
    const manifest = buildManifest({
      files: [fileRecord(archivedNew)],
      selected: [selectedRecord(archivedNew)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))

    await mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'a.json') })
    const first = await readTree(directory)
    await mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'b.json') })
    expect(await readTree(directory)).toEqual(first)
  })

  it('rejects archived bytes that no longer match the manifest inventory', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })
    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const archivedNew = await writeSnapshot(archive, '14178b', 'historical-new')
    const manifest = buildManifest({
      files: [fileRecord(archivedNew)],
      selected: [selectedRecord(archivedNew)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))
    await writeFile(join(archive, archivedNew.url), Buffer.from('tampered'))

    await expect(
      mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'r.json') }),
    ).rejects.toThrow(/does not match the manifest inventory/)
  })

  it('rejects a selected legacy schema v2 snapshot', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })
    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const legacy = await writeSnapshot(archive, '14172', 'legacy', 2)
    const manifest = buildManifest({
      files: [fileRecord(legacy)],
      selected: [selectedRecord(legacy)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))

    await expect(
      mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'r.json') }),
    ).rejects.toThrow(/snapshot body game version or schema/)
  })

  it('rejects an index entry whose metadata disagrees with the snapshot body', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })
    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const archivedNew = await writeSnapshot(archive, '14178b', 'historical-new')
    const manifest = buildManifest({
      files: [fileRecord(archivedNew)],
      selected: [selectedRecord(archivedNew, { fileCount: 2 })],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))

    await expect(
      mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'r.json') }),
    ).rejects.toThrow(/file count does not match index entry/)
  })

  it('rejects a conflicting same-path snapshot present in the build output', async () => {
    const root = await temporaryRoot()
    const directory = join(root, 'dist', 'gamesymbols')
    const archive = join(root, 'archive', 'gamesymbols')
    const { mkdir } = await import('node:fs/promises')
    await mkdir(directory, { recursive: true })
    await mkdir(archive, { recursive: true })
    const currentAsset = await writeSnapshot(directory, '14179', 'current')
    await writeIndex(directory, [currentAsset])
    const archivedNew = await writeSnapshot(archive, '14178b', 'historical-new')
    await writeFile(join(directory, archivedNew.url), Buffer.from('conflicting-bytes'))
    const manifest = buildManifest({
      files: [fileRecord(archivedNew)],
      selected: [selectedRecord(archivedNew)],
      gamedataVersions: ['14178b'],
    })
    const manifestPath = join(root, 'legacy-inputs.json')
    await writeFile(manifestPath, canonicalJsonBytes(manifest))

    await expect(
      mergeLegacyGameSymbols({ directory, archiveDirectory: archive, manifestPath, receiptPath: join(root, 'r.json') }),
    ).rejects.toThrow(/conflicts with existing bytes|filename SHA-256 does not match content bytes/)
  })
})
