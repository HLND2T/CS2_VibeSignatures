import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { compareGameVersions, loadLegacyInputs } from './legacyInputs.mjs'
import { verifyGameSymbolAssetDirectory, verifySnapshotBytes } from './verifyGameSymbolAssets.mjs'

const SNAPSHOT_FILE_PATTERN = /^(\d{4,10}[a-z]?)\.([0-9a-f]{64})\.json$/
const GAMESYMBOLS_PREFIX = 'gamesymbols/'
const INDEX_FILE_NAME = 'index.json'
const MERGE_RECEIPT_SCHEMA_VERSION = 1
const CURRENT_DATASET_SCHEMA_VERSION = 3

class LegacyMergeError extends Error {}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function archivedSnapshots(archiveDirectory) {
  const root = resolve(archiveDirectory)
  const entries = await readdir(root, { withFileTypes: true })
  const records = []
  for (const entry of entries) {
    if (!entry.isFile()) throw new LegacyMergeError(`${join(root, entry.name)}: only regular files are allowed`)
    if (!SNAPSHOT_FILE_PATTERN.test(entry.name)) throw new LegacyMergeError(`${join(root, entry.name)}: unexpected archive file`)
    const bytes = await readFile(join(root, entry.name))
    records.push({ fileName: entry.name, bytes, size: bytes.byteLength, sha256: sha256(bytes) })
  }
  records.sort((left, right) => left.fileName.localeCompare(right.fileName))
  return { root, records }
}

function verifyArchiveInventory(records, manifest, source) {
  const expected = manifest.gamesymbols.files
    .filter((item) => item.path.startsWith(GAMESYMBOLS_PREFIX))
    .map((item) => ({ fileName: item.path.slice(GAMESYMBOLS_PREFIX.length), size: item.size, sha256: item.sha256 }))
  if (expected.length !== records.length) {
    throw new LegacyMergeError(`${source}: archive file count ${records.length} does not match manifest ${expected.length}`)
  }
  records.forEach((record, index) => {
    const entry = expected[index]
    if (!entry || record.fileName !== entry.fileName || record.size !== entry.size || record.sha256 !== entry.sha256) {
      throw new LegacyMergeError(`${source}: archive file ${record.fileName} does not match the manifest inventory`)
    }
  })
}

async function copyOrVerify(sourceBytes, targetPath) {
  let existing
  try {
    existing = await readFile(targetPath)
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      await writeFile(targetPath, sourceBytes, { flag: 'wx' })
      return
    }
    throw error
  }
  if (!sourceBytes.equals(existing)) {
    throw new LegacyMergeError(`${targetPath}: historical snapshot conflicts with existing bytes`)
  }
}

function verifyArchiveAgainstManifest(manifest, archive) {
  verifyArchiveInventory(archive.records, manifest, archive.root)
  for (const entry of manifest.gamesymbols.selected) {
    const record = archive.records.find((item) => item.fileName === entry.url)
    if (!record) throw new LegacyMergeError(`${archive.root}: selected snapshot ${entry.url} is absent from the archive`)
    verifySnapshotBytes(entry.url, record.bytes, join(archive.root, entry.url), entry, CURRENT_DATASET_SCHEMA_VERSION)
  }
}

export async function validateLegacyArchive({ manifestPath, archiveDirectory }) {
  const manifest = await loadLegacyInputs(manifestPath)
  const archive = await archivedSnapshots(archiveDirectory)
  verifyArchiveAgainstManifest(manifest, archive)
  return {
    historicalFileCount: manifest.gamesymbols.files.length,
    selectedCount: manifest.gamesymbols.selected.length,
  }
}

function buildMergedIndex(currentIndex, selectedEntries) {
  const versions = currentIndex.versions.map((entry) => ({ ...entry }))
  const existingVersions = new Set(versions.map((entry) => entry.gameVersion))
  const added = []
  for (const entry of selectedEntries) {
    if (existingVersions.has(entry.gameVersion)) continue
    existingVersions.add(entry.gameVersion)
    versions.push({ ...entry })
    added.push(entry.url)
  }
  versions.sort((left, right) => compareGameVersions(left.gameVersion, right.gameVersion))
  return { index: { schemaVersion: 4, versions }, added }
}

function assertHistoricalFilesPresent(verifiedSnapshots, manifest, source) {
  const byName = new Map(verifiedSnapshots.map((snapshot) => [snapshot.fileName, snapshot]))
  for (const item of manifest.gamesymbols.files) {
    const fileName = item.path.slice(GAMESYMBOLS_PREFIX.length)
    const record = byName.get(fileName)
    if (!record || record.size !== item.size || record.sha256 !== item.sha256) {
      throw new LegacyMergeError(`${source}: merged output is missing historical file ${item.path}`)
    }
  }
}

export async function mergeLegacyGameSymbols({ directory, archiveDirectory, manifestPath, receiptPath }) {
  const directoryRoot = resolve(directory)
  const manifestRaw = await readFile(resolve(manifestPath))
  const manifest = await loadLegacyInputs(manifestPath)

  const archive = await archivedSnapshots(archiveDirectory)
  verifyArchiveAgainstManifest(manifest, archive)

  const current = await verifyGameSymbolAssetDirectory(directoryRoot)
  const parent = dirname(directoryRoot)
  const staging = await mkdtemp(join(parent, '.legacy-merge-'))
  const backup = await mkdtemp(join(parent, '.legacy-backup-'))
  await rm(backup, { recursive: true, force: true })
  try {
    for (const entry of await readdir(directoryRoot, { withFileTypes: true })) {
      if (entry.name === INDEX_FILE_NAME) continue
      if (!entry.isFile()) throw new LegacyMergeError(`${join(directoryRoot, entry.name)}: only regular files are allowed`)
      await copyOrVerify(await readFile(join(directoryRoot, entry.name)), join(staging, entry.name))
    }
    for (const record of archive.records) await copyOrVerify(record.bytes, join(staging, record.fileName))

    const merged = buildMergedIndex(current.index, manifest.gamesymbols.selected)
    await writeFile(join(staging, INDEX_FILE_NAME), JSON.stringify(merged.index))

    const verified = await verifyGameSymbolAssetDirectory(staging)
    assertHistoricalFilesPresent(verified.snapshots, manifest, staging)

    await rename(directoryRoot, backup)
    try {
      await rename(staging, directoryRoot)
    } catch (error) {
      await rename(backup, directoryRoot)
      throw error
    }
    await rm(backup, { recursive: true, force: true })

    const receipt = {
      schema_version: MERGE_RECEIPT_SCHEMA_VERSION,
      manifest_sha256: sha256(manifestRaw),
      archive_commit: manifest.archiveCommit,
      repository: manifest.repository,
      historical_file_count: manifest.gamesymbols.files.length,
      added_index_entries: merged.added.sort(),
      current_versions: current.index.versions.map((entry) => entry.gameVersion),
      merged_versions: verified.index.versions.map((entry) => entry.gameVersion),
    }
    if (receiptPath) await writeFile(resolve(receiptPath), JSON.stringify(receipt))
    return receipt
  } catch (error) {
    await rm(staging, { recursive: true, force: true })
    throw error
  }
}

function argumentValue(args, name) {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  if (index + 1 >= args.length) throw new LegacyMergeError(`${name} requires a value`)
  return args[index + 1]
}

async function main(args) {
  const directory = argumentValue(args, '--directory')
  const archiveDirectory = argumentValue(args, '--archive')
  const manifestPath = argumentValue(args, '--manifest')
  const receiptPath = argumentValue(args, '--receipt')
  if (!archiveDirectory || !manifestPath) {
    throw new LegacyMergeError('Expected --archive and --manifest')
  }
  if (args.includes('--validate-archive')) {
    const result = await validateLegacyArchive({ manifestPath, archiveDirectory })
    console.log(
      `Validated ${result.historicalFileCount} archived game-symbol files and ${result.selectedCount} selected snapshots.`,
    )
    return
  }
  if (!directory) throw new LegacyMergeError('Expected --directory for a merge')
  const receipt = await mergeLegacyGameSymbols({ directory, archiveDirectory, manifestPath, receiptPath })
  console.log(
    `Merged ${receipt.historical_file_count} historical game-symbol files; ${receipt.added_index_entries.length} index entries added.`,
  )
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  })
}
