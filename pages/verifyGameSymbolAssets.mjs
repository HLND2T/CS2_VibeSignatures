import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { copyFile, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const GAME_VERSION_PATTERN = /^\d{4,10}[a-z]?$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const MD5_PATTERN = /^[0-9a-f]{32}$/
const CRC32_PATTERN = /^[0-9a-f]{8}$/
const CRC64_PATTERN = /^[0-9a-f]{16}$/
const SNAPSHOT_FILE_PATTERN = /^(\d{4,10}[a-z]?)\.([0-9a-f]{64})\.json$/
const LEGACY_DATASET_SCHEMA_VERSION = 2
const CURRENT_DATASET_SCHEMA_VERSION = 3
const SUPPORTED_DATASET_SCHEMA_VERSIONS = new Set([
  LEGACY_DATASET_SCHEMA_VERSION,
  CURRENT_DATASET_SCHEMA_VERSION,
])

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function parseJson(bytes, source) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch (error) {
    throw new Error(`${source}: invalid UTF-8 JSON`, { cause: error })
  }
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function validateGameSymbolIndex(value, source = 'gamesymbols/index.json') {
  if (!isObject(value) || value.schemaVersion !== 4 || !Array.isArray(value.versions)) {
    throw new Error(`${source}: expected index schema v4`)
  }

  const seenGameVersions = new Set()
  const seenUrls = new Set()
  for (const [index, entry] of value.versions.entries()) {
    const entrySource = `${source}: versions[${index}]`
    if (!isObject(entry)) throw new Error(`${entrySource} must be an object`)
    if (typeof entry.gameVersion !== 'string' || !GAME_VERSION_PATTERN.test(entry.gameVersion)) {
      throw new Error(`${entrySource}.gameVersion is invalid`)
    }
    if (typeof entry.sha256 !== 'string' || !SHA256_PATTERN.test(entry.sha256)) {
      throw new Error(`${entrySource}.sha256 is invalid`)
    }
    const expectedUrl = `${entry.gameVersion}.${entry.sha256}.json`
    if (entry.url !== expectedUrl) {
      throw new Error(`${entrySource}.url must be ${expectedUrl}`)
    }
    if (!Number.isInteger(entry.size) || entry.size <= 0) throw new Error(`${entrySource}.size must be a positive integer`)
    if (!Number.isInteger(entry.snapshotSchemaVersion)) throw new Error(`${entrySource}.snapshotSchemaVersion must be an integer`)
    if (!Number.isInteger(entry.fileCount) || entry.fileCount < 0) throw new Error(`${entrySource}.fileCount must be a non-negative integer`)
    if (typeof entry.lastPublishTime !== 'string') throw new Error(`${entrySource}.lastPublishTime must be a string`)
    if (seenGameVersions.has(entry.gameVersion)) throw new Error(`${source}: duplicate gameVersion ${entry.gameVersion}`)
    if (seenUrls.has(entry.url)) throw new Error(`${source}: duplicate url ${entry.url}`)
    seenGameVersions.add(entry.gameVersion)
    seenUrls.add(entry.url)
  }
  return value
}

function validateBinaryMetadata(value, source) {
  if (!isObject(value)) throw new Error(`${source}: binary metadata must be an object`)
  if (typeof value.path !== 'string' || value.path.length === 0) throw new Error(`${source}.path is invalid`)
  if (typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256)) throw new Error(`${source}.sha256 is invalid`)
  if (typeof value.md5 !== 'string' || !MD5_PATTERN.test(value.md5)) throw new Error(`${source}.md5 is invalid`)
  if (typeof value.crc32 !== 'string' || !CRC32_PATTERN.test(value.crc32)) throw new Error(`${source}.crc32 is invalid`)
  if (typeof value.crc64 !== 'string' || !CRC64_PATTERN.test(value.crc64)) throw new Error(`${source}.crc64 is invalid`)
  if (!Number.isInteger(value.size) || value.size < 0) throw new Error(`${source}.size must be a non-negative integer`)
}

function validateGameSymbolDataset(value, source, gameVersion, requiredSchemaVersion) {
  if (
    !isObject(value)
    || !SUPPORTED_DATASET_SCHEMA_VERSIONS.has(value.schemaVersion)
    || !isObject(value.source)
    || value.source.gameVersion !== gameVersion
    || (requiredSchemaVersion !== undefined && value.schemaVersion !== requiredSchemaVersion)
  ) {
    throw new Error(`${source}: snapshot body game version or schema is invalid`)
  }
  if (value.schemaVersion === LEGACY_DATASET_SCHEMA_VERSION) return
  if (!isObject(value.binaries)) throw new Error(`${source}: binaries must be an object`)
  for (const [module, platforms] of Object.entries(value.binaries)) {
    if (!isObject(platforms)) throw new Error(`${source}: binaries.${module} must be an object`)
    for (const [platform, metadata] of Object.entries(platforms)) {
      if (platform !== 'windows' && platform !== 'linux') throw new Error(`${source}: binaries.${module}.${platform} is unsupported`)
      validateBinaryMetadata(metadata, `${source}: binaries.${module}.${platform}`)
    }
  }
}

export function validateGameSymbolVerificationManifest(value, source = 'game-symbol-verification.json') {
  if (!isObject(value) || value.schemaVersion !== 1 || !isObject(value.index) || !Array.isArray(value.snapshots)) {
    throw new Error(`${source}: expected verification manifest schema v1`)
  }
  if (typeof value.index.sha256 !== 'string' || !SHA256_PATTERN.test(value.index.sha256)) {
    throw new Error(`${source}: index.sha256 is invalid`)
  }
  if (!Number.isInteger(value.index.size) || value.index.size <= 0) throw new Error(`${source}: index.size must be a positive integer`)

  const seenUrls = new Set()
  for (const [index, snapshot] of value.snapshots.entries()) {
    const snapshotSource = `${source}: snapshots[${index}]`
    if (!isObject(snapshot)) throw new Error(`${snapshotSource} must be an object`)
    const match = typeof snapshot.url === 'string' ? SNAPSHOT_FILE_PATTERN.exec(snapshot.url) : null
    if (!match) throw new Error(`${snapshotSource}.url is invalid`)
    if (snapshot.gameVersion !== match[1]) throw new Error(`${snapshotSource}.gameVersion does not match url`)
    if (snapshot.sha256 !== match[2]) throw new Error(`${snapshotSource}.sha256 does not match url`)
    if (!Number.isInteger(snapshot.size) || snapshot.size <= 0) throw new Error(`${snapshotSource}.size must be a positive integer`)
    if (seenUrls.has(snapshot.url)) throw new Error(`${source}: duplicate snapshot url ${snapshot.url}`)
    seenUrls.add(snapshot.url)
  }
  return value
}

function verifySnapshotBytes(fileName, bytes, source, expectedEntry, requiredSchemaVersion) {
  const match = SNAPSHOT_FILE_PATTERN.exec(fileName)
  if (!match) throw new Error(`${source}: snapshot filename must be <gameVersion>.<sha256>.json`)
  const actualSha256 = sha256(bytes)
  if (actualSha256 !== match[2]) throw new Error(`${source}: filename SHA-256 does not match content bytes`)
  const value = parseJson(bytes, source)
  validateGameSymbolDataset(value, source, match[1], requiredSchemaVersion)
  if (expectedEntry) {
    if (fileName !== expectedEntry.url) throw new Error(`${source}: index URL does not match filename`)
    if (bytes.byteLength !== expectedEntry.size) {
      throw new Error(`${source}: size ${bytes.byteLength} does not match index size ${expectedEntry.size}`)
    }
    if (actualSha256 !== expectedEntry.sha256) throw new Error(`${source}: content SHA-256 does not match index`)
  }
  return { fileName, gameVersion: match[1], sha256: actualSha256, size: bytes.byteLength }
}

async function snapshotFileNames(directory, allowIndex) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    if (!entry.isFile()) throw new Error(`${join(directory, entry.name)}: only files are allowed`)
    if (allowIndex && entry.name === 'index.json') continue
    if (!SNAPSHOT_FILE_PATTERN.test(entry.name)) throw new Error(`${join(directory, entry.name)}: unexpected archive file`)
    files.push(entry.name)
  }
  return files.sort()
}

async function verifySnapshotDirectory(directory, allowIndex) {
  const verified = new Map()
  for (const fileName of await snapshotFileNames(directory, allowIndex)) {
    const filePath = join(directory, fileName)
    const bytes = await readFile(filePath)
    verified.set(fileName, verifySnapshotBytes(fileName, bytes, filePath))
  }
  return verified
}

export async function verifyGameSymbolAssetDirectory(directory) {
  const root = resolve(directory)
  const indexPath = join(root, 'index.json')
  const indexBytes = await readFile(indexPath)
  const index = validateGameSymbolIndex(parseJson(indexBytes, indexPath), indexPath)
  const snapshots = await verifySnapshotDirectory(root, true)
  for (const entry of index.versions) {
    const filePath = join(root, entry.url)
    const bytes = await readFile(filePath)
    verifySnapshotBytes(entry.url, bytes, filePath, entry, CURRENT_DATASET_SCHEMA_VERSION)
    if (!snapshots.has(entry.url)) throw new Error(`${filePath}: indexed snapshot is missing from the asset inventory`)
  }
  return {
    index,
    indexSha256: sha256(indexBytes),
    indexSize: indexBytes.byteLength,
    snapshots: [...snapshots.values()],
    snapshotCount: snapshots.size,
  }
}

export async function writeGameSymbolVerificationManifest(directory, manifestPath) {
  const result = await verifyGameSymbolAssetDirectory(directory)
  const manifest = {
    schemaVersion: 1,
    index: {
      sha256: result.indexSha256,
      size: result.indexSize,
    },
    snapshots: result.snapshots
      .map(({ fileName, gameVersion, sha256: snapshotSha256, size }) => ({
        gameVersion,
        url: fileName,
        sha256: snapshotSha256,
        size,
      }))
      .sort((left, right) => left.url.localeCompare(right.url)),
  }
  const outputPath = resolve(manifestPath)
  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(outputPath, JSON.stringify(manifest))
  return manifest
}

export async function mergeImmutableArchive(currentDirectory, archiveDirectory) {
  const currentRoot = resolve(currentDirectory)
  const archiveRoot = resolve(archiveDirectory)
  const { index } = await verifyGameSymbolAssetDirectory(currentRoot)
  await mkdir(archiveRoot, { recursive: true })
  await verifySnapshotDirectory(archiveRoot, false)

  let added = 0
  for (const entry of index.versions) {
    const sourcePath = join(currentRoot, entry.url)
    const targetPath = join(archiveRoot, entry.url)
    const sourceBytes = await readFile(sourcePath)
    try {
      const targetBytes = await readFile(targetPath)
      if (!sourceBytes.equals(targetBytes)) throw new Error(`${targetPath}: immutable snapshot already exists with different bytes`)
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        await copyFile(sourcePath, targetPath, fsConstants.COPYFILE_EXCL)
        added += 1
      } else {
        throw error
      }
    }
  }

  const archiveSnapshots = await verifySnapshotDirectory(archiveRoot, false)
  for (const fileName of archiveSnapshots.keys()) {
    const sourcePath = join(archiveRoot, fileName)
    const targetPath = join(currentRoot, fileName)
    try {
      const targetBytes = await readFile(targetPath)
      const sourceBytes = await readFile(sourcePath)
      if (!sourceBytes.equals(targetBytes)) throw new Error(`${targetPath}: build output conflicts with immutable archive`)
    } catch (error) {
      if (error && error.code === 'ENOENT') await copyFile(sourcePath, targetPath, fsConstants.COPYFILE_EXCL)
      else throw error
    }
  }

  const result = await verifyGameSymbolAssetDirectory(currentRoot)
  return { added, archived: archiveSnapshots.size, ...result }
}

async function fetchBytes(url) {
  const response = await fetch(url, {
    cache: 'no-store',
    headers: {
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache',
    },
  })
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status} ${response.statusText}`)
  return new Uint8Array(await response.arrayBuffer())
}

async function verifyRemoteSnapshotBatch(root, snapshots) {
  await Promise.all(snapshots.map(async (snapshot) => {
    const assetUrl = new URL(snapshot.url, root)
    const bytes = await fetchBytes(assetUrl)
    verifySnapshotBytes(snapshot.url, bytes, assetUrl.href, snapshot)
  }))
}

export async function verifyRemoteGameSymbolAssets(baseUrl, expectedManifest, { attempts = 12, delayMs = 5000, batchSize = 4 } = {}) {
  const root = new URL(baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`)
  const manifest = validateGameSymbolVerificationManifest(expectedManifest)
  let lastError
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const indexUrl = new URL(`index.json?verify=${Date.now()}-${attempt}`, root)
      const indexBytes = await fetchBytes(indexUrl)
      const actualIndexSha256 = sha256(indexBytes)
      if (indexBytes.byteLength !== manifest.index.size || actualIndexSha256 !== manifest.index.sha256) {
        throw new Error(`${indexUrl.href}: deployed index does not match this workflow's build`)
      }
      const index = validateGameSymbolIndex(parseJson(indexBytes, indexUrl.href), indexUrl.href)
      const snapshotsByUrl = new Map(manifest.snapshots.map((snapshot) => [snapshot.url, snapshot]))
      for (const entry of index.versions) {
        const snapshot = snapshotsByUrl.get(entry.url)
        if (!snapshot || snapshot.sha256 !== entry.sha256 || snapshot.size !== entry.size) {
          throw new Error(`${indexUrl.href}: indexed snapshot ${entry.url} is absent from the expected artifact manifest`)
        }
      }
      for (let offset = 0; offset < manifest.snapshots.length; offset += batchSize) {
        await verifyRemoteSnapshotBatch(root, manifest.snapshots.slice(offset, offset + batchSize))
      }
      return { index, verified: manifest.snapshots.length }
    } catch (error) {
      lastError = error
      if (attempt < attempts) await new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs))
    }
  }
  throw new Error(`Remote game-symbol verification failed after ${attempts} attempts`, { cause: lastError })
}

function argumentValue(args, name) {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  if (index + 1 >= args.length) throw new Error(`${name} requires a value`)
  return args[index + 1]
}

async function main(args) {
  const directory = argumentValue(args, '--directory')
  const archive = argumentValue(args, '--archive')
  const baseUrl = argumentValue(args, '--base-url')
  const manifestPath = argumentValue(args, '--manifest')
  const writeManifestPath = argumentValue(args, '--write-manifest')
  if (directory && baseUrl) throw new Error('Choose either --directory or --base-url')
  if (!directory && !baseUrl) throw new Error('Expected --directory or --base-url')
  if (archive && !directory) throw new Error('--archive requires --directory')
  if (writeManifestPath && !directory) throw new Error('--write-manifest requires --directory')
  if (manifestPath && !baseUrl) throw new Error('--manifest requires --base-url')
  if (baseUrl && !manifestPath) throw new Error('--base-url requires --manifest')

  if (directory) {
    const result = archive
      ? await mergeImmutableArchive(directory, archive)
      : await verifyGameSymbolAssetDirectory(directory)
    if (writeManifestPath) await writeGameSymbolVerificationManifest(directory, writeManifestPath)
    console.log(`Verified ${result.snapshotCount} game-symbol snapshot files${archive ? `; archive contains ${result.archived} files (${result.added} added)` : ''}.`)
    return
  }

  const manifestSource = resolve(manifestPath)
  const manifest = validateGameSymbolVerificationManifest(parseJson(await readFile(manifestSource), manifestSource), manifestSource)
  const result = await verifyRemoteGameSymbolAssets(baseUrl, manifest)
  console.log(`Verified ${result.verified} game-symbol snapshots from ${baseUrl}.`)
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
}
