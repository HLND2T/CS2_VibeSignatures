import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const GAME_VERSION_PATTERN = /^\d{4,10}[a-z]?$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const PAYLOAD_URL_PATTERN = /^payloads\/([0-9a-f]{64})\.(json|jsonc|txt)$/
const METADATA_URL_PATTERN = /^metadata\/([0-9a-f]{64})\.json$/

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseJson(bytes, source) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch (error) {
    throw new Error(`${source}: invalid UTF-8 JSON`, { cause: error })
  }
}

function validateReference(value, source, pattern) {
  if (!isObject(value) || typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256)) {
    throw new Error(`${source}: invalid asset reference`)
  }
  if (!Number.isInteger(value.size) || value.size <= 0) throw new Error(`${source}: invalid asset size`)
  const match = typeof value.url === 'string' ? pattern.exec(value.url) : null
  if (!match || match[1] !== value.sha256) throw new Error(`${source}: URL does not match SHA-256`)
}

function addReference(references, reference, source) {
  const existing = references.get(reference.url)
  if (existing && (existing.sha256 !== reference.sha256 || existing.size !== reference.size)) {
    throw new Error(`${source}: duplicate URL has inconsistent integrity metadata`)
  }
  references.set(reference.url, existing ?? { url: reference.url, sha256: reference.sha256, size: reference.size })
}

export function validateGameDataIndex(value, source = 'gamedata/index.json') {
  if (!isObject(value) || value.schemaVersion !== 1 || !Array.isArray(value.versions)) {
    throw new Error(`${source}: expected gamedata index schema v1`)
  }
  const references = new Map()
  const bindings = []
  const versions = new Set()
  for (const [versionIndex, version] of value.versions.entries()) {
    const versionSource = `${source}: versions[${versionIndex}]`
    if (!isObject(version) || typeof version.gameVersion !== 'string' || !GAME_VERSION_PATTERN.test(version.gameVersion)) {
      throw new Error(`${versionSource}: invalid game version`)
    }
    if (versions.has(version.gameVersion)) throw new Error(`${versionSource}: duplicate game version`)
    versions.add(version.gameVersion)
    if (!Array.isArray(version.files) || version.fileCount !== version.files.length) {
      throw new Error(`${versionSource}: file inventory mismatch`)
    }
    let metadataCount = 0
    const ids = new Set()
    for (const [fileIndex, file] of version.files.entries()) {
      const fileSource = `${versionSource}.files[${fileIndex}]`
      if (!isObject(file) || typeof file.id !== 'string' || file.id.includes('\\') || file.id.startsWith('/')) {
        throw new Error(`${fileSource}: invalid file descriptor`)
      }
      const parts = file.id.split('/')
      if (parts.some((part) => !part || part === '.' || part === '..')) throw new Error(`${fileSource}: invalid file path`)
      if (file.plugin !== parts[0] || file.fileName !== parts.at(-1)) throw new Error(`${fileSource}: display identity mismatch`)
      if (ids.has(file.id)) throw new Error(`${fileSource}: duplicate file id`)
      ids.add(file.id)
      validateReference(file.content, `${fileSource}.content`, PAYLOAD_URL_PATTERN)
      addReference(references, file.content, `${fileSource}.content`)
      if (file.metadata !== undefined) {
        metadataCount += 1
        validateReference(file.metadata, `${fileSource}.metadata`, METADATA_URL_PATTERN)
        if (!Number.isInteger(file.metadata.schemaVersion) || !isObject(file.metadata.summary)) {
          throw new Error(`${fileSource}.metadata: invalid schema or summary`)
        }
        addReference(references, file.metadata, `${fileSource}.metadata`)
        bindings.push({ gameVersion: version.gameVersion, fileId: file.id, reference: file.metadata })
      }
    }
    if (version.metadataFileCount !== metadataCount) throw new Error(`${versionSource}: metadata inventory mismatch`)
  }
  return { index: value, references, bindings }
}

function verifyBytes(bytes, source, reference) {
  if (bytes.byteLength !== reference.size) throw new Error(`${source}: size does not match index`)
  const digest = sha256(bytes)
  if (digest !== reference.sha256) throw new Error(`${source}: SHA-256 does not match index`)
  return { url: reference.url, sha256: digest, size: bytes.byteLength }
}

async function recursiveFileNames(root) {
  const files = []
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) throw new Error(`${path}: symbolic links are not allowed`)
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) files.push(relative(root, path).split(sep).join('/'))
      else throw new Error(`${path}: unsupported filesystem entry`)
    }
  }
  await visit(root)
  return files.sort()
}

export async function verifyGameDataAssetDirectory(directory) {
  const root = resolve(directory)
  const indexPath = join(root, 'index.json')
  const indexBytes = await readFile(indexPath)
  const { index, references, bindings } = validateGameDataIndex(parseJson(indexBytes, indexPath), indexPath)
  const expectedFiles = new Set(['index.json', ...references.keys()])
  const actualFiles = await recursiveFileNames(root)
  if (actualFiles.length !== expectedFiles.size || actualFiles.some((file) => !expectedFiles.has(file))) {
    throw new Error(`${root}: emitted gamedata asset inventory does not match index`)
  }

  const assets = []
  const bytesByUrl = new Map()
  for (const reference of references.values()) {
    const path = join(root, ...reference.url.split('/'))
    const bytes = await readFile(path)
    assets.push(verifyBytes(bytes, path, reference))
    bytesByUrl.set(reference.url, bytes)
  }
  for (const binding of bindings) {
    const metadata = parseJson(bytesByUrl.get(binding.reference.url), binding.reference.url)
    if (
      !isObject(metadata)
      || metadata.schema_version !== binding.reference.schemaVersion
      || metadata.gamever !== binding.gameVersion
      || metadata.file !== binding.fileId
      || !isObject(metadata.summary)
      || JSON.stringify(metadata.summary) !== JSON.stringify(binding.reference.summary)
    ) throw new Error(`${binding.reference.url}: metadata identity or summary does not match index`)
  }
  return {
    index,
    indexSha256: sha256(indexBytes),
    indexSize: indexBytes.byteLength,
    assets: assets.sort((left, right) => left.url.localeCompare(right.url)),
  }
}

export function validateGameDataVerificationManifest(value, source = 'gamedata-verification.json') {
  if (!isObject(value) || value.schemaVersion !== 1 || !isObject(value.index) || !Array.isArray(value.assets)) {
    throw new Error(`${source}: expected verification manifest schema v1`)
  }
  if (typeof value.index.sha256 !== 'string' || !SHA256_PATTERN.test(value.index.sha256) || !Number.isInteger(value.index.size)) {
    throw new Error(`${source}: invalid index integrity metadata`)
  }
  const urls = new Set()
  for (const [index, asset] of value.assets.entries()) {
    if (!isObject(asset) || typeof asset.url !== 'string') throw new Error(`${source}.assets[${index}]: invalid asset`)
    const pattern = asset.url.startsWith('payloads/') ? PAYLOAD_URL_PATTERN : METADATA_URL_PATTERN
    validateReference(asset, `${source}.assets[${index}]`, pattern)
    if (urls.has(asset.url)) throw new Error(`${source}: duplicate asset URL`)
    urls.add(asset.url)
  }
  return value
}

export async function writeGameDataVerificationManifest(directory, manifestPath) {
  const result = await verifyGameDataAssetDirectory(directory)
  const manifest = {
    schemaVersion: 1,
    index: { sha256: result.indexSha256, size: result.indexSize },
    assets: result.assets,
  }
  const output = resolve(manifestPath)
  await mkdir(dirname(output), { recursive: true })
  await writeFile(output, JSON.stringify(manifest))
  return manifest
}

async function fetchBytes(url) {
  const response = await fetch(url, {
    cache: 'no-store',
    headers: { 'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache' },
  })
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status} ${response.statusText}`)
  return new Uint8Array(await response.arrayBuffer())
}

export async function verifyRemoteGameDataAssets(baseUrl, expectedManifest, { attempts = 12, delayMs = 5000, batchSize = 8 } = {}) {
  const root = new URL(baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`)
  const manifest = validateGameDataVerificationManifest(expectedManifest)
  let lastError
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const indexUrl = new URL(`index.json?verify=${Date.now()}-${attempt}`, root)
      const indexBytes = await fetchBytes(indexUrl)
      if (indexBytes.byteLength !== manifest.index.size || sha256(indexBytes) !== manifest.index.sha256) {
        throw new Error(`${indexUrl.href}: deployed index does not match this workflow build`)
      }
      const { references } = validateGameDataIndex(parseJson(indexBytes, indexUrl.href), indexUrl.href)
      const expectedByUrl = new Map(manifest.assets.map((asset) => [asset.url, asset]))
      if (references.size !== expectedByUrl.size) throw new Error(`${indexUrl.href}: asset inventory size mismatch`)
      for (const reference of references.values()) {
        const expected = expectedByUrl.get(reference.url)
        if (!expected || expected.sha256 !== reference.sha256 || expected.size !== reference.size) {
          throw new Error(`${indexUrl.href}: indexed asset ${reference.url} is absent from the build manifest`)
        }
      }
      for (let offset = 0; offset < manifest.assets.length; offset += batchSize) {
        await Promise.all(manifest.assets.slice(offset, offset + batchSize).map(async (asset) => {
          const assetUrl = new URL(asset.url, root)
          verifyBytes(await fetchBytes(assetUrl), assetUrl.href, asset)
        }))
      }
      return { index: parseJson(indexBytes, indexUrl.href), verified: manifest.assets.length }
    } catch (error) {
      lastError = error
      if (attempt < attempts) await new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs))
    }
  }
  throw new Error(`Remote gamedata verification failed after ${attempts} attempts`, { cause: lastError })
}

function argumentValue(args, name) {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  if (index + 1 >= args.length) throw new Error(`${name} requires a value`)
  return args[index + 1]
}

async function main(args) {
  const directory = argumentValue(args, '--directory')
  const baseUrl = argumentValue(args, '--base-url')
  const manifestPath = argumentValue(args, '--manifest')
  const writeManifestPath = argumentValue(args, '--write-manifest')
  if (directory && baseUrl) throw new Error('Choose either --directory or --base-url')
  if (!directory && !baseUrl) throw new Error('Expected --directory or --base-url')
  if (writeManifestPath && !directory) throw new Error('--write-manifest requires --directory')
  if (manifestPath && !baseUrl) throw new Error('--manifest requires --base-url')
  if (baseUrl && !manifestPath) throw new Error('--base-url requires --manifest')

  if (directory) {
    const result = await verifyGameDataAssetDirectory(directory)
    if (writeManifestPath) await writeGameDataVerificationManifest(directory, writeManifestPath)
    console.log(`Verified ${result.assets.length} gamedata assets.`)
    return
  }
  const manifestSource = resolve(manifestPath)
  const manifest = validateGameDataVerificationManifest(parseJson(await readFile(manifestSource), manifestSource), manifestSource)
  const result = await verifyRemoteGameDataAssets(baseUrl, manifest)
  console.log(`Verified ${result.verified} gamedata assets from ${baseUrl}.`)
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
}
