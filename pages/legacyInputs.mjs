import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

export const ALLOWED_REPOSITORY = 'HLND2T/CS2_VibeSignatures'
export const LEGACY_INPUTS_SCHEMA_VERSION = 1

const GAME_VERSION_PATTERN = /^\d{4,10}[a-z]?$/
const SHA_RE = /^[0-9a-f]{40}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const PUBLISH_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const GAMESYMBOL_FILE_PATTERN = /^gamesymbols\/(\d{4,10}[a-z]?)\.([0-9a-f]{64})\.json$/
const GAMEDATA_FILE_PREFIX = 'gamedata/'
const GAMESYMBOLS_PREFIX = 'gamesymbols/'

export class LegacyInputsError extends Error {}

function fail(source, message) {
  throw new LegacyInputsError(`${source}: ${message}`)
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requireExactKeys(value, keys, source) {
  if (!isObject(value)) fail(source, 'must be an object')
  const actual = Object.keys(value)
  const expected = [...keys].sort()
  const sorted = [...actual].sort()
  if (sorted.length !== expected.length || sorted.some((key, index) => key !== expected[index])) {
    fail(source, `expected keys ${expected.join(', ')}`)
  }
}

function requireString(value, source) {
  if (typeof value !== 'string' || value.length === 0) fail(source, 'must be a non-empty string')
  return value
}

function requireInteger(value, source, { minimum = 0 } = {}) {
  if (!Number.isInteger(value) || value < minimum) fail(source, `must be an integer >= ${minimum}`)
  return value
}

function requireGameVersion(value, source) {
  if (typeof value !== 'string' || !GAME_VERSION_PATTERN.test(value)) fail(source, 'is not a game version')
  return value
}

function requireSha(value, source) {
  if (typeof value !== 'string' || !SHA_RE.test(value)) fail(source, 'must be a lowercase 40-hex commit SHA')
  return value
}

function normalizedRelativePath(value, source) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\')) {
    fail(source, 'must be a non-empty POSIX relative path')
  }
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.includes(':')) {
    fail(source, 'must not be absolute or contain a drive/stream separator')
  }
  const parts = value.split('/')
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    fail(source, 'contains an unsafe path segment')
  }
  return value
}

function assertSorted(values, compare, source, label) {
  for (let index = 1; index < values.length; index += 1) {
    if (compare(values[index - 1], values[index]) >= 0) fail(source, `${label} must be strictly sorted and unique`)
  }
}

const GAME_VERSION_PARTS = /^(\d{4,10})([a-z]?)$/

function compareGameVersionKeys(left, right) {
  const leftMatch = GAME_VERSION_PARTS.exec(left)
  const rightMatch = GAME_VERSION_PARTS.exec(right)
  if (!leftMatch || !rightMatch) return left < right ? -1 : left > right ? 1 : 0
  const numeric = Number(leftMatch[1]) - Number(rightMatch[1])
  if (numeric !== 0) return numeric
  return leftMatch[2] < rightMatch[2] ? -1 : leftMatch[2] > rightMatch[2] ? 1 : 0
}

export function compareGameVersions(left, right) {
  return -compareGameVersionKeys(left, right)
}

function canonicalJsonText(value) {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new LegacyInputsError('canonical JSON only supports integers')
    return String(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJsonText).join(',')}]`
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJsonText(value[key])}`)
      .join(',')}}`
  }
  throw new LegacyInputsError('canonical JSON only supports JSON values')
}

export function canonicalJsonBytes(value) {
  return Buffer.from(`${canonicalJsonText(value)}\n`, 'utf8')
}

export function parseLegacyInputs(rawBytes, source = 'legacy-inputs.json') {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes)
  } catch (error) {
    throw new LegacyInputsError(`${source}: invalid UTF-8`, { cause: error })
  }
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw new LegacyInputsError(`${source}: invalid JSON`, { cause: error })
  }
  const canonical = canonicalJsonBytes(value)
  if (!Buffer.from(rawBytes).equals(canonical)) {
    throw new LegacyInputsError(`${source}: manifest is not canonical JSON`)
  }
  return validateLegacyInputs(value, source)
}

function validateFileInventory(value, source, { prefix, pattern }) {
  if (!Array.isArray(value) || value.length === 0) fail(source, 'must be a non-empty file inventory')
  const records = []
  const seen = new Set()
  value.forEach((item, index) => {
    const itemSource = `${source}[${index}]`
    requireExactKeys(item, ['path', 'size', 'sha256'], itemSource)
    const path = normalizedRelativePath(item.path, `${itemSource}.path`)
    if (!path.startsWith(prefix)) fail(`${itemSource}.path`, `must be under ${prefix}`)
    if (pattern && !pattern.test(path)) fail(`${itemSource}.path`, 'has an unexpected file name')
    requireInteger(item.size, `${itemSource}.size`)
    if (typeof item.sha256 !== 'string' || !SHA256_RE.test(item.sha256)) fail(`${itemSource}.sha256`, 'must be a lowercase SHA-256')
    if (seen.has(path)) fail(source, `duplicate path ${path}`)
    seen.add(path)
    records.push({ path, size: item.size, sha256: item.sha256 })
  })
  assertSorted(records.map((item) => item.path), (left, right) => (left < right ? -1 : left > right ? 1 : 0), source, 'file inventory')
  return records
}

function validateSelected(value, source, fileByPath) {
  if (!Array.isArray(value) || value.length === 0) fail(source, 'must be a non-empty selected list')
  const seenVersions = new Set()
  const versions = []
  value.forEach((item, index) => {
    const itemSource = `${source}[${index}]`
    requireExactKeys(
      item,
      ['gameVersion', 'url', 'sha256', 'size', 'fileCount', 'snapshotSchemaVersion', 'lastPublishTime'],
      itemSource,
    )
    const gameVersion = requireGameVersion(item.gameVersion, `${itemSource}.gameVersion`)
    if (typeof item.sha256 !== 'string' || !SHA256_RE.test(item.sha256)) fail(`${itemSource}.sha256`, 'must be a lowercase SHA-256')
    if (item.url !== `${gameVersion}.${item.sha256}.json`) fail(`${itemSource}.url`, 'must be <gameVersion>.<sha256>.json')
    const record = fileByPath.get(`${GAMESYMBOLS_PREFIX}${item.url}`)
    if (!record) fail(`${itemSource}.url`, 'is absent from the archived file inventory')
    if (record.sha256 !== item.sha256 || record.size !== item.size) fail(`${itemSource}`, 'size or SHA-256 differs from the archived file inventory')
    requireInteger(item.size, `${itemSource}.size`, { minimum: 1 })
    requireInteger(item.fileCount, `${itemSource}.fileCount`)
    requireInteger(item.snapshotSchemaVersion, `${itemSource}.snapshotSchemaVersion`)
    if (typeof item.lastPublishTime !== 'string' || !PUBLISH_TIME_RE.test(item.lastPublishTime)) {
      fail(`${itemSource}.lastPublishTime`, 'must be UTC ISO 8601 with second precision')
    }
    if (seenVersions.has(gameVersion)) fail(source, `duplicate gameVersion ${gameVersion}`)
    seenVersions.add(gameVersion)
    versions.push(gameVersion)
  })
  assertSorted(versions, compareGameVersionKeys, source, 'selected game versions')
  return value
}

function validateGamesymbols(value, source) {
  requireExactKeys(value, ['files', 'selected'], source)
  const files = validateFileInventory(value.files, `${source}.files`, {
    prefix: GAMESYMBOLS_PREFIX,
    pattern: GAMESYMBOL_FILE_PATTERN,
  })
  const fileByPath = new Map(files.map((item) => [item.path, item]))
  validateSelected(value.selected, `${source}.selected`, fileByPath)
  return value
}

function validateGamedata(value, source) {
  requireExactKeys(value, ['versions'], source)
  if (!Array.isArray(value.versions) || value.versions.length === 0) fail(`${source}.versions`, 'must be a non-empty list')
  const versionKeys = []
  const seenVersions = new Set()
  const seenPaths = new Set()
  value.versions.forEach((version, index) => {
    const versionSource = `${source}.versions[${index}]`
    requireExactKeys(version, ['gameVersion', 'files'], versionSource)
    const gameVersion = requireGameVersion(version.gameVersion, `${versionSource}.gameVersion`)
    if (seenVersions.has(gameVersion)) fail(source, `duplicate gamedata gameVersion ${gameVersion}`)
    seenVersions.add(gameVersion)
    const files = validateFileInventory(version.files, `${versionSource}.files`, { prefix: `${GAMEDATA_FILE_PREFIX}${gameVersion}/` })
    files.forEach((item) => {
      const relative = item.path.slice(`${GAMEDATA_FILE_PREFIX}`.length)
      const [directory, ...rest] = relative.split('/')
      if (directory !== gameVersion || rest.length === 0) fail(`${versionSource}.files`, `path directory must be ${gameVersion}`)
      if (seenPaths.has(item.path)) fail(source, `duplicate gamedata path ${item.path}`)
      seenPaths.add(item.path)
    })
    versionKeys.push(gameVersion)
  })
  assertSorted(versionKeys, compareGameVersionKeys, source, 'gamedata game versions')
  return value
}

function validateExcluded(value, source) {
  if (!Array.isArray(value)) fail(source, 'must be a list')
  const keys = []
  value.forEach((item, index) => {
    const itemSource = `${source}[${index}]`
    requireExactKeys(item, ['kind', 'gameVersion', 'reason'], itemSource)
    requireString(item.kind, `${itemSource}.kind`)
    const gameVersion = requireGameVersion(item.gameVersion, `${itemSource}.gameVersion`)
    requireString(item.reason, `${itemSource}.reason`)
    keys.push(`${item.kind} ${gameVersion}`)
  })
  assertSorted(keys, (left, right) => (left < right ? -1 : left > right ? 1 : 0), source, 'excluded entries')
  return value
}

function validateReleases(value, source) {
  if (!Array.isArray(value) || value.length === 0) fail(source, 'must be a non-empty list')
  const tags = []
  value.forEach((item, index) => {
    const itemSource = `${source}[${index}]`
    requireExactKeys(item, ['tag', 'releaseId', 'assetId', 'assetName', 'assetSize', 'sha256', 'apiDigest'], itemSource)
    const tag = requireGameVersion(item.tag, `${itemSource}.tag`)
    requireInteger(item.releaseId, `${itemSource}.releaseId`, { minimum: 1 })
    requireInteger(item.assetId, `${itemSource}.assetId`, { minimum: 1 })
    if (item.assetName !== `gamedata-${tag}.7z`) fail(`${itemSource}.assetName`, `must be gamedata-${tag}.7z`)
    requireInteger(item.assetSize, `${itemSource}.assetSize`, { minimum: 1 })
    if (typeof item.sha256 !== 'string' || !SHA256_RE.test(item.sha256)) fail(`${itemSource}.sha256`, 'must be a lowercase SHA-256')
    if (item.apiDigest !== null && (typeof item.apiDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(item.apiDigest))) {
      fail(`${itemSource}.apiDigest`, 'must be null or sha256:<hex>')
    }
    tags.push(tag)
  })
  assertSorted(tags, compareGameVersionKeys, source, 'release tags')
  return value
}

function validateDifferences(value, source) {
  if (!Array.isArray(value)) fail(source, 'must be a list')
  const seen = new Set()
  const paths = []
  value.forEach((item, index) => {
    const itemSource = `${source}[${index}]`
    requireExactKeys(item, ['path', 'releaseSha256', 'trackedSha256'], itemSource)
    const path = normalizedRelativePath(item.path, `${itemSource}.path`)
    if (!path.startsWith(GAMEDATA_FILE_PREFIX)) fail(`${itemSource}.path`, 'must be under gamedata/')
    for (const key of ['releaseSha256', 'trackedSha256']) {
      const digest = item[key]
      if (digest !== null && (typeof digest !== 'string' || !SHA256_RE.test(digest))) {
        fail(`${itemSource}.${key}`, 'must be null or a lowercase SHA-256')
      }
    }
    if (item.releaseSha256 === null && item.trackedSha256 === null) fail(itemSource, 'must record at least one side')
    if (seen.has(path)) fail(source, `duplicate difference ${path}`)
    seen.add(path)
    paths.push(path)
  })
  assertSorted(paths, (left, right) => (left < right ? -1 : left > right ? 1 : 0), source, 'differences')
}

function validateGamedataSource(value, source) {
  requireExactKeys(value, ['kind', 'commit', 'subtree', 'inventorySha256', 'selectionReason', 'differences'], source)
  if (value.kind !== 'switch-pre-tracked' && value.kind !== 'release-assets') fail(`${source}.kind`, 'is unsupported')
  if (value.kind === 'switch-pre-tracked') requireSha(value.commit, `${source}.commit`)
  else if (value.commit !== null) fail(`${source}.commit`, 'must be null for release-assets')
  if (value.subtree !== 'gamedata') fail(`${source}.subtree`, 'must be gamedata')
  if (typeof value.inventorySha256 !== 'string' || !SHA256_RE.test(value.inventorySha256)) {
    fail(`${source}.inventorySha256`, 'must be a lowercase SHA-256')
  }
  requireString(value.selectionReason, `${source}.selectionReason`)
  validateDifferences(value.differences, `${source}.differences`)
  if (value.kind === 'release-assets' && value.differences.length !== 0) {
    fail(`${source}.differences`, 'must be empty for release-assets')
  }
}

function validateImportProvenance(value, source, expected) {
  requireExactKeys(value, ['sourceArchiveCommit', 'importBaseCommit', 'selectedBasis', 'gamedataSource', 'releases'], source)
  requireSha(value.sourceArchiveCommit, `${source}.sourceArchiveCommit`)
  requireSha(value.importBaseCommit, `${source}.importBaseCommit`)
  requireExactKeys(value.selectedBasis, ['kind', 'sourceCommit', 'indexSha256', 'indexSize'], `${source}.selectedBasis`)
  requireString(value.selectedBasis.kind, `${source}.selectedBasis.kind`)
  requireSha(value.selectedBasis.sourceCommit, `${source}.selectedBasis.sourceCommit`)
  if (typeof value.selectedBasis.indexSha256 !== 'string' || !SHA256_RE.test(value.selectedBasis.indexSha256)) {
    fail(`${source}.selectedBasis.indexSha256`, 'must be a lowercase SHA-256')
  }
  requireInteger(value.selectedBasis.indexSize, `${source}.selectedBasis.indexSize`, { minimum: 1 })
  validateGamedataSource(value.gamedataSource, `${source}.gamedataSource`)
  validateReleases(value.releases, `${source}.releases`)
  const releaseTags = value.releases.map((item) => item.tag)
  if (releaseTags.length !== expected.gamedataVersions.length || releaseTags.some((tag, index) => tag !== expected.gamedataVersions[index])) {
    fail(`${source}.releases`, 'must cover exactly the archived gamedata versions')
  }
}

export function validateLegacyInputs(value, source = 'legacy-inputs.json') {
  requireExactKeys(
    value,
    ['schemaVersion', 'repository', 'archiveCommit', 'gamesymbols', 'gamedata', 'excluded', 'importProvenance'],
    source,
  )
  if (value.schemaVersion !== LEGACY_INPUTS_SCHEMA_VERSION) fail(source, `expected schemaVersion ${LEGACY_INPUTS_SCHEMA_VERSION}`)
  if (value.repository !== ALLOWED_REPOSITORY) fail(`${source}.repository`, `must be ${ALLOWED_REPOSITORY}`)
  requireSha(value.archiveCommit, `${source}.archiveCommit`)
  validateGamesymbols(value.gamesymbols, `${source}.gamesymbols`)
  validateGamedata(value.gamedata, `${source}.gamedata`)
  validateExcluded(value.excluded, `${source}.excluded`)
  validateImportProvenance(value.importProvenance, `${source}.importProvenance`, {
    gamedataVersions: value.gamedata.versions.map((version) => version.gameVersion),
  })

  const selectedVersions = new Set(value.gamesymbols.selected.map((item) => item.gameVersion))
  const gamedataVersions = new Set(value.gamedata.versions.map((item) => item.gameVersion))
  for (const item of value.excluded) {
    const included = item.kind === 'gamesymbols' ? selectedVersions.has(item.gameVersion) : gamedataVersions.has(item.gameVersion)
    if (included) fail(`${source}.excluded`, `${item.kind} ${item.gameVersion} is both excluded and included`)
  }
  return value
}

export async function loadLegacyInputs(path, source = path) {
  return parseLegacyInputs(await readFile(path), source)
}

function argumentValue(args, name) {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  if (index + 1 >= args.length) throw new LegacyInputsError(`${name} requires a value`)
  return args[index + 1]
}

async function main(args) {
  const manifestPath = argumentValue(args, '--manifest')
  if (!manifestPath) throw new LegacyInputsError('Expected --manifest <path>')
  const manifest = await loadLegacyInputs(resolve(manifestPath))
  if (args.includes('--print-archive-commit')) {
    process.stdout.write(`${manifest.archiveCommit}\n`)
    return
  }
  throw new LegacyInputsError('Expected --print-archive-commit')
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  })
}
