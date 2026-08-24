import type {
  GameDataAssetReference,
  GameDataFileDescriptor,
  GameDataIndex,
  GameDataMetadata,
  GameDataSummary,
} from './types'

const GAME_VERSION_PATTERN = /^\d{4,10}[a-z]?$/
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const PAYLOAD_URL_PATTERN = /^payloads\/([0-9a-f]{64})\.(json|jsonc|txt)$/
const METADATA_URL_PATTERN = /^metadata\/([0-9a-f]{64})\.json$/

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0
}

function validateSummary(value: unknown, source: string): asserts value is GameDataSummary {
  if (
    !isObject(value)
    || !nonNegativeInteger(value.total)
    || !nonNegativeInteger(value.covered)
    || !nonNegativeInteger(value.updated)
    || value.covered > value.total
    || value.updated > value.total
  ) throw new Error(`${source}: invalid summary`)
}

function validateAssetReference(
  value: unknown,
  source: string,
  pattern: RegExp,
): asserts value is GameDataAssetReference {
  if (!isObject(value)) throw new Error(`${source}: asset reference must be an object`)
  if (typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256)) {
    throw new Error(`${source}: invalid SHA-256`)
  }
  if (!Number.isInteger(value.size) || (value.size as number) <= 0) throw new Error(`${source}: invalid size`)
  const match = typeof value.url === 'string' ? pattern.exec(value.url) : null
  if (!match || match[1] !== value.sha256) throw new Error(`${source}: content-addressed URL does not match SHA-256`)
}

function validateFile(value: unknown, source: string): asserts value is GameDataFileDescriptor {
  if (!isObject(value)) throw new Error(`${source}: file descriptor must be an object`)
  if (
    typeof value.id !== 'string'
    || value.id.startsWith('/')
    || value.id.includes('\\')
    || value.id.split('/').some((part) => !part || part === '.' || part === '..')
  ) throw new Error(`${source}: invalid file id`)
  const parts = value.id.split('/')
  if (typeof value.plugin !== 'string' || typeof value.fileName !== 'string' || typeof value.language !== 'string') {
    throw new Error(`${source}: invalid plugin, file name, or language`)
  }
  if (value.plugin !== parts[0] || value.fileName !== parts.at(-1)) throw new Error(`${source}: invalid plugin or file name`)
  if (!['json', 'jsonc', 'vdf', 'flat'].includes(String(value.language))) throw new Error(`${source}: invalid language`)
  if (value.fileName.endsWith('.json') && value.language !== 'json') throw new Error(`${source}: JSON language mismatch`)
  if (value.fileName.endsWith('.jsonc') && value.language !== 'jsonc') throw new Error(`${source}: JSONC language mismatch`)
  if (value.fileName.endsWith('.txt') && value.language !== 'vdf' && value.language !== 'flat') {
    throw new Error(`${source}: text language mismatch`)
  }
  validateAssetReference(value.content, `${source}.content`, PAYLOAD_URL_PATTERN)
  if (value.metadata !== undefined) {
    validateAssetReference(value.metadata, `${source}.metadata`, METADATA_URL_PATTERN)
    if (!isObject(value.metadata) || !Number.isInteger(value.metadata.schemaVersion)) {
      throw new Error(`${source}.metadata: invalid schema version`)
    }
    validateSummary(value.metadata.summary, `${source}.metadata.summary`)
  }
}

export function validateGameDataIndex(value: unknown, source = 'gamedata/index.json'): asserts value is GameDataIndex {
  if (!isObject(value) || value.schemaVersion !== 1 || !Array.isArray(value.versions)) {
    throw new Error(`${source}: expected index schema v1`)
  }
  const versions = new Set<string>()
  for (const [versionIndex, version] of value.versions.entries()) {
    const versionSource = `${source}: versions[${versionIndex}]`
    if (!isObject(version) || typeof version.gameVersion !== 'string' || !GAME_VERSION_PATTERN.test(version.gameVersion)) {
      throw new Error(`${versionSource}: invalid game version`)
    }
    if (versions.has(version.gameVersion)) throw new Error(`${versionSource}: duplicate game version`)
    versions.add(version.gameVersion)
    if (!Array.isArray(version.files)) throw new Error(`${versionSource}: files must be an array`)
    version.files.forEach((file, fileIndex) => validateFile(file, `${versionSource}.files[${fileIndex}]`))
    if (version.fileCount !== version.files.length) throw new Error(`${versionSource}: fileCount mismatch`)
    const metadataCount = version.files.filter((file) => file.metadata !== undefined).length
    if (version.metadataFileCount !== metadataCount) throw new Error(`${versionSource}: metadataFileCount mismatch`)
    const ids = new Set(version.files.map((file) => file.id))
    if (ids.size !== version.files.length) throw new Error(`${versionSource}: duplicate file id`)
  }
}

export function validateGameDataMetadata(
  value: unknown,
  { gameVersion, fileId, lineCount, source = `${gameVersion}/${fileId}` }: {
    gameVersion: string
    fileId: string
    lineCount: number
    source?: string
  },
): asserts value is GameDataMetadata {
  if (
    !isObject(value)
    || (value.schema_version !== 1 && value.schema_version !== 2)
    || value.gamever !== gameVersion
    || value.file !== fileId
    || !Array.isArray(value.entries)
  ) throw new Error(`${source}: invalid metadata identity or schema`)
  validateSummary(value.summary, `${source}.summary`)

  let covered = 0
  let updated = 0
  const names = new Set<string>()
  for (const [entryIndex, entry] of value.entries.entries()) {
    const entrySource = `${source}.entries[${entryIndex}]`
    if (
      !isObject(entry)
      || typeof entry.name !== 'string'
      || !entry.name
      || typeof entry.covered !== 'boolean'
      || typeof entry.updated !== 'boolean'
    ) throw new Error(`${entrySource}: invalid entry`)
    if (names.has(entry.name)) throw new Error(`${entrySource}: duplicate name`)
    names.add(entry.name)
    const coveredLines = entry.covered_lines
    if (value.schema_version === 2) {
      if (
        !Array.isArray(coveredLines)
        || coveredLines.some((line) => !Number.isInteger(line) || line < 1 || line > lineCount)
        || coveredLines.some((line, index) => index > 0 && coveredLines[index - 1] >= line)
        || (!entry.covered && coveredLines.length > 0)
      ) throw new Error(`${entrySource}: invalid covered_lines`)
    } else if (coveredLines !== undefined) {
      throw new Error(`${entrySource}: schema v1 cannot contain covered_lines`)
    }
    const changes = entry.changes ?? []
    if (!Array.isArray(changes) || entry.updated !== (changes.length > 0)) {
      throw new Error(`${entrySource}: inconsistent updated/changes state`)
    }
    for (const [changeIndex, change] of changes.entries()) {
      const changeSource = `${entrySource}.changes[${changeIndex}]`
      if (
        !isObject(change)
        || !Array.isArray(change.path)
        || !change.path.every((segment) => typeof segment === 'string' || Number.isInteger(segment))
        || !Object.hasOwn(change, 'before')
        || !Object.hasOwn(change, 'after')
        || (change.line !== null && (!Number.isInteger(change.line) || (change.line as number) < 1 || (change.line as number) > lineCount))
      ) throw new Error(`${changeSource}: invalid change`)
      if (
        value.schema_version === 2
        && entry.covered
        && change.line !== null
        && !(coveredLines as number[]).includes(change.line as number)
      ) throw new Error(`${changeSource}: updated line is not covered`)
    }
    covered += Number(entry.covered)
    updated += Number(entry.updated)
  }
  if (value.summary.total !== value.entries.length || value.summary.covered !== covered || value.summary.updated !== updated) {
    throw new Error(`${source}: summary does not match entries`)
  }
}
