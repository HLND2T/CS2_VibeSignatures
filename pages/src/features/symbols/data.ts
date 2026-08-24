import type { GameSymbolDataset, GameSymbolIndex, GameSymbolIndexVersion } from './types'
import { decodeUtf8, fetchVerifiedBytes, requestJson } from '../../assets/integrity'

const SYMBOL_ASSET_ROOT = `${import.meta.env.BASE_URL}gamesymbols/`
const SHA256_PATTERN = /^[0-9a-f]{64}$/
const MD5_PATTERN = /^[0-9a-f]{32}$/
const CRC32_PATTERN = /^[0-9a-f]{8}$/
const CRC64_PATTERN = /^[0-9a-f]{16}$/

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function validateIndexVersion(value: unknown, index: number): asserts value is GameSymbolIndexVersion {
  if (!isObject(value)) throw new Error(`Invalid game-symbol index v4 entry at versions[${index}]`)
  const { gameVersion, url, sha256, size, snapshotSchemaVersion, fileCount, lastPublishTime } = value
  if (typeof gameVersion !== 'string' || !/^\d{4,10}[a-z]?$/.test(gameVersion)) throw new Error(`Invalid gameVersion at versions[${index}]`)
  if (typeof sha256 !== 'string' || !SHA256_PATTERN.test(sha256)) throw new Error(`Invalid sha256 at versions[${index}]`)
  if (url !== `${gameVersion}.${sha256}.json`) throw new Error(`Invalid content-addressed url at versions[${index}]`)
  if (!Number.isInteger(size) || (size as number) <= 0) throw new Error(`Invalid size at versions[${index}]`)
  if (!Number.isInteger(snapshotSchemaVersion)) throw new Error(`Invalid snapshotSchemaVersion at versions[${index}]`)
  if (!Number.isInteger(fileCount) || (fileCount as number) < 0) throw new Error(`Invalid fileCount at versions[${index}]`)
  if (typeof lastPublishTime !== 'string') throw new Error(`Invalid lastPublishTime at versions[${index}]`)
}

export async function getGameSymbolIndex(signal?: AbortSignal): Promise<GameSymbolIndex> {
  const value = await requestJson(`${SYMBOL_ASSET_ROOT}index.json`, signal)
  if (!isObject(value) || value.schemaVersion !== 4 || !Array.isArray(value.versions)) {
    throw new Error('Invalid game-symbol index schema; expected v4')
  }
  value.versions.forEach(validateIndexVersion)
  return value as unknown as GameSymbolIndex
}

function validateBinaryMetadata(value: unknown, context: string): void {
  if (!isObject(value)) throw new Error(`Invalid binary metadata at ${context}`)
  if (typeof value.path !== 'string' || value.path.length === 0) throw new Error(`Invalid binary path at ${context}`)
  if (typeof value.sha256 !== 'string' || !SHA256_PATTERN.test(value.sha256)) throw new Error(`Invalid binary sha256 at ${context}`)
  if (typeof value.md5 !== 'string' || !MD5_PATTERN.test(value.md5)) throw new Error(`Invalid binary md5 at ${context}`)
  if (typeof value.crc32 !== 'string' || !CRC32_PATTERN.test(value.crc32)) throw new Error(`Invalid binary crc32 at ${context}`)
  if (typeof value.crc64 !== 'string' || !CRC64_PATTERN.test(value.crc64)) throw new Error(`Invalid binary crc64 at ${context}`)
  if (!Number.isInteger(value.size) || (value.size as number) < 0) throw new Error(`Invalid binary size at ${context}`)
}

function validateDatasetBinaries(value: unknown): void {
  if (!isObject(value)) throw new Error('Invalid game-symbol snapshot binaries')
  for (const [module, platforms] of Object.entries(value)) {
    if (!isObject(platforms)) throw new Error(`Invalid binary platforms for ${module}`)
    for (const [platform, metadata] of Object.entries(platforms)) {
      if (platform !== 'windows' && platform !== 'linux') throw new Error(`Invalid binary platform ${platform} for ${module}`)
      validateBinaryMetadata(metadata, `${module}.${platform}`)
    }
  }
}

export async function getGameSymbolDataset(version: GameSymbolIndexVersion, signal?: AbortSignal): Promise<GameSymbolDataset> {
  validateIndexVersion(version, 0)
  const bytes = await fetchVerifiedBytes(`${SYMBOL_ASSET_ROOT}${version.url}`, version, signal)
  const value = JSON.parse(decodeUtf8(bytes)) as unknown
  if (!isObject(value) || value.schemaVersion !== 3 || !isObject(value.source) || value.source.gameVersion !== version.gameVersion) {
    throw new Error(`Invalid game-symbol snapshot for ${version.gameVersion}`)
  }
  validateDatasetBinaries(value.binaries)
  return value as unknown as GameSymbolDataset
}
