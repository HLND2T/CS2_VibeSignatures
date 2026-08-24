import { decodeUtf8, fetchVerifiedBytes, requestJson } from '../../assets/integrity'
import { validateGameDataIndex, validateGameDataMetadata } from './schema'
import type { GameDataFileDescriptor, GameDataIndex, GameDataMetadata } from './types'

const GAMEDATA_ASSET_ROOT = `${import.meta.env.BASE_URL}gamedata/`

export async function getGameDataIndex(signal?: AbortSignal): Promise<GameDataIndex> {
  const value = await requestJson(`${GAMEDATA_ASSET_ROOT}index.json`, signal)
  validateGameDataIndex(value)
  return value
}

export async function getGameDataFile(file: GameDataFileDescriptor, signal?: AbortSignal): Promise<string> {
  const bytes = await fetchVerifiedBytes(`${GAMEDATA_ASSET_ROOT}${file.content.url}`, file.content, signal)
  return decodeUtf8(bytes)
}

export async function getGameDataMetadata(
  file: GameDataFileDescriptor,
  lineCount: number,
  gameVersion: string,
  signal?: AbortSignal,
): Promise<GameDataMetadata> {
  if (!file.metadata) throw new Error(`No metadata companion for ${gameVersion}/${file.id}`)
  const bytes = await fetchVerifiedBytes(`${GAMEDATA_ASSET_ROOT}${file.metadata.url}`, file.metadata, signal)
  let value: unknown
  try {
    value = JSON.parse(decodeUtf8(bytes))
  } catch (error) {
    throw new Error(`Invalid metadata JSON for ${gameVersion}/${file.id}`, { cause: error })
  }
  validateGameDataMetadata(value, { gameVersion, fileId: file.id, lineCount })
  if (value.schema_version !== file.metadata.schemaVersion) throw new Error(`Metadata schema mismatch for ${gameVersion}/${file.id}`)
  if (
    value.summary.total !== file.metadata.summary.total
    || value.summary.covered !== file.metadata.summary.covered
    || value.summary.updated !== file.metadata.summary.updated
  ) throw new Error(`Metadata summary mismatch for ${gameVersion}/${file.id}`)
  return value
}
