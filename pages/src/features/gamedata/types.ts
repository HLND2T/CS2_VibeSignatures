export type GameDataLanguage = 'json' | 'jsonc' | 'vdf' | 'flat'

export interface GameDataSummary {
  total: number
  covered: number
  updated: number
}

export interface GameDataAssetReference {
  url: string
  sha256: string
  size: number
}

export interface GameDataMetadataReference extends GameDataAssetReference {
  schemaVersion: number
  summary: GameDataSummary
}

export interface GameDataFileDescriptor {
  id: string
  plugin: string
  fileName: string
  language: GameDataLanguage
  content: GameDataAssetReference
  metadata?: GameDataMetadataReference
}

export interface GameDataIndexVersion {
  gameVersion: string
  fileCount: number
  metadataFileCount: number
  files: GameDataFileDescriptor[]
}

export interface GameDataIndex {
  schemaVersion: 1
  versions: GameDataIndexVersion[]
}

export interface GameDataChange {
  path: Array<string | number>
  before: unknown
  after: unknown
  line: number | null
}

export interface GameDataMetadataEntry {
  name: string
  covered: boolean
  covered_lines?: number[]
  updated: boolean
  changes?: GameDataChange[]
}

export interface GameDataMetadata {
  schema_version: 1 | 2
  gamever: string
  file: string
  summary: GameDataSummary
  entries: GameDataMetadataEntry[]
}
