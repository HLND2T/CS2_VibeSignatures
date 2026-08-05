export type GameSymbolPlatform = 'windows' | 'linux'

export interface GameSymbolBinary {
  path: string
  sha256: string
  md5: string
  crc32: string
  crc64: string
  size: number
}

export type GameSymbolBinaries = Record<string, Partial<Record<GameSymbolPlatform, GameSymbolBinary>>>

export interface GameSymbolIndexVersion {
  gameVersion: string
  url: string
  sha256: string
  size: number
  snapshotSchemaVersion: number
  fileCount: number
  lastPublishTime: string
}

export interface GameSymbolIndex {
  schemaVersion: 4
  versions: GameSymbolIndexVersion[]
}

export interface GameSymbolRecord {
  id: string
  module: string
  artifact: string
  symbolName: string
  platform: GameSymbolPlatform
  kind: string
  payload: Record<string, unknown>
  aliases?: string[]
}

export interface GameSymbolDataset {
  schemaVersion: 3
  source: {
    gameVersion: string
    snapshotSchemaVersion: number
    configDigestVersion: number
    analysisOutputContractVersion: number
    configSha256: string
    fileCount: number
    lastPublishTime: string
  }
  binaries: GameSymbolBinaries
  modules: Array<{
    name: string
    count: number
    windowsCount: number
    linuxCount: number
  }>
  records: GameSymbolRecord[]
}

export interface SymbolFilters {
  module?: string
  query: string
  platform?: GameSymbolPlatform
}
