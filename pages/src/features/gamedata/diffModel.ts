import type { GameDataChange, GameDataMetadata } from './types'

export interface GameDataDiffLineModel {
  coveredLines: Set<number>
  updatedLines: Map<number, GameDataChange[]>
  unanchoredChanges: GameDataChange[]
}

export function buildGameDataDiffLineModel(metadata?: GameDataMetadata): GameDataDiffLineModel {
  const coveredLines = new Set<number>()
  const updatedLines = new Map<number, GameDataChange[]>()
  const unanchoredChanges: GameDataChange[] = []
  if (!metadata) return { coveredLines, updatedLines, unanchoredChanges }

  for (const entry of metadata.entries) {
    if (entry.covered) entry.covered_lines?.forEach((line) => coveredLines.add(line))
    for (const change of entry.changes ?? []) {
      if (change.line === null) {
        unanchoredChanges.push(change)
        continue
      }
      const changes = updatedLines.get(change.line) ?? []
      changes.push(change)
      updatedLines.set(change.line, changes)
    }
  }
  return { coveredLines, updatedLines, unanchoredChanges }
}

export function formatChangePath(path: Array<string | number>): string {
  return path.map((segment, index) => typeof segment === 'number' ? `[${segment}]` : `${index === 0 ? '' : '.'}${segment}`).join('')
}

export function formatChangeValue(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'string') return value
  return JSON.stringify(value) ?? String(value)
}
