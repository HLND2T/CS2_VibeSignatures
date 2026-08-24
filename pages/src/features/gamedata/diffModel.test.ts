import { describe, expect, it } from 'vitest'
import { buildGameDataDiffLineModel, formatChangePath, formatChangeValue } from './diffModel'
import type { GameDataMetadata } from './types'

describe('gamedata diff line model', () => {
  it('keeps covered lines and groups multiple updates on the same line', () => {
    const metadata: GameDataMetadata = {
      schema_version: 2,
      gamever: '14176',
      file: 'Plugin/data.jsonc',
      summary: { total: 2, covered: 1, updated: 2 },
      entries: [
        {
          name: 'Covered',
          covered: true,
          covered_lines: [2, 3],
          updated: true,
          changes: [
            { path: ['Covered', 'windows'], before: 'OLD', after: 'NEW', line: 3 },
            { path: ['Covered', 'linux'], before: 'OLD2', after: 'NEW2', line: 3 },
          ],
        },
        {
          name: 'Deleted',
          covered: false,
          covered_lines: [],
          updated: true,
          changes: [{ path: ['Deleted'], before: 1, after: null, line: null }],
        },
      ],
    }

    const model = buildGameDataDiffLineModel(metadata)

    expect([...model.coveredLines]).toEqual([2, 3])
    expect(model.updatedLines.get(3)).toHaveLength(2)
    expect(model.unanchoredChanges).toHaveLength(1)
  })

  it('formats nested paths and scalar tooltip values', () => {
    expect(formatChangePath(['Games', 'Signatures', 0, 'windows'])).toBe('Games.Signatures[0].windows')
    expect(formatChangeValue(null)).toBe('null')
    expect(formatChangeValue({ value: 1 })).toBe('{"value":1}')
  })
})
