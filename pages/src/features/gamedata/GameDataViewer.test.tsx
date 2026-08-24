import { render, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { GameDataViewer } from './GameDataViewer'
import type { GameDataMetadata } from './types'

const metadata: GameDataMetadata = {
  schema_version: 2,
  gamever: '14176',
  file: 'Plugin/data.jsonc',
  summary: { total: 2, covered: 2, updated: 1 },
  entries: [
    { name: 'Covered', covered: true, covered_lines: [2], updated: false },
    {
      name: 'Updated',
      covered: true,
      covered_lines: [3],
      updated: true,
      changes: [{ path: ['Updated'], before: 1, after: 2, line: 3 }],
    },
  ],
}

describe('GameDataViewer', () => {
  it('renders a non-editable CodeMirror view with covered and updated line decorations', async () => {
    const { container, getByRole } = render(
      <GameDataViewer
        content={'{\n  "Covered": 1,\n  "Updated": 2\n}\n'}
        language="jsonc"
        metadata={metadata}
        diffEnabled
        ariaLabel="viewer"
      />,
    )

    expect(getByRole('region', { name: 'viewer' })).toBeInTheDocument()
    await waitFor(() => expect(container.querySelector('.cm-editor')).toBeInTheDocument())
    expect(container.querySelector('.cm-content')).toHaveAttribute('contenteditable', 'false')
    expect(container.querySelectorAll('.gamedata-line-covered')).toHaveLength(1)
    expect(container.querySelectorAll('.gamedata-line-updated')).toHaveLength(1)
  })
})
