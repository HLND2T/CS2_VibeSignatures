import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ExploreGameDataPage } from './ExploreGameDataPage'
import { getGameDataFile, getGameDataIndex } from './data'
import i18n from '../../i18n'

vi.mock('./data', () => ({ getGameDataFile: vi.fn(), getGameDataIndex: vi.fn(), getGameDataMetadata: vi.fn() }))
vi.mock('./GameDataViewer', () => ({ GameDataViewer: () => <div>File contents</div> }))

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('gamedata browsing', () => {
  it('downloads the selected static file with its original name and contents', async () => {
    const contents = '{"Symbol": "value"}\n'
    vi.mocked(getGameDataIndex).mockResolvedValue({
      schemaVersion: 1,
      versions: [{
        gameVersion: '14179', fileCount: 1, metadataFileCount: 0,
        files: [{
          id: 'Plugin/data.jsonc', plugin: 'Plugin', fileName: 'data.jsonc', language: 'jsonc',
          content: { url: 'payloads/example.jsonc', sha256: 'a'.repeat(64), size: contents.length },
        }],
      }],
    })
    vi.mocked(getGameDataFile).mockResolvedValue(contents)
    const createObjectURL = vi.fn((blob: Blob) => {
      expect(blob.size).toBe(contents.length)
      return 'blob:static-file'
    })
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', class extends URL {
      static createObjectURL = createObjectURL
      static revokeObjectURL = revokeObjectURL
    })
    let downloaded: { name: string; url: string } | undefined
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      downloaded = { name: this.download, url: this.href }
    })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><ExploreGameDataPage /></QueryClientProvider>)
    const button = await screen.findByRole('button', { name: new RegExp(i18n.t('gamedata.download')) })
    await waitFor(() => expect(button).toBeEnabled())
    await userEvent.click(button)
    expect(downloaded).toEqual({ name: 'data.jsonc', url: 'blob:static-file' })
    expect(createObjectURL.mock.calls[0][0]).toBeInstanceOf(Blob)
    expect(createObjectURL.mock.calls[0][0].size).toBe(contents.length)
    const reader = new FileReader()
    const downloadedText = new Promise((resolve) => { reader.onload = () => resolve(reader.result) })
    reader.readAsText(createObjectURL.mock.calls[0][0])
    expect(await downloadedText).toBe(contents)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:static-file')
  })
})
