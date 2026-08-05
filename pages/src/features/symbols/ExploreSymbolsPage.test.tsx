import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import dayjs from 'dayjs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getGameSymbolDataset, getGameSymbolIndex } from './data'
import { ExploreSymbolsPage } from './ExploreSymbolsPage'
import type { GameSymbolDataset } from './types'

vi.mock('./data', () => ({
  getGameSymbolIndex: vi.fn(),
  getGameSymbolDataset: vi.fn(),
}))

const dataset: GameSymbolDataset = {
  schemaVersion: 3,
  source: {
    gameVersion: '14172', snapshotSchemaVersion: 5, configDigestVersion: 2,
    analysisOutputContractVersion: 1, configSha256: 'sha256:test', fileCount: 3,
    lastPublishTime: '2026-07-27T04:42:43Z',
  },
  binaries: {
    server: {
      windows: { path: 'game/bin/win64/server.dll', sha256: '1'.repeat(64), md5: '2'.repeat(32), crc32: '3'.repeat(8), crc64: '4'.repeat(16), size: 123 },
    },
  },
  modules: [
    { name: 'client', count: 1, windowsCount: 1, linuxCount: 0 },
    { name: 'server', count: 2, windowsCount: 1, linuxCount: 1 },
  ],
  records: [
    { id: 'server/CBaseEntity_Teleport.windows.yaml', module: 'server', artifact: 'CBaseEntity_Teleport', symbolName: 'CBaseEntity_Teleport', platform: 'windows', kind: 'function', payload: { func_name: 'CBaseEntity_Teleport', func_rva: '0x123' } },
    { id: 'server/CBaseEntity_Teleport.linux.yaml', module: 'server', artifact: 'CBaseEntity_Teleport', symbolName: 'CBaseEntity_Teleport', platform: 'linux', kind: 'function', payload: { func_name: 'CBaseEntity_Teleport', func_rva: '0x456' } },
    { id: 'client/CEntityInstance_vtable.windows.yaml', module: 'client', artifact: 'CEntityInstance_vtable', symbolName: 'CEntityInstance', platform: 'windows', kind: 'vtable', payload: { vtable_class: 'CEntityInstance' } },
  ],
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><ExploreSymbolsPage /></QueryClientProvider>)
}

describe('ExploreSymbolsPage', () => {
  afterEach(cleanup)

  beforeEach(() => {
    vi.mocked(getGameSymbolIndex).mockResolvedValue({
      schemaVersion: 4,
      versions: [
        { gameVersion: '14172', url: `14172.${'a'.repeat(64)}.json`, sha256: 'a'.repeat(64), size: 123, snapshotSchemaVersion: 5, fileCount: 3, lastPublishTime: '2026-07-27T04:42:43Z' },
        { gameVersion: '14171', url: `14171.${'b'.repeat(64)}.json`, sha256: 'b'.repeat(64), size: 122, snapshotSchemaVersion: 5, fileCount: 2, lastPublishTime: '2026-07-26T01:02:03Z' },
      ],
    })
    vi.mocked(getGameSymbolDataset).mockImplementation(async (version) => ({
      ...dataset,
      source: { ...dataset.source, gameVersion: version.gameVersion },
    }))
  })

  it('loads the latest version and filters by module, name, and platform', async () => {
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('共 3 条记录')).toBeInTheDocument()
    expect(screen.getByText(`最后更新 ${dayjs('2026-07-27T04:42:43Z').format('YYYY-MM-DD HH:mm:ss')} · 3 个符号`)).toBeInTheDocument()
    expect(getGameSymbolDataset).toHaveBeenCalledWith(expect.objectContaining({
      gameVersion: '14172',
      url: `14172.${'a'.repeat(64)}.json`,
    }), expect.any(AbortSignal))

    await user.click(screen.getByRole('combobox', { name: '全部模块' }))
    await user.click(await screen.findByText('server', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText('共 2 条记录')).toBeInTheDocument()

    await user.type(screen.getByPlaceholderText('搜索符号名或 Artifact'), 'Teleport')
    await user.click(screen.getByRole('combobox', { name: '全部平台' }))
    await user.click(await screen.findByText('Linux', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText('共 1 条记录')).toBeInTheDocument()
    expect(screen.getAllByText('CBaseEntity_Teleport').length).toBeGreaterThan(0)
  })

  it('opens full details from a search result', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('共 3 条记录')
    const searchCard = document.querySelector('.symbol-search-card')
    expect(searchCard).not.toBeNull()
    await user.click(within(searchCard as HTMLElement).getByRole('button', { name: 'CEntityInstance' }))
    expect(await screen.findByText('符号详情')).toBeInTheDocument()
    expect(screen.getByText('client/CEntityInstance_vtable.windows.yaml')).toBeInTheDocument()
    expect(screen.getByText(/"vtable_class": "CEntityInstance"/)).toBeInTheDocument()
  })

  it('switches game versions and loads the selected snapshot', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText(`最后更新 ${dayjs('2026-07-27T04:42:43Z').format('YYYY-MM-DD HH:mm:ss')} · 3 个符号`)

    await user.click(screen.getByLabelText('游戏版本'))
    await user.click(await screen.findByText('14171', { selector: '.ant-select-item-option-content' }))

    expect(getGameSymbolDataset).toHaveBeenCalledWith(expect.objectContaining({
      gameVersion: '14171',
      url: `14171.${'b'.repeat(64)}.json`,
    }), expect.any(AbortSignal))
    expect(screen.getByText(`最后更新 ${dayjs('2026-07-26T01:02:03Z').format('YYYY-MM-DD HH:mm:ss')} · 2 个符号`)).toBeInTheDocument()
    expect(screen.queryByText(/14171 · 2/)).not.toBeInTheDocument()
  })
})
