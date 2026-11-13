import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../App'
import i18n, { changeLanguage } from '../i18n'
import { ThemeProvider } from '../theme/ThemeProvider'

vi.mock('../features/symbols/ExploreSymbolsPage', () => ({ ExploreSymbolsPage: () => <h2>Symbols fixture</h2> }))
vi.mock('../features/gamedata/ExploreGameDataPage', () => ({ ExploreGameDataPage: () => <h2>Game Data fixture</h2> }))

afterEach(() => {
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

describe('static browsing shell', () => {
  it('opens Symbols at an old run URL and switches pages without API requests', async () => {
    const fetchMock = vi.fn(() => { throw new Error('Unexpected API request') })
    vi.stubGlobal('fetch', fetchMock)
    window.history.replaceState({}, '', '/CS2_VibeSignatures/runs/old-run')
    render(<ThemeProvider><App /></ThemeProvider>)
    expect(await screen.findByRole('heading', { name: 'Symbols fixture' })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(2)
    await userEvent.click(screen.getByRole('tab', { name: i18n.t('navigation.gamedata') }))
    expect(await screen.findByRole('heading', { name: 'Game Data fixture' })).toBeInTheDocument()
    await act(() => changeLanguage('en'))
    expect(screen.getByRole('tab', { name: 'Game Data' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: i18n.t('theme.switchToLight') }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
