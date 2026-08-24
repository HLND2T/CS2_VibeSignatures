import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import i18n from '../i18n'
import { THEME_STORAGE_KEY } from './index'
import { ThemeProvider } from './ThemeProvider'
import { ThemeToggle } from './ThemeToggle'

function renderToggle() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  )
}

describe('ThemeToggle', () => {
  it('toggles between dark and light and persists the choice', async () => {
    const user = userEvent.setup()
    renderToggle()
    expect(document.documentElement.dataset.theme).toBe('dark')
    await user.click(screen.getByRole('button', { name: i18n.t('theme.switchToLight') }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
    await user.click(screen.getByRole('button', { name: i18n.t('theme.switchToDark') }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
  })

  it('restores a stored light theme on mount', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light')
    renderToggle()
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(screen.getByRole('button', { name: i18n.t('theme.switchToDark') })).toBeInTheDocument()
  })
})
