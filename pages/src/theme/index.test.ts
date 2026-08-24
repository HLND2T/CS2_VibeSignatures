import { afterEach, describe, expect, it } from 'vitest'
import { applyTheme, persistTheme, readStoredTheme, resolveTheme, THEME_STORAGE_KEY } from './index'

describe('theme', () => {
  afterEach(() => {
    localStorage.removeItem(THEME_STORAGE_KEY)
    applyTheme('dark')
  })

  it('treats only light as light and everything else as dark', () => {
    expect(resolveTheme('light')).toBe('light')
    expect(resolveTheme('dark')).toBe('dark')
    expect(resolveTheme('system')).toBe('dark')
    expect(resolveTheme(null)).toBe('dark')
  })

  it('persists the selected theme and applies it to the document', () => {
    persistTheme('light')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.documentElement.style.colorScheme).toBe('light')
    expect(readStoredTheme()).toBe('light')
  })
})
