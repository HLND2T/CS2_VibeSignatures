export const THEME_STORAGE_KEY = 'cs2vibe.theme'
export const APP_THEMES = ['dark', 'light'] as const
export type AppTheme = (typeof APP_THEMES)[number]

export function resolveTheme(value?: string | null): AppTheme {
  return value === 'light' ? 'light' : 'dark'
}

export function readStoredTheme(): AppTheme {
  try {
    return resolveTheme(localStorage.getItem(THEME_STORAGE_KEY))
  } catch {
    return 'dark'
  }
}

export function applyTheme(theme: AppTheme): void {
  const resolved = resolveTheme(theme)
  document.documentElement.dataset.theme = resolved
  document.documentElement.style.colorScheme = resolved
}

export function persistTheme(theme: AppTheme): void {
  const resolved = resolveTheme(theme)
  localStorage.setItem(THEME_STORAGE_KEY, resolved)
  applyTheme(resolved)
}

applyTheme(readStoredTheme())
