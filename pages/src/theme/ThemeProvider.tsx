import { useCallback, useLayoutEffect, useMemo, useState, type ReactNode } from 'react'
import { applyTheme, persistTheme, readStoredTheme, resolveTheme, type AppTheme } from './index'
import { ThemeContext } from './themeContext'

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<AppTheme>(readStoredTheme)

  useLayoutEffect(() => {
    applyTheme(theme)
  }, [theme])

  const setTheme = useCallback((next: AppTheme) => {
    const resolved = resolveTheme(next)
    persistTheme(resolved)
    setThemeState(resolved)
  }, [])

  const toggleTheme = useCallback(() => {
    setThemeState((current) => {
      const next = current === 'dark' ? 'light' : 'dark'
      persistTheme(next)
      return next
    })
  }, [])

  const value = useMemo(() => ({ theme, setTheme, toggleTheme }), [setTheme, theme, toggleTheme])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
