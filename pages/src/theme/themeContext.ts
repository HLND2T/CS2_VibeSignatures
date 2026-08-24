import { createContext, useContext } from 'react'
import type { AppTheme } from './index'

export interface ThemeContextValue {
  theme: AppTheme
  setTheme(theme: AppTheme): void
  toggleTheme(): void
}

export const ThemeContext = createContext<ThemeContextValue | null>(null)

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext)
  if (!value) throw new Error('useTheme must be used within ThemeProvider')
  return value
}
