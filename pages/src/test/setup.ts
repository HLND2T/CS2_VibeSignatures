import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll, beforeEach } from 'vitest'
import { server } from './server'
import i18n from '../i18n'
import { applyTheme, THEME_STORAGE_KEY } from '../theme'

class ResizeObserverStub {
  disconnect() {}
  observe() {}
  unobserve() {}
}

Object.defineProperty(window, 'ResizeObserver', {
  configurable: true,
  value: ResizeObserverStub,
})

Object.defineProperty(window, 'matchMedia', {
  configurable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  }),
})

const nativeGetComputedStyle = window.getComputedStyle
window.getComputedStyle = (element: Element) => nativeGetComputedStyle(element)

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  localStorage.removeItem(THEME_STORAGE_KEY)
  applyTheme('dark')
})
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
