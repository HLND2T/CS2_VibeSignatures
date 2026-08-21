import { describe, expect, it } from 'vitest'
import i18n, { APP_LANGUAGES, changeLanguage, resolveLanguage } from './index'
import { phaseLabel, statusLabel } from './labels'

describe('i18n', () => {
  it('resolves browser Chinese variants to a supported language', () => {
    expect(resolveLanguage('zh-HK')).toBe('zh-TW')
    expect(resolveLanguage('zh')).toBe('zh-CN')
    expect(resolveLanguage('ja-JP')).toBe('en')
  })

  it('translates status and phase labels for every supported language', async () => {
    for (const language of APP_LANGUAGES) {
      await changeLanguage(language)
      expect(statusLabel('running', i18n.t)).not.toBe('running')
      expect(phaseLabel('preprocessing', i18n.t)).not.toBe('preprocessing')
      expect(i18n.t('symbols.versionMetadata', { time: '2026-01-02 03:04:05', count: 3 })).not.toContain('symbols.versionMetadata')
    }
  })

  it('persists the selected language and updates the document language', async () => {
    await changeLanguage('zh-TW')
    expect(localStorage.getItem('cs2vibe.language')).toBe('zh-TW')
    expect(document.documentElement.lang).toBe('zh-TW')
  })
})
