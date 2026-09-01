import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gameDataPlugin } from './gameDataPlugin'
import { gameSymbolsPlugin } from './gameSymbolsPlugin'

const configuredInputRoot = process.env.PAGES_RELEASE_INPUT_ROOT
if (process.env.CI && !configuredInputRoot) {
  throw new Error('PAGES_RELEASE_INPUT_ROOT is required for CI Pages builds')
}
const inputRoot = configuredInputRoot
  ? resolve(configuredInputRoot)
  : fileURLToPath(new URL('..', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    gameSymbolsPlugin(join(inputRoot, 'gamesymbols')),
    gameDataPlugin(join(inputRoot, 'gamedata')),
  ],
  base: '/CS2_VibeSignatures/',
})
