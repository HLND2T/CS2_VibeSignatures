import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { gameDataPlugin } from './gameDataPlugin'
import { gameSymbolsPlugin } from './gameSymbolsPlugin'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    gameSymbolsPlugin(fileURLToPath(new URL('../gamesymbols', import.meta.url))),
    gameDataPlugin(fileURLToPath(new URL('../gamedata', import.meta.url))),
  ],
  base: '/CS2_VibeSignatures/',
})
