import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { gameSymbolsPlugin } from './gameSymbolsPlugin'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), gameSymbolsPlugin(fileURLToPath(new URL('../gamesymbols', import.meta.url)))],
  base: '/CS2_VibeSignatures/',
})
