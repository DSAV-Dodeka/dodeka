import {defineConfig} from 'vite'
import { resolve } from 'path'
import react from '@vitejs/plugin-react'
import topLevelAwait from "vite-plugin-top-level-await";
import svgr from "vite-plugin-svgr"
import wasm from "vite-plugin-wasm-esm";

// https://vitejs.dev/config/
export default defineConfig({
  base: "/credentials/",
  plugins: [
      react(),
      wasm(["@tiptenbrink/opaquewasm"]),
      topLevelAwait(),
      svgr()
  ],
  build: {
    target: "es2016",
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        register: resolve(__dirname, 'register/index.html'),
        email: resolve(__dirname, 'email/index.html'),
        reset: resolve(__dirname, 'reset/index.html')
      }
    },
    outDir: '../backend/src/apiserver/resources/static/credentials'
  },
  server: {
    port: 4244
  }
})

