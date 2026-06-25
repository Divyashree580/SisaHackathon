import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom')) {
              return 'vendor';
            }
            if (id.includes('d3')) {
              return 'd3';
            }
            if (id.includes('cytoscape') || id.includes('react-cytoscapejs')) {
              return 'cytoscape';
            }
            if (id.includes('recharts')) {
              return 'recharts';
            }
          }
        }
      }
    }
  }
})

