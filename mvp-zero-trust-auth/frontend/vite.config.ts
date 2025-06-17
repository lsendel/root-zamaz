import { defineConfig } from 'vite'
// import react from '@vitejs/plugin-react' // Example for React

// https://vitejs.dev/config/
export default defineConfig({
  // plugins: [react()] // Example for React
  server: {
    port: 3000,
    // proxy: { // Example proxy configuration
    //   '/api': {
    //     target: 'http://localhost:8080', // Your backend API
    //     changeOrigin: true,
    //   }
    // }
  }
})
