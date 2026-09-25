import { defineConfig } from 'vite';

export default defineConfig({
  // The existing ClickBites frontend is a static HTML/CSS/JS app in /public.
  root: 'public',
  server: {
    port: Number(process.env.FRONTEND_PORT || 5173),
    strictPort: false,
    proxy: {
      '/api': {
        target: `http://${process.env.BACKEND_HOST || '127.0.0.1'}:${process.env.PORT || 4000}`,
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: Number(process.env.FRONTEND_PORT || 5173),
    strictPort: false,
  },
});
