// import { defineConfig } from 'vite'
// import react from '@vitejs/plugin-react'

// // https://vite.dev/config/
// export default defineConfig({
//   plugins: [react()],
// })


import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // 添加以下 proxy 配置
    proxy: {
      '/api': {
        target: 'http://localhost:8000', // 后端的真实地址
        changeOrigin: true,
        secure: false,
        // 如果后端接口路径本身就包含 /api，通常不需要 rewrite
        // 如果后端是 /v1/... 而前端请求 /api/v1/...，则需要把 /api 去掉，如下：
        // rewrite: (path) => path.replace(/^\/api/, ''), 
      }
    }
  }
})