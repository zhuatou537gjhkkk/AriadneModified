import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import viteCompression from 'vite-plugin-compression'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // 开启 gzip 压缩，大幅减小产物体积，提升首屏加载速度
    viteCompression({
      algorithm: 'gzip',
      ext: '.gz',
      threshold: 10240, // 只有大小大于 10kb 的文件才会压缩
      deleteOriginFile: false // 保留源文件
    })
  ],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000', // 后端的真实地址
        changeOrigin: true,
        secure: false,
      }
    }
  },
  build: {
    rollupOptions: {
      output: {
        // 手动分包逻辑 (Manual Chunks)
        // 将巨型依赖单独拆分，利用浏览器长效缓存机制，避免每次业务代码更新都重新下载整个 vendor
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router')) {
              return 'vendor-react'; // React 生态核心包
            }
            if (id.includes('echarts') || id.includes('zrender')) {
              return 'vendor-echarts'; // ECharts 图表库极其庞大，必须独立分包
            }
            if (id.includes('antd') || id.includes('@ant-design') || id.includes('rc-')) {
              return 'vendor-antd'; // Ant Design 组件库及底层 rc 组件
            }
            return 'vendor-base'; // 其他第三方依赖
          }
        }
      }
    },
    chunkSizeWarningLimit: 1000 // 提高警告阈值至 1000 KB
  }
})