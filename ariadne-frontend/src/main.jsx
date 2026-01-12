import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
// 1. 引入 Ant Design 和 暗黑算法
import { ConfigProvider, theme } from 'antd';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/* 2. 配置全局暗黑主题，并自定义“安全蓝”主色调 */}
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm, // 开启暗黑模式
        token: {
          colorPrimary: '#1890ff', // 科技蓝
          colorBgBase: '#000000',  // 基础背景色设为纯黑（贴近参考图）
          colorBgContainer: '#141414', // 卡片背景色（稍亮一点的黑）
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>,
)