import React from 'react';
import { Result, Button } from 'antd';
import { WarningOutlined } from '@ant-design/icons';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  // 捕获子组件抛出的错误，更新 state 以渲染降级 UI
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  // 记录错误日志，可对接 Sentry 等前端监控平台
  componentDidCatch(error, errorInfo) {
    console.error('【Ariadne 监控系统】大屏组件渲染崩溃:', error, errorInfo);
  }

  // 重置错误状态，尝试重新渲染
  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      // 降级 UI：当发生崩溃时，显示友好的赛博风错误提示而不是白屏
      return (
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100%', 
          minHeight: '400px', 
          background: 'rgba(15, 23, 42, 0.6)', 
          borderRadius: '8px', 
          border: '1px solid rgba(244, 63, 94, 0.3)' 
        }}>
          <Result
            icon={<WarningOutlined style={{ color: '#f43f5e', filter: 'drop-shadow(0 0 8px rgba(244,63,94,0.6))' }} />}
            title={<span style={{ color: '#e2e8f0', fontFamily: '"Chakra Petch", sans-serif', letterSpacing: '1px' }}>局部视图渲染异常</span>}
            subTitle={<span style={{ color: '#94a3b8' }}>检测到脏数据或组件崩溃，已隔离该区域以保护大屏主进程。</span>}
            extra={[
              <Button type="primary" danger key="retry" onClick={this.handleRetry} style={{ boxShadow: '0 0 10px rgba(244,63,94,0.4)' }}>
                尝试恢复 (REBOOT)
              </Button>
            ]}
          />
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;