/* src/App.jsx - 完整重构版 */
import React, { useState, useEffect, Suspense } from 'react';
import { BrowserRouter, Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import wsService from './services/websocket';
import { Layout, Menu, ConfigProvider, theme, message, Spin } from 'antd';
import {
  DashboardOutlined, DeploymentUnitOutlined, TableOutlined, ClusterOutlined,
  SafetyCertificateOutlined, WarningOutlined, DoubleLeftOutlined, DoubleRightOutlined,BugOutlined
} from '@ant-design/icons';

import ErrorBoundary from './components/ErrorBoundary';
import useDashboardStore from './store/useDashboardStore';
import CyberClock from './components/CyberClock';

import logoIcon from './images/Ariadne Logo.png';
import logoText from './images/logo文字部分.png';

// 路由按需加载 (Code Splitting)
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Investigation = React.lazy(() => import('./pages/Investigation'));
const AttackMatrix = React.lazy(() => import('./pages/AttackMatrix'));
const Assets = React.lazy(() => import('./pages/Assets'));
const Attribution = React.lazy(() => import('./pages/Attribution'));

const { Header, Content, Sider } = Layout;

const items = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '态势总览 (Dashboard)' },
  { key: 'investigation', icon: <DeploymentUnitOutlined />, label: '溯源画布 (Investigation)' },
  { key: 'attack', icon: <TableOutlined />, label: '战术分析 (ATT&CK)' },
  { key: 'assets', icon: <ClusterOutlined />, label: '资产与探针 (Sensors)' },
  { key: 'attribution', icon: <SafetyCertificateOutlined />, label: '情报与归因 (Attribution)' },
];

const viewTitles = {
  'dashboard': '态势总览 (DASHBOARD)',
  'investigation': '溯源画布 (INVESTIGATION)',
  'attack': '战术分析 (ATT&CK)',
  'assets': '资产与探针 (SENSORS)',
  'attribution': '情报与归因 (ATTRIBUTION)'
};

// 内部组件，以便使用 useNavigate 和 useLocation
const AppContent = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);
  
  const navigate = useNavigate();
  const location = useLocation();
  const currentPath = location.pathname === '/' ? 'dashboard' : location.pathname.substring(1);

  const { fetchStats, updateFromWS, triggerRefresh } = useDashboardStore();

  useEffect(() => {
    fetchStats();
    wsService.connect();

    const unsubscribe = wsService.subscribe((messages) => {
      updateFromWS(messages);

      let hasAnalysisReport = false;
      messages.forEach(msg => {
        if (msg.type === 'analysis_report') hasAnalysisReport = true;
        else if (msg.type === 'etl_error' || msg.type === 'analysis_error') message.error(`系统后台错误: ${msg.error}`);
      });

      if (hasAnalysisReport) {
        message.info(`收到新的实时分析报告`);
        fetchStats();
        triggerRefresh(); // 触发所有子页面重新拉取数据
      }
    });

    return () => {
      unsubscribe();
      wsService.disconnect();
    };
  }, []);

  const handleMenuClick = (e) => {
    navigate(`/${e.key}`);
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={(value) => {
          document.body.classList.add('sidebar-animating');
          setCollapsed(value);
          setIsAnimating(true);
          if (document.activeElement && document.activeElement.blur) {
            document.activeElement.blur();
          }
          setTimeout(() => {
            setIsAnimating(false);
            document.body.classList.remove('sidebar-animating');
          }, 300);
        }}
        width={240}
        style={{ overflow: 'hidden', pointerEvents: isAnimating ? 'none' : 'auto' }}
        trigger={
          <div className="cyber-sider-trigger">
            {collapsed ? (
              <DoubleRightOutlined style={{ color: '#38bdf8', fontSize: '16px' }} />
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8' }}>
                <DoubleLeftOutlined style={{ color: '#38bdf8' }} />
                <span style={{ fontSize: '12px', fontFamily: '"Share Tech Mono", monospace', letterSpacing: '1px' }}>
                  COLLAPSE
                </span>
              </div>
            )}
          </div>
        }
      >
        <div style={{ height: 64, margin: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
          <img src={logoIcon} alt="Ariadne Icon" style={{ height: collapsed ? '36px' : '48px', width: 'auto', transition: 'height 0.2s ease' }} />
          <div style={{ width: collapsed ? 0 : '120px', opacity: collapsed ? 0 : 1, transition: 'all 0.2s ease', overflow: 'hidden', marginLeft: collapsed ? 0 : '12px', display: 'flex', alignItems: 'center' }}>
            <img src={logoText} alt="Ariadne Text" style={{ height: '24px', width: 'auto' }} />
          </div>
        </div>
        <Menu theme="dark" selectedKeys={[currentPath]} mode="inline" items={items} onClick={handleMenuClick} />
      </Sider>
      <Layout>
        <Header style={{ padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '64px', background: 'rgba(15, 23, 42, 0.6)', backdropFilter: 'blur(10px)', borderBottom: '1px solid rgba(56, 189, 248, 0.1)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <h2 style={{ margin: 0, color: '#fff', fontSize: '20px', fontWeight: 600, letterSpacing: '1px', textShadow: '0 0 10px rgba(56, 189, 248, 0.5)' }}>
              {viewTitles[currentPath] || 'Ariadne'}
            </h2>
            <CyberClock />
            {currentPath === 'dashboard' && (
              <div className="threat-badge-animate" style={{ marginLeft: '16px', borderWidth: '1px', borderStyle: 'solid', color: '#f43f5e', fontSize: '11px', fontWeight: 700, fontFamily: '"Chakra Petch", sans-serif', padding: '2px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px', letterSpacing: '1px' }}>
                <BugOutlined /> THREAT LEVEL: CRITICAL
              </div>
            )}
          </div>
          <div className="alert-status-container" style={{ height: '32px', display: 'flex', alignItems: 'center', padding: '0 16px', borderLeft: '3px solid #f43f5e', borderRadius: '0 4px 4px 0', color: '#f43f5e', fontSize: '13px', fontWeight: '600', letterSpacing: '1px', fontFamily: '"Chakra Petch", sans-serif', boxShadow: 'inset -10px 0 20px -10px rgba(244, 63, 94, 0.2)', cursor: 'default', userSelect: 'none' }}>
            <WarningOutlined spin style={{ marginRight: '8px', fontSize: '14px', filter: 'drop-shadow(0 0 5px #f43f5e)' }} />
            <span>SYSTEM ALERTING</span>
            <div style={{ width: 6, height: 6, background: '#f43f5e', borderRadius: '50%', marginLeft: '10px', boxShadow: '0 0 5px #f43f5e' }}></div>
          </div>
        </Header>
        <Content style={{ margin: '20px', overflowY: 'auto', height: 'calc(100vh - 100px)' }}>
          <ErrorBoundary>
            <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', marginTop: 100 }}><Spin size="large" tip="模块加载中..." /></div>}>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/investigation" element={<Investigation />} />
                <Route path="/attack" element={<AttackMatrix />} />
                <Route path="/assets" element={<Assets />} />
                <Route path="/attribution" element={<Attribution />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </Content>
      </Layout>
    </Layout>
  );
};

const App = () => {
  return (
    <BrowserRouter>
      <ConfigProvider theme={{ algorithm: theme.darkAlgorithm, token: { colorBgBase: '#0b1121', colorBorder: 'rgba(56, 189, 248, 0.2)' }, components: { Table: { colorBgContainer: 'transparent', borderColor: '#1e293b' }, Drawer: { colorBgElevated: '#0f172a' } } }}>
        <AppContent />
      </ConfigProvider>
    </BrowserRouter>
  );
};

export default App;