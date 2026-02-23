/* src/App.jsx - 完整重构版 */
import React, { useState, useMemo, useEffect, Suspense } from 'react';
import wsService from './services/websocket'; // 引入刚才创建的服务
import { Layout, Menu, Card, Row, Col, Statistic, Table, Tag, ConfigProvider, theme, Switch, Progress, Timeline, Button, List, Avatar, Empty, Drawer, Descriptions, Slider, Spin, message } from 'antd';
import {
  DashboardOutlined, DeploymentUnitOutlined, TableOutlined, ClusterOutlined,
  SafetyCertificateOutlined, WarningOutlined, BugOutlined, CodeOutlined,
  WifiOutlined, ThunderboltFilled, PlayCircleOutlined, DoubleLeftOutlined, DoubleRightOutlined
} from '@ant-design/icons';

// 2. 引入虚拟列表和错误边界组件
import VirtualList from 'rc-virtual-list';
import ErrorBoundary from './components/ErrorBoundary';

// 引入 Zustand Store
import useDashboardStore from './store/useDashboardStore';

// 引入组件
import AttackGraph from './components/AttackGraph';
import TrafficTrend from './components/TrafficTrend';
// 3. 将 EntropyChart 改为懒加载 (按需加载，首屏不加载该图表代码)
const EntropyChart = React.lazy(() => import('./components/EntropyChart'));
import TopologyGraph from './components/TopologyGraph';
import CyberClock from './components/CyberClock'; // 引入独立的时钟组件

// 引入 API 服务
import { getDashboardStats, getTrafficTrend, getLatestAlerts, getAttackGraph, getAssetsList, getAttackHighlights, getAttributionResult, getChainsList, getSingleChainGraph } from './services/api';

// --- 1. 新增：引入图片资源 ---
import logoIcon from './images/Ariadne Logo.png';
import logoText from './images/logo文字部分.png';

const { Header, Content, Sider } = Layout;

// 导航配置
const items = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '态势总览 (Dashboard)' },
  { key: 'investigation', icon: <DeploymentUnitOutlined />, label: '溯源画布 (Investigation)' },
  { key: 'attack', icon: <TableOutlined />, label: '战术分析 (ATT&CK)' },
  { key: 'assets', icon: <ClusterOutlined />, label: '资产与探针 (Sensors)' },
  { key: 'attribution', icon: <SafetyCertificateOutlined />, label: '情报与归因 (Attribution)' },
];

// ATT&CK 静态数据 - 与后端 endpoints.py 和 attribution.py 保持一致
// 技术分类基于题目要求：主机日志、主机行为监控、网络流量分析
const attackMatrix = {
  "Initial Access": ["Web Shell", "Exploit Public-Facing Application", "Phishing"],
  "Execution": ["Command and Scripting Interpreter", "Windows Command Shell", "PowerShell"],
  "Persistence": ["Scheduled Task/Job", "Boot or Logon Autostart Execution", "Create Account"],
  "Privilege Escalation": ["Process Injection", "Elevated Execution with Prompt", "Access Token Manipulation"],
  "Defense Evasion": ["Regsvr32", "Rundll32", "File Deletion", "Masquerading", "Obfuscated Files"],
  "Credential Access": ["OS Credential Dumping", "Brute Force", "Credentials from Password Stores"],
  "Discovery": ["System Information Discovery", "File and Directory Discovery", "Process Discovery", "Network Service Scanning"],
  "Lateral Movement": ["Remote Desktop Protocol", "SMB/Windows Admin Shares", "SSH"],
  "Collection": ["Data from Local System", "Screen Capture", "Clipboard Data"],
  "Exfiltration": ["Exfiltration Over C2 Channel", "Exfiltration Over Alternative Protocol", "Exfiltration Over Web Service"],
  "Command and Control": ["Application Layer Protocol", "Encrypted Channel", "DNS Tunneling"],
  "Impact": ["Data Encrypted for Impact", "Service Stop", "Inhibit System Recovery"]
};
const hitTactics = ["Command and Scripting Interpreter", "Process Injection", "Obfuscated Files", "Encrypted Channel"];

const App = () => {
  const [collapsed, setCollapsed] = useState(false);
  // 1. 新增：动画状态锁，用于解决收缩时的气泡闪烁问题
  const [isAnimating, setIsAnimating] = useState(false);
  const [currentView, setCurrentView] = useState('dashboard');
  const [loading, setLoading] = useState(true); // 全局加载状态
  // 移除原有的 currentTime 状态和 useEffect 定时器，避免全局重渲染

  // 2. 新增：页面标题映射 (根据 currentView 显示不同的大标题)
  const viewTitles = {
    'dashboard': '态势总览 (DASHBOARD)',
    'investigation': '溯源画布 (INVESTIGATION)',
    'attack': '战术分析 (ATT&CK)',
    'assets': '资产与探针 (SENSORS)',
    'attribution': '情报与归因 (ATTRIBUTION)'
  };

  // === 1. 动态数据状态 (State) ===
  // 移除原有的 stats useState，改用 Zustand Store
  const { stats, fetchStats, updateFromWS } = useDashboardStore();

  const [trafficData, setTrafficData] = useState(null); // 传给 TrafficTrend
  const [alertList, setAlertList] = useState([]);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] }); // 溯源图数据
  const [assetData, setAssetData] = useState([]);
  const [hitTactics, setHitTactics] = useState([]);
  const [attribution, setAttribution] = useState({ name: 'Unknown', code: '???', score: 0 });
  // const [storyline, setStoryline] = useState([]); // 攻击叙事线功能已禁用

  // 【新增】攻击链相关状态
  const [chainsList, setChainsList] = useState([]);  // 攻击链列表
  const [selectedChainId, setSelectedChainId] = useState(null);  // 当前选中的攻击链

  // === 2. 交互状态 ===
  const [selectedNode, setSelectedNode] = useState(null);
  const [highlightPath, setHighlightPath] = useState([]);
  const [analysisVisible, setAnalysisVisible] = useState(false);
  const [currentAlert, setCurrentAlert] = useState(null);
  const [timeStep, setTimeStep] = useState(4);

  // 移除原有的 useEffect 定时器逻辑

  // === 3. 数据加载逻辑 (Lifecycle) ===
  useEffect(() => {
    // 定义加载函数
    const loadAllData = async () => {
      setLoading(true);
      try {
        // 并行请求所有关键数据 (stats 改为通过 store 获取)
        await fetchStats();
        const [trafficRes, alertsRes, chainsListRes, assetsRes, attackRes, attrRes] = await Promise.all([
          getTrafficTrend(),
          getLatestAlerts(),
          getChainsList(),  // ← 新增：获取攻击链列表
          getAssetsList(),
          getAttackHighlights(),
          getAttributionResult(),
        ]);

        console.log(trafficRes);

        setTrafficData(trafficRes);
        setAlertList(alertsRes);
        setChainsList(chainsListRes.chains || []);  // ← 存储攻击链列表
        setAssetData(assetsRes);
        setHitTactics(attackRes);
        setAttribution(attrRes);

        // 【新增】默认加载第一个攻击链的图谱
        if (chainsListRes.chains && chainsListRes.chains.length > 0) {
          const firstChain = chainsListRes.chains[0];
          setSelectedChainId(firstChain.id);
          const graphRes = await getSingleChainGraph(firstChain.id);
          setGraphData(graphRes);
        } else {
          setGraphData({ nodes: [], links: [] });
        }

        // message.success("实时数据已同步");
      } catch (error) {
        console.error("Data load failed:", error);
      } finally {
        setLoading(false);
      }
    };

    loadAllData();
    // 真实场景可以设置定时器轮询: const timer = setInterval(loadAllData, 30000);

    // ==========================================
    // 2. 新增：WebSocket 实时通信集成
    // ==========================================
    // 连接 WebSocket
    wsService.connect();

    // 订阅消息处理函数 (接收批量消息数组)
    const unsubscribe = wsService.subscribe((messages) => {
      // 1. 将批量消息交给 Zustand 处理，局部更新 stats，避免 App.jsx 顶层雪崩
      updateFromWS(messages);

      // 2. 遍历消息处理其他副作用
      let hasAnalysisReport = false;

      messages.forEach(msg => {
        switch (msg.type) {
          case 'analysis_report':
            hasAnalysisReport = true;
            break;
          case 'etl_error':
          case 'analysis_error':
            message.error(`系统后台错误: ${msg.error}`);
            break;
          default:
            break;
        }
      });

      // 如果这批消息里包含分析报告，统一触发一次 API 刷新，避免高频请求
      if (hasAnalysisReport) {
        message.info(`收到新的实时分析报告`);
        fetchStats(); // 重新获取完整的统计数据（包括 intercepted_today）
        getAttackHighlights().then(hitList => setHitTactics(hitList || []));
        getLatestAlerts().then(setAlertList);
        getAttributionResult().then(setAttribution);
        getAssetsList().then(setAssetData);

        // 刷新流量趋势和攻击链列表
        getTrafficTrend().then(setTrafficData);
        getChainsList().then(newChainsList => {
          setChainsList(newChainsList.chains || []);
          // 注意：由于闭包问题，这里 selectedChainId 可能是旧值，
          // 实际项目中建议用 useRef 追踪 selectedChainId，这里保持原逻辑结构
          if (selectedChainId) {
            getSingleChainGraph(selectedChainId).then(setGraphData);
          }
        });
      }
    });

    // 组件卸载时断开连接
    return () => {
      unsubscribe(); // 取消订阅
      wsService.disconnect(); // 关闭 socket
    };

  }, []);

  // === 4. 时序回放逻辑 ===
  const filteredGraphData = useMemo(() => {
    if (!graphData || !graphData.nodes) return { nodes: [], links: [] };
    const nodesToShowCount = [1, 2, 3, 4, 5][timeStep] || 5;
    // 注意：这里假设 graphData.nodes 的顺序就是时序顺序
    const visibleNodes = graphData.nodes.slice(0, nodesToShowCount);
    const visibleLinks = graphData.links.filter(link =>
      visibleNodes.find(n => n.id === link.source) && visibleNodes.find(n => n.id === link.target)
    );
    return { nodes: visibleNodes, links: visibleLinks };
  }, [timeStep, graphData]);

  const ATTACK_PATH = ['192.168.1.5', 'cmd.exe', 'powershell.exe', '114.114.114.114'];

  // === 事件处理 ===
  const handleMenuClick = (e) => {
    setCurrentView(e.key);
    setSelectedNode(null);
    setHighlightPath([]);
  };

  // 【新增】处理攻击链点击事件
  const handleChainClick = async (chainId) => {
    if (selectedChainId === chainId) return; // 已经选中，不重复加载

    setSelectedChainId(chainId);
    setSelectedNode(null);  // 清除节点选择
    setHighlightPath([]);   // 清除高亮路径

    try {
      const graphRes = await getSingleChainGraph(chainId);
      setGraphData(graphRes);
    } catch (error) {
      console.error("Failed to load chain graph:", error);
      message.error("加载攻击链失败");
    }
  };

  const handleAlertClick = (item) => {
    if (item.title.includes('DNS Tunnel')) {
      setCurrentAlert(item);
      setAnalysisVisible(true);
    }
  };

  const handleTacticClick = (tech) => {
    if (hitTactics.includes(tech)) {
      setCurrentView('investigation');
      if (tech === "Process Injection") {
        setHighlightPath(['cmd.exe', 'powershell.exe']);
        const node = graphData.nodes.find(n => n.id === 'powershell.exe');
        if (node) setSelectedNode(node);
      }
    }
  };

  // === 渲染内容 ===
  const renderContent = () => {
    if (loading && currentView === 'dashboard') {
      return <div style={{ display: 'flex', justifyContent: 'center', marginTop: 100 }}><Spin size="large" tip="系统连接中..." /></div>;
    }

    switch (currentView) {
      case 'dashboard':
        return (
          <>
            <Row gutter={[16, 16]}>
              <Col span={6}>
                <Card bordered={false} className="cyber-card">
                  {/* 使用 API 数据替换硬编码 */}
                  <Statistic title="活跃威胁源" value={stats.active_threats} valueStyle={{ color: '#f43f5e' }} prefix={<BugOutlined />} />
                </Card>
              </Col>
              <Col span={6}>
                <Card bordered={false} className="cyber-card">
                  <Statistic title="今日拦截" value={stats.intercepted_today} valueStyle={{ color: '#34d399' }} />
                </Card>
              </Col>
              <Col span={6}>
                <Card bordered={false} className="cyber-card">
                  <Statistic title="数据吞吐 (EPS)" value={stats.throughput_eps} suffix="Evt/s" valueStyle={{ color: '#38bdf8' }} />
                </Card>
              </Col>
              <Col span={6}>
                <Card bordered={false} className="cyber-card">
                  <Statistic title="时间同步偏差" value={stats.time_sync_offset} suffix="ms" valueStyle={{ color: '#fbbf24' }} />
                </Card>
              </Col>
            </Row>

            <Row gutter={[16, 16]} style={{ marginTop: '16px' }}>
              <Col span={16} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <Card title="流量趋势对比 (EPS TREND)" bordered={false} className="cyber-card" style={{ height: '400px' }}>
                  {/* 将 API 数据传递给组件 */}
                  <TrafficTrend data={trafficData} />
                </Card>
                <Card title="全网拓扑监控 (TOPOLOGY VIEW)" bordered={false} className="cyber-card" style={{ height: '400px' }}>
                  <TopologyGraph />
                </Card>
              </Col>

              <Col span={8}>
                <Card title="实时告警 (LATEST ALERTS)" bordered={false} className="cyber-card" style={{ height: '100%', minHeight: '816px' }}>
                  {/* 4. 虚拟列表改造：只渲染可视区域内的 DOM 节点，防止海量日志卡死浏览器 */}
                  <List size="small">
                    <VirtualList
                      data={alertList}
                      height={700}       // 虚拟列表容器高度
                      itemHeight={65}    // 预估每个列表项的高度
                      itemKey={(item, index) => item.id || index} // 唯一键值
                    >
                      {(item, index) => (
                        <List.Item
                          key={item.id || index}
                          style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', cursor: item.clickable ? 'pointer' : 'default' }}
                          onClick={() => item.clickable && handleAlertClick(item)}
                        >
                          <List.Item.Meta
                            avatar={<WarningOutlined style={{ fontSize: '18px', color: item.level === 'High' ? '#f43f5e' : '#fbbf24', marginTop: '5px' }} />}
                            title={<div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: '#cbd5e1' }}>{item.title}</span>{item.clickable && <Tag color="blue" style={{ transform: 'scale(0.8)', margin: 0 }}>点击分析</Tag>}</div>}
                            description={<span style={{ color: '#64748b', fontSize: '12px' }}>{item.source} | {item.time}</span>}
                          />
                        </List.Item>
                      )}
                    </VirtualList>
                  </List>
                </Card>
              </Col>
            </Row>
          </>
        );

      case 'investigation':
        return (
          <Row gutter={[16, 16]}>
            <Col span={18}>
              <Card
                title={
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>交互式攻击图谱 (INTERACTIVE GRAPH)</span>
                    <div style={{ display: 'flex', gap: 10 }}>
                      <Button size="small" icon={<PlayCircleOutlined />} onClick={() => { setTimeStep(0); let i = 0; const t = setInterval(() => { i++; if (i <= 4) setTimeStep(i); else clearInterval(t); }, 1000); }}>回放</Button>
                      <Button type="primary" danger={highlightPath.length > 0} icon={<ThunderboltFilled />} onClick={() => setHighlightPath(highlightPath.length > 0 ? [] : ATTACK_PATH)}>
                        {highlightPath.length > 0 ? "清除路径" : "一键溯源"}
                      </Button>
                    </div>
                  </div>
                }
                bordered={false} className="cyber-card" bodyStyle={{ padding: 0 }} style={{ marginBottom: '16px' }}
              >
                <div style={{ height: 600, width: '100%', position: 'relative' }}>
                  {graphData.nodes && graphData.nodes.length > 0 ? (
                    <AttackGraph onNodeClick={setSelectedNode} highlightNodes={highlightPath} graphData={graphData} />
                  ) : (
                    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#94a3b8' }}>
                      <Empty description="请从右侧选择攻击链" />
                    </div>
                  )}
                </div>
                <div style={{ padding: '20px 24px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid #1e293b' }}>
                  <div style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '5px' }}>
                    当前攻击链: {selectedChainId ? chainsList.find(c => c.id === selectedChainId)?.name : '未选择'}
                  </div>
                </div>
              </Card>
            </Col>

            {/* 【修改】右侧面板：从节点详情改为攻击链列表 */}
            <Col span={6}>
              <Card
                title="攻击链列表 (ATTACK CHAINS)"
                bordered={false}
                className="cyber-card"
                style={{ height: '100%', maxHeight: '680px' }}
                bodyStyle={{ padding: '8px', overflowY: 'auto', maxHeight: '600px' }}
              >
                {chainsList.length > 0 ? (
                  <List
                    size="small"
                    dataSource={chainsList}
                    renderItem={chain => (
                      <List.Item
                        key={chain.id}
                        onClick={() => handleChainClick(chain.id)}
                        style={{
                          cursor: 'pointer',
                          borderLeft: selectedChainId === chain.id ? '3px solid #f43f5e' : '3px solid transparent',
                          backgroundColor: selectedChainId === chain.id ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
                          padding: '10px 12px',
                          marginBottom: '6px',
                          borderRadius: '4px',
                          transition: 'all 0.3s',
                          border: '1px solid rgba(255,255,255,0.05)'
                        }}
                        onMouseEnter={(e) => {
                          if (selectedChainId !== chain.id) {
                            e.currentTarget.style.backgroundColor = 'rgba(56, 189, 248, 0.1)';
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (selectedChainId !== chain.id) {
                            e.currentTarget.style.backgroundColor = 'transparent';
                          }
                        }}
                      >
                        <List.Item.Meta
                          avatar={
                            <Avatar
                              size="small"
                              style={{
                                backgroundColor: chain.severity === 'high' ? '#f43f5e' : chain.severity === 'medium' ? '#fbbf24' : '#22d3ee',
                                fontWeight: 'bold',
                                fontSize: '11px'
                              }}
                            >
                              {chain.length}
                            </Avatar>
                          }
                          title={
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <span style={{ color: '#fff', fontSize: '12px', fontWeight: selectedChainId === chain.id ? 'bold' : 'normal' }}>
                                {chain.name}
                              </span>
                              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                <Tag
                                  color={chain.severity === 'high' ? 'red' : chain.severity === 'medium' ? 'orange' : 'blue'}
                                  style={{ margin: 0, fontSize: '10px', padding: '0 4px' }}
                                >
                                  {chain.severity.toUpperCase()}
                                </Tag>
                                <Tag
                                  color={chain.type === 'process_tree' ? 'purple' : 'cyan'}
                                  style={{ margin: 0, fontSize: '10px', padding: '0 4px' }}
                                >
                                  {chain.type === 'process_tree' ? '进程链' : '网络链'}
                                </Tag>
                              </div>
                            </div>
                          }
                          description={
                            <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>
                              <div>{chain.host_id}</div>
                              <div style={{ marginTop: '2px' }}>{chain.description}</div>
                            </div>
                          }
                        />
                      </List.Item>
                    )}
                  />
                ) : (
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description={<span style={{ color: '#64748b' }}>暂无攻击链数据</span>}
                  />
                )}
              </Card>
            </Col>
          </Row>
        );

      case 'attack':
        const tactics = Object.keys(attackMatrix);
        const firstRowTactics = tactics.slice(0, 6);  // 前6个战术
        const secondRowTactics = tactics.slice(6, 12); // 后6个战术

        const renderTacticColumn = (tactic) => (
          <div key={tactic} style={{ minWidth: '180px', flex: 1, background: 'rgba(255,255,255,0.02)', borderRadius: '6px', padding: '10px' }}>
            <div style={{ color: '#cbd5e1', fontWeight: 'bold', marginBottom: '10px', borderBottom: '2px solid #334155', paddingBottom: '8px' }}>{tactic}</div>
            {attackMatrix[tactic].length > 0 ? (
              attackMatrix[tactic].map(tech => (
                <div key={tech} onClick={() => handleTacticClick(tech)} style={{ padding: '8px', fontSize: '12px', borderRadius: '4px', background: hitTactics.includes(tech) ? 'rgba(244, 63, 94, 0.2)' : 'rgba(30, 41, 59, 0.5)', border: hitTactics.includes(tech) ? '1px solid #f43f5e' : '1px solid #334155', color: hitTactics.includes(tech) ? '#fff' : '#94a3b8', cursor: 'pointer', marginBottom: 4 }}>{tech}</div>
              ))
            ) : (
              <div style={{ padding: '8px', fontSize: '12px', color: '#475569', fontStyle: 'italic' }}>暂无检测技术</div>
            )}
          </div>
        );

        return (
          <Row style={{ height: '100%' }}>
            <Col span={24}>
              <Card title="ATT&CK 动态矩阵" bordered={false} className="cyber-card" style={{ height: '100%', overflowY: 'auto' }}>
                {/* 第一行：前6个战术 */}
                <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                  {firstRowTactics.map(renderTacticColumn)}
                </div>
                {/* 第二行：后6个战术 */}
                <div style={{ display: 'flex', gap: '12px' }}>
                  {secondRowTactics.map(renderTacticColumn)}
                </div>
              </Card>
            </Col>
          </Row>
        );

      case 'assets':
        // === 修复开始：给数据加个保险 ===
        // 如果 assetData 是 null/undefined，就用空数组 [] 代替，防止 Table 崩溃
        const safeAssetData = Array.isArray(assetData) ? assetData : [];
        // === 修复结束 ===
        return (
          <Card title="资产与探针管理 (SENSOR FLEET)" bordered={false} className="cyber-card">
            {/* 使用 API 获取的 assetData */}
            <Table dataSource={safeAssetData} columns={[
              { title: '节点名称', dataIndex: 'name', render: (t) => <b style={{ color: '#fff' }}>{t}</b> },
              { title: 'IP 地址', dataIndex: 'ip', render: (t) => <span style={{ fontFamily: 'monospace' }}>{t}</span> },
              { title: '角色', dataIndex: 'role', render: (r) => <Tag color="blue">{r}</Tag> },
              { title: 'Wazuh 采集', key: 'wazuh', render: (_, record) => <Switch checkedChildren={<CodeOutlined />} unCheckedChildren={<CodeOutlined />} defaultChecked={record.wazuh} /> },
              { title: 'Zeek 流量', key: 'zeek', render: (_, record) => <Switch checkedChildren={<WifiOutlined />} unCheckedChildren={<WifiOutlined />} defaultChecked={record.zeek} /> },
              {
                title: '状态', dataIndex: 'status', render: (status) => {
                  const statusConfig = {
                    online: { color: 'success', text: 'Online' },
                    offline: { color: 'default', text: 'Offline' },
                    suspicious: { color: 'warning', text: 'Suspicious' },
                    compromised: { color: 'error', text: 'Compromised' }
                  };
                  const config = statusConfig[status?.toLowerCase()] || statusConfig.online;
                  return <Tag color={config.color}>{config.text}</Tag>;
                }
              },
            ]} pagination={false} rowClassName={() => 'cyber-table-row'} />
          </Card>
        );

      case 'attribution':
        // === 修复 1: 定义一个安全的变量 ===
        // 防止 attribution 本身是 null 导致后面报错
        const safeAttr = attribution || {
          name: 'Loading...',
          code: '...',
          confidence: 0,
          evidence: []
        };

        return (
          <Row gutter={[16, 16]}>
            <Col span={10}>
              <Card title="APT 组织画像" bordered={false} className="cyber-card">
                <div style={{ textAlign: 'center', padding: '20px' }}>
                  <Avatar size={100} style={{ backgroundColor: '#f43f5e', fontSize: '32px' }}>
                    {safeAttr.code}
                  </Avatar>
                  <h2 style={{ color: '#fff', marginTop: '20px' }}>{safeAttr.name}</h2>
                  <Progress
                    percent={safeAttr.confidence}
                    strokeColor="#f43f5e"
                    trailColor="#334155"
                    style={{ marginTop: 20 }}
                  />
                </div>
              </Card>
            </Col>
            <Col span={14}>
              <Card title="证据链" bordered={false} className="cyber-card">
                <Timeline
                  // === 修复 2: 给 evidence 加保险 ===
                  // 如果 evidence 是 undefined，就用空数组 [] 代替，防止 .map 报错
                  items={(safeAttr.evidence || []).map(item => ({
                    color: item.color,
                    children: <span style={{ color: '#cbd5e1' }}>{item.content}</span>
                  }))}
                />
              </Card>
            </Col>
          </Row>
        );
      default: return null;
    }
  };

  return (
    <ConfigProvider theme={{ algorithm: theme.darkAlgorithm, token: { colorBgBase: '#0b1121', colorBorder: 'rgba(56, 189, 248, 0.2)' }, components: { Table: { colorBgContainer: 'transparent', borderColor: '#1e293b' }, Drawer: { colorBgElevated: '#0f172a' } } }}>
      <Layout style={{ minHeight: '100vh' }}>
        <Sider
          collapsible
          collapsed={collapsed}
          // 2. 修改 onCollapse：点击收缩时，上锁 300ms (对应 CSS 动画时间)
          onCollapse={(value) => {
            // === 1.【同步拦截】点击瞬间，立马给 body 加锁，不给 Tooltip 任何机会 ===
            document.body.classList.add('sidebar-animating');
            setCollapsed(value);
            setIsAnimating(true);
            if (document.activeElement && document.activeElement.blur) {
              document.activeElement.blur();
            }
            // === 2.【定时解锁】动画结束后 (300ms) 移除锁 ===
            setTimeout(() => {
              setIsAnimating(false);
              document.body.classList.remove('sidebar-animating');
            }, 300);
          }}
          width={240}
          // 3. 修改 style：在动画期间禁用鼠标事件 (pointerEvents: 'none')
          style={{
            overflow: 'hidden',
            // 核心修复代码：如果正在动画中，禁止一切鼠标交互（也就不会触发 Tooltip 了）
            pointerEvents: isAnimating ? 'none' : 'auto'
          }}
          // --- 修改开始：自定义底部触发器 ---
          trigger={
            <div className="cyber-sider-trigger">
              {/* 根据收缩状态切换图标 */}
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
        // --- 修改结束 ---
        >
          {/* --- 修改开始：侧边栏 Logo 区域 (防抖动优化版) --- */}
          <div style={{
            height: 64,
            margin: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            overflow: 'hidden',
          }}>
            {/* 1. 图标 Logo */}
            <img
              src={logoIcon}
              alt="Ariadne Icon"
              style={{
                height: collapsed ? '36px' : '48px',
                width: 'auto',
                // 【修改】速度改为 0.2s，与侧边栏收缩同步
                transition: 'all 0.2s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
                objectFit: 'contain'
              }}
            />

            {/* 2. 文字 Logo 的容器 */}
            <div style={{
              maxWidth: collapsed ? 0 : 200,
              opacity: collapsed ? 0 : 1,
              marginLeft: collapsed ? 0 : 6,

              display: 'flex',
              alignItems: 'center',
              overflow: 'hidden',
              whiteSpace: 'nowrap',
              // 【修改】速度改为 0.2s，快速收缩，避免撑开侧边栏
              transition: 'all 0.2s cubic-bezier(0.25, 0.46, 0.45, 0.94)',
            }}>
              <img
                src={logoText}
                alt="Ariadne Text"
                style={{
                  height: '34px',
                  objectFit: 'contain'
                }}
              />
            </div>
          </div>
          {/* --- 修改结束 --- */}
          <Menu theme="dark" defaultSelectedKeys={['dashboard']} mode="inline" items={items} onClick={handleMenuClick} />
        </Sider>
        <Layout>
          <Header style={{
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            height: '64px',
            background: 'rgba(15, 23, 42, 0.6)', // 稍微加深背景
            backdropFilter: 'blur(10px)',
            borderBottom: '1px solid rgba(56, 189, 248, 0.1)'
          }}>
            {/* --- 修改开始：头部左侧 (标题 + 时间) --- */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>

              {/* 1. 当前页面大标题 */}
              <h2 style={{
                margin: 0,
                color: '#fff',
                fontSize: '20px',
                fontWeight: 800, // 字体加粗
                letterSpacing: '1px', // 增加字间距，更有科技感
                fontFamily: '"Chakra Petch", sans-serif', // 如果有赛博字体最好，没有就用默认
                textTransform: 'uppercase'
              }}>
                {viewTitles[currentView] || 'SYSTEM CONSOLE'}
              </h2>

              {/* 2. 分隔竖线 */}
              <div style={{ width: '1px', height: '16px', background: '#334155' }}></div>

              {/* 3. 实时时间 (使用独立的 CyberClock 组件阻断重渲染) */}
              <div style={{
                fontFamily: '"Share Tech Mono", monospace',
                background: 'rgba(15, 23, 42, 0.8)',
              }}>
                <CyberClock />
              </div>

              {/* 4. (可选) 威胁等级 Badge - 仅在 Dashboard 显示 */}
              {currentView === 'dashboard' && (
                <div
                  className="threat-badge-animate" // 引用刚才在 index.css 定义的呼吸动画
                  style={{
                    marginLeft: '16px', // 稍微离时间远一点
                    // 移除原来的固定背景和边框颜色，交给 CSS 动画控制以实现呼吸效果
                    borderWidth: '1px',
                    borderStyle: 'solid',

                    color: '#f43f5e',
                    fontSize: '11px', // 字体改小一点，更精致
                    fontWeight: 700,
                    fontFamily: '"Chakra Petch", sans-serif',

                    // 【关键修改】紧凑布局设置
                    height: '24px',        // 强制固定高度，防止变得太胖
                    padding: '0 10px',     // 左右留白，上下为0 (靠 align-items 居中)
                    borderRadius: '4px',   // 稍微圆润一点

                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    letterSpacing: '0.5px',
                    cursor: 'default',
                    userSelect: 'none'
                  }}>
                  {/* 红点指示器 */}
                  <div style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: '#f43f5e',
                    boxShadow: '0 0 6px #f43f5e' // 红点自带常亮光晕
                  }}></div>
                  HIGH THREAT LEVEL
                </div>
              )}
            </div>
            {/* --- 修改结束 --- */}

            {/* --- 修改开始：Header 右侧 (高级状态指示器) --- */}
            <div
              className="alert-status-container" // 引用光影扫描动画
              style={{
                height: '32px',              // 1. 压低高度，使其紧凑
                display: 'flex',
                alignItems: 'center',
                padding: '0 16px',           // 左右留出空间

                // 2. 科技感设计核心：
                // 不用全边框，只用左侧亮条作为视觉锚点
                borderLeft: '3px solid #f43f5e',
                // 右侧加个圆角，左侧直角，增加几何美感
                borderRadius: '0 4px 4px 0',

                color: '#f43f5e',
                fontSize: '13px',
                fontWeight: '600',
                letterSpacing: '1px',
                fontFamily: '"Chakra Petch", sans-serif',
                boxShadow: 'inset -10px 0 20px -10px rgba(244, 63, 94, 0.2)', // 内部微光
                cursor: 'default',
                userSelect: 'none'
              }}>
              {/* 旋转的图标，加一个发光滤镜 */}
              <WarningOutlined spin style={{ marginRight: '8px', fontSize: '14px', filter: 'drop-shadow(0 0 5px #f43f5e)' }} />

              <span>SYSTEM ALERTING</span>

              {/* 可选：加一个小小的 LIVE 状态点 */}
              <div style={{ width: 6, height: 6, background: '#f43f5e', borderRadius: '50%', marginLeft: '10px', boxShadow: '0 0 5px #f43f5e' }}></div>
            </div>
            {/* --- 修改结束 --- */}
          </Header>
          <Content style={{ margin: '20px', overflowY: 'auto', height: 'calc(100vh - 100px)' }}>
            {/* 5. 使用 ErrorBoundary 包裹核心大屏内容，防止局部崩溃导致全局白屏 */}
            <ErrorBoundary>
              {renderContent()}
            </ErrorBoundary>
          </Content>
          <Drawer title="威胁深度分析" placement="right" width={600} onClose={() => setAnalysisVisible(false)} open={analysisVisible} styles={{ body: { background: '#0b1121' } }}>
            {currentAlert && (
              <>
                <h3 style={{ color: '#f43f5e' }}>{currentAlert.title}</h3>
                <div style={{ height: '220px', margin: '20px 0' }}>
                  {/* 6. Suspense 配合 React.lazy，在加载图表代码时显示科技感 Spin */}
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}><Spin size="large" tip="加载深度分析引擎..." /></div>}>
                    <EntropyChart />
                  </Suspense>
                </div>
              </>
            )}
          </Drawer>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
};

export default App;