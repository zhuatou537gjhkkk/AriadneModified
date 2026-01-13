/* src/App.jsx - 完整重构版 */
import React, { useState, useMemo, useEffect } from 'react';
import wsService from './services/websocket'; // 引入刚才创建的服务
import { Layout, Menu, Card, Row, Col, Statistic, Table, Tag, ConfigProvider, theme, Switch, Progress, Timeline, Button, List, Avatar, Empty, Drawer, Descriptions, Slider, Spin, message } from 'antd';
import {
  DashboardOutlined, DeploymentUnitOutlined, TableOutlined, ClusterOutlined,
  SafetyCertificateOutlined, WarningOutlined, BugOutlined, CodeOutlined,
  WifiOutlined, ThunderboltFilled, PlayCircleOutlined
} from '@ant-design/icons';


// 引入组件
import AttackGraph from './components/AttackGraph';
import TrafficTrend from './components/TrafficTrend';
import EntropyChart from './components/EntropyChart';
import TopologyGraph from './components/TopologyGraph';

// 引入 API 服务
import { getDashboardStats, getTrafficTrend, getLatestAlerts, getAttackGraph, getAssetsList, getAttackHighlights, getAttributionResult, getAttackStoryline } from './services/api';

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
  const [currentView, setCurrentView] = useState('dashboard');
  const [loading, setLoading] = useState(true); // 全局加载状态

  // === 1. 动态数据状态 (State) ===
  const [stats, setStats] = useState({ active_threats: 0, intercepted_today: 0, throughput_eps: 0, time_sync_offset: 0 });
  const [trafficData, setTrafficData] = useState(null); // 传给 TrafficTrend
  const [alertList, setAlertList] = useState([]);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] }); // 溯源图数据
  const [assetData, setAssetData] = useState([]);
  const [hitTactics, setHitTactics] = useState([]);
  const [attribution, setAttribution] = useState({ name: 'Unknown', code: '???', score: 0 });
  const [storyline, setStoryline] = useState([]);

  // === 2. 交互状态 ===
  const [selectedNode, setSelectedNode] = useState(null);
  const [highlightPath, setHighlightPath] = useState([]);
  const [analysisVisible, setAnalysisVisible] = useState(false);
  const [currentAlert, setCurrentAlert] = useState(null);
  const [timeStep, setTimeStep] = useState(4);

  // === 3. 数据加载逻辑 (Lifecycle) ===
  useEffect(() => {
    // 定义加载函数
    const loadAllData = async () => {
      setLoading(true);
      try {
        // 并行请求所有关键数据（修复：Promise.all 的顺序和解构必须一一对应）
        const [statsRes, trafficRes, alertsRes, graphRes, assetsRes, attackRes, attrRes, storylineRes] = await Promise.all([
          getDashboardStats(),
          getTrafficTrend(),
          getLatestAlerts(),
          getAttackGraph(),
          getAssetsList(),
          getAttackHighlights(),
          getAttributionResult(),
          getAttackStoryline()
        ]);

        console.log(statsRes);

        setStats(statsRes);
        setTrafficData(trafficRes);
        setAlertList(alertsRes);
        setGraphData(graphRes);
        setAssetData(assetsRes);
        setHitTactics(attackRes);
        setAttribution(attrRes);
        setStoryline(storylineRes);

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

    // 订阅消息处理函数
    // 订阅消息处理函数
    const unsubscribe = wsService.subscribe((msg) => {
      console.log('收到 WebSocket 消息:', msg);

      switch (msg.type) {

        // === 情况 A: 收到最新的分析报告 ===
        // === 情况 A: 收到最新的分析报告 ===
        case 'analysis_report':
          message.info(`收到新的实时分析报告 (${msg.timestamp})`);

          // 1. 更新统计数据 (严格对齐 endpoints.py 公式)
          const chainCount = msg.attack_chains?.total || 0;
          const lateralCount = msg.lateral_movement || 0;
          const exfilCount = msg.data_exfiltration || 0;
          const totalThreats = chainCount + lateralCount + exfilCount;

          setStats(prev => ({
            ...prev,
            active_threats: totalThreats,
            intercepted_today: totalThreats * 45,
          }));

          // 2. 【核心修复】更新 ATT&CK 矩阵高亮
          // WebSocket 只推了统计数字，具体的“技术名称”需要调用 API 获取
          // 这里直接调用我们在 api.js 里定义的接口，它会返回 ["Web Shell", "Process Injection"...]
          getAttackHighlights().then(hitList => {
            console.log("刷新 ATT&CK 高亮:", hitList);
            setHitTactics(hitList || []);
          });

          // 3. 触发其他详情刷新
          getLatestAlerts().then(setAlertList);
          getAttributionResult().then(setAttribution);
          getAttackStoryline().then(setStoryline);
          getAttackGraph().then(setGraphData);
          getAssetsList().then(setAssetData);
          getTrafficTrend().then(setTrafficData);

          break;

        // === 情况 B: ETL 状态更新 ===
        case 'etl_status':
          // 如果后端发来了 EPS (Events Per Second) 数据，可以在这里更新
          // if (msg.events_processed) {
          //    setStats(prev => ({ ...prev, throughput_eps: msg.events_processed }));
          // }
          break;

        // === 情况 C: 错误处理 ===
        case 'etl_error':
        case 'analysis_error':
          message.error(`系统后台错误: ${msg.error}`);
          break;

        default:
          break;
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
                  <List
                    size="small"
                    dataSource={alertList} // 使用 API 数据
                    renderItem={item => (
                      <List.Item
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
                  />
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
                  {filteredGraphData.nodes.length > 0 ? (
                    <AttackGraph onNodeClick={setSelectedNode} highlightNodes={highlightPath} graphData={filteredGraphData} />
                  ) : (
                    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#94a3b8' }}><Empty description="暂无数据" /></div>
                  )}
                </div>
                <div style={{ padding: '20px 24px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid #1e293b' }}>
                  <div style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '5px' }}>时序回放轴 (TIMELINE REPLAY)</div>
                  <Slider min={0} max={4} value={timeStep} onChange={setTimeStep}
                    marks={{ 0: { style: { color: '#cbd5e1' }, label: '10:00:00' }, 4: { style: { color: '#f43f5e' }, label: 'C2 Connect' } }}
                  />
                </div>
              </Card>
              <Card title="攻击叙事线 (STORYLINE)" bordered={false} className="cyber-card">
                <Timeline mode="left" style={{ marginTop: '20px' }}>

                  {/* === 动态渲染开始 === */}
                  {storyline && storyline.length > 0 ? (
                    storyline.map((item, index) => (
                      <Timeline.Item
                        key={index}
                        // 根据后端返回的 type 字段决定颜色 (danger=红, warning=黄, info=蓝)
                        color={item.type === 'danger' ? 'red' : (item.type === 'warning' ? 'orange' : 'blue')}
                        label={<span style={{ color: '#64748b' }}>{item.time}</span>}
                      >
                        <span style={{ color: '#cbd5e1' }}>
                          {item.content}
                        </span>
                      </Timeline.Item>
                    ))
                  ) : (
                    <Timeline.Item>暂无数据</Timeline.Item>
                  )}
                  {/* === 动态渲染结束 === */}

                </Timeline>
              </Card>
            </Col>
            <Col span={6}>
              <Card title="节点详情 (DETAILS)" bordered={false} className="cyber-card" style={{ height: '100%' }}>
                {selectedNode ? (
                  <div style={{ color: '#94a3b8', animation: 'fadeIn 0.3s' }}>
                    <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                      <Tag color="blue" style={{ fontSize: '14px', padding: '4px 10px' }}>{selectedNode.category}</Tag>
                      <h3 style={{ color: '#fff', margin: '10px 0' }}>{selectedNode.name}</h3>
                    </div>
                    <Descriptions column={1} size="small" labelStyle={{ color: '#94a3b8' }} contentStyle={{ color: '#fff' }}>
                      <Descriptions.Item label="ID">{selectedNode.id}</Descriptions.Item>
                      <Descriptions.Item label="Info">{selectedNode.details}</Descriptions.Item>
                    </Descriptions>
                  </div>
                ) : (<Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<span style={{ color: '#64748b' }}>点击节点查看详情...</span>} />)}
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
              { title: '状态', render: (_, r) => <Tag color={r.role === 'Victim' ? 'error' : 'success'}>{r.role === 'Victim' ? 'Compromised' : 'Online'}</Tag> },
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
        <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} width={240}>
          <div style={{ height: 50, margin: 16, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8', fontSize: '18px', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>{collapsed ? 'A' : 'ARIADNE'}</div>
          <Menu theme="dark" defaultSelectedKeys={['dashboard']} mode="inline" items={items} onClick={handleMenuClick} />
        </Sider>
        <Layout>
          <Header style={{ padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '64px' }}>
            <h2 style={{ margin: 0, color: '#fff', fontSize: '20px' }}>全球威胁态势感知中心</h2>
            <div style={{ color: '#f43f5e', border: '1px solid #f43f5e', padding: '4px 12px', borderRadius: '4px' }}><WarningOutlined spin /> 实时告警中</div>
          </Header>
          <Content style={{ margin: '20px', overflowY: 'auto', height: 'calc(100vh - 100px)' }}>
            {renderContent()}
          </Content>
          <Drawer title="威胁深度分析" placement="right" width={600} onClose={() => setAnalysisVisible(false)} open={analysisVisible} styles={{ body: { background: '#0b1121' } }}>
            {currentAlert && (<><h3 style={{ color: '#f43f5e' }}>{currentAlert.title}</h3><div style={{ height: '220px', margin: '20px 0' }}><EntropyChart /></div></>)}
          </Drawer>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
};

export default App;