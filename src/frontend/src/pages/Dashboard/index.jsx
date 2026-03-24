import React, { useState, useEffect, Suspense } from 'react';
import { Row, Col, Card, List, Tag, Drawer, Spin } from 'antd';
import { BugOutlined, WarningOutlined } from '@ant-design/icons';
import VirtualList from 'rc-virtual-list';
import useDashboardStore from '../../store/useDashboardStore';
import StatCard from '../../components/StatCard';
import TrafficTrend from '../../components/TrafficTrend';
import TopologyGraph from '../../components/TopologyGraph';
import { getTrafficTrend, getLatestAlerts } from '../../services/api';

const EntropyChart = React.lazy(() => import('../../components/EntropyChart'));

const Dashboard = () => {
    const stats = useDashboardStore(state => state.stats);
    const refreshKey = useDashboardStore(state => state.refreshKey);
    const [trafficData, setTrafficData] = useState(null);
    const [alertList, setAlertList] = useState([]);
    const [analysisVisible, setAnalysisVisible] = useState(false);
    const [currentAlert, setCurrentAlert] = useState(null);

    useEffect(() => {
        getTrafficTrend().then(setTrafficData);
        getLatestAlerts().then(setAlertList);
    }, [refreshKey]);

    const handleAlertClick = (item) => {
        if (item.title.includes('DNS Tunnel')) {
            setCurrentAlert(item);
            setAnalysisVisible(true);
        }
    };

    return (
        <>
            <Row gutter={[16, 16]}>
                <Col span={6}>
                    <StatCard title="活跃威胁源" value={stats.active_threats} valueStyle={{ color: '#f43f5e' }} prefix={<BugOutlined />} />
                </Col>
                <Col span={6}>
                    <StatCard title="今日拦截" value={stats.intercepted_today} valueStyle={{ color: '#34d399' }} />
                </Col>
                <Col span={6}>
                    <StatCard title="数据吞吐 (EPS)" value={stats.throughput_eps} suffix="Evt/s" valueStyle={{ color: '#38bdf8' }} />
                </Col>
                <Col span={6}>
                    <StatCard title="时间同步偏差" value={stats.time_sync_offset} suffix="ms" valueStyle={{ color: '#fbbf24' }} />
                </Col>
            </Row>

            <Row gutter={[16, 16]} style={{ marginTop: '16px' }}>
                <Col span={16} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <Card title="流量趋势对比 (EPS TREND)" bordered={false} className="cyber-card" style={{ height: '400px' }}>
                        <TrafficTrend data={trafficData} />
                    </Card>
                    <Card title="全网拓扑监控 (TOPOLOGY VIEW)" bordered={false} className="cyber-card" style={{ height: '400px' }}>
                        <TopologyGraph />
                    </Card>
                </Col>

                <Col span={8}>
                    <Card title="实时告警 (LATEST ALERTS)" bordered={false} className="cyber-card" style={{ height: '100%', minHeight: '816px' }}>
                        <List size="small">
                            <VirtualList
                                data={alertList}
                                height={700}
                                itemHeight={65}
                                itemKey={(item, index) => item.id || index}
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

            <Drawer title="威胁深度分析" placement="right" width={600} onClose={() => setAnalysisVisible(false)} open={analysisVisible} styles={{ body: { background: '#0b1121' } }}>
                {currentAlert && (
                    <>
                        <h3 style={{ color: '#f43f5e' }}>{currentAlert.title}</h3>
                        <div style={{ height: '220px', margin: '20px 0' }}>
                            <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}><Spin size="large" tip="加载深度分析引擎..." /></div>}>
                                <EntropyChart />
                            </Suspense>
                        </div>
                    </>
                )}
            </Drawer>
        </>
    );
};

export default Dashboard;