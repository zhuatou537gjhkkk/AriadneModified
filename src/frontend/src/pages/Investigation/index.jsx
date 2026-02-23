import React, { useState, useEffect, useMemo } from 'react';
import { Row, Col, Card, List, Tag, Avatar, Empty, Button, message } from 'antd';
import { PlayCircleOutlined, ThunderboltFilled } from '@ant-design/icons';
import AttackGraph from '../../components/AttackGraph';
import { getChainsList, getSingleChainGraph } from '../../services/api';
import useDashboardStore from '../../store/useDashboardStore';

const Investigation = () => {
    const { refreshKey } = useDashboardStore();
    const [chainsList, setChainsList] = useState([]);
    const [selectedChainId, setSelectedChainId] = useState(null);
    const [graphData, setGraphData] = useState({ nodes: [], links: [] });
    const [selectedNode, setSelectedNode] = useState(null);
    const [highlightPath, setHighlightPath] = useState([]);
    const [timeStep, setTimeStep] = useState(4);

    const ATTACK_PATH = ['192.168.1.5', 'cmd.exe', 'powershell.exe', '114.114.114.114'];

    useEffect(() => {
        getChainsList().then(res => {
            const chains = res.chains || [];
            setChainsList(chains);
            if (chains.length > 0 && !selectedChainId) {
                setSelectedChainId(chains[0].id);
                getSingleChainGraph(chains[0].id).then(setGraphData);
            } else if (selectedChainId) {
                getSingleChainGraph(selectedChainId).then(setGraphData);
            }
        });
    }, [refreshKey]);

    const handleChainClick = async (chainId) => {
        if (selectedChainId === chainId) return;
        setSelectedChainId(chainId);
        setSelectedNode(null);
        setHighlightPath([]);
        try {
            const graphRes = await getSingleChainGraph(chainId);
            setGraphData(graphRes);
        } catch (error) {
            message.error("加载攻击链失败");
        }
    };

    const filteredGraphData = useMemo(() => {
        if (!graphData || !graphData.nodes) return { nodes: [], links: [] };
        const nodesToShowCount = [1, 2, 3, 4, 5][timeStep] || 5;
        const visibleNodes = graphData.nodes.slice(0, nodesToShowCount);
        const visibleLinks = graphData.links.filter(link =>
            visibleNodes.find(n => n.id === link.source) && visibleNodes.find(n => n.id === link.target)
        );
        return { nodes: visibleNodes, links: visibleLinks };
    }, [timeStep, graphData]);

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
                            <AttackGraph onNodeClick={setSelectedNode} highlightNodes={highlightPath} graphData={filteredGraphData} />
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
                                                    <Tag color={chain.severity === 'high' ? 'red' : chain.severity === 'medium' ? 'orange' : 'blue'} style={{ margin: 0, fontSize: '10px', padding: '0 4px' }}>
                                                        {chain.severity.toUpperCase()}
                                                    </Tag>
                                                    <Tag color={chain.type === 'process_tree' ? 'purple' : 'cyan'} style={{ margin: 0, fontSize: '10px', padding: '0 4px' }}>
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
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<span style={{ color: '#64748b' }}>暂无攻击链数据</span>} />
                    )}
                </Card>
            </Col>
        </Row>
    );
};

export default Investigation;