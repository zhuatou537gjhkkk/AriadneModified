import React, { useState, useEffect, useMemo, memo, useRef } from 'react';
import ReactECharts from 'echarts-for-react';
import { getTopologyData } from '../services/api';
import useChartResize from '../hooks/useChartResize';

const TopologyGraph = () => {
    const [topologyData, setTopologyData] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);

    const containerRef = useRef(null);
    const echartRef = useRef(null);

    useChartResize(echartRef, containerRef);

    // 定义节点分类对应的样式
    const categoryStyles = {
        Server: { color: '#5070dd', symbolSize: 50 },      // 天蓝色
        Sensor: { color: '#a3e635', symbolSize: 40 },      // 黄绿色
        Endpoint: { color: '#64748b', symbolSize: 30 },    // 深灰色
        Compromised: {                                      // 红色（带发光效果）
            color: '#f97316',
            symbolSize: 35,
            borderColor: '#f97316',
            borderWidth: 2,
            shadowBlur: 10,
            shadowColor: '#f97316'
        }
    };

    // 计算节点位置布局
    const calculateNodePositions = (nodes) => {
        // 按照层级分组：顶层(Server)、中层(Sensor)、底层(Endpoint + Compromised)
        const topLayer = [];      // Server
        const middleLayer = [];   // Sensor
        const bottomLayer = [];   // Endpoint + Compromised (合并到同一行)

        nodes.forEach(node => {
            const category = node.category || 'Endpoint';
            if (category === 'Server') {
                topLayer.push(node);
            } else if (category === 'Sensor') {
                middleLayer.push(node);
            } else {
                // Endpoint 和 Compromised 都放在底层
                bottomLayer.push(node);
            }
        });

        const positionedNodes = [];
        const centerX = 400;
        const spacing = 200;

        // 处理顶层 (y=0)
        const topStartX = centerX - ((topLayer.length - 1) * spacing) / 2;
        topLayer.forEach((node, index) => {
            const style = categoryStyles.Server;
            positionedNodes.push({
                name: node.name,
                ip: node.ip || 'N/A',
                status: node.status || 'online',
                x: topStartX + index * spacing,
                y: 0,
                symbolSize: style.symbolSize,
                itemStyle: { color: style.color },
                category: 'Server'
            });
        });

        // 处理中层 (y=100)
        const middleStartX = centerX - ((middleLayer.length - 1) * spacing) / 2;
        middleLayer.forEach((node, index) => {
            const style = categoryStyles.Sensor;
            positionedNodes.push({
                name: node.name,
                ip: node.ip || 'N/A',
                status: node.status || 'online',
                x: middleStartX + index * spacing,
                y: 100,
                symbolSize: style.symbolSize,
                itemStyle: { color: style.color },
                category: 'Sensor'
            });
        });

        // 处理底层 (y=200) - Endpoint 和 Compromised 合并计算位置
        const bottomStartX = centerX - ((bottomLayer.length - 1) * spacing) / 2;
        bottomLayer.forEach((node, index) => {
            const category = node.category || 'Endpoint';
            const style = categoryStyles[category] || categoryStyles.Endpoint;
            positionedNodes.push({
                name: node.name,
                ip: node.ip || 'N/A',
                status: node.status || 'online',
                x: bottomStartX + index * spacing,
                y: 200,
                symbolSize: style.symbolSize,
                itemStyle: {
                    color: style.color,
                    ...(style.borderColor && { borderColor: style.borderColor }),
                    ...(style.borderWidth && { borderWidth: style.borderWidth }),
                    ...(style.shadowBlur && { shadowBlur: style.shadowBlur }),
                    ...(style.shadowColor && { shadowColor: style.shadowColor })
                },
                category: category
            });
        });

        return positionedNodes;
    };

    // 处理链接数据
    const processLinks = (links) => {
        return links.map(link => {
            const baseLink = {
                source: link.source,
                target: link.target
            };

            // 如果是 tunnel 类型（隐蔽信道），使用特殊样式
            if (link.type === 'tunnel') {
                return {
                    ...baseLink,
                    lineStyle: { type: 'dashed', color: '#f43f5e', width: 2, curveness: 0.3 },
                    label: { show: true, formatter: 'Hidden Tunnel', color: '#f43f5e', fontSize: 10 }
                };
            }

            // 如果源节点是 Analysis Center，使用粗线
            if (link.source === 'Analysis Center') {
                return {
                    ...baseLink,
                    lineStyle: { width: 4 }
                };
            }

            return baseLink;
        });
    };

    // 加载数据
    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const data = await getTopologyData();
                setTopologyData(data);
            } catch (error) {
                console.error('Failed to fetch topology data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);

    // 处理后的节点和链接
    const processedNodes = useMemo(() => calculateNodePositions(topologyData.nodes), [topologyData.nodes]);
    const processedLinks = useMemo(() => processLinks(topologyData.links), [topologyData.links]);

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'item',
            formatter: (params) => {
                if (params.dataType === 'node') {
                    const { name, category, ip, status } = params.data;
                    const statusText = status === 'compromised' ? '已沦陷' : (status === 'online' ? '在线' : '离线');
                    return `<b>${name}</b><br/>IP: ${ip}<br/>类型: ${category}<br/>状态: ${statusText}`;
                }
                return `${params.data.source} → ${params.data.target}`;
            }
        },
        legend: {
            show: true,
            orient: 'vertical',
            right: 20,
            top: 'center',
            textStyle: { color: '#94a3b8' },
            data: ['Server', 'Sensor', 'Endpoint', 'Compromised'],
            itemGap: 15
        },
        series: [{
            type: 'graph',
            layout: 'none',
            data: processedNodes.map(n => ({
                ...n,
                label: { show: true, position: 'bottom', distance: 8, color: '#cbd5e1', fontSize: 11 }
            })),
            links: processedLinks,
            categories: [
                { name: 'Server' },
                { name: 'Sensor' },
                { name: 'Endpoint' },
                { name: 'Compromised' }
            ],
            lineStyle: { color: '#475569', width: 2, curveness: 0.1 },
            roam: true,
            center: ['50%', '35%'],
            zoom: 0.8
        }]
    };

    if (loading && topologyData.nodes.length === 0) {
        return <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8' }}>加载中...</div>;
    }

    return (
        <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
            <ReactECharts ref={echartRef} option={option} style={{ height: '100%', width: '100%' }} />
        </div>
    );
};

export default memo(TopologyGraph);