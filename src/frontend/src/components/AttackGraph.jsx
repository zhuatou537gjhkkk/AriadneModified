import React, { useRef, useEffect, useState } from 'react';
import ReactECharts from 'echarts-for-react';

// 接收 graphData (来自父组件的动态数据)
const AttackGraph = ({ onNodeClick, highlightNodes = [], graphData }) => {
    const [isReady, setIsReady] = useState(false);
    const containerRef = useRef(null);
    const echartRef = useRef(null);

    // 默认空数据防止报错
    const safeData = graphData || { nodes: [], links: [] };

    // ECharts categories 配置 - 定义四种节点类型的颜色（全部使用圆形）
    const categories = [
        { name: 'IP', itemStyle: { color: '#a78bfa' } },           // 紫色
        { name: 'Process', itemStyle: { color: '#22d3ee' } },      // 青色
        { name: 'File', itemStyle: { color: '#4ade80' } },         // 绿色
        { name: 'External_IP', itemStyle: { color: '#fb7185' } }   // 红色
    ];

    // category 字符串到索引的映射
    const categoryIndex = {
        'IP': 0,
        'Process': 1,
        'File': 2,
        'External_IP': 3
    };

    // 处理节点样式
    const processedNodes = safeData.nodes.map(node => {
        const isHighlighted = highlightNodes.includes(node.id);
        const catIdx = categoryIndex[node.category] ?? 0;

        // 无文件/内存攻击的可视化 (文档要求: 场景B)
        const isFileless = node.details && (node.details.includes("内存") || node.details.includes("Injected"));

        return {
            ...node,
            category: catIdx, // ECharts 需要数字索引
            symbol: 'circle', // 统一使用圆形
            symbolSize: isHighlighted ? 45 : (node.symbolSize || 32),
            itemStyle: {
                borderType: isFileless ? 'dashed' : 'solid',
                borderWidth: isHighlighted ? 3 : 1,
                borderColor: isFileless ? '#fb7185' : (isHighlighted ? '#fff' : 'rgba(255,255,255,0.2)'),
                shadowBlur: isHighlighted ? 8 : 0,
                shadowColor: isHighlighted ? '#fff' : 'transparent'
            },
            label: {
                show: true,
                position: 'right',
                distance: 8,
                fontSize: isHighlighted ? 12 : 11,
                fontWeight: (isHighlighted || isFileless) ? 'bold' : 'normal',
                color: isHighlighted ? '#fff' : '#cbd5e1',
                formatter: isFileless ? '{b}\n(Mem Only)' : '{b}'
            }
        };
    });

    // 处理连线样式
    const processedLinks = safeData.links.map(link => {
        const isHighlighted = highlightNodes.includes(link.source) && highlightNodes.includes(link.target);
        return {
            ...link,
            lineStyle: {
                color: isHighlighted ? '#fb7185' : '#475569',
                width: isHighlighted ? 3 : 1.5,
                curveness: 0.2,
                opacity: isHighlighted ? 1 : 0.6
            },
            label: {
                show: false  // 不显示边上的文字
            }
        };
    });

    useEffect(() => {
        if (!containerRef.current) return;
        const resizeObserver = new ResizeObserver((entries) => {
            for (let entry of entries) {
                const { width, height } = entry.contentRect;
                if (width > 0 && height > 0) {
                    setIsReady(true);
                    if (echartRef.current) echartRef.current.getEchartsInstance().resize();
                }
            }
        });
        resizeObserver.observe(containerRef.current);
        return () => resizeObserver.disconnect();
    }, []);

    const onEvents = {
        'click': (params) => {
            if (params.dataType === 'node' && onNodeClick) {
                onNodeClick(params.data);
            }
        }
    };

    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'item',
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: 'rgba(56, 189, 248, 0.3)',
            borderWidth: 1,
            textStyle: {
                color: '#fff'
            },
            formatter: (params) => {
                if (params.dataType === 'node') {
                    const node = params.data;
                    const categoryName = categories[node.category]?.name || 'Unknown';
                    return `
                        <div style="font-weight: bold; margin-bottom: 5px; color: #22d3ee;">${node.name}</div>
                        <div style="color: #94a3b8; font-size: 12px;">
                            <div>类型: ${categoryName}</div>
                            <div style="margin-top: 4px; white-space: pre-wrap;">${node.details || '暂无详情'}</div>
                        </div>
                    `;
                }
                if (params.dataType === 'edge') {
                    return `${params.data.source} → ${params.data.target}<br/><span style="color:#94a3b8">${params.data.value || params.data.label || ''}</span>`;
                }
                return '';
            }
        },
        legend: {
            show: true,
            top: 10,
            right: 10,
            orient: 'vertical',
            textStyle: {
                color: '#cbd5e1',
                fontSize: 11
            },
            data: categories.map(c => c.name)
        },
        series: [
            {
                type: 'graph',
                layout: 'force',
                roam: true,
                draggable: true,
                categories: categories,
                data: processedNodes,
                links: processedLinks,
                edgeSymbol: ['none', 'arrow'],  // 起点无符号，终点箭头
                edgeSymbolSize: [0, 8],         // 箭头大小
                force: {
                    repulsion: 1200,
                    edgeLength: 100,
                    gravity: 0.15,
                    friction: 0.6,              // 增加摩擦力，让节点快速稳定
                    layoutAnimation: false      // 关闭布局动画，防止乱动
                },
                autoCurveness: true,            // 自动曲率，避免边重叠
                label: {
                    show: true,
                    position: 'right',
                    formatter: '{b}',
                    fontSize: 11,
                    color: '#cbd5e1'
                },
                lineStyle: {
                    curveness: 0.2,
                    opacity: 0.6
                },
                emphasis: {
                    focus: 'none',
                    scale: 1.1,
                    itemStyle: {
                        shadowBlur: 8,
                        shadowColor: 'rgba(255,255,255,0.4)'
                    }
                },
                edgeLabel: {
                    show: false  // 不显示边上的文字
                }
            }
        ]
    };

    return (
        <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
            {isReady && (
                <ReactECharts
                    ref={echartRef}
                    option={option}
                    style={{ height: '100%', width: '100%' }}
                    onEvents={onEvents}
                />
            )}
        </div>
    );
};

export default AttackGraph;
