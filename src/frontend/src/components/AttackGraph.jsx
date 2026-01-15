import React, { useRef, useEffect, useState } from 'react';
import ReactECharts from 'echarts-for-react';
// 删除 import mockData from '../mock/graph_data.json'; 

// 接收 graphData (来自父组件的动态数据)
const AttackGraph = ({ onNodeClick, highlightNodes = [], graphData }) => {
    const [isReady, setIsReady] = useState(false);
    const containerRef = useRef(null);
    const echartRef = useRef(null);

    // 默认空数据防止报错
    const safeData = graphData || { nodes: [], links: [] };

    const colorMap = {
        'IP': '#818cf8',
        'Process': '#38bdf8',
        'Process_Inferred': '#64748b',  // 灰色 - 推断的父进程（无详细日志）
        'File': '#34d399',
        'External_IP': '#f43f5e'
    };

    // 处理节点样式
    const processedNodes = safeData.nodes.map(node => {
        const isHighlighted = highlightNodes.includes(node.id);
        const baseColor = colorMap[node.category] || '#ccc';

        // --- 新增：无文件/内存攻击的可视化 (文档要求: 场景B) ---
        const isFileless = node.details && (node.details.includes("内存") || node.details.includes("Injected"));

        return {
            ...node,
            symbolSize: isHighlighted ? 50 : (node.symbolSize || 30),
            itemStyle: {
                color: baseColor,
                // 虚线边框逻辑
                borderType: isFileless ? 'dashed' : 'solid',
                borderWidth: isFileless ? 3 : (isHighlighted ? 4 : 0),
                borderColor: isFileless ? '#f43f5e' : (isHighlighted ? '#fff' : 'transparent'),
                shadowBlur: (isHighlighted || isFileless) ? 10 : 0,
                shadowColor: isHighlighted ? '#fff' : (isFileless ? '#f43f5e' : 'transparent')
            },
            label: {
                show: true,
                fontSize: isHighlighted ? 14 : 11,
                fontWeight: (isHighlighted || isFileless) ? 'bold' : 'normal',
                formatter: isFileless ? '{b}\n(Mem Only)' : '{b}'
            }
        };
    });

    // 处理连线高亮
    const processedLinks = safeData.links.map(link => {
        const isHighlighted = highlightNodes.includes(link.source) && highlightNodes.includes(link.target);
        return {
            ...link,
            lineStyle: {
                color: isHighlighted ? '#f43f5e' : '#475569',
                width: isHighlighted ? 4 : 2,
                curveness: 0.2,
                opacity: isHighlighted ? 1 : 0.3
            }
        };
    });

    useEffect(() => {
        if (!containerRef.current) return;

        let resizeObserver;
        try {
            resizeObserver = new ResizeObserver((entries) => {
                for (let entry of entries) {
                    const { width, height } = entry.contentRect;
                    if (width > 0 && height > 0) {
                        setIsReady(true);
                        if (echartRef.current) {
                            const echartsInstance = echartRef.current.getEchartsInstance();
                            if (echartsInstance) {
                                echartsInstance.resize();
                            }
                        }
                    }
                }
            });
            resizeObserver.observe(containerRef.current);
        } catch (error) {
            console.warn('ResizeObserver not supported:', error);
            setIsReady(true);
        }

        return () => {
            if (resizeObserver) {
                try {
                    resizeObserver.disconnect();
                } catch (error) {
                    console.warn('Error disconnecting ResizeObserver:', error);
                }
            }
        };
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
            borderColor: '#334155',
            borderWidth: 1,
            padding: [12, 16],
            textStyle: {
                color: '#e2e8f0',
                fontSize: 13
            },
            formatter: (params) => {
                if (params.dataType === 'node') {
                    const data = params.data;
                    const name = data.name || '未知';
                    const category = data.category || '未知';
                    const details = data.details || '';
                    
                    // 将详情文本按换行符分割并格式化
                    const detailLines = details.split('\n').map(line => {
                        const [key, ...valueParts] = line.split(':');
                        const value = valueParts.join(':').trim() || '未知';
                        return `<div style="margin: 4px 0;"><span style="color: #94a3b8;">${key}:</span> <span style="color: #f1f5f9;">${value}</span></div>`;
                    }).join('');
                    
                    return `
                        <div style="min-width: 200px;">
                            <div style="font-size: 15px; font-weight: bold; color: #38bdf8; margin-bottom: 8px; border-bottom: 1px solid #334155; padding-bottom: 6px;">
                                ${name}
                            </div>
                            <div style="margin-bottom: 6px;">
                                <span style="color: #94a3b8;">类型:</span> 
                                <span style="color: #818cf8; font-weight: 500;">${category}</span>
                            </div>
                            ${detailLines}
                        </div>
                    `;
                } else if (params.dataType === 'edge') {
                    // 边的 tooltip
                    const data = params.data;
                    return `
                        <div>
                            <span style="color: #94a3b8;">关系:</span> 
                            <span style="color: #f43f5e;">${data.label || 'SPAWNED'}</span>
                        </div>
                    `;
                }
                return params.name;
            }
        },
        series: [
            {
                type: 'graph',
                layout: 'force',
                roam: true,
                data: processedNodes,
                links: processedLinks,
                edgeSymbol: ['none', 'arrow'],  // 起点无符号，终点箭头
                edgeSymbolSize: [0, 8],         // 箭头大小
                force: {
                    repulsion: 1200,
                    edgeLength: 100,
                    gravity: 0.15,
                    friction: 0.6,              // 增加摩擦力，让节点快速稳定
                    layoutAnimation: true      // 关闭布局动画，防止乱动
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