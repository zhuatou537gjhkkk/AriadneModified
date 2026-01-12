import React from 'react';
import ReactECharts from 'echarts-for-react';

const TopologyGraph = () => {
    // === 关键修复：使用更紧凑的坐标体系 ===
    // 我们将整体高度压缩在 0 - 200 之间，配合 center 属性让图表上移
    const nodes = [
        // 顶层节点 (Y: 0)
        { name: 'Analysis Center', x: 400, y: 0, symbolSize: 50, itemStyle: { color: '#38bdf8' }, category: 'Server' },

        // 中间节点 (Y: 100)
        { name: 'Zeek Sensor', x: 400, y: 100, symbolSize: 40, itemStyle: { color: '#818cf8' }, category: 'Sensor' },

        // 底层节点 (Y: 200) - 之前是 280，现在改为 200，大幅向上收缩
        { name: 'Victim-01 (Web)', x: 200, y: 200, symbolSize: 30, itemStyle: { color: '#34d399' }, category: 'Endpoint' },
        { name: 'Victim-02 (DB)', x: 400, y: 200, symbolSize: 30, itemStyle: { color: '#34d399' }, category: 'Endpoint' },
        { name: 'Victim-03 (Admin)', x: 600, y: 200, symbolSize: 30, itemStyle: { color: '#f43f5e', borderColor: '#f43f5e', borderWidth: 2, shadowBlur: 10, shadowColor: '#f43f5e' }, category: 'Compromised' },
    ];

    const links = [
        { source: 'Analysis Center', target: 'Zeek Sensor', lineStyle: { width: 4 } },
        { source: 'Zeek Sensor', target: 'Victim-01 (Web)' },
        { source: 'Zeek Sensor', target: 'Victim-02 (DB)' },
        { source: 'Zeek Sensor', target: 'Victim-03 (Admin)' },
        // 隐蔽信道
        {
            source: 'Victim-03 (Admin)',
            target: 'Zeek Sensor',
            lineStyle: { type: 'dashed', color: '#f43f5e', width: 2, curveness: 0.3 },
            label: { show: true, formatter: 'Hidden Tunnel', color: '#f43f5e', fontSize: 10 }
        }
    ];

    const option = {
        backgroundColor: 'transparent',
        tooltip: { trigger: 'item' },
        legend: {
            show: true,
            bottom: 15, // 距离底部 15px
            textStyle: { color: '#94a3b8' },
            data: ['Server', 'Sensor', 'Endpoint', 'Compromised'],
            itemGap: 20
        },
        series: [{
            type: 'graph',
            layout: 'none',
            data: nodes.map(n => ({
                ...n,
                // 标签保持在下方，颜色调亮一点
                label: { show: true, position: 'bottom', distance: 8, color: '#cbd5e1', fontSize: 11 }
            })),
            links: links,
            categories: [{ name: 'Server' }, { name: 'Sensor' }, { name: 'Endpoint' }, { name: 'Compromised' }],
            lineStyle: { color: '#475569', width: 2, curveness: 0.1 },

            roam: true,

            // === 关键修复点 ===
            // center: ['50%', '35%'] 意思是：把图表的中心点放在容器高度 35% 的位置（偏上）。
            // 这样底部就会留出 65% 的空间，绝对不会再和底部的 Legend 重叠。
            center: ['50%', '35%'],
            zoom: 0.8 // 稍微缩小一点，防止横向溢出
        }]
    };

    return <ReactECharts option={option} style={{ height: '100%', width: '100%' }} />;
};

export default TopologyGraph;