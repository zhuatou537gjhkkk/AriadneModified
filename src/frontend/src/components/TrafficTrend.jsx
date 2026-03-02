/* src/components/TrafficTrend.jsx */
import React, { memo } from 'react';
import ReactECharts from 'echarts-for-react';

const TrafficTrend = ({ data }) => {
    // === 修复核心逻辑 START ===
    // 即使 data 是 {} (空对象)，我们也通过解构赋值给它强行加上默认值
    const {
        categories = ['10:00', '10:05', '10:10', '10:15', '10:20', '10:25', '10:30'],
        series = { zeek: [], wazuh: [] }
    } = data || {};

    // 二重保险：防止 series 存在但内部属性缺失
    const zeekData = series?.zeek || [];
    const wazuhData = series?.wazuh || [];
    // === 修复核心逻辑 END ===

    const option = {
        backgroundColor: 'transparent',
        tooltip: { trigger: 'axis' },
        legend: {
            data: ['Zeek (Network)', 'Wazuh (Endpoint)'],
            textStyle: { color: '#94a3b8' },
            bottom: 0
        },
        grid: { top: 30, left: 40, right: 20, bottom: 30, containLabel: true },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            // 使用处理后的变量
            data: categories,
            axisLine: { lineStyle: { color: '#334155' } },
            axisLabel: { color: '#94a3b8' }
        },
        yAxis: {
            type: 'value',
            splitLine: { lineStyle: { color: '#1e293b', type: 'dashed' } },
            axisLabel: { color: '#94a3b8' }
        },
        series: [
            {
                name: 'Zeek (Network)',
                type: 'line',
                smooth: true,
                showSymbol: false,
                lineStyle: { width: 3, color: '#38bdf8' },
                areaStyle: {
                    color: {
                        type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
                        colorStops: [{ offset: 0, color: 'rgba(56, 189, 248, 0.3)' }, { offset: 1, color: 'rgba(56, 189, 248, 0.0)' }]
                    }
                },
                // 使用处理后的变量
                data: zeekData
            },
            {
                name: 'Wazuh (Endpoint)',
                type: 'line',
                smooth: true,
                showSymbol: false,
                lineStyle: { width: 3, color: '#f43f5e' },
                areaStyle: {
                    color: {
                        type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
                        colorStops: [{ offset: 0, color: 'rgba(244, 63, 94, 0.3)' }, { offset: 1, color: 'rgba(244, 63, 94, 0.0)' }]
                    }
                },
                // 使用处理后的变量
                data: wazuhData
            }
        ]
    };

    return <ReactECharts option={option} style={{ height: '100%', width: '100%' }} />;
};

export default memo(TrafficTrend);