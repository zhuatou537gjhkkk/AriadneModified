import React from 'react';
import ReactECharts from 'echarts-for-react';

const EntropyChart = () => {
    const option = {
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'axis',
            formatter: '{b} <br/> {a}: {c}'
        },
        grid: { top: 30, left: 10, right: 10, bottom: 20, containLabel: true },
        xAxis: {
            type: 'category',
            data: ['Pkt-1', 'Pkt-2', 'Pkt-3', 'Pkt-4', 'Pkt-5', 'Pkt-6', 'Pkt-7', 'Pkt-8'],
            axisLine: { lineStyle: { color: '#334155' } },
            axisLabel: { color: '#94a3b8', fontSize: 10 }
        },
        yAxis: {
            type: 'value',
            name: 'Shannon Entropy',
            nameTextStyle: { color: '#94a3b8', padding: [0, 0, 0, 20] },
            splitLine: { lineStyle: { color: '#1e293b', type: 'dashed' } },
            axisLabel: { color: '#94a3b8' },
            min: 0,
            max: 8
        },
        visualMap: {
            show: false,
            pieces: [
                { gt: 0, lte: 4, color: '#34d399' }, // 正常流量绿色
                { gt: 4, lte: 8, color: '#f43f5e' }  // 异常高熵红色
            ],
            outOfRange: { color: '#f43f5e' }
        },
        series: [
            {
                name: 'Payload Entropy',
                type: 'bar',
                data: [3.2, 3.5, 3.1, 7.8, 7.9, 7.5, 3.3, 3.4], // 中间那三个高的是隧道特征
                barWidth: '40%',
                itemStyle: { borderRadius: [4, 4, 0, 0] },
                markLine: {
                    data: [{ yAxis: 5, name: 'Threshold' }],
                    lineStyle: { color: '#fbbf24', type: 'dashed' },
                    label: { formatter: 'Threshold (5.0)', color: '#fbbf24' }
                }
            }
        ]
    };

    return <ReactECharts option={option} style={{ height: '200px', width: '100%' }} />;
};

export default EntropyChart;