import React from 'react';
import ReactECharts from 'echarts-for-react';

const AttackPie = () => {
    const option = {
        tooltip: { trigger: 'item' },
        legend: {
            bottom: '0%',
            left: 'center',
            textStyle: { color: '#94a3b8', fontSize: 10 },
            itemWidth: 10,
            itemHeight: 10
        },
        series: [
            {
                name: '威胁类型',
                type: 'pie',
                radius: ['40%', '70%'], // 变成环形图
                center: ['50%', '45%'],
                avoidLabelOverlap: false,
                itemStyle: {
                    borderRadius: 5,
                    borderColor: '#1e293b',
                    borderWidth: 2
                },
                label: { show: false },
                labelLine: { show: false },
                data: [
                    { value: 1048, name: 'DDoS', itemStyle: { color: '#38bdf8' } }, // 赛博蓝
                    { value: 735, name: 'SQL注入', itemStyle: { color: '#818cf8' } }, // 紫色
                    { value: 580, name: '恶意软件', itemStyle: { color: '#f472b6' } }, // 粉色
                    { value: 484, name: '提权', itemStyle: { color: '#34d399' } },   // 绿色
                    { value: 300, name: '钓鱼', itemStyle: { color: '#fbbf24' } }    // 黄色
                ]
            }
        ]
    };

    return <ReactECharts option={option} style={{ height: '220px', width: '100%' }} />;
};

export default AttackPie;