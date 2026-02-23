import React from 'react';
import { Card, Statistic } from 'antd';

const StatCard = ({ title, value, valueStyle, prefix, suffix }) => (
    <Card bordered={false} className="cyber-card">
        <Statistic
            title={title}
            value={value}
            valueStyle={valueStyle}
            prefix={prefix}
            suffix={suffix}
        />
    </Card>
);

export default StatCard;