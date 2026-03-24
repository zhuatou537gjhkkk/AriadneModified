import React, { useState, useEffect } from 'react';
import { Row, Col, Card, Avatar, Progress, Timeline } from 'antd';
import { getAttributionResult } from '../../services/api';
import useDashboardStore from '../../store/useDashboardStore';

const Attribution = () => {
    const refreshKey = useDashboardStore(state => state.refreshKey);
    const [attribution, setAttribution] = useState({ name: 'Unknown', code: '???', confidence: 0, evidence: [] });

    useEffect(() => {
        getAttributionResult().then(setAttribution);
    }, [refreshKey]);

    const safeAttr = attribution || {
        name: 'Loading...',
        code: '...',
        confidence: 0,
        evidence: []
    };

    return (
        <Row gutter={[16, 16]}>
            <Col span={10}>
                <Card title="APT 组织画像" bordered={false} className="cyber-card">
                    <div style={{ textAlign: 'center', padding: '20px' }}>
                        <Avatar size={100} style={{ backgroundColor: '#f43f5e', fontSize: '32px' }}>
                            {safeAttr.code}
                        </Avatar>
                        <h2 style={{ color: '#fff', marginTop: '20px' }}>{safeAttr.name}</h2>
                        <Progress
                            percent={safeAttr.confidence}
                            strokeColor="#f43f5e"
                            trailColor="#334155"
                            style={{ marginTop: 20 }}
                        />
                    </div>
                </Card>
            </Col>
            <Col span={14}>
                <Card title="证据链" bordered={false} className="cyber-card">
                    <Timeline
                        items={(safeAttr.evidence || []).map(item => ({
                            color: item.color,
                            children: <span style={{ color: '#cbd5e1' }}>{item.content}</span>
                        }))}
                    />
                </Card>
            </Col>
        </Row>
    );
};

export default Attribution;