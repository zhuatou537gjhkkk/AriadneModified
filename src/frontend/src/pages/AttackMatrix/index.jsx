import React, { useState, useEffect } from 'react';
import { Row, Col, Card } from 'antd';
import { useNavigate } from 'react-router-dom';
import { getAttackHighlights } from '../../services/api';
import useDashboardStore from '../../store/useDashboardStore';

const attackMatrix = {
    "Initial Access": ["Web Shell", "Exploit Public-Facing Application", "Phishing"],
    "Execution": ["Command and Scripting Interpreter", "Scheduled Task/Job", "WMI"],
    "Persistence": ["Create or Modify System Process", "Registry Run Keys / Startup Folder", "Scheduled Task/Job"],
    "Privilege Escalation": ["Process Injection", "Valid Accounts", "Abuse Elevation Control Mechanism"],
    "Defense Evasion": ["Obfuscated Files", "Indicator Removal on Host", "Hide Artifacts"],
    "Credential Access": ["OS Credential Dumping", "Brute Force", "Credentials from Password Stores"],
    "Discovery": ["System Information Discovery", "Network Service Scanning", "Process Discovery"],
    "Lateral Movement": ["Remote Services", "Pass the Hash", "Lateral Tool Transfer"],
    "Collection": ["Data from Local System", "Data from Network Shared Drive", "Archive Collected Data"],
    "Exfiltration": ["Exfiltration Over C2 Channel", "Automated Exfiltration", "Scheduled Transfer"],
    "Command and Control": ["Application Layer Protocol", "Encrypted Channel", "DNS Tunneling"],
    "Impact": ["Data Encrypted for Impact", "Service Stop", "Inhibit System Recovery"]
};

const AttackMatrix = () => {
    const refreshKey = useDashboardStore(state => state.refreshKey);
    const [hitTactics, setHitTactics] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        getAttackHighlights().then(res => setHitTactics(res || []));
    }, [refreshKey]);

    const handleTacticClick = (tech) => {
        if (hitTactics.includes(tech)) {
            navigate('/investigation');
        }
    };

    const tactics = Object.keys(attackMatrix);
    const firstRowTactics = tactics.slice(0, 6);
    const secondRowTactics = tactics.slice(6, 12);

    const renderTacticColumn = (tactic) => (
        <div key={tactic} style={{ minWidth: '180px', flex: 1, background: 'rgba(255,255,255,0.02)', borderRadius: '6px', padding: '10px' }}>
            <div style={{ color: '#cbd5e1', fontWeight: 'bold', marginBottom: '10px', borderBottom: '2px solid #334155', paddingBottom: '8px' }}>{tactic}</div>
            {attackMatrix[tactic].length > 0 ? (
                attackMatrix[tactic].map(tech => (
                    <div key={tech} onClick={() => handleTacticClick(tech)} style={{ padding: '8px', fontSize: '12px', borderRadius: '4px', background: hitTactics.includes(tech) ? 'rgba(244, 63, 94, 0.2)' : 'rgba(30, 41, 59, 0.5)', border: hitTactics.includes(tech) ? '1px solid #f43f5e' : '1px solid #334155', color: hitTactics.includes(tech) ? '#fff' : '#94a3b8', cursor: 'pointer', marginBottom: 4 }}>{tech}</div>
                ))
            ) : (
                <div style={{ padding: '8px', fontSize: '12px', color: '#475569', fontStyle: 'italic' }}>暂无检测技术</div>
            )}
        </div>
    );

    return (
        <Row style={{ height: '100%' }}>
            <Col span={24}>
                <Card title="ATT&CK 动态矩阵" bordered={false} className="cyber-card" style={{ height: '100%', overflowY: 'auto' }}>
                    <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                        {firstRowTactics.map(renderTacticColumn)}
                    </div>
                    <div style={{ display: 'flex', gap: '12px' }}>
                        {secondRowTactics.map(renderTacticColumn)}
                    </div>
                </Card>
            </Col>
        </Row>
    );
};

export default AttackMatrix;