import React, { useState, useEffect } from 'react';
import { Card, Table, Tag, Switch } from 'antd';
import { CodeOutlined, WifiOutlined } from '@ant-design/icons';
import { getAssetsList } from '../../services/api';
import useDashboardStore from '../../store/useDashboardStore';

const Assets = () => {
    const { refreshKey } = useDashboardStore();
    const [assetData, setAssetData] = useState([]);

    useEffect(() => {
        getAssetsList().then(setAssetData);
    }, [refreshKey]);

    const safeAssetData = Array.isArray(assetData) ? assetData : [];

    return (
        <Card title="资产与探针管理 (SENSOR FLEET)" bordered={false} className="cyber-card">
            <Table dataSource={safeAssetData} columns={[
                { title: '节点名称', dataIndex: 'name', render: (t) => <b style={{ color: '#fff' }}>{t}</b> },
                { title: 'IP 地址', dataIndex: 'ip', render: (t) => <span style={{ fontFamily: 'monospace' }}>{t}</span> },
                { title: '角色', dataIndex: 'role', render: (r) => <Tag color="blue">{r}</Tag> },
                { title: 'Wazuh 采集', key: 'wazuh', render: (_, record) => <Switch checkedChildren={<CodeOutlined />} unCheckedChildren={<CodeOutlined />} defaultChecked={record.wazuh} /> },
                { title: 'Zeek 流量', key: 'zeek', render: (_, record) => <Switch checkedChildren={<WifiOutlined />} unCheckedChildren={<WifiOutlined />} defaultChecked={record.zeek} /> },
                {
                    title: '状态', dataIndex: 'status', render: (status) => {
                        const statusConfig = {
                            online: { color: 'success', text: 'Online' },
                            offline: { color: 'default', text: 'Offline' },
                            suspicious: { color: 'warning', text: 'Suspicious' },
                            compromised: { color: 'error', text: 'Compromised' }
                        };
                        const config = statusConfig[status?.toLowerCase()] || statusConfig.online;
                        return <Tag color={config.color}>{config.text}</Tag>;
                    }
                },
            ]} pagination={false} rowClassName={() => 'cyber-table-row'} />
        </Card>
    );
};

export default Assets;