/* src/services/api.js */
import request from '../utils/request';

// 引入本地 Mock 数据作为兜底 (Fallback)
import mockGraphData from '../mock/graph_data.json';
// 如果没有 mockLogs, 可以造一个简单的或者引用 logs.json
import mockLogs from '../mock/logs.json';

// ================= 1. 态势总览 (Dashboard) =================

// 获取统计卡片数据
export const getDashboardStats = async () => {
    try {
        return await request.get('/dashboard/summary');
    } catch (e) {
        console.log('API Fail, using Mock');
        // 模拟返回后端定义的 JSON 结构
        return {
            active_threats: 20,
            intercepted_today: 903,
            throughput_eps: 4600,
            time_sync_offset: 12
        };
    }
};

// 获取流量趋势
export const getTrafficTrend = async () => {
    try {
        return await request.get('/dashboard/traffic-trend');
    } catch (e) {
        return {
            categories: ['10:00', '10:05', '10:10', '10:15', '10:20', '10:25', '10:30'],
            series: {
                zeek: [120, 132, 101, 134, 290, 230, 210],
                wazuh: [220, 182, 191, 234, 290, 330, 310]
            }
        };
    }
};

// 获取全网拓扑数据
export const getTopologyData = async () => {
    try {
        return await request.get('/dashboard/topology');
    } catch (e) {
        console.log('Topology API Fail, using Mock');
        // 返回默认的拓扑数据作为兜底
        return {
            nodes: [
                { name: 'Analysis Center', category: 'Server', status: 'online', ip: '192.168.1.1' },
                { name: 'Zeek Sensor', category: 'Sensor', status: 'online', ip: '192.168.1.3' },
                { name: 'Victim-01 (Web)', category: 'Endpoint', status: 'online', ip: '192.168.1.10' },
                { name: 'Victim-02 (DB)', category: 'Endpoint', status: 'online', ip: '192.168.1.11' },
                { name: 'Victim-03 (Admin)', category: 'Compromised', status: 'compromised', ip: '192.168.1.12' }
            ],
            links: [
                { source: 'Analysis Center', target: 'Zeek Sensor' },
                { source: 'Zeek Sensor', target: 'Victim-01 (Web)' },
                { source: 'Zeek Sensor', target: 'Victim-02 (DB)' },
                { source: 'Zeek Sensor', target: 'Victim-03 (Admin)' },
                { source: 'Victim-03 (Admin)', target: 'Zeek Sensor', type: 'tunnel' }
            ]
        };
    }
};

// 获取实时告警
export const getLatestAlerts = async () => {
    try {
        return await request.get('/alerts/latest');
    } catch (e) {
        return mockLogs.map((log, index) => ({
            title: log.event_type || 'Unknown Alert',
            source: log.source,
            time: log.timestamp.split(' ')[1], // 只取时间部分
            level: log.severity,
            clickable: index === 0 // 模拟第一个可点击
        })) || [];
    }
};

// ================= 2. 溯源画布 (Investigation) =================

// 获取攻击图谱
export const getAttackGraph = async () => {
    try {
        return await request.get('/investigation/graph');
    } catch (e) {
        return mockGraphData;
    }
};

// ================= 3. 资产管理 (Assets) =================

export const getAssetsList = async () => {
    try {
        return await request.get('/assets');
    } catch (e) {
        return [
            { key: '1', name: 'Node-01 (Analysis)', ip: '192.168.1.2', role: 'Server', wazuh: true, zeek: true },
            { key: '2', name: 'Node-02 (Zeek)', ip: '192.168.1.3', role: 'Sensor', wazuh: true, zeek: true },
            { key: '3', name: 'Node-03 (Agent)', ip: '192.168.1.5', role: 'Victim', wazuh: false, zeek: false },
        ];
    }
};

// === 新增：获取 ATT&CK 命中高亮数据 ===
export const getAttackHighlights = async () => {
    try {
        // 假设后端返回一个数组，包含当前检测到的攻击技术名称
        return await request.get('/attack/highlights');
    } catch (e) {
        // Mock 数据：模拟后端告诉我们需要点亮哪些格子
        return ["Command and Scripting Interpreter", "Process Injection", "Obfuscated Files", "Encrypted Channel"];
    }
};

export const getAttributionResult = async () => {
    try {
        return await request.get('/attribution/result');
    } catch (e) {
        // Mock 数据：如果后端没准备好，就返回这个默认值
        return {
            name: "Fancy Bear",
            code: "APT28",
            score: 92,
            description: "检测到特异性 C2 域名通信特征"
        };
    }
};

// === 新增：获取攻击叙事线 (Storyline) ===
export const getAttackStoryline = async () => {
    // 这里直接向后端发请求，假设后端接口是 /investigation/storyline
    // request 已经封装了 axios，会自动带上 baseURL
    try {
        return await request.get(`/investigation/storyline${noCache()}`);
    } catch (e) {
        // Mock 数据逻辑保持不变...
        return [
            { time: '09:59:00', content: '正常业务流量基线建立完毕', type: 'info' },
            { time: '10:00:01', content: '检测到 WebShell 访问 (192.168.1.5)', type: 'danger' },
            { time: '10:02:15', content: '执行可疑 PowerShell 脚本', type: 'warning' },
            { time: '10:05:30', content: '向恶意 C2 (114.x.x.x) 发起连接', type: 'danger' }
        ];
    }
};


