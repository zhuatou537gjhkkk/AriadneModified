import { create } from 'zustand';
import { getDashboardStats } from '../services/api';

const useDashboardStore = create((set, get) => ({
    // 基础状态
    stats: {
        active_threats: 0,
        intercepted_today: 0,
        throughput_eps: 0,
        time_sync_offset: 0
    },

    // 异步拉取首屏数据
    fetchStats: async () => {
        try {
            const data = await getDashboardStats();
            set({ stats: data });
        } catch (error) {
            console.error('Failed to fetch dashboard stats:', error);
        }
    },

    // 接收 WebSocket 批量消息并局部更新
    updateFromWS: (wsMessages) => {
        if (!Array.isArray(wsMessages) || wsMessages.length === 0) return;

        // 从批量消息中筛选出所有的 analysis_report
        const reports = wsMessages.filter(msg => msg.type === 'analysis_report');
        if (reports.length === 0) return;

        // 只需要取最新的一条报告进行状态计算即可（丢弃中间的冗余状态）
        const latestReport = reports[reports.length - 1];

        const chainCount = latestReport.attack_chains?.total || 0;
        const lateralCount = latestReport.lateral_movement || 0;
        const exfilCount = latestReport.data_exfiltration || 0;
        const totalThreats = chainCount + lateralCount + exfilCount;

        // 局部合并更新，触发最小范围重渲染
        set((state) => ({
            stats: {
                ...state.stats,
                active_threats: totalThreats
            }
        }));
    }
}));

export default useDashboardStore;