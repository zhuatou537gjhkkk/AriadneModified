import React, { useState, useEffect, memo } from 'react';

// 使用 React.memo 阻断不必要的父组件重渲染传递
const CyberClock = memo(() => {
    const [currentTime, setCurrentTime] = useState(new Date().toLocaleString());

    useEffect(() => {
        const timer = setInterval(() => {
            const now = new Date();
            const timeString = now.getFullYear() + '-' +
                String(now.getMonth() + 1).padStart(2, '0') + '-' +
                String(now.getDate()).padStart(2, '0') + ' ' +
                String(now.getHours()).padStart(2, '0') + ':' +
                String(now.getMinutes()).padStart(2, '0') + ':' +
                String(now.getSeconds()).padStart(2, '0');
            setCurrentTime(timeString);
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    return (
        <div style={{
            border: '1px solid rgba(56, 189, 248, 0.3)',
            padding: '0 12px',
            borderRadius: '2px',
            display: 'flex',
            alignItems: 'center',
            height: '32px',
            gap: '12px',
            userSelect: 'none',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.3)'
        }}>
            {/* 左侧：元数据列 (T-SYNC + ACTIVE) */}
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'flex-start',
                borderRight: '1px solid rgba(255,255,255,0.1)',
                paddingRight: '12px',
                height: '20px'
            }}>
                <span style={{
                    color: '#64748b',
                    fontSize: '9px',
                    fontWeight: 'bold',
                    lineHeight: '1',
                    letterSpacing: '1px',
                    marginBottom: '3px'
                }}>T-SYNC</span>
                <span style={{
                    color: '#4ade80',
                    fontSize: '9px',
                    lineHeight: '1',
                    letterSpacing: '1px',
                    display: 'flex',
                    alignItems: 'center',
                    textShadow: '0 0 5px rgba(74, 222, 128, 0.4)'
                }}>
                    <span className="status-dot-green"></span>
                    ACTIVE
                </span>
            </div>

            {/* 右侧：时间本体 */}
            <div style={{
                fontSize: '18px',
                color: '#38bdf8',
                textShadow: '0 0 10px rgba(56, 189, 248, 0.6)',
                letterSpacing: '2px',
                lineHeight: '32px'
            }}>
                {currentTime}
            </div>
        </div>
    );
});

export default CyberClock;