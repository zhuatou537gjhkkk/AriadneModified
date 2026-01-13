/* src/services/websocket.js */

// 【注意】如果你后端 main.py 是 app.include_router(..., prefix="/api/v1")，则保留 /api/v1
// 如果 main.py 没有 prefix，请去掉 /api/v1，改为 'ws://localhost:8000/ws/alerts'
const WS_URL = 'ws://localhost:8000/api/v1/ws/alerts';

class WebSocketService {
    constructor() {
        this.ws = null;
        this.listeners = [];
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectTimeout = 3000;
        // 增加一个标志位，防止严格模式下的竞态条件
        this.isConnecting = false;
    }

    // 1. 初始化连接
    connect() {
        // 【核心修复】如果当前正在连接(0) 或 已经连接(1)，则不再发起新连接
        if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
            console.log('[WebSocket] Connection already active or connecting...');
            return;
        }

        console.log('[WebSocket] Attempting to connect:', WS_URL);
        this.isConnecting = true;
        this.ws = new WebSocket(WS_URL);

        this.ws.onopen = () => {
            console.log('[WebSocket] Connected Successfully');
            this.isConnecting = false;
            this.reconnectAttempts = 0;
            this.sendMessage({ type: 'ping' });
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.listeners.forEach(callback => callback(message));
            } catch (e) {
                console.error('[WebSocket] Parse error:', e);
            }
        };

        this.ws.onclose = (event) => {
            this.isConnecting = false;
            // 只有非正常关闭（非1000）才打印断开日志，减少控制台噪音
            if (event.code !== 1000) {
                console.log('[WebSocket] Disconnected (Code: ' + event.code + ')');
                this.handleReconnect();
            } else {
                console.log('[WebSocket] Disconnected normally');
            }
        };

        this.ws.onerror = (error) => {
            // 忽略连接过程中的这类报错，因为可能是热重载导致的
            if (this.ws && this.ws.readyState !== WebSocket.OPEN) {
                // console.warn('[WebSocket] Connection error (likely strict mode cleanup)');
                return;
            }
            console.error('[WebSocket] Error:', error);
        };
    }

    // 2. 断线重连机制
    handleReconnect() {
        // 如果是手动关闭的，或者正在连接中，不执行重连
        if (!this.ws || this.ws.readyState === WebSocket.OPEN || this.isConnecting) return;

        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`[WebSocket] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            setTimeout(() => this.connect(), this.reconnectTimeout);
        }
    }

    // 3. 订阅消息
    subscribe(callback) {
        this.listeners.push(callback);
        return () => {
            this.listeners = this.listeners.filter(cb => cb !== callback);
        };
    }

    // 4. 发送消息
    sendMessage(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        }
    }

    // 5. 关闭连接
    disconnect() {
        if (this.ws) {
            // 设置重连次数上限，防止 close 触发重连
            this.reconnectAttempts = this.maxReconnectAttempts;

            // 只有当连接已建立时才关闭，避免打断 connecting 状态
            // 但为了组件卸载安全，还是强制关闭
            this.ws.close(1000, "Component Unmounted");
            this.ws = null;
            this.isConnecting = false;
        }
    }
}

export default new WebSocketService();