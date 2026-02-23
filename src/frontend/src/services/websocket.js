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
        this.isConnecting = false;

        // 1. 心跳保活机制 (Heartbeat)
        this.pingInterval = null;
        this.pongTimeout = null;
        this.HEARTBEAT_INTERVAL = 15000; // 每 15 秒发送一次 ping
        this.PONG_TIMEOUT = 5000;       // 5 秒未收到 pong 则认为断线

        // 2. 消息缓冲队列与 rAF 节流 (Backpressure)
        this.messageQueue = [];
        this.isFlushing = false;
    }

    // 1. 初始化连接
    connect() {
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
            this.startHeartbeat();
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);

                // 拦截 pong 响应，不向下分发
                if (message.type === 'pong') {
                    this.handlePong();
                    return;
                }

                // 将业务消息推入缓冲队列
                this.enqueueMessage(message);
            } catch (e) {
                console.error('[WebSocket] Parse error:', e);
            }
        };

        this.ws.onclose = (event) => {
            this.isConnecting = false;
            this.stopHeartbeat();
            if (event.code !== 1000) {
                console.log('[WebSocket] Disconnected (Code: ' + event.code + ')');
                this.handleReconnect();
            } else {
                console.log('[WebSocket] Disconnected normally');
            }
        };

        this.ws.onerror = (error) => {
            if (this.ws && this.ws.readyState !== WebSocket.OPEN) return;
            console.error('[WebSocket] Error:', error);
        };
    }

    // === 核心：消息缓冲与节流 ===
    enqueueMessage(message) {
        this.messageQueue.push(message);
        // 如果当前没有在清空队列，则利用 rAF 在下一帧统一清空
        if (!this.isFlushing) {
            this.isFlushing = true;
            requestAnimationFrame(() => this.flushQueue());
        }
    }

    flushQueue() {
        if (this.messageQueue.length === 0) {
            this.isFlushing = false;
            return;
        }
        // 拷贝当前队列并清空原队列
        const messages = [...this.messageQueue];
        this.messageQueue = [];
        this.isFlushing = false;

        // 将打包好的消息数组分发给所有订阅者
        this.listeners.forEach(callback => callback(messages));
    }

    // === 核心：心跳保活 ===
    startHeartbeat() {
        this.stopHeartbeat();
        this.pingInterval = setInterval(() => {
            this.sendMessage({ type: 'ping' });

            // 设置超时检测
            this.pongTimeout = setTimeout(() => {
                console.warn('[WebSocket] Pong timeout, closing connection...');
                if (this.ws) this.ws.close(); // 主动关闭以触发重连
            }, this.PONG_TIMEOUT);
        }, this.HEARTBEAT_INTERVAL);
    }

    handlePong() {
        if (this.pongTimeout) {
            clearTimeout(this.pongTimeout);
            this.pongTimeout = null;
        }
    }

    stopHeartbeat() {
        if (this.pingInterval) clearInterval(this.pingInterval);
        if (this.pongTimeout) clearTimeout(this.pongTimeout);
        this.pingInterval = null;
        this.pongTimeout = null;
    }

    // 2. 断线重连机制
    handleReconnect() {
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
            this.reconnectAttempts = this.maxReconnectAttempts;
            this.stopHeartbeat();
            this.ws.close(1000, "Component Unmounted");
            this.ws = null;
            this.isConnecting = false;
        }
    }
}

export default new WebSocketService();