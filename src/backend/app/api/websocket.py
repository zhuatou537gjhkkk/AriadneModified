from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List

router = APIRouter()


class ConnectionManager:
    """
    WebSocket 连接管理器
    负责管理所有活跃的连接，以及向它们广播消息
    """

    def __init__(self):
        # 存放所有活跃的 WebSocket 连接对象
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """前端发起连接时调用"""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[+] New WebSocket connection. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """前端关闭页面或断网时调用"""
        self.active_connections.remove(websocket)
        print(f"[!] WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """
        核心功能：向所有连接的前端推送消息
        比如：收到一个攻击告警，群发给所有开着的 Dashboard
        """
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[!] Failed to send message: {e}")


# 实例化一个全局管理器
manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """
    前端连接的入口 URL: ws://localhost:8000/api/v1/ws/alerts
    """
    await manager.connect(websocket)
    try:
        while True:
            # 保持连接活跃。
            # 这里虽然是接收消息，但主要目的是为了检测客户端是否还在线。
            # 如果前端发消息过来，data 会收到；如果前端断开，这里会抛出异常。
            data = await websocket.receive_text()

            # (可选) 如果前端发了 "ping"，我们可以回一个 "pong"
            # await websocket.send_text(f"Message text was: {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        manager.disconnect(websocket)
