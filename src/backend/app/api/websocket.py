from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import logging
import json

logger = logging.getLogger("FusionTrace.WebSocket")

router = APIRouter()


class ConnectionManager:
    """
    WebSocket 连接管理器
    负责管理所有活跃的连接，以及向它们广播消息
    """

    def __init__(self):
        # 存放所有活跃的 WebSocket 连接对象
        self.active_connections: List[WebSocket] = []
        # 存储最新的系统状态和分析报告
        self.latest_etl_status: Dict[str, Any] = {}
        self.latest_analysis_report: Dict[str, Any] = {}

    async def connect(self, websocket: WebSocket):
        """前端发起连接时调用"""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"[+] New WebSocket connection. Total: {len(self.active_connections)}")
        
        # 新连接立即推送最新状态
        if self.latest_etl_status:
            await websocket.send_json({
                "type": "etl_status",
                "status": "synced",
                **self.latest_etl_status
            })
        if self.latest_analysis_report:
            await websocket.send_json({
                "type": "analysis_report",
                "status": "synced",
                **self.latest_analysis_report
            })

    def disconnect(self, websocket: WebSocket):
        """前端关闭页面或断网时调用"""
        self.active_connections.remove(websocket)
        logger.info(f"[!] WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """
        核心功能：向所有连接的前端推送消息
        比如：收到一个攻击告警，群发给所有开着的 Dashboard
        """
        # 存储最新的状态以供新连接使用
        msg_type = message.get("type")
        if msg_type == "etl_status" and message.get("status") != "error":
            self.latest_etl_status = message
        elif msg_type == "analysis_report":
            self.latest_analysis_report = message
        
        logger.info(f"[Broadcast] Sending {msg_type} to {len(self.active_connections)} connections")
        
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"[!] Failed to send message to connection: {e}")
                dead_connections.append(connection)
        
        # 清理掉线的连接
        for conn in dead_connections:
            self.disconnect(conn)

    async def send_to_connection(self, websocket: WebSocket, message: Dict[str, Any]):
        """向特定连接发送消息"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"[!] Failed to send message to specific connection: {e}")

    def get_connection_count(self) -> int:
        """获取当前连接数"""
        return len(self.active_connections)

    def get_system_status(self) -> Dict[str, Any]:
        """获取当前系统状态"""
        return {
            "active_connections": len(self.active_connections),
            "latest_etl_status": self.latest_etl_status,
            "latest_analysis_report": self.latest_analysis_report
        }


# 实例化一个全局管理器
manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """
    前端连接的入口 URL: ws://localhost:8000/api/v1/ws/alerts
    
    推送数据格式：
    - ETL状态: {"type": "etl_status", "status": "completed", "timestamp": "...", "events_processed": ...}
    - ETL错误: {"type": "etl_error", "status": "failed", "timestamp": "...", "error": "..."}
    - 分析报告: {"type": "analysis_report", "timestamp": "...", "attack_chains": {...}, ...}
    - 分析错误: {"type": "analysis_error", "timestamp": "...", "error": "..."}
    """
    await manager.connect(websocket)
    try:
        while True:
            # 保持连接活跃。
            # 这里虽然是接收消息，但主要目的是为了检测客户端是否还在线。
            # 如果前端发消息过来，data 会收到；如果前端断开，这里会抛出异常。
            data = await websocket.receive_text()
            
            # 解析前端消息（可选）
            try:
                message = json.loads(data)
                msg_type = message.get("type")
                
                # 处理前端的心跳或查询请求
                if msg_type == "ping":
                    await manager.send_to_connection(websocket, {
                        "type": "pong",
                        "timestamp": __import__("datetime").datetime.now().isoformat()
                    })
                elif msg_type == "get_status":
                    await manager.send_to_connection(websocket, {
                        "type": "system_status",
                        **manager.get_system_status()
                    })
                    
            except json.JSONDecodeError:
                logger.warning(f"[!] Received invalid JSON from client: {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("[!] WebSocket client disconnected normally")
    except Exception as e:
        logger.error(f"[!] WebSocket error: {e}", exc_info=True)
        manager.disconnect(websocket)


@router.get("/ws/status")
async def get_websocket_status():
    """获取WebSocket管理器的当前状态（REST接口）"""
    return manager.get_system_status()
