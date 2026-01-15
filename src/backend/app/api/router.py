from fastapi import APIRouter
from app.api import endpoints
from app.api import websocket

api_router = APIRouter()

# 注册 HTTP 接口
api_router.include_router(endpoints.router, tags=["General"])

# 注册 WebSocket 接口
api_router.include_router(websocket.router, tags=["Real-time"])
