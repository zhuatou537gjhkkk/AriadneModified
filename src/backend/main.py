import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.api.router import api_router
from app.core.database import db


# 1. 定义生命周期管理器 (Startup/Shutdown)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- 启动时执行 ---
    print("[+] System Starting... Connecting to Database...")
    try:
        db.connect()  # 连接 Neo4j
    except Exception as e:
        print(f"[!] Database connection failed: {e}")

    yield  # 应用运行中

    # --- 关闭时执行 ---
    print("[!] System Shutting down... Closing Database...")
    db.close()


# 2. 初始化 FastAPI 应用
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# 3. 配置 CORS (解决前端跨域问题)
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# 4. 注册路由
app.include_router(api_router, prefix=settings.API_V1_STR)


# 5. 根路径欢迎语
@app.get("/")
async def root():
    return {
        "message": "Welcome to FusionTrace API",
        "docs": "http://localhost:8000/docs"
    }


# 6. 本地调试启动入口
if __name__ == "__main__":
    # 使用 uvicorn 启动服务
    # host="0.0.0.0" 允许局域网访问，port=8000 是默认端口
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
