import uvicorn
import asyncio
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime

from app.core.config import settings
from app.api.router import api_router
from app.core.database import db
from app.etl.etl_pipeline import ETLPipeline
from app.analysis.analysis_pipeline import AnalysisPipeline
from app.api.websocket import manager as ws_manager
from app.api.endpoints import init_default_assets

logger = logging.getLogger("FusionTrace.Main")

# 全局变量存储后台任务
background_tasks = {}


async def run_etl_pipeline():
    """
    持续运行ETL Pipeline，监听日志并处理
    """
    # test_mode=True: 从文件开头读取历史数据（测试/导入用）
    # test_mode=False: 只监听新增数据（生产环境用）
    etl_pipeline = ETLPipeline(test_mode=True)
    logger.info("[ETL] Starting continuous ETL pipeline monitoring...")
    
    try:
        logger.info("[ETL] Running ETL pipeline...")
        # 执行ETL流程 (异步启动 - 此处会一直运行直到出错)
        await etl_pipeline.start()
        
    except Exception as e:
        logger.error(f"[ETL] Pipeline error: {str(e)}", exc_info=True)
        
        # 推送错误状态
        await ws_manager.broadcast({
            "type": "etl_error",
            "status": "failed",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        })


async def run_analysis_pipeline():
    """
    定时运行分析Pipeline，每10分钟执行一次
    """
    analysis_pipeline = AnalysisPipeline()
    logger.info("[Analysis] Starting periodic analysis pipeline (every 10 minutes)...")
    
    while True:
        try:
            await asyncio.sleep(6)  # 等待10分钟
            
            logger.info("[Analysis] Running analysis pipeline...")
            report = analysis_pipeline.analyze(time_range_hours=24)
            logger.info("[Analysis] Analysis completed successfully")
            
            # 构建分析报告摘要用于推送
            summary = {
                "type": "analysis_report",
                "timestamp": datetime.now().isoformat(),
                "attack_chains": {
                    "total": report.get("attack_chains", {}).get("total_count", 0),
                    "suspicious_ips": len(report.get("attack_chains", {}).get("suspicious_ips", [])),
                    "suspicious_processes": len(report.get("attack_chains", {}).get("suspicious_processes", []))
                },
                "lateral_movement": len(report.get("lateral_movement", [])),
                "data_exfiltration": len(report.get("data_exfiltration", [])),
                "persistence": len(report.get("persistence", [])),
                "mitre_analysis": report.get("mitre_analysis", {}).get("summary", {}),
                "attribution": {
                    "apt_name": None,
                    "confidence": 0
                }
            }
            
            # 从归因结果提取APT信息
            apt_candidates = report.get("attribution", {}).get("apt_candidates", [])
            if apt_candidates:
                top_apt = apt_candidates[0]
                summary["attribution"]["apt_name"] = top_apt.get("apt_name")
                summary["attribution"]["confidence"] = top_apt.get("confidence")
            
            # 推送分析报告给前端
            await ws_manager.broadcast(summary)
            logger.info("[Analysis] Report broadcasted to frontend")
            
        except Exception as e:
            logger.error(f"[Analysis] Pipeline error: {str(e)}", exc_info=True)
            
            # 推送错误状态
            await ws_manager.broadcast({
                "type": "analysis_error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })


# 1. 定义生命周期管理器 (Startup/Shutdown)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- 启动时执行 ---
    print("[+] System Starting... Connecting to Database...")
    try:
        db.connect()  # 连接 Neo4j
    except Exception as e:
        print(f"[!] Database connection failed: {e}")

    # 初始化默认资产数据
    print("[+] Initializing default assets...")
    try:
        await init_default_assets()
        print("[+] Default assets initialized successfully")
    except Exception as e:
        print(f"[!] Failed to initialize default assets: {e}")

    # 启动后台任务
    print("[+] Starting background tasks...")
    etl_task = asyncio.create_task(run_etl_pipeline())
    analysis_task = asyncio.create_task(run_analysis_pipeline())
    
    background_tasks["etl"] = etl_task
    background_tasks["analysis"] = analysis_task
    
    print("[+] Background tasks started successfully")

    yield  # 应用运行中

    # --- 关闭时执行 ---
    print("[!] System Shutting down... Canceling background tasks...")
    
    # 取消后台任务
    for task_name, task in background_tasks.items():
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                print(f"[!] Task '{task_name}' cancelled")
    
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
        "docs": "http://localhost:8000/docs",
        "background_tasks": {
            "etl_pipeline": "running",
            "analysis_pipeline": "running every 10 minutes"
        }
    }


# 6. 本地调试启动入口
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 使用 uvicorn 启动服务
    # host="0.0.0.0" 允许局域网访问，port=8000 是默认端口
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
