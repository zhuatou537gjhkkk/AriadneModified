import os
from pathlib import Path
from pydantic_settings import BaseSettings

# 动态获取项目根目录 (向上寻找 5 级目录到达根目录)
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent

class Settings(BaseSettings):
    # 项目基础信息
    PROJECT_NAME: str = "Ariadne"
    API_V1_STR: str = "/api/v1"

    # CORS设置 (允许前端跨域访问)
    BACKEND_CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Neo4j 图数据库配置
    NEO4J_URI: str = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "ariadne_neo4j")

    # ==========================================
    # 动态跨平台日志路径（自动适配 Windows/Linux）
    # ==========================================
    LOG_PATH_WAZUH: str = os.getenv("LOG_PATH_WAZUH", str(BASE_DIR / "data" / "logs" / "wazuh" / "archives.json"))
    LOG_DIR_ZEEK: str = os.getenv("LOG_DIR_ZEEK", str(BASE_DIR / "data" / "logs" / "zeek"))
    
    # 监听的 Zeek 文件列表
    ZEEK_FILES_TO_WATCH: list = os.getenv("ZEEK_FILES_TO_WATCH", ["conn.log", "dns.log", "http.log", "files.log"])

    class Config:
        # 动态指向根目录的 .env 文件
        env_file = str(BASE_DIR / ".env")
        case_sensitive = True


settings = Settings()