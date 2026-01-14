import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 项目基础信息
    PROJECT_NAME: str = "Ariadne"
    API_V1_STR: str = "/api/v1"

    # CORS设置 (允许前端跨域访问)
    BACKEND_CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Neo4j 图数据库配置 (从 .env 读取，若无则使用默认值)
    NEO4J_URI: str = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "ariadne_neo4j")

    # ==========================================
    # 生产环境配置
    # ==========================================
    LOG_PATH_WAZUH: str = os.getenv("LOG_PATH_WAZUH", "/home/Ariadne/data/logs/wazuh/archives.json")
    LOG_DIR_ZEEK: str = os.getenv("LOG_DIR_ZEEK", "/home/Ariadne/data/logs/zeek/")
    ZEEK_FILES_TO_WATCH: list = os.getenv("ZEEK_FILES_TO_WATCH", ["conn.log", "dns.log", "http.log", "files.log"])

    class Config:
        # 指定环境变量文件路径
        # env_file = "../../../.env"
        env_file = "/home/Ariadne/.env"
        case_sensitive = True


settings = Settings()
