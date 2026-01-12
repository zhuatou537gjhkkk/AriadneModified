import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 项目基础信息
    PROJECT_NAME: str = "Ariadne"
    API_V1_STR: str = "/api/v1"

    # CORS设置 (允许前端跨域访问)
    BACKEND_CORS_ORIGINS: list = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Neo4j 图数据库配置 (从 .env 读取，若无则使用默认值)
    NEO4J_URI: str = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "ariadne_neo4j")


    class Config:
        # 指定环境变量文件路径 (向上两级找到根目录的 .env)
        # env_file = "../../../.env"
        env_file = "D:\\Projects\\Python\\Courses\\Ariadne\\.env"
        case_sensitive = True


settings = Settings()
