from neo4j import GraphDatabase
from app.core.config import settings


class Neo4jHandler:
    def __init__(self):
        self.driver = None

    def connect(self):
        """建立数据库连接"""
        try:
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            # 测试连接
            self.driver.verify_connectivity()
            print("[+] Neo4j Connected successfully.")
        except Exception as e:
            print(f"[!] Failed to connect to Neo4j: {e}")
            raise e

    def close(self):
        """关闭数据库连接"""
        if self.driver:
            self.driver.close()
            print("[+] neo4j connection closed.")

    def get_session(self):
        """获取一个会话"""
        if not self.driver:
            self.connect()
        return self.driver.session()


# 单例模式
db = Neo4jHandler()
