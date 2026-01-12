import logging
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase, Driver
from datetime import datetime
from app.core.config import settings

logger = logging.getLogger("FusionTrace.GraphSync")


class GraphSync:
    """
    图数据库同步器 (ETL - Load)
    
    职责:
    1. 将 Parser 输出的节点和关系写入 Neo4j
    2. 管理节点去重（基于唯一ID）
    3. 批量写入优化
    4. 连接池管理
    """

    def __init__(self, uri: str = None, user: str = None, password: str = None):
        """
        初始化 Neo4j 连接
        
        Args:
            uri: Neo4j 连接 URI（默认从配置读取）
            user: 用户名（默认从配置读取）
            password: 密码（默认从配置读取）
        """
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        
        self.driver: Optional[Driver] = None
        self.synced_count = 0
        self.error_count = 0
        
        self._connect()

    def _connect(self):
        """建立 Neo4j 连接"""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60
            )
            # 测试连接
            self.driver.verify_connectivity()
            logger.info(f"成功连接到 Neo4j: {self.uri}")
        except Exception as e:
            logger.error(f"Neo4j 连接失败: {str(e)}", exc_info=True)
            raise

    def sync(self, graph_data: Dict[str, Any]) -> bool:
        """
        同步图数据到 Neo4j
        
        Args:
            graph_data: Parser 输出的图数据
                {
                    "nodes": [...],
                    "edges": [...],
                    "metadata": {...}
                }
        
        Returns:
            bool: 是否成功
        """
        if not graph_data:
            return False

        try:
            nodes = graph_data.get("nodes", [])
            edges = graph_data.get("edges", [])

            with self.driver.session() as session:
                # 1. 创建/更新节点
                for node in nodes:
                    self._create_or_update_node(session, node)

                # 2. 创建关系
                for edge in edges:
                    self._create_relationship(session, edge)

            self.synced_count += 1
            if self.synced_count % 100 == 0:
                logger.info(f"已同步 {self.synced_count} 条图数据，错误: {self.error_count}")

            return True

        except Exception as e:
            logger.error(f"图数据同步失败: {str(e)}", exc_info=True)
            self.error_count += 1
            return False

    def _create_or_update_node(self, session, node: Dict):
        """
        创建或更新节点（基于 MERGE，避免重复）
        
        Args:
            session: Neo4j session
            node: 节点数据
                {
                    "id": "unique_id",
                    "type": "Process",
                    "labels": ["Process"],
                    "properties": {...}
                }
        """
        node_id = node.get("id")
        node_type = node.get("type")
        labels = node.get("labels", [node_type])
        properties = node.get("properties", {})

        if not node_id or not node_type:
            logger.warning("节点缺少 id 或 type，跳过")
            return

        # 构建标签字符串
        labels_str = ":".join(labels)

        # 清理 properties（移除 None 值，转换 datetime）
        clean_props = self._clean_properties(properties)
        clean_props["id"] = node_id  # 确保 id 在属性中

        # MERGE 查询（基于 id 去重）
        query = f"""
        MERGE (n:{labels_str} {{id: $id}})
        SET n += $properties
        SET n.last_updated = datetime()
        """

        try:
            session.run(query, id=node_id, properties=clean_props)
        except Exception as e:
            logger.error(f"创建节点失败 ({node_type}): {str(e)}")

    def _create_relationship(self, session, edge: Dict):
        """
        创建关系
        
        Args:
            session: Neo4j session
            edge: 关系数据
                {
                    "type": "SPAWNED",
                    "source": "source_node_id",
                    "target": "target_node_id",
                    "properties": {...}
                }
        """
        edge_type = edge.get("type")
        source_id = edge.get("source")
        target_id = edge.get("target")
        properties = edge.get("properties", {})

        if not all([edge_type, source_id, target_id]):
            logger.warning("关系缺少必要字段，跳过")
            return

        # 清理 properties
        clean_props = self._clean_properties(properties)

        # MERGE 关系（避免重复创建）
        # 注意：根据业务需求，某些关系可能需要多次创建（如多次连接）
        query = f"""
        MATCH (source {{id: $source_id}})
        MATCH (target {{id: $target_id}})
        MERGE (source)-[r:{edge_type}]->(target)
        SET r += $properties
        SET r.last_updated = datetime()
        """

        try:
            session.run(query, source_id=source_id, target_id=target_id, properties=clean_props)
        except Exception as e:
            logger.error(f"创建关系失败 ({edge_type}): {str(e)}")

    def _clean_properties(self, properties: Dict) -> Dict:
        """
        清理属性字典
        
        - 移除 None 值
        - 转换 datetime 为 ISO 字符串
        - 转换不支持的类型
        """
        cleaned = {}
        for key, value in properties.items():
            if value is None:
                continue
            
            # 转换 datetime
            if isinstance(value, datetime):
                cleaned[key] = value.isoformat()
            # 转换 list（Neo4j 支持列表属性）
            elif isinstance(value, list):
                cleaned[key] = value
            # 转换 dict（展平为字符串）
            elif isinstance(value, dict):
                cleaned[key] = str(value)
            # 基本类型直接保留
            else:
                cleaned[key] = value
        
        return cleaned

    def batch_sync(self, graph_data_list: List[Dict[str, Any]]) -> int:
        """
        批量同步图数据
        
        Args:
            graph_data_list: 图数据列表
        
        Returns:
            int: 成功同步的数量
        """
        success_count = 0
        for graph_data in graph_data_list:
            if self.sync(graph_data):
                success_count += 1
        
        return success_count

    def execute_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """
        执行自定义 Cypher 查询
        
        Args:
            query: Cypher 查询语句
            parameters: 查询参数
        
        Returns:
            List[Dict]: 查询结果
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"查询执行失败: {str(e)}", exc_info=True)
            return []

    def create_constraints(self):
        """
        创建 Neo4j 约束（确保节点唯一性）
        """
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (f:File) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IP) REQUIRE i.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
        ]

        logger.info("开始创建 Neo4j 约束...")
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.info(f"约束已创建: {constraint}")
                except Exception as e:
                    logger.warning(f"约束创建失败（可能已存在）: {str(e)}")

        logger.info("Neo4j 约束创建完成")

    def create_indexes(self):
        """
        创建索引（优化查询性能）
        """
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.pid)",
            "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.host_id)",
            "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.process_name)",
            "CREATE INDEX IF NOT EXISTS FOR (f:File) ON (f.file_hash)",
            "CREATE INDEX IF NOT EXISTS FOR (f:File) ON (f.file_path)",
            "CREATE INDEX IF NOT EXISTS FOR (i:IP) ON (i.ip_address)",
            "CREATE INDEX IF NOT EXISTS FOR (d:Domain) ON (d.domain)",
            "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.host_id)",
        ]

        logger.info("开始创建 Neo4j 索引...")
        
        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index)
                    logger.info(f"索引已创建: {index}")
                except Exception as e:
                    logger.warning(f"索引创建失败（可能已存在）: {str(e)}")

        logger.info("Neo4j 索引创建完成")

    def clear_database(self):
        """
        清空数据库（谨慎使用！）
        """
        logger.warning("即将清空 Neo4j 数据库...")
        
        query = "MATCH (n) DETACH DELETE n"
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                logger.info("Neo4j 数据库已清空")
        except Exception as e:
            logger.error(f"清空数据库失败: {str(e)}", exc_info=True)

    def get_stats(self) -> Dict:
        """
        获取数据库统计信息
        """
        queries = {
            "total_nodes": "MATCH (n) RETURN count(n) as count",
            "total_relationships": "MATCH ()-[r]->() RETURN count(r) as count",
            "process_nodes": "MATCH (n:Process) RETURN count(n) as count",
            "ip_nodes": "MATCH (n:IP) RETURN count(n) as count",
            "domain_nodes": "MATCH (n:Domain) RETURN count(n) as count",
            "file_nodes": "MATCH (n:File) RETURN count(n) as count",
        }

        stats = {}
        with self.driver.session() as session:
            for key, query in queries.items():
                try:
                    result = session.run(query)
                    record = result.single()
                    stats[key] = record["count"] if record else 0
                except Exception as e:
                    stats[key] = f"Error: {str(e)}"

        return stats

    def close(self):
        """关闭数据库连接"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j 连接已关闭")


# ==========================================
# 测试入口
# ==========================================
if __name__ == "__main__":
    import json
    from datetime import timezone

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 初始化
    graph_sync = GraphSync()

    print("=" * 70)
    print("FusionTrace GraphSync - 测试")
    print("=" * 70)

    # 创建约束和索引
    print("\n[步骤 1] 创建约束和索引")
    graph_sync.create_constraints()
    graph_sync.create_indexes()

    # 测试数据
    test_graph_data = {
        "nodes": [
            {
                "id": "process_001",
                "type": "Process",
                "labels": ["Process"],
                "properties": {
                    "pid": 1234,
                    "process_name": "cmd.exe",
                    "process_path": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                    "host_id": "agent_001",
                    "host_name": "Windows11",
                    "start_time": datetime.now(timezone.utc),
                }
            },
            {
                "id": "ip_1_1_1_1",
                "type": "IP",
                "labels": ["IP"],
                "properties": {
                    "ip_address": "1.1.1.1",
                    "is_private": False,
                }
            }
        ],
        "edges": [
            {
                "type": "CONNECTED_TO",
                "source": "process_001",
                "target": "ip_1_1_1_1",
                "properties": {
                    "timestamp": datetime.now(timezone.utc),
                    "dst_port": 443,
                    "protocol": "tcp",
                }
            }
        ],
        "metadata": {
            "event_id": "test_001",
            "timestamp": datetime.now(timezone.utc),
            "source": "wazuh",
        }
    }

    print("\n[步骤 2] 同步测试数据")
    success = graph_sync.sync(test_graph_data)
    print(f"同步结果: {'成功' if success else '失败'}")

    print("\n[步骤 3] 查询统计信息")
    stats = graph_sync.get_stats()
    print(json.dumps(stats, indent=2))

    print("\n[步骤 4] 测试查询")
    query = "MATCH (p:Process)-[r:CONNECTED_TO]->(i:IP) RETURN p.process_name, i.ip_address LIMIT 5"
    results = graph_sync.execute_query(query)
    print(json.dumps(results, indent=2, default=str))

    # 关闭连接
    graph_sync.close()

    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
