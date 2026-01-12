# src/backend/app/api/endpoints.py
from fastapi import APIRouter, HTTPException
from app.core.database import db

# 假设这里引入了你的业务逻辑模块
# from app.analysis.graph_algo import find_attack_path
# from app.etl.collector import get_system_status

router = APIRouter()


@router.get("/health")
async def health_check():
    """系统健康状态检查 (对应 Dashboard)"""
    return {"status": "ok", "components": {"neo4j": "connected", "wazuh": "connected"}}


@router.get("/dashboard/summary")
async def get_dashboard_summary():
    """获取态势感知总览数据"""
    # 实际开发中，这里应调用 Neo4j 查询统计数据
    query = """
    MATCH (n:Alert) 
    RETURN count(n) as total_alerts
    """
    try:
        with db.get_session() as session:
            result = session.run(query).single()
            count = result["total_alerts"] if result else 0

        return {
            "total_alerts": count,
            "infected_hosts": 3,  # 模拟数据
            "risk_level": "High"
        }
    except Exception as e:
        return {"error": str(e)}


@router.get("/graph/explore")
async def explore_graph(node_id: str = None):
    """
    溯源画布数据接口
    前端传入一个节点ID，后端返回其关联的节点和边
    """
    # 模拟数据，实际应调用 app/analysis/graph_algo.py
    return {
        "nodes": [
            {"id": "node1", "label": "Process: bash", "type": "process"},
            {"id": "node2", "label": "IP: 192.168.1.5", "type": "ip"}
        ],
        "edges": [
            {"source": "node1", "target": "node2", "label": "CONNECTED_TO"}
        ]
    }
