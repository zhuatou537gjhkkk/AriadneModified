"""
测试 EPS 计算
"""
import sys
import logging

# 添加路径
sys.path.insert(0, "D:\\Projects\\Python\\Courses\\Ariadne\\src\\backend")

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from app.core.database import db
from app.api.endpoints import _calculate_throughput_eps, _calculate_time_sync_offset

print("=" * 70)
print("测试 EPS 和时间偏差计算")
print("=" * 70)

try:
    # 连接数据库
    db.connect()
    print("[✓] 数据库连接成功\n")
    
    # 测试 EPS 计算
    print("--- 测试 EPS 计算 ---")
    eps = _calculate_throughput_eps()
    print(f"结果: {eps} Evt/s\n")
    
    # 测试时间偏差计算
    print("--- 测试时间偏差计算 ---")
    offset = _calculate_time_sync_offset()
    print(f"结果: {offset} ms\n")
    
    # 查询数据库统计
    print("--- 数据库统计 ---")
    session = db.get_session()
    try:
        # 查询总节点数
        node_result = session.run("MATCH (n) RETURN count(n) as cnt")
        node_count = node_result.single()["cnt"]
        print(f"总节点数: {node_count}")
        
        # 查询总关系数
        rel_result = session.run("MATCH ()-[r]->() RETURN count(r) as cnt")
        rel_count = rel_result.single()["cnt"]
        print(f"总关系数: {rel_count}")
        
        # 查询最近 60 秒的数据
        from datetime import datetime, timedelta
        one_min_ago = (datetime.now() - timedelta(seconds=60)).isoformat()
        recent_result = session.run("""
            MATCH (n)
            WHERE n.last_updated IS NOT NULL 
              AND n.last_updated >= datetime($since_time)
            RETURN count(n) as cnt
        """, since_time=one_min_ago)
        recent_count = recent_result.single()["cnt"]
        print(f"最近 60 秒节点数: {recent_count}")
        
    finally:
        session.close()
    
    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
    
except Exception as e:
    print(f"[✗] 错误: {str(e)}")
    import traceback
    traceback.print_exc()
finally:
    db.close()
