"""
测试分析流水线
"""
import sys
import logging

# 添加路径
sys.path.insert(0, "src/backend")

from app.analysis.chain_builder import ChainBuilder
from app.analysis.graph_algo import GraphAlgorithms
from app.analysis.mitre_mapper import MITREMapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("TestAnalysis")

def test_neo4j_connection():
    """测试 Neo4j 连接"""
    from app.etl.graph_sync import GraphSync
    
    print("=" * 70)
    print("测试 Neo4j 连接")
    print("=" * 70)
    
    try:
        graph = GraphSync()
        # 简单查询测试
        result = graph.execute_query("RETURN 1 as test", {})
        print(f"✓ Neo4j 连接成功: {result}")
        
        # 查询节点数量
        result = graph.execute_query("""
            MATCH (n)
            RETURN labels(n) as label, count(n) as count
        """, {})
        
        print("\n当前图数据库节点统计:")
        if result:
            for record in result:
                print(f"  {record.get('label')}: {record.get('count')} 个")
        else:
            print("  ⚠ 数据库为空，请先运行 ETL Pipeline 入库数据")
        
        return True
    except Exception as e:
        print(f"✗ Neo4j 连接失败: {str(e)}")
        print("\n解决方案:")
        print("1. 确认 Neo4j 服务已启动")
        print("2. 检查 config.py 中的连接配置")
        print("3. 确认用户名密码正确")
        return False


def test_analysis_modules():
    """测试分析模块"""
    print("\n" + "=" * 70)
    print("测试分析模块")
    print("=" * 70)
    
    # 1. 测试攻击链构建
    print("\n[1] 测试攻击链构建...")
    try:
        builder = ChainBuilder()
        chains = builder.build_attack_chain()
        print(f"  ✓ 攻击链: {chains['total_count']} 条")
        print(f"  ✓ 可疑IP: {len(chains.get('suspicious_ips', []))} 个")
        print(f"  ✓ 可疑进程: {len(chains.get('suspicious_processes', []))} 个")
    except Exception as e:
        print(f"  ✗ 失败: {str(e)}")
    
    # 2. 测试攻击模式检测
    print("\n[2] 测试攻击模式检测...")
    try:
        algo = GraphAlgorithms()
        patterns = {
            "reverse_shell": algo.find_attack_patterns("reverse_shell"),
            "credential_dump": algo.find_attack_patterns("credential_dump"),
            "lateral_movement": algo.find_attack_patterns("lateral_movement"),
            "webshell": algo.find_attack_patterns("webshell"),
        }
        for pattern_type, results in patterns.items():
            print(f"  ✓ {pattern_type}: {len(results)} 个")
    except Exception as e:
        print(f"  ✗ 失败: {str(e)}")
    
    # 3. 测试横向移动检测
    print("\n[3] 测试横向移动检测...")
    try:
        builder = ChainBuilder()
        lateral = builder.find_lateral_movement()
        print(f"  ✓ 横向移动: {len(lateral)} 个")
    except Exception as e:
        print(f"  ✗ 失败: {str(e)}")
    
    # 4. 测试数据外泄检测
    print("\n[4] 测试数据外泄检测...")
    try:
        builder = ChainBuilder()
        exfil = builder.find_data_exfiltration()
        print(f"  ✓ 数据外泄: {len(exfil)} 个")
    except Exception as e:
        print(f"  ✗ 失败: {str(e)}")
    
    # 5. 测试持久化检测
    print("\n[5] 测试持久化检测...")
    try:
        builder = ChainBuilder()
        persist = builder.find_persistence_mechanisms()
        print(f"  ✓ 持久化: {len(persist)} 个")
    except Exception as e:
        print(f"  ✗ 失败: {str(e)}")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("FusionTrace 分析模块测试")
    print("=" * 70)
    
    # 测试连接
    if test_neo4j_connection():
        # 测试分析功能
        test_analysis_modules()
    
    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
    
    print("\n使用步骤:")
    print("1. 启动 Neo4j 数据库")
    print("2. 运行 ETL Pipeline: python -m app.etl.pipeline")
    print("3. 运行分析流水线: python -m app.analysis.analysis_pipeline")
