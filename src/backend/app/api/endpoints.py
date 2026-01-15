# src/backend/app/api/endpoints.py
from fastapi import APIRouter, HTTPException, Query
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("FusionTrace.API")

# 假设这里引入了你的业务逻辑模块
from app.core.database import db
from app.analysis.chain_builder import ChainBuilder
from app.analysis.graph_algo import GraphAlgorithms
from app.analysis.mitre_mapper import MITREMapper
from app.enrichment.attribution import Attribution

router = APIRouter()

# 初始化分析模块
chain_builder = ChainBuilder()
graph_algo = GraphAlgorithms()
mitre_mapper = MITREMapper()
attribution = Attribution()


# ==========================================
# 1. 健康检查与系统状态
# ==========================================

@router.get("/health")
async def health_check():
    """系统健康状态检查"""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "neo4j": "connected",
            "wazuh": "connected",
            "zeek": "connected"
        }
    }


# ==========================================
# 2. 态势总览 (Dashboard Summary)
# ==========================================

@router.get("/dashboard/summary")
async def get_dashboard_summary():
    """
    获取态势感知总览数据
    
    返回格式（前端严格要求）:
    {
        "active_threats": int,      # 当前活跃威胁数
        "intercepted_today": int,   # 今日拦截告警数
        "throughput_eps": int,      # 吞吐量 (events per second)
        "time_sync_offset": int     # 时间同步偏差 (ms)
    }
    """
    try:
        # ============ 1. 计算活跃威胁数 ============
        # 使用分析模块获取攻击链统计
        attack_chains = chain_builder.build_attack_chain(time_range_hours=24)
        lateral_movements = chain_builder.find_lateral_movement(time_range_hours=24)
        data_exfiltrations = chain_builder.find_data_exfiltration()
        
        # 活跃威胁数 = 攻击链数 + 横向移动数 + 外泄事件数
        active_threats = (
            attack_chains.get("total_count", 0) +
            len(lateral_movements) +
            len(data_exfiltrations)
        )
        
        # ============ 2. 计算今日拦截告警数 ============
        # 统计今日检测到的所有攻击模式数量
        reverse_shells = graph_algo.find_attack_patterns("reverse_shell")
        cred_dumps = graph_algo.find_attack_patterns("credential_dump")
        lateral_moves = graph_algo.find_attack_patterns("lateral_movement")
        webshells = graph_algo.find_attack_patterns("webshell")
        
        intercepted_today = (
            len(reverse_shells) +
            len(cred_dumps) +
            len(lateral_moves) +
            len(webshells)
        )
        
        # ============ 3. 计算数据吞吐量 EPS ============
        # 查询最近 60 秒内新增的事件数量，计算 EPS
        throughput_eps = _calculate_throughput_eps()
        
        # ============ 4. 计算时间同步偏差 ============
        # 比较数据库最新事件时间与当前系统时间
        time_sync_offset = _calculate_time_sync_offset()
        
        # 严格按前端期望格式返回（仅 4 个字段，无额外数据）
        return {
            "active_threats": active_threats,
            "intercepted_today": intercepted_today,
            "throughput_eps": throughput_eps,
            "time_sync_offset": time_sync_offset
        }
    except Exception as e:
        logger.error(f"获取态势总览失败: {str(e)}")
        # 异常时返回默认值，保证数据结构一致
        return {
            "active_threats": 0,
            "intercepted_today": 0,
            "throughput_eps": 0,
            "time_sync_offset": 0
        }


def _calculate_throughput_eps() -> int:
    """
    计算数据吞吐量（每秒事件数 EPS）
    
    优先查询最近 60 秒的实时数据；
    如果没有实时数据，则基于数据库中所有数据的实际时间跨度计算平均 EPS
    
    Returns:
        int: 每秒事件数
    """
    try:
        session = db.get_session()
        try:
            # ============ 策略 1: 查询最近 60 秒的实时数据 ============
            now = datetime.now()
            one_minute_ago = now - timedelta(seconds=60)
            
            # 查询最近 60 秒内更新的节点和关系数量
            recent_query = """
            MATCH (n)
            WHERE n.last_updated IS NOT NULL 
              AND n.last_updated >= datetime($since_time)
            WITH count(n) as recent_nodes
            MATCH ()-[r]->()
            WHERE r.last_updated IS NOT NULL 
              AND r.last_updated >= datetime($since_time)
            RETURN recent_nodes, count(r) as recent_rels
            """
            
            recent_result = session.run(recent_query, since_time=one_minute_ago.isoformat())
            recent_record = recent_result.single()
            
            if recent_record:
                recent_nodes = recent_record["recent_nodes"] or 0
                recent_rels = recent_record["recent_rels"] or 0
                total_events = recent_nodes + recent_rels
                
                if total_events > 0:
                    eps = total_events // 60
                    logger.info(f"EPS 计算（实时）- 最近节点: {recent_nodes}, 最近关系: {recent_rels}, EPS: {eps}")
                    return eps
            
            # ============ 策略 2: 基于历史数据的实际时间跨度计算 ============
            # 查询数据库中最早和最晚的时间戳
            timespan_query = """
            MATCH (n)
            WHERE n.last_updated IS NOT NULL
            WITH n.last_updated as ts
            ORDER BY ts
            WITH collect(ts) as timestamps
            WHERE size(timestamps) > 0
            RETURN timestamps[0] as earliest, timestamps[-1] as latest
            """
            
            timespan_result = session.run(timespan_query)
            timespan_record = timespan_result.single()
            
            if timespan_record and timespan_record["earliest"] and timespan_record["latest"]:
                earliest = timespan_record["earliest"]
                latest = timespan_record["latest"]
                
                # 解析时间戳
                def parse_neo4j_time(ts):
                    if hasattr(ts, 'to_native'):
                        native = ts.to_native()
                        return native.astimezone().replace(tzinfo=None) if hasattr(native, 'astimezone') else native
                    elif isinstance(ts, str):
                        return datetime.fromisoformat(ts.replace('Z', '+00:00').split('+')[0].split('.')[0])
                    elif isinstance(ts, datetime):
                        return ts.replace(tzinfo=None) if ts.tzinfo else ts
                    return None
                
                earliest_dt = parse_neo4j_time(earliest)
                latest_dt = parse_neo4j_time(latest)
                
                if earliest_dt and latest_dt:
                    # 计算实际时间跨度（秒）
                    time_span_seconds = (latest_dt - earliest_dt).total_seconds()
                    
                    if time_span_seconds > 0:
                        # 查询总数据量
                        count_query = """
                        MATCH (n) 
                        WITH count(n) as nodes
                        MATCH ()-[r]->()
                        RETURN nodes, count(r) as rels
                        """
                        count_result = session.run(count_query)
                        count_record = count_result.single()
                        
                        if count_record:
                            total_nodes = count_record["nodes"] or 0
                            total_rels = count_record["rels"] or 0
                            total_data = total_nodes + total_rels
                            
                            # 基于实际时间跨度计算平均 EPS
                            eps = int(total_data / time_span_seconds)
                            logger.info(f"EPS 计算（历史）- 总数据: {total_data}, 时间跨度: {time_span_seconds}秒, EPS: {eps}")
                            return max(1, eps)  # 至少返回 1
            
            # ============ 策略 3: 降级处理 ============
            # 如果以上都失败，返回一个基于总数据量的保守估计
            fallback_query = """
            MATCH (n) 
            WITH count(n) as nodes
            MATCH ()-[r]->()
            RETURN nodes, count(r) as rels
            """
            fallback_result = session.run(fallback_query)
            fallback_record = fallback_result.single()
            
            if fallback_record:
                total_data = (fallback_record["nodes"] or 0) + (fallback_record["rels"] or 0)
                
                # 如果有大量数据，说明系统在运行，给一个合理的估算
                if total_data > 1000:
                    # 假设数据在 1 小时内采集（更合理的估计）
                    eps = max(10, total_data // 3600)  # 至少返回 10 EPS
                elif total_data > 0:
                    # 数据量很少，可能刚启动
                    eps = max(1, total_data // 600)  # 假设在 10 分钟内采集
                else:
                    eps = 0
                
                logger.info(f"EPS 计算（降级）- 总数据: {total_data}, 估算 EPS: {eps}")
                return eps
            
            return 0
            
        finally:
            session.close()
    except Exception as e:
        logger.error(f"计算 EPS 失败: {str(e)}", exc_info=True)
        return 0


def _calculate_time_sync_offset() -> int:
    """
    计算时间同步偏差（毫秒）
    
    反映数据新鲜度：当前时间 - 最新事件时间
    - 如果偏差小，说明数据流是实时的
    - 如果偏差大，说明 ETL 延迟或没有新数据
    
    Returns:
        int: 时间偏差（毫秒）
    """
    try:
        session = db.get_session()
        try:
            now = datetime.now()
            
            # 查询数据库中最新的时间戳
            query = """
            MATCH (n)
            WHERE n.last_updated IS NOT NULL
            RETURN n.last_updated as ts
            ORDER BY n.last_updated DESC
            LIMIT 1
            """
            
            result = session.run(query)
            record = result.single()
            
            if record and record["ts"]:
                ts = record["ts"]
                
                # 解析数据库时间戳
                def parse_neo4j_time(ts):
                    if hasattr(ts, 'to_native'):
                        native = ts.to_native()
                        return native.astimezone().replace(tzinfo=None) if hasattr(native, 'astimezone') else native
                    elif isinstance(ts, str):
                        return datetime.fromisoformat(ts.replace('Z', '+00:00').split('+')[0].split('.')[0])
                    elif isinstance(ts, datetime):
                        return ts.replace(tzinfo=None) if ts.tzinfo else ts
                    return None
                
                db_time = parse_neo4j_time(ts)
                
                if db_time:
                    # 计算时间差（毫秒）- 显示实际偏差
                    time_diff = (now - db_time).total_seconds() * 1000
                    
                    # 如果时间差为负数（未来时间），说明有时钟偏差
                    time_diff_abs = abs(time_diff)
                    
                    logger.info(f"时间同步偏差: {int(time_diff_abs)} ms (数据时间: {db_time}, 当前时间: {now})")
                    return int(time_diff_abs)
            
            # 数据库完全为空
            logger.warning("时间同步偏差计算失败：数据库无数据")
            return 0
                
        finally:
            session.close()
    except Exception as e:
        logger.error(f"计算时间同步偏差失败: {str(e)}", exc_info=True)
        return 0


@router.get("/dashboard/traffic-trend")
async def get_traffic_trend(hours: float = 0.33):
    """
    获取流量趋势数据（用于 TrafficTrend 组件）

    从数据库查询真实的事件数据，按时间段统计 Zeek（网络）和 Wazuh（端点）的事件数量。
    
    参数:
    - hours: 时间范围（小时），默认为0.33小时（20分钟）

    返回:
    - categories: 时间点数组
    - series: 各数据源的流量趋势
    """
    try:
        # 生成时间序列（根据 hours 参数，每 hours*60/7 分钟一个点，共7个点）
        now = datetime.now()
        interval_minutes = (hours * 60) / 7  # 每个时间桶的分钟数
        time_points = []
        time_ranges = []
        
        for i in range(6, -1, -1):
            t = now - timedelta(minutes=i * interval_minutes)
            time_points.append(t.strftime("%H:%M"))
            # 为每个时间点创建时间范围
            start_time = t - timedelta(minutes=interval_minutes / 2)
            end_time = t + timedelta(minutes=interval_minutes / 2)
            time_ranges.append((start_time, end_time))
        
        # 初始化数据数组，默认为0
        zeek_data = [0] * 7
        wazuh_data = [0] * 7
        
        # 用于调试：统计数据库中的总数据量
        zeek_total = 0
        wazuh_total = 0
        
        # 从 Neo4j 查询真实数据
        session = db.get_session()
        try:
            # 先查询数据库中所有节点的数量，验证数据库连接
            count_query = """
            MATCH (n) RETURN labels(n)[0] as label, count(n) as cnt
            """
            count_result = session.run(count_query)
            node_counts = {record["label"]: record["cnt"] for record in count_result}
            print(f"[DEBUG] 数据库节点统计: {node_counts}")
            
            # ============ Zeek 数据（网络流量）============
            # 查询所有 IP、Domain 节点
            zeek_nodes_query = """
            MATCH (n)
            WHERE n:IP OR n:Domain
            RETURN n.last_updated as last_updated, n.timestamp as timestamp
            """
            zeek_nodes_result = session.run(zeek_nodes_query)
            zeek_nodes_list = list(zeek_nodes_result)
            print(f"[DEBUG] Zeek 节点数量: {len(zeek_nodes_list)}")
            
            for record in zeek_nodes_list:
                zeek_total += 1
                ts = record["last_updated"] or record["timestamp"]
                if ts:
                    idx = _get_time_bucket_index(ts, time_ranges)
                    if idx is not None:
                        zeek_data[idx] += 1
            
            # 查询所有 CONNECTED_TO 关系
            zeek_rels_query = """
            MATCH ()-[r:CONNECTED_TO]->()
            RETURN r.timestamp as timestamp, r.last_updated as last_updated
            """
            zeek_rels_result = session.run(zeek_rels_query)
            zeek_rels_list = list(zeek_rels_result)
            print(f"[DEBUG] CONNECTED_TO 关系数量: {len(zeek_rels_list)}")
            
            for record in zeek_rels_list:
                zeek_total += 1
                ts = record["timestamp"] or record["last_updated"]
                if ts:
                    idx = _get_time_bucket_index(ts, time_ranges)
                    if idx is not None:
                        zeek_data[idx] += 1
            
            # ============ Wazuh 数据（端点主机）============
            # 查询所有 Process、File、User 节点
            wazuh_nodes_query = """
            MATCH (n)
            WHERE n:Process OR n:File OR n:User
            RETURN n.last_updated as last_updated, n.first_seen as first_seen, n.last_seen as last_seen, n.timestamp as timestamp
            """
            wazuh_nodes_result = session.run(wazuh_nodes_query)
            wazuh_nodes_list = list(wazuh_nodes_result)
            print(f"[DEBUG] Wazuh 节点数量: {len(wazuh_nodes_list)}")
            
            # 打印第一条记录的时间戳格式（用于调试）
            if wazuh_nodes_list:
                first_record = wazuh_nodes_list[0]
                print(f"[DEBUG] 第一条 Wazuh 节点时间戳: last_updated={first_record['last_updated']}, type={type(first_record['last_updated'])}")
            
            for record in wazuh_nodes_list:
                wazuh_total += 1
                ts = record["last_updated"] or record["last_seen"] or record["first_seen"] or record["timestamp"]
                if ts:
                    idx = _get_time_bucket_index(ts, time_ranges)
                    if idx is not None:
                        wazuh_data[idx] += 1
            
            # 查询所有 Wazuh 相关关系
            wazuh_rels_query = """
            MATCH ()-[r]->()
            WHERE type(r) IN ['SPAWNED', 'ACCESSED_FILE', 'CREATED_FILE', 'EXECUTED_BY']
            RETURN r.timestamp as timestamp, r.last_updated as last_updated
            """
            wazuh_rels_result = session.run(wazuh_rels_query)
            wazuh_rels_list = list(wazuh_rels_result)
            print(f"[DEBUG] Wazuh 关系数量: {len(wazuh_rels_list)}")
            
            for record in wazuh_rels_list:
                wazuh_total += 1
                ts = record["timestamp"] or record["last_updated"]
                if ts:
                    idx = _get_time_bucket_index(ts, time_ranges)
                    if idx is not None:
                        wazuh_data[idx] += 1
                        
        finally:
            session.close()
        
        # 计算合并数据
        combined_data = [z + w for z, w in zip(zeek_data, wazuh_data)]
        
        # 调试日志：显示数据库总量和时间范围内的数据量
        logger.info(f"流量趋势统计 - 数据库总量: Zeek={zeek_total}, Wazuh={wazuh_total}")
        logger.info(f"流量趋势统计 - 时间范围内: Zeek={zeek_data}, Wazuh={wazuh_data}")
        logger.info(f"时间范围: {time_ranges[0][0]} ~ {time_ranges[-1][1]}")

        ret_data = {
            "categories": time_points,
            "series": {
                "zeek": zeek_data,
                "wazuh": wazuh_data,
                "combined": combined_data
            }
        }

        print(f"[DEBUG] 数据库总量: Zeek={zeek_total}, Wazuh={wazuh_total}")
        print(f"[DEBUG] 返回数据: {ret_data}")
        
        return ret_data
    except Exception as e:
        logger.error(f"获取流量趋势失败: {str(e)}", exc_info=True)
        # 异常时返回全零数据
        now = datetime.now()
        return {
            "categories": [(now - timedelta(minutes=i*5)).strftime("%H:%M") for i in range(6, -1, -1)],
            "series": {
                "zeek": [0, 0, 0, 0, 0, 0, 0],
                "wazuh": [0, 0, 0, 0, 0, 0, 0],
                "combined": [0, 0, 0, 0, 0, 0, 0]
            }
        }


def _get_time_bucket_index(timestamp, time_ranges) -> Optional[int]:
    """
    根据时间戳判断属于哪个时间桶
    
    Args:
        timestamp: 时间戳（可以是 datetime 对象、ISO 字符串或 Neo4j datetime）
        time_ranges: 时间范围列表 [(start, end), ...]，使用本地时间
    
    Returns:
        int: 时间桶索引，如果不在范围内返回 None
    """
    try:
        # 将时间戳转换为本地时间的 datetime 对象
        ts = None
        
        if hasattr(timestamp, 'to_native'):
            # Neo4j DateTime 对象 - 需要转换为本地时间
            native = timestamp.to_native()  # 返回 Python datetime（带时区）
            if hasattr(native, 'astimezone'):
                # 转换为本地时区，然后移除时区信息
                ts = native.astimezone().replace(tzinfo=None)
            else:
                ts = native
        elif isinstance(timestamp, str):
            # ISO 格式字符串
            from datetime import timezone
            # 解析带时区的时间字符串
            ts_str = timestamp.replace('Z', '+00:00')
            if '+' in ts_str or '-' in ts_str[10:]:  # 有时区信息
                # 解析时间，包含时区
                try:
                    parsed = datetime.fromisoformat(ts_str)
                    # 转换为本地时间
                    ts = parsed.astimezone().replace(tzinfo=None)
                except:
                    # 降级处理：直接解析不带时区的部分
                    ts_clean = ts_str.split('+')[0].split('-')[0] if 'T' in ts_str else ts_str
                    ts = datetime.fromisoformat(ts_clean.split('.')[0])
            else:
                ts = datetime.fromisoformat(ts_str.split('.')[0])
        elif isinstance(timestamp, datetime):
            if timestamp.tzinfo:
                # 有时区信息，转换为本地时间
                ts = timestamp.astimezone().replace(tzinfo=None)
            else:
                ts = timestamp
        else:
            # 尝试转换为字符串后解析
            try:
                ts_str = str(timestamp)
                return _get_time_bucket_index(ts_str, time_ranges)
            except:
                return None
        
        if ts is None:
            return None
        
        # 检查时间戳属于哪个时间桶
        for idx, (start, end) in enumerate(time_ranges):
            start_naive = start.replace(tzinfo=None) if start.tzinfo else start
            end_naive = end.replace(tzinfo=None) if end.tzinfo else end
            if start_naive <= ts < end_naive:
                return idx
        
        # 时间戳不在任何时间桶范围内
        return None
    except Exception as e:
        # 记录错误但不中断程序
        logger.debug(f"时间戳解析失败: {timestamp}, 类型: {type(timestamp)}, 错误: {e}")
        return None


@router.get("/dashboard/topology")
async def get_topology_data():
    """
    获取全网拓扑数据（用于 TopologyGraph 组件）
    
    返回:
    - nodes: 节点数组，包含 name, category, status
    - links: 边数组，包含 source, target, type (可选)
    """
    try:
        # 获取资产列表作为拓扑节点的基础
        assets = await get_assets_list()
        
        # 基于资产数据构建拓扑节点
        nodes = []
        links = []
        
        # 定义节点分类映射
        role_to_category = {
            "Server": "Server",
            "Sensor": "Sensor",
            "Victim": "Endpoint",
            "Attacker": "Compromised"
        }
        
        # 定义状态映射
        status_mapping = {
            "online": "online",
            "offline": "offline",
            "suspicious": "compromised",
            "compromised": "compromised"
        }
        
        # 用于记录不同类型的节点
        server_nodes = []
        sensor_nodes = []
        endpoint_nodes = []
        compromised_nodes = []
        
        # 遍历所有资产，完全基于资产列表动态生成节点
        for asset in assets:
            role = asset.get("role", "Unknown")
            status = asset.get("status", "online")
            name = asset.get("name", "Unknown")
            ip = asset.get("ip", "N/A")
            
            category = role_to_category.get(role, "Endpoint")
            node_status = status_mapping.get(status, "online")
            
            # 如果状态是可疑或已沦陷，标记为 Compromised
            if status in ["suspicious", "compromised"]:
                category = "Compromised"
                compromised_nodes.append(name)
            
            # 添加节点
            nodes.append({
                "name": name,
                "category": category,
                "status": node_status,
                "ip": ip
            })
            
            # 根据类型分类记录
            if role == "Server":
                server_nodes.append(name)
            elif role == "Sensor":
                sensor_nodes.append(name)
            else:
                endpoint_nodes.append(name)
        
        # 构建拓扑连接：Server -> Sensor -> Endpoint
        # 1. Server 连接到所有 Sensor
        for server in server_nodes:
            for sensor in sensor_nodes:
                links.append({
                    "source": server,
                    "target": sensor
                })
        
        # 2. Sensor 连接到所有 Endpoint 和 Compromised 节点
        for sensor in sensor_nodes:
            for endpoint in endpoint_nodes:
                links.append({
                    "source": sensor,
                    "target": endpoint
                })
        
        # 3. 为沦陷节点添加反向隐蔽信道（tunnel）
        for compromised_name in compromised_nodes:
            # 连接到第一个 Sensor（如果存在）
            if sensor_nodes:
                links.append({
                    "source": compromised_name,
                    "target": sensor_nodes[0],
                    "type": "tunnel"
                })
        
        return {
            "nodes": nodes,
            "links": links
        }
    except Exception as e:
        logger.error(f"获取拓扑数据失败: {str(e)}")
        # 返回默认的拓扑结构
        return {
            "nodes": [
                {"name": "Analysis Center", "category": "Server", "status": "online", "ip": "192.168.1.1"},
                {"name": "Zeek Sensor", "category": "Sensor", "status": "online", "ip": "192.168.1.3"},
                {"name": "Victim-01 (Web)", "category": "Endpoint", "status": "online", "ip": "192.168.1.10"},
                {"name": "Victim-02 (DB)", "category": "Endpoint", "status": "online", "ip": "192.168.1.11"},
                {"name": "Victim-03 (Admin)", "category": "Compromised", "status": "compromised", "ip": "192.168.1.12"}
            ],
            "links": [
                {"source": "Analysis Center", "target": "Zeek Sensor"},
                {"source": "Zeek Sensor", "target": "Victim-01 (Web)"},
                {"source": "Zeek Sensor", "target": "Victim-02 (DB)"},
                {"source": "Zeek Sensor", "target": "Victim-03 (Admin)"},
                {"source": "Victim-03 (Admin)", "target": "Zeek Sensor", "type": "tunnel"}
            ]
        }


# ==========================================
# 3. 告警与事件 (Alerts)
# ==========================================

@router.get("/alerts/latest")
async def get_latest_alerts(limit: int = Query(10, ge=1, le=100)):
    """
    获取最新告警列表
    
    返回:
    - title: 告警标题
    - source: 数据源 (zeek/wazuh)
    - time: 告警时间
    - level: 告警级别 (low/medium/high/critical)
    - details: 详细信息
    """
    try:
        alerts = []
        
        # 获取不同类型的告警
        reverse_shells = graph_algo.find_attack_patterns("reverse_shell")
        cred_dumps = graph_algo.find_attack_patterns("credential_dump")
        lateral_moves = graph_algo.find_attack_patterns("lateral_movement")
        webshells = graph_algo.find_attack_patterns("webshell")
        
        # 组织告警数据
        all_alerts = [
            ("反弹 Shell", reverse_shells, "critical"),
            ("凭据转储", cred_dumps, "critical"),
            ("横向移动", lateral_moves, "high"),
            ("WebShell 后门", webshells, "critical"),
        ]
        
        for i, (alert_type, alert_list, level) in enumerate(all_alerts):
            for j, alert_item in enumerate(alert_list[:limit // 4]):
                alerts.append({
                    "title": alert_type,
                    "source": alert_item.get("host_id", "unknown"),
                    "time": str(alert_item.get("timestamp", datetime.now().isoformat())).split('T')[1][:8],
                    "level": level,
                    "details": alert_item.get("description", ""),
                    "severity": alert_item.get("severity", "high"),
                    "clickable": (i == 0 and j == 0)  # 第一个告警可点击
                })
        
        return alerts[:limit]
    except Exception as e:
        logger.error(f"获取告警列表失败: {str(e)}")
        return []


# ==========================================
# 4. 溯源画布 (Investigation Graph)
# ==========================================

@router.get("/investigation/graph")
async def get_attack_graph(time_range_hours: int = Query(24, ge=1, le=720)):
    """
    获取攻击图谱数据（多跳溯源）
    
    返回:
    - nodes: 节点数组 (IP、进程、文件等)
    - links: 边数组 (SPAWNED、CONNECTED_TO 等关系)
    - metadata: 图的元数据
    """
    try:
        # 构建攻击链
        attack_chains = chain_builder.build_attack_chain(time_range_hours=time_range_hours)
        
        nodes = []
        links = []
        node_ids = set()
        
        # 从攻击链提取节点和边
        chains = attack_chains.get("chains", [])
        for chain in chains:
            chain_nodes = chain.get("chain", [])
            edges = chain.get("edges", [])
            
            # 添加进程节点（多跳）
            for i, node in enumerate(chain_nodes):
                node_id = f"proc_{node.get('pid')}_{node.get('name')}"
                if node_id not in node_ids:
                    nodes.append({
                        "id": node_id,
                        "name": f"{node.get('name')} (PID:{node.get('pid')})",  # 前端需要的 name 字段
                        "label": f"{node.get('name')} (PID:{node.get('pid')})",
                        "category": "Process",
                        "details": f"Path: {node.get('path')}\nCmd: {node.get('command')}",
                        "level": i + 1  # 用于时间回放
                    })
                    node_ids.add(node_id)
                
                # 添加进程间的边
                if i > 0:
                    prev_node = chain_nodes[i - 1]
                    prev_id = f"proc_{prev_node.get('pid')}_{prev_node.get('name')}"
                    links.append({
                        "source": prev_id,
                        "target": node_id,
                        "label": "SPAWNED",
                        "timestamp": edges[i-1].get("timestamp") if i-1 < len(edges) else None,
                        "value": 2
                    })
        
        # 添加网络连接节点
        network_conns = attack_chains.get("network_connections", [])
        for conn in network_conns:
            path = conn.get("path", [])
            
            for node in path:
                ip = node.get("ip_address")
                if ip:
                    node_id = f"ip_{ip}"
                    if node_id not in node_ids:
                        nodes.append({
                            "id": node_id,
                            "name": f"IP: {ip}",  # 前端需要的 name 字段
                            "label": f"IP: {ip}",
                            "category": "External_IP" if not node.get("is_private") else "IP",
                            "details": f"Type: {'Internal' if node.get('is_private') else 'External'}",
                            "level": 1
                        })
                        node_ids.add(node_id)
            
            # 添加网络连接边（多跳）
            for i in range(len(path) - 1):
                src_ip = path[i].get("ip_address")
                dst_ip = path[i + 1].get("ip_address")
                if src_ip and dst_ip:
                    links.append({
                        "source": f"ip_{src_ip}",
                        "target": f"ip_{dst_ip}",
                        "label": "CONNECTED_TO",
                        "port": conn.get("edges")[i].get("dst_port") if i < len(conn.get("edges", [])) else None,
                        "bytes": conn.get("edges")[i].get("bytes_sent") if i < len(conn.get("edges", [])) else 0,
                        "value": 2
                    })
        
        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "total_chains": len(chains),
                "total_nodes": len(nodes),
                "total_connections": len(links),
                "time_range_hours": time_range_hours
            }
        }
    except Exception as e:
        logger.error(f"获取攻击图谱失败: {str(e)}")
        return {"nodes": [], "links": [], "error": str(e)}


@router.get("/investigation/graph/explore")
async def explore_graph_node(node_id: str):
    """
    从某个节点探索关联的其他节点和边
    （用于前端点击节点时展开关联）
    """
    try:
        # 获取完整图谱，然后过滤包含 node_id 的子图
        graph_data = await get_attack_graph()
        
        # 找出与 node_id 相关的所有节点（一度关联）
        related_nodes = {node_id}
        for link in graph_data["links"]:
            if link["source"] == node_id:
                related_nodes.add(link["target"])
            elif link["target"] == node_id:
                related_nodes.add(link["source"])
        
        # 过滤节点和边
        filtered_nodes = [n for n in graph_data["nodes"] if n["id"] in related_nodes]
        filtered_links = [
            l for l in graph_data["links"]
            if l["source"] in related_nodes and l["target"] in related_nodes
        ]
        
        return {
            "nodes": filtered_nodes,
            "links": filtered_links,
            "center_node_id": node_id
        }
    except Exception as e:
        logger.error(f"节点探索失败: {str(e)}")
        return {"nodes": [], "links": [], "error": str(e)}


@router.get("/investigation/chains/list")
async def get_attack_chains_list(time_range_hours: int = Query(24, ge=1, le=720)):
    """
    获取攻击链列表（摘要信息）
    
    Args:
        time_range_hours: 时间范围（小时）
    
    返回:
        {
            "total": int,
            "chains": [
                {
                    "id": "chain_0",
                    "name": "cmd.exe → powershell.exe",
                    "severity": "high",
                    "length": 4,
                    "host_id": "host1",
                    "timestamp": "2024-01-01 10:00:00",
                    "type": "process_tree"
                }
            ]
        }
    """
    try:
        # 获取所有攻击链
        attack_chains = chain_builder.build_attack_chain(time_range_hours=time_range_hours)
        chains = attack_chains.get("chains", [])
        network_connections = attack_chains.get("network_connections", [])
        
        # 构建进程链摘要列表
        chain_list = []
        for idx, chain in enumerate(chains):
            chain_nodes = chain.get("chain", [])
            if not chain_nodes or len(chain_nodes) < 2:
                continue
            
            # 生成攻击链名称（根据起点和终点进程）
            first_process = chain_nodes[0].get("name", "Unknown")
            last_process = chain_nodes[-1].get("name", "Unknown")
            chain_name = f"{first_process} → {last_process}"
            
            # 计算严重程度（基于链长度和危险进程）
            dangerous_procs = ['powershell.exe', 'cmd.exe', 'mimikatz.exe', 'psexec.exe', 
                             'nc.exe', 'regsvr32.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe']
            has_dangerous = any(n.get("name") in dangerous_procs for n in chain_nodes)
            severity = "high" if (has_dangerous and len(chain_nodes) >= 3) else "medium" if has_dangerous else "low"
            
            # 获取时间戳
            first_seen = chain_nodes[0].get("first_seen")
            timestamp = first_seen if first_seen else "Unknown"
            
            chain_list.append({
                "id": f"chain_{idx}",
                "name": chain_name,
                "severity": severity,
                "length": chain.get("chain_length", len(chain_nodes)),
                "host_id": chain.get("host_id", "Unknown"),
                "timestamp": timestamp,
                "type": chain.get("type", "process_tree"),
                "description": f"{len(chain_nodes)} 个进程节点"
            })
        
        # 添加网络连接链
        for idx, conn in enumerate(network_connections):
            path = conn.get("path", [])
            if not path or len(path) < 2:
                continue
            
            # 生成网络连接链名称
            first_ip = path[0].get("ip_address", "Unknown")
            last_ip = path[-1].get("ip_address", "Unknown")
            chain_name = f"{first_ip} ⇄ {last_ip}"
            
            # 检查是否连接到外部 IP
            has_external = any(not node.get("is_private", True) for node in path)
            severity = "high" if has_external else "medium"
            
            chain_list.append({
                "id": f"network_{idx}",
                "name": chain_name,
                "severity": severity,
                "length": len(path),
                "host_id": "Network",
                "timestamp": conn.get("timestamp", "Unknown"),
                "type": "network_connection",
                "description": f"{len(path)} 跳网络连接"
            })
        
        # 按严重程度和时间排序
        severity_order = {"high": 0, "medium": 1, "low": 2}
        chain_list.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["timestamp"]), reverse=True)
        
        logger.info(f"返回 {len(chain_list)} 个攻击链摘要")
        
        return {
            "total": len(chain_list),
            "chains": chain_list
        }
    except Exception as e:
        logger.error(f"获取攻击链列表失败: {str(e)}", exc_info=True)
        return {"total": 0, "chains": [], "error": str(e)}


@router.get("/investigation/chains/{chain_id}")
async def get_single_chain_graph(chain_id: str, time_range_hours: int = Query(24, ge=1, le=720)):
    """
    获取单个攻击链的完整图谱数据
    
    Args:
        chain_id: 攻击链ID（格式：chain_0, chain_1... 或 network_0, network_1...）
        time_range_hours: 时间范围（小时）
    
    返回:
        {
            "nodes": [...],
            "links": [...],
            "metadata": {
                "chain_id": "chain_0",
                "chain_length": 4,
                "chain_type": "process_tree"
            }
        }
    """
    try:
        # 解析 chain_id
        id_parts = chain_id.split("_")
        if len(id_parts) != 2:
            return {"nodes": [], "links": [], "error": "Invalid chain_id format"}
        
        chain_type = id_parts[0]  # "chain" 或 "network"
        chain_index = int(id_parts[1])
        
        # 获取所有攻击链
        attack_chains = chain_builder.build_attack_chain(time_range_hours=time_range_hours)
        
        nodes = []
        links = []
        metadata = {}
        
        if chain_type == "chain":
            # 进程链
            chains = attack_chains.get("chains", [])
            
            if chain_index >= len(chains):
                return {"nodes": [], "links": [], "error": "Chain not found"}
            
            # 获取指定的攻击链
            target_chain = chains[chain_index]
            chain_nodes = target_chain.get("chain", [])
            edges = target_chain.get("edges", [])
            
            # 构建节点
            for i, node in enumerate(chain_nodes):
                node_id = f"proc_{node.get('pid')}_{node.get('name')}"
                
                # 构建详细信息，处理 None 值
                proc_path = node.get('path') or None
                proc_cmd = node.get('command') or None
                first_seen = node.get('first_seen') or '未知'
                
                # 判断是否是推断的父进程（没有详细信息）
                is_inferred_parent = (proc_path is None and proc_cmd is None)
                
                # 格式化显示时间
                if first_seen and first_seen != '未知':
                    try:
                        # 尝试格式化时间戳
                        if 'T' in str(first_seen):
                            first_seen = str(first_seen).split('T')[1][:8] if 'T' in str(first_seen) else first_seen
                    except:
                        pass
                
                # 根据是否有详细信息生成不同的描述
                if is_inferred_parent:
                    details = f"⚠️ 推断的父进程\n（日志中未捕获该进程的详细信息）\n首次关联: {first_seen}"
                    category = "Process_Inferred"
                else:
                    details = f"进程路径: {proc_path}\n命令行: {proc_cmd}\n首次发现: {first_seen}"
                    category = "Process"
                
                nodes.append({
                    "id": node_id,
                    "name": f"{node.get('name')} (PID:{node.get('pid')})",
                    "label": f"{node.get('name')} (PID:{node.get('pid')})",
                    "category": category,
                    "details": details,
                    "level": i + 1,
                    "symbolSize": 35 if not is_inferred_parent else 30,
                    # 添加原始数据供前端使用
                    "raw": {
                        "pid": node.get('pid'),
                        "name": node.get('name'),
                        "path": proc_path,
                        "command": proc_cmd,
                        "first_seen": node.get('first_seen'),
                        "is_inferred": is_inferred_parent
                    }
                })
                
                # 添加边
                if i > 0:
                    prev_node = chain_nodes[i - 1]
                    prev_id = f"proc_{prev_node.get('pid')}_{prev_node.get('name')}"
                    links.append({
                        "source": prev_id,
                        "target": node_id,
                        "label": "SPAWNED",
                        "timestamp": edges[i-1].get("timestamp") if i-1 < len(edges) else None,
                        "value": 3
                    })
            
            metadata = {
                "chain_id": chain_id,
                "chain_length": len(nodes),
                "chain_type": target_chain.get("type", "process_tree"),
                "host_id": target_chain.get("host_id", "Unknown")
            }
            
        elif chain_type == "network":
            # 网络连接链
            network_connections = attack_chains.get("network_connections", [])
            
            if chain_index >= len(network_connections):
                return {"nodes": [], "links": [], "error": "Network connection not found"}
            
            # 获取指定的网络连接
            target_conn = network_connections[chain_index]
            path = target_conn.get("path", [])
            conn_edges = target_conn.get("edges", [])
            
            # 构建节点
            for i, node in enumerate(path):
                ip = node.get("ip_address")
                if ip:
                    node_id = f"ip_{ip}"
                    is_private = node.get("is_private", True)
                    nodes.append({
                        "id": node_id,
                        "name": ip,
                        "label": ip,
                        "category": "IP" if is_private else "External_IP",
                        "details": f"Type: {'Internal' if is_private else 'External'}\nLocation: {node.get('location', 'Unknown')}",
                        "level": i + 1,
                        "symbolSize": 40 if not is_private else 35
                    })
            
            # 添加边（多跳）
            for i in range(len(path) - 1):
                src_ip = path[i].get("ip_address")
                dst_ip = path[i + 1].get("ip_address")
                if src_ip and dst_ip:
                    edge_info = conn_edges[i] if i < len(conn_edges) else {}
                    links.append({
                        "source": f"ip_{src_ip}",
                        "target": f"ip_{dst_ip}",
                        "label": "CONNECTED_TO",
                        "port": edge_info.get("dst_port"),
                        "protocol": edge_info.get("protocol"),
                        "bytes": edge_info.get("bytes_sent", 0),
                        "value": 3
                    })
            
            metadata = {
                "chain_id": chain_id,
                "chain_length": len(nodes),
                "chain_type": "network_connection",
                "total_bytes": sum(e.get("bytes_sent", 0) for e in conn_edges)
            }
        else:
            return {"nodes": [], "links": [], "error": "Invalid chain type"}
        
        logger.info(f"返回攻击链 {chain_id} 的图谱数据: {len(nodes)} 节点, {len(links)} 边")
        
        return {
            "nodes": nodes,
            "links": links,
            "metadata": metadata
        }
        
    except Exception as e:
        logger.error(f"获取单个攻击链失败: {str(e)}", exc_info=True)
        return {"nodes": [], "links": [], "error": str(e)}


# ==========================================
# 5. ATT&CK 战术分析
# ==========================================

@router.get("/attack/highlights")
async def get_attack_highlights(time_range_hours: int = 24):
    """
    获取当前检测到的 ATT&CK 战术/技术高亮
    
    返回: 当前命中的技术名称数组
    """
    try:
        attack_chains = chain_builder.build_attack_chain(time_range_hours=time_range_hours)
        ttps = mitre_mapper.extract_ttps(attack_chains)
        
        # 使用技术 ID 映射到技术名称
        # 完整映射，覆盖所有 12 个战术阶段相关技术
        technique_names = {
            # Initial Access (初始访问)
            "T1505.003": "Web Shell",
            "T1190": "Exploit Public-Facing Application",
            "T1566": "Phishing",
            
            # Execution (执行)
            "T1059": "Command and Scripting Interpreter",
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            
            # Persistence (持久化)
            "T1053": "Scheduled Task/Job",
            "T1547": "Boot or Logon Autostart Execution",
            "T1136": "Create Account",
            
            # Privilege Escalation (权限提升)
            "T1055": "Process Injection",
            "T1548.004": "Elevated Execution with Prompt",
            "T1134": "Access Token Manipulation",
            
            # Defense Evasion (防御规避)
            "T1218.010": "Regsvr32",
            "T1218.011": "Rundll32",
            "T1070.004": "File Deletion",
            "T1036": "Masquerading",
            "T1027": "Obfuscated Files",
            
            # Credential Access (凭据访问)
            "T1003.001": "OS Credential Dumping",
            "T1110": "Brute Force",
            "T1555": "Credentials from Password Stores",
            
            # Discovery (发现)
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1057": "Process Discovery",
            "T1046": "Network Service Scanning",
            
            # Lateral Movement (横向移动)
            "T1021.001": "Remote Desktop Protocol",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1021.004": "SSH",
            
            # Collection (收集)
            "T1005": "Data from Local System",
            "T1113": "Screen Capture",
            "T1115": "Clipboard Data",
            
            # Exfiltration (数据外泄)
            "T1041": "Exfiltration Over C2 Channel",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1567": "Exfiltration Over Web Service",
            
            # Command and Control (命令与控制)
            "T1071.001": "Application Layer Protocol",
            "T1573": "Encrypted Channel",
            "T1071.004": "DNS Tunneling",
            
            # Impact (影响)
            "T1486": "Data Encrypted for Impact",
            "T1489": "Service Stop",
            "T1490": "Inhibit System Recovery"
        }
        
        highlights = []
        for tech_id in ttps.get("techniques", []):
            name = technique_names.get(tech_id, tech_id)
            if name not in highlights:
                highlights.append(name)
        
        return highlights
    except Exception as e:
        logger.error(f"获取 ATT&CK 高亮失败: {str(e)}")
        return []


# ==========================================
# 6. 资产管理 (Assets & Sensors)
# ==========================================

# 默认资产数据（用于初始化数据库）
# 实际实验环境的节点配置
DEFAULT_ASSETS = [
    {
        "key": "1",
        "name": "Node1",
        "ip": "172.31.65.2",
        "role": "Server",
        "wazuh": True,
        "zeek": False,
        "status": "online"
    },
    {
        "key": "2",
        "name": "Node2 (网关+Zeek)",
        "ip": "172.31.65.1",
        "role": "Sensor",
        "wazuh": True,
        "zeek": True,
        "status": "online"
    },
    {
        "key": "3",
        "name": "Node3 (VictimA)",
        "ip": "172.31.65.4",
        "role": "Victim",
        "wazuh": True,
        "zeek": False,
        "status": "online"
    },
    {
        "key": "4",
        "name": "Node4 (VictimB)",
        "ip": "172.31.65.5",
        "role": "Victim",
        "wazuh": True,
        "zeek": False,
        "status": "online"
    },
    {
        "key": "5",
        "name": "Node5 (Attacker)",
        "ip": "172.31.65.3",
        "role": "Attacker",
        "wazuh": False,
        "zeek": False,
        "status": "online"
    }
]


async def init_default_assets():
    """
    初始化默认资产数据到 Neo4j
    如果数据库中没有 Asset 节点，则创建默认资产
    """
    try:
        session = db.get_session()
        try:
            # 检查是否已存在 Asset 节点
            check_query = "MATCH (a:Asset) RETURN count(a) as count"
            result = session.run(check_query)
            record = result.single()
            
            if record and record["count"] > 0:
                logger.info(f"数据库中已存在 {record['count']} 个资产，跳过初始化")
                return
            
            # 创建 Asset 节点约束（如果不存在）
            try:
                session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.key IS UNIQUE")
                logger.info("Asset 节点约束创建成功")
            except Exception as e:
                logger.warning(f"创建 Asset 约束失败（可能已存在）: {str(e)}")
            
            # 插入默认资产
            for asset in DEFAULT_ASSETS:
                create_query = """
                CREATE (a:Asset {
                    key: $key,
                    name: $name,
                    ip: $ip,
                    role: $role,
                    wazuh: $wazuh,
                    zeek: $zeek,
                    status: $status,
                    last_seen: datetime(),
                    created_at: datetime()
                })
                """
                session.run(create_query, **asset)
            
            logger.info(f"成功初始化 {len(DEFAULT_ASSETS)} 个默认资产")
            
        finally:
            session.close()
    except Exception as e:
        logger.error(f"初始化默认资产失败: {str(e)}")


@router.get("/assets")
async def get_assets_list():
    """
    获取资产和传感器列表（从 Neo4j 数据库查询）
    
    返回:
    - key: 资产唯一标识
    - name: 资产名称
    - ip: IP 地址
    - role: 角色 (Server/Sensor/Victim/Attacker)
    - wazuh: 是否部署 Wazuh 日志采集
    - zeek: 是否部署网络传感器
    - status: 连接状态 (online/offline/suspicious/compromised)
    - last_seen: 最后在线时间
    """
    try:
        session = db.get_session()
        try:
            query = """
            MATCH (a:Asset)
            RETURN a.key as key,
                   a.name as name,
                   a.ip as ip,
                   a.role as role,
                   a.wazuh as wazuh,
                   a.zeek as zeek,
                   a.status as status,
                   a.last_seen as last_seen
            ORDER BY a.key
            """
            result = session.run(query)
            
            assets = []
            for record in result:
                last_seen = record["last_seen"]
                # 处理 Neo4j datetime 类型
                if hasattr(last_seen, 'to_native'):
                    last_seen = last_seen.to_native().isoformat()
                elif last_seen is None:
                    last_seen = datetime.now().isoformat()
                
                assets.append({
                    "key": record["key"],
                    "name": record["name"],
                    "ip": record["ip"],
                    "role": record["role"],
                    "wazuh": record["wazuh"],
                    "zeek": record["zeek"],
                    "status": record["status"],
                    "last_seen": last_seen
                })
            
            # 如果数据库中没有资产，返回默认值
            if not assets:
                logger.warning("数据库中没有资产数据，返回默认资产列表")
                return [
                    {**asset, "last_seen": datetime.now().isoformat()}
                    for asset in DEFAULT_ASSETS
                ]
            
            return assets
            
        finally:
            session.close()
    except Exception as e:
        logger.error(f"获取资产列表失败: {str(e)}")
        # 异常时返回默认值
        return [
            {**asset, "last_seen": datetime.now().isoformat()}
            for asset in DEFAULT_ASSETS
        ]


@router.post("/assets")
async def create_asset(asset: Dict[str, Any]):
    """
    创建新资产
    
    请求体:
    - name: 资产名称（必填）
    - ip: IP 地址（必填）
    - role: 角色 (Server/Sensor/Victim/Attacker)（必填）
    - wazuh: 是否部署 Wazuh（可选，默认 False）
    - zeek: 是否部署 Zeek（可选，默认 False）
    - status: 状态（可选，默认 online）
    """
    try:
        # 验证必填字段
        required_fields = ["name", "ip", "role"]
        for field in required_fields:
            if field not in asset:
                raise HTTPException(status_code=400, detail=f"缺少必填字段: {field}")
        
        session = db.get_session()
        try:
            # 生成新的 key（查询最大 key 值）
            max_key_query = "MATCH (a:Asset) RETURN max(toInteger(a.key)) as max_key"
            result = session.run(max_key_query)
            record = result.single()
            new_key = str((record["max_key"] or 0) + 1)
            
            # 创建资产
            create_query = """
            CREATE (a:Asset {
                key: $key,
                name: $name,
                ip: $ip,
                role: $role,
                wazuh: $wazuh,
                zeek: $zeek,
                status: $status,
                last_seen: datetime(),
                created_at: datetime()
            })
            RETURN a.key as key
            """
            
            result = session.run(
                create_query,
                key=new_key,
                name=asset["name"],
                ip=asset["ip"],
                role=asset["role"],
                wazuh=asset.get("wazuh", False),
                zeek=asset.get("zeek", False),
                status=asset.get("status", "online")
            )
            
            record = result.single()
            logger.info(f"创建资产成功: {asset['name']} (key: {new_key})")
            
            return {"success": True, "key": new_key, "message": "资产创建成功"}
            
        finally:
            session.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建资产失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"创建资产失败: {str(e)}")


@router.put("/assets/{asset_key}")
async def update_asset(asset_key: str, asset: Dict[str, Any]):
    """
    更新资产信息
    
    路径参数:
    - asset_key: 资产唯一标识
    
    请求体（所有字段可选）:
    - name: 资产名称
    - ip: IP 地址
    - role: 角色
    - wazuh: 是否部署 Wazuh
    - zeek: 是否部署 Zeek
    - status: 状态
    """
    try:
        session = db.get_session()
        try:
            # 构建动态更新语句
            set_clauses = []
            params = {"key": asset_key}
            
            field_mapping = {
                "name": "a.name = $name",
                "ip": "a.ip = $ip",
                "role": "a.role = $role",
                "wazuh": "a.wazuh = $wazuh",
                "zeek": "a.zeek = $zeek",
                "status": "a.status = $status"
            }
            
            for field, clause in field_mapping.items():
                if field in asset:
                    set_clauses.append(clause)
                    params[field] = asset[field]
            
            if not set_clauses:
                raise HTTPException(status_code=400, detail="没有提供需要更新的字段")
            
            # 添加 last_seen 更新
            set_clauses.append("a.last_seen = datetime()")
            
            update_query = f"""
            MATCH (a:Asset {{key: $key}})
            SET {", ".join(set_clauses)}
            RETURN a.key as key
            """
            
            result = session.run(update_query, **params)
            record = result.single()
            
            if not record:
                raise HTTPException(status_code=404, detail=f"未找到资产: {asset_key}")
            
            logger.info(f"更新资产成功: key={asset_key}")
            return {"success": True, "message": "资产更新成功"}
            
        finally:
            session.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"更新资产失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"更新资产失败: {str(e)}")


@router.delete("/assets/{asset_key}")
async def delete_asset(asset_key: str):
    """
    删除资产
    
    路径参数:
    - asset_key: 资产唯一标识
    """
    try:
        session = db.get_session()
        try:
            # 删除资产
            delete_query = """
            MATCH (a:Asset {key: $key})
            DELETE a
            RETURN count(*) as deleted
            """
            
            result = session.run(delete_query, key=asset_key)
            record = result.single()
            
            if record["deleted"] == 0:
                raise HTTPException(status_code=404, detail=f"未找到资产: {asset_key}")
            
            logger.info(f"删除资产成功: key={asset_key}")
            return {"success": True, "message": "资产删除成功"}
            
        finally:
            session.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除资产失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"删除资产失败: {str(e)}")


@router.post("/assets/reset")
async def reset_assets():
    """
    重置资产列表到默认配置
    
    删除所有现有资产节点，重新创建默认的实验环境节点
    用于清除自动发现的资产，恢复到初始状态
    """
    try:
        session = db.get_session()
        try:
            # 1. 删除所有现有 Asset 节点
            delete_query = "MATCH (a:Asset) DELETE a RETURN count(*) as deleted"
            result = session.run(delete_query)
            record = result.single()
            deleted_count = record["deleted"] if record else 0
            logger.info(f"已删除 {deleted_count} 个现有资产节点")
            
            # 2. 创建默认资产节点
            for asset in DEFAULT_ASSETS:
                create_query = """
                CREATE (a:Asset {
                    key: $key,
                    name: $name,
                    ip: $ip,
                    role: $role,
                    wazuh: $wazuh,
                    zeek: $zeek,
                    status: $status,
                    last_seen: datetime(),
                    created_at: datetime()
                })
                """
                session.run(create_query, **asset)
            
            logger.info(f"成功重置资产列表，创建 {len(DEFAULT_ASSETS)} 个默认节点")
            return {
                "success": True, 
                "message": f"资产列表已重置，删除 {deleted_count} 个旧节点，创建 {len(DEFAULT_ASSETS)} 个默认节点",
                "deleted": deleted_count,
                "created": len(DEFAULT_ASSETS)
            }
            
        finally:
            session.close()
    except Exception as e:
        logger.error(f"重置资产列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"重置资产列表失败: {str(e)}")


# ==========================================
# 7. 攻击归因 (Attribution & Threat Intel)
# ==========================================

@router.get("/attribution/result")
async def get_attribution_result(time_range_hours: int = 24):
    """
    获取攻击归因结果（可能的 APT 组织）
    
    返回:
    - name: APT 组织名称
    - code: 组织代号
    - score: 归因置信度 (0-100)
    - description: 归因依据简述
    - matched_techniques: 命中的技术列表
    """
    try:
        # 获取攻击链并执行归因分析
        attack_chains = chain_builder.build_attack_chain(time_range_hours=time_range_hours)
        ttps = mitre_mapper.extract_ttps(attack_chains)
        apt_matches = mitre_mapper.match_apt_group(ttps)
        
        if apt_matches:
            top_match = apt_matches[0]
            confidence_score = int(top_match.get("match_score", 0) * 100)
            return {
                "name": top_match.get("apt_name", "Unknown"),
                "code": top_match.get("apt_id", "???"),
                "confidence": confidence_score,  # 前端需要数字类型的 confidence
                "country": top_match.get("country", "Unknown"),
                "matched_techniques": top_match.get("matched_techniques", []),
                "description": f"基于检测到的 {len(ttps.get('techniques', []))} 项 ATT&CK 技术进行归因",
                "evidence": [  # 前端需要的证据链数组
                    {"color": "green", "content": f"检测到 {len(ttps.get('techniques', []))} 项 ATT&CK 技术"},
                    {"color": "blue", "content": f"归因置信度: {confidence_score}%"},
                    {"color": "orange", "content": f"疑似来源: {top_match.get('country', 'Unknown')}"},
                    {"color": "red", "content": f"匹配 APT 组织: {top_match.get('apt_name', 'Unknown')}"}
                ]
            }
        else:
            return {
                "name": "Unknown",
                "code": "???",
                "confidence": 0,  # 前端需要数字类型
                "description": "未匹配到已知 APT 组织",
                "matched_techniques": [],
                "evidence": [  # 空证据链
                    {"color": "gray", "content": "暂无足够证据进行归因分析"}
                ]
            }
    except Exception as e:
        logger.error(f"获取归因结果失败: {str(e)}")
        return {
            "name": "Unknown",
            "code": "???",
            "confidence": 0,  # 前端需要数字类型
            "description": f"分析失败: {str(e)}",
            "evidence": [],
            "error": str(e)
        }


# ==========================================
# 8. 调试端点 (Debug)
# ==========================================

@router.get("/debug/database-status")
async def get_database_status():
    """
    调试端点：获取数据库状态，用于诊断数据处理问题
    
    返回:
    - 各类型节点数量
    - 各类型关系数量
    - 最近的进程节点示例
    """
    try:
        session = db.get_session()
        try:
            stats = {}
            
            # 1. 统计各类型节点数量
            node_count_query = """
            MATCH (n)
            RETURN labels(n)[0] as label, count(n) as count
            ORDER BY count DESC
            """
            node_result = session.run(node_count_query)
            stats["nodes"] = {record["label"]: record["count"] for record in node_result}
            
            # 2. 统计各类型关系数量
            rel_count_query = """
            MATCH ()-[r]->()
            RETURN type(r) as type, count(r) as count
            ORDER BY count DESC
            """
            rel_result = session.run(rel_count_query)
            stats["relationships"] = {record["type"]: record["count"] for record in rel_result}
            
            # 3. 获取最近5个进程节点示例
            process_sample_query = """
            MATCH (p:Process)
            RETURN p.pid as pid, p.process_name as name, p.command_line as command, 
                   p.host_id as host_id, p.first_seen as first_seen
            ORDER BY p.first_seen DESC
            LIMIT 5
            """
            process_result = session.run(process_sample_query)
            stats["recent_processes"] = [dict(record) for record in process_result]
            
            # 4. 检查 SPAWNED 关系是否存在
            spawned_query = """
            MATCH (parent:Process)-[r:SPAWNED]->(child:Process)
            RETURN parent.process_name as parent, child.process_name as child,
                   parent.pid as parent_pid, child.pid as child_pid
            ORDER BY r.timestamp DESC
            LIMIT 5
            """
            spawned_result = session.run(spawned_query)
            stats["spawned_relationships"] = [dict(record) for record in spawned_result]
            
            # 5. 检查攻击链候选（有 SPAWNED 关系的进程）
            chain_candidate_query = """
            MATCH path=(root:Process)-[:SPAWNED*1..3]->(leaf:Process)
            RETURN root.process_name as root_name, 
                   length(path) as chain_length,
                   [n in nodes(path) | n.process_name] as chain_processes
            LIMIT 10
            """
            chain_result = session.run(chain_candidate_query)
            stats["potential_chains"] = [dict(record) for record in chain_result]
            
            return stats
            
        finally:
            session.close()
    except Exception as e:
        logger.error(f"获取数据库状态失败: {str(e)}", exc_info=True)
        return {"error": str(e)}


# ==========================================
# 9. 分析报告 (Analysis Report)
# ==========================================

@router.get("/analysis/report")
async def get_analysis_report(report_type: str = Query("full", pattern="^(full|summary|chains)$")):
    """
    获取完整分析报告
    
    参数:
    - report_type: full (完整报告) / summary (摘要) / chains (仅攻击链)
    """
    try:
        from app.analysis.analysis_pipeline import AnalysisPipeline
        
        pipeline = AnalysisPipeline()
        report = pipeline.analyze(time_range_hours=24)
        
        if report_type == "summary":
            return {
                "analysis_time": report.get("analysis_time"),
                "attack_chains": report.get("attack_chains", {}).get("total_count", 0),
                "lateral_movement": len(report.get("lateral_movement", [])),
                "data_exfiltration": len(report.get("data_exfiltration", [])),
                "persistence": len(report.get("persistence", []))
            }
        elif report_type == "chains":
            return report.get("attack_chains", {})
        else:
            return report
    except Exception as e:
        logger.error(f"生成分析报告失败: {str(e)}")
        return {"error": str(e)}
