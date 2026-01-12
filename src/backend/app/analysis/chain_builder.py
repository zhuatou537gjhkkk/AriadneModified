"""
攻击链构建器模块

基于图数据库进行时空关联分析，构建可能的攻击链（进程父子关系、网络连接等），
并提取可疑 IP 与可疑进程集合。提供用于横向移动、数据外泄、持久化检测的查询封装。

主要类与方法：
- `ChainBuilder.build_attack_chain(...)`：构建攻击链主流程，整合进程链与网络连接。
- `_find_process_chains` / `_find_network_connections`：具体 Cypher 查询及结果解析。
- `_extract_suspicious_ips` / `_extract_suspicious_processes`：从查询结果提取可疑指标。
- `find_lateral_movement` / `find_data_exfiltration` / `find_persistence_mechanisms`：常用分析查询。
"""

import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.etl.graph_sync import GraphSync

logger = logging.getLogger("FusionTrace.ChainBuilder")


class ChainBuilder:
    """攻击链构建器"""

    def __init__(self, graph_sync: GraphSync = None):
        self.graph_sync = graph_sync or GraphSync()

    def build_attack_chain(
        self,
        suspicious_ip: str = None,
        suspicious_process: str = None,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """构建攻击链 - 查找进程树和网络连接"""
        logger.info(f"开始构建攻击链 (时间范围: {time_range_hours}小时)...")
        
        # 查找所有进程链（重点关注可疑进程）
        process_chains = self._find_process_chains()
        
        # 查找网络连接
        network_connections = self._find_network_connections()
        
        logger.info(f"找到 {len(process_chains)} 个进程链, {len(network_connections)} 个网络连接")
        
        return {
            "total_count": len(process_chains),
            "chains": process_chains,
            "network_connections": network_connections,
            "suspicious_ips": self._extract_suspicious_ips(network_connections),
            "suspicious_processes": self._extract_suspicious_processes(process_chains)
        }

    def _find_process_chains(self) -> List[Dict]:
        """
        查找所有进程链（可变长度的父子关系，最深5层）。
        利用边属性中的timestamp进行事件排序和去重。
        """
        query = """
        MATCH path=(root:Process)-[edges:SPAWNED*1..5]->(leaf:Process)
        WHERE root.process_name IN ['cmd.exe', 'powershell.exe', 'w3wp.exe', 'nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
           OR leaf.process_name IN ['cmd.exe', 'powershell.exe', 'nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
        RETURN 
            root.host_id as host_id,
            nodes(path) as path_nodes,
            [rel in relationships(path) | {type: type(rel), timestamp: rel.timestamp, event_id: rel.event_id}] as path_edges
        ORDER BY root.first_seen DESC
        LIMIT 100
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            chains = []
            
            for record in results:
                host_id = record.get("host_id")
                path_nodes = record.get("path_nodes", [])
                path_edges = record.get("path_edges", [])
                
                # 如果获取不到完整路径节点，则跳过
                if not path_nodes or len(path_nodes) < 2:
                    continue
                
                # 构建多节点链：[{node1}, {node2}, ..., {nodeN}]
                chain_nodes = []
                for node in path_nodes:
                    chain_nodes.append({
                        "pid": node.get("pid"),
                        "name": node.get("process_name"),
                        "command": node.get("command_line"),
                        "first_seen": node.get("first_seen"),  # 使用first_seen而非start_time
                        "path": node.get("process_path"),
                        "lifecycle_version": node.get("lifecycle_version", 1)  # PID重用版本号
                    })
                
                # 构建关系列表，按timestamp排序确保事件顺序正确
                edges = []
                if path_edges:
                    for rel in path_edges:
                        edges.append({
                            "type": rel.get("type", "SPAWNED") if isinstance(rel, dict) else "SPAWNED",
                            "timestamp": rel.get("timestamp") if isinstance(rel, dict) else None,
                            "event_id": rel.get("event_id") if isinstance(rel, dict) else None
                        })
                    # 按timestamp排序关系，确保事件顺序
                    edges.sort(key=lambda e: e.get("timestamp") or "")
                
                chains.append({
                    "host_id": host_id,
                    "chain": chain_nodes,  # 多节点链数组
                    "edges": edges,        # 关系数组（按时间排序）
                    "chain_length": len(chain_nodes),
                    "type": "process_tree"
                })
            
            return chains
        except Exception as e:
            logger.error(f"查询进程链失败: {str(e)}", exc_info=True)
            return []

    def _find_network_connections(self) -> List[Dict]:
        """
        查找网络连接（可变长度的网络路径，最深3跳）。
        利用边属性中的timestamp进行事件时间排序。
        """
        query = """
        MATCH path=(src:IP)-[edges:CONNECTED_TO*1..3]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address IN ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        RETURN 
            nodes(path) as path_nodes,
            [rel in relationships(path) | {type: type(rel), timestamp: rel.timestamp, dst_port: rel.dst_port, protocol: rel.protocol, bytes_sent: rel.bytes_sent, bytes_received: rel.bytes_received}] as path_edges
        ORDER BY src.ip_address DESC
        LIMIT 100
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            connections = []
            
            for record in results:
                path_nodes = record.get("path_nodes", [])
                path_edges = record.get("path_edges", [])
                
                # 如果获取不到完整路径节点，则跳过
                if not path_nodes or len(path_nodes) < 2:
                    continue
                
                # 构建多节点网络路径：[{ip1}, {ip2}, ..., {ipN}]
                network_nodes = []
                for node in path_nodes:
                    network_nodes.append({
                        "ip_address": node.get("ip_address"),
                        "is_private": node.get("is_private"),
                        "type": node.get("type", "IP")
                    })
                
                # 构建网络连接关系列表，按timestamp排序
                edges = []
                if path_edges:
                    for rel in path_edges:
                        edges.append({
                            "type": rel.get("type", "CONNECTED_TO") if isinstance(rel, dict) else "CONNECTED_TO",
                            "dst_port": rel.get("dst_port") if isinstance(rel, dict) else None,
                            "protocol": rel.get("protocol") if isinstance(rel, dict) else None,
                            "timestamp": rel.get("timestamp") if isinstance(rel, dict) else None,
                            "bytes_sent": rel.get("bytes_sent") if isinstance(rel, dict) else None,
                            "bytes_received": rel.get("bytes_received") if isinstance(rel, dict) else None
                        })
                    # 按timestamp排序关系，确保事件顺序
                    edges.sort(key=lambda e: e.get("timestamp") or "")
                
                connections.append({
                    "path": network_nodes,        # 多节点网络路径
                    "edges": edges,               # 连接关系数组（按时间排序）
                    "path_length": len(network_nodes),
                    "src_ip": network_nodes[0].get("ip_address"),
                    "dst_ip": network_nodes[-1].get("ip_address"),
                    "type": "network_connection"
                })
            
            return connections
        except Exception as e:
            logger.error(f"查询网络连接失败: {str(e)}", exc_info=True)
            return []

    def _extract_suspicious_ips(self, connections: List[Dict]) -> List[str]:
        """提取可疑IP（支持多节点网络路径）"""
        ips = set()
        for conn in connections:
            # 支持新格式（多节点网络路径）
            path = conn.get("path", [])
            if path:
                # 新格式：从 path 中提取所有 IP
                for node in path:
                    ip = node.get("ip_address")
                    if ip and not ip.startswith("192.168."):
                        ips.add(ip)
            else:
                # 向后兼容旧格式（单一连接对）
                dst_ip = conn.get("dst_ip")
                if dst_ip and not dst_ip.startswith("192.168."):
                    ips.add(dst_ip)
        return list(ips)

    def _extract_suspicious_processes(self, chains: List[Dict]) -> List[Dict]:
        """提取可疑进程（支持多节点链）"""
        suspicious = []
        seen = set()
        suspicious_names = ['nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
        
        for chain in chains:
            # 支持新格式（多节点链）
            chain_nodes = chain.get("chain", [])
            if chain_nodes:
                for node in chain_nodes:
                    if not node:  # 跳过None节点
                        continue
                    proc_name = node.get("name") or ""
                    if proc_name and proc_name.lower() in suspicious_names:
                        # 去重避免重复
                        proc_id = (node.get("pid"), node.get("name"))
                        if proc_id not in seen:
                            suspicious.append(node)
                            seen.add(proc_id)
            else:
                # 向后兼容旧格式（两节点链）
                parent = chain.get("parent", {})
                child = chain.get("child", {})
                
                if parent and parent.get("name") and parent.get("name") in suspicious_names:
                    proc_id = (parent.get("pid"), parent.get("name"))
                    if proc_id not in seen:
                        suspicious.append(parent)
                        seen.add(proc_id)
                if child and child.get("name") and child.get("name") in suspicious_names:
                    proc_id = (child.get("pid"), child.get("name"))
                    if proc_id not in seen:
                        suspicious.append(child)
                        seen.add(proc_id)
        
        return suspicious

    def find_lateral_movement(self, time_range_hours: int = 24) -> List[Dict]:
        """检测横向移动 - SMB/RDP/SSH 连接到内网其他主机（可变长度路径）"""
        query = """
        MATCH path=(src:IP)-[:CONNECTED_TO*1..3]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND dst.ip_address =~ '^192\\.168\\..*'
          AND src.ip_address <> dst.ip_address
        WITH path, [rel in relationships(path) | {type: type(rel), dst_port: rel.dst_port, protocol: rel.protocol, timestamp: rel.timestamp}] as rels
        WHERE ANY(rel IN rels WHERE rel.dst_port IN [445, 3389, 22, 135, 139])
        RETURN 
            nodes(path) as path_nodes,
            [rel in relationships(path) | {type: type(rel), dst_port: rel.dst_port, protocol: rel.protocol, timestamp: rel.timestamp}] as path_rels
        ORDER BY path_nodes[0].ip_address DESC
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            movements = []
            
            for record in results:
                path_nodes = record.get("path_nodes", [])
                path_rels = record.get("path_rels", [])
                
                if not path_nodes or len(path_nodes) < 2:
                    continue
                
                # 构建网络路径
                network_path = []
                for node in path_nodes:
                    network_path.append({
                        "ip_address": node.get("ip_address"),
                        "is_private": node.get("is_private")
                    })
                
                # 提取关键连接特征（最后一跳）
                last_rel = path_rels[-1] if path_rels else {}
                port = last_rel.get("dst_port", 0) if isinstance(last_rel, dict) else 0
                service = {445: "SMB", 3389: "RDP", 22: "SSH", 135: "RPC", 139: "NetBIOS"}.get(port, "Unknown")
                
                movements.append({
                    "path": network_path,
                    "path_length": len(network_path),
                    "src_ip": network_path[0].get("ip_address"),
                    "dst_ip": network_path[-1].get("ip_address"),
                    "last_port": port,
                    "last_service": service,
                    "last_protocol": last_rel.get("protocol"),
                    "timestamp": last_rel.get("timestamp"),
                    "severity": "high"
                })
            
            logger.info(f"检测到 {len(movements)} 个横向移动事件")
            return movements
        except Exception as e:
            logger.error(f"横向移动检测失败: {str(e)}", exc_info=True)
            return []

    def find_data_exfiltration(self) -> List[Dict]:
        """检测数据外泄 - 大流量传输到外部IP（支持多节点路径）"""
        query = """
        MATCH path=(src:IP)-[:CONNECTED_TO*1..3]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address =~ '^192\\.168\\..*'
        WITH path, [rel in relationships(path) | {bytes_sent: rel.bytes_sent, timestamp: rel.timestamp, protocol: rel.protocol, dst_port: rel.dst_port}] as rels
        WHERE ANY(rel IN rels WHERE rel.bytes_sent > 10485760)
        RETURN 
            nodes(path) as path_nodes,
            [rel in relationships(path) | {bytes_sent: rel.bytes_sent, timestamp: rel.timestamp, protocol: rel.protocol, dst_port: rel.dst_port}] as path_rels,
            reduce(total_bytes = 0, rel IN rels | total_bytes + rel.bytes_sent) as total_bytes
        ORDER BY total_bytes DESC
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            exfiltrations = []
            
            for record in results:
                path_nodes = record.get("path_nodes", [])
                path_rels = record.get("path_rels", [])
                total_bytes = record.get("total_bytes", 0)
                
                if not path_nodes or len(path_nodes) < 2:
                    continue
                
                # 构建网络路径
                network_path = []
                for node in path_nodes:
                    network_path.append({
                        "ip_address": node.get("ip_address"),
                        "is_private": node.get("is_private")
                    })
                
                size_mb = round(total_bytes / 1048576, 2)
                last_timestamp = None
                if path_rels and len(path_rels) > 0:
                    last_rel = path_rels[-1]
                    if isinstance(last_rel, dict):
                        last_timestamp = last_rel.get("timestamp")
                
                exfiltrations.append({
                    "path": network_path,
                    "path_length": len(network_path),
                    "src_ip": network_path[0].get("ip_address"),
                    "dst_ip": network_path[-1].get("ip_address"),
                    "total_bytes_sent": total_bytes,
                    "size_mb": size_mb,
                    "edge_count": len(path_rels) if path_rels else 0,
                    "last_timestamp": last_timestamp,
                    "severity": "critical" if size_mb > 50 else "high"
                })
            
            logger.info(f"检测到 {len(exfiltrations)} 个数据外泄事件")
            return exfiltrations
        except Exception as e:
            logger.error(f"数据外泄检测失败: {str(e)}", exc_info=True)
            return []

    def find_persistence_mechanisms(self) -> List[Dict]:
        """检测持久化机制 - 注册表/启动项修改"""
        query = """
        MATCH (p:Process)
        WHERE p.command_line CONTAINS 'reg add'
           OR p.command_line CONTAINS 'schtasks'
           OR p.command_line CONTAINS 'CurrentVersion\\Run'
           OR p.process_name IN ['reg.exe', 'schtasks.exe']
        RETURN 
            p.pid as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.first_seen as timestamp
        ORDER BY p.first_seen DESC
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            persistence = []
            
            for record in results:
                persistence.append({
                    "pid": record.get("pid"),
                    "process_name": record.get("name"),
                    "command_line": record.get("command"),
                    "host_id": record.get("host_id"),
                    "timestamp": record.get("timestamp"),
                    "mechanism": self._identify_persistence_type(record.get("command", "")),
                    "severity": "high"
                })
            
            logger.info(f"检测到 {len(persistence)} 个持久化事件")
            return persistence
        except Exception as e:
            logger.error(f"持久化检测失败: {str(e)}", exc_info=True)
            return []

    def _identify_persistence_type(self, command: str) -> str:
        """识别持久化类型"""
        if "CurrentVersion\\Run" in command or "reg add" in command:
            return "Registry Run Key"
        elif "schtasks" in command:
            return "Scheduled Task"
        elif "startup" in command.lower():
            return "Startup Folder"
        else:
            return "Unknown"

    def filter_chains_by_time_range(
        self, 
        chains: List[Dict], 
        start_time: datetime = None, 
        end_time: datetime = None,
        detect_pid_reuse: bool = True
    ) -> List[Dict]:
        """
        按时间范围过滤进程链，支持PID重用检测和生命周期版本过滤
        
        Args:
            chains: ChainBuilder返回的进程链列表
            start_time: 查询时间范围的开始（None表示不限制）
            end_time: 查询时间范围的结束（None表示不限制）
            detect_pid_reuse: 是否启用PID重用检测（基于lifecycle_version）
        
        Returns:
            List[Dict]: 过滤后的进程链列表
            
        使用示例：
            chains = builder.find_process_chains()
            # 过滤最近24小时内的链，启用PID重用检测
            filtered = builder.filter_chains_by_time_range(
                chains,
                start_time=datetime.now() - timedelta(hours=24),
                detect_pid_reuse=True
            )
        """
        if not chains:
            return []
        
        filtered_chains = []
        
        for chain in chains:
            chain_nodes = chain.get("chain", [])
            chain_edges = chain.get("edges", [])
            
            if not chain_nodes:
                continue
            
            # 检查链中的所有节点是否在时间范围内
            valid_chain = True
            
            for i, node in enumerate(chain_nodes):
                node_time = node.get("first_seen")
                if not node_time:
                    continue
                
                # 尝试解析ISO格式的时间戳
                try:
                    if isinstance(node_time, str):
                        node_datetime = datetime.fromisoformat(node_time.replace('Z', '+00:00'))
                    else:
                        node_datetime = node_time
                except:
                    logger.warning(f"无法解析节点时间戳: {node_time}")
                    node_datetime = datetime.now()
                
                # 时间范围检查
                if start_time and node_datetime < start_time:
                    valid_chain = False
                    break
                if end_time and node_datetime > end_time:
                    valid_chain = False
                    break
                
                # PID重用检测：相邻节点的lifecycle_version不应该相差太大
                if detect_pid_reuse and i > 0:
                    prev_node = chain_nodes[i - 1]
                    prev_version = prev_node.get("lifecycle_version", 1)
                    curr_version = node.get("lifecycle_version", 1)
                    
                    # 如果版本跳跃超过2，说明可能是PID被重用，链可能不连贯
                    if abs(curr_version - prev_version) > 2:
                        logger.warning(
                            f"检测到PID重用迹象: {prev_node.get('pid')} "
                            f"(v{prev_version}) -> {node.get('pid')} (v{curr_version})"
                        )
                        # 可选：标记链但不过滤
                        chain["pid_reuse_detected"] = True
            
            if valid_chain:
                filtered_chains.append(chain)
        
        logger.info(f"过滤后保留 {len(filtered_chains)}/{len(chains)} 个进程链")
        return filtered_chains


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    builder = ChainBuilder()
    
    print("=" * 70)
    print("测试攻击链构建")
    print("=" * 70)
    
    # 测试攻击链构建
    chains = builder.build_attack_chain()
    print(f"\n攻击链: {chains['total_count']} 条")
    
    # 测试横向移动
    lateral = builder.find_lateral_movement()
    print(f"横向移动: {len(lateral)} 个")
    
    # 测试数据外泄
    exfil = builder.find_data_exfiltration()
    print(f"数据外泄: {len(exfil)} 个")
    
    # 测试持久化
    persist = builder.find_persistence_mechanisms()
    print(f"持久化: {len(persist)} 个")
