"""
攻击链构建器 - 基于图数据库的时空关联分析
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
        """查找所有进程链（父子关系）"""
        query = """
        MATCH (parent:Process)-[r:SPAWNED]->(child:Process)
        WHERE parent.process_name IN ['cmd.exe', 'powershell.exe', 'w3wp.exe', 'nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
           OR child.process_name IN ['cmd.exe', 'powershell.exe', 'nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
        RETURN 
            parent.process_id as parent_pid,
            parent.process_name as parent_name,
            parent.command_line as parent_cmd,
            parent.start_time as parent_time,
            child.process_id as child_pid,
            child.process_name as child_name,
            child.command_line as child_cmd,
            child.start_time as child_time,
            parent.host_id as host_id
        ORDER BY parent.start_time DESC
        LIMIT 100
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            chains = []
            
            for record in results:
                chains.append({
                    "host_id": record.get("host_id"),
                    "parent": {
                        "pid": record.get("parent_pid"),
                        "name": record.get("parent_name"),
                        "command": record.get("parent_cmd"),
                        "time": record.get("parent_time")
                    },
                    "child": {
                        "pid": record.get("child_pid"),
                        "name": record.get("child_name"),
                        "command": record.get("child_cmd"),
                        "time": record.get("child_time")
                    },
                    "type": "process_tree"
                })
            
            return chains
        except Exception as e:
            logger.error(f"查询进程链失败: {str(e)}", exc_info=True)
            return []

    def _find_network_connections(self) -> List[Dict]:
        """查找网络连接（重点关注外部IP）"""
        query = """
        MATCH (src:IP)-[conn:CONNECTED_TO]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address IN ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        RETURN 
            src.ip_address as src_ip,
            dst.ip_address as dst_ip,
            conn.dst_port as dst_port,
            conn.protocol as protocol,
            conn.timestamp as timestamp,
            conn.bytes_sent as bytes_sent,
            conn.bytes_received as bytes_received
        ORDER BY conn.timestamp DESC
        LIMIT 100
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            connections = []
            
            for record in results:
                connections.append({
                    "src_ip": record.get("src_ip"),
                    "dst_ip": record.get("dst_ip"),
                    "dst_port": record.get("dst_port"),
                    "protocol": record.get("protocol"),
                    "timestamp": record.get("timestamp"),
                    "bytes_sent": record.get("bytes_sent"),
                    "bytes_received": record.get("bytes_received"),
                    "type": "network_connection"
                })
            
            return connections
        except Exception as e:
            logger.error(f"查询网络连接失败: {str(e)}", exc_info=True)
            return []

    def _extract_suspicious_ips(self, connections: List[Dict]) -> List[str]:
        """提取可疑IP"""
        ips = set()
        for conn in connections:
            dst_ip = conn.get("dst_ip")
            # 排除常见的公共服务IP
            if dst_ip and not dst_ip.startswith("192.168."):
                ips.add(dst_ip)
        return list(ips)

    def _extract_suspicious_processes(self, chains: List[Dict]) -> List[Dict]:
        """提取可疑进程"""
        suspicious = []
        suspicious_names = ['nc.exe', 'mimikatz.exe', 'psexec.exe', 'regsvr32.exe']
        
        for chain in chains:
            parent = chain.get("parent", {})
            child = chain.get("child", {})
            
            if parent.get("name") in suspicious_names:
                suspicious.append(parent)
            if child.get("name") in suspicious_names:
                suspicious.append(child)
        
        return suspicious

    def find_lateral_movement(self, time_range_hours: int = 24) -> List[Dict]:
        """检测横向移动 - SMB/RDP/SSH 连接到内网其他主机"""
        query = """
        MATCH (src:IP)-[conn:CONNECTED_TO]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND dst.ip_address =~ '^192\\.168\\..*'
          AND src.ip_address <> dst.ip_address
          AND conn.dst_port IN [445, 3389, 22, 135, 139]
        RETURN 
            src.ip_address as src_ip,
            dst.ip_address as dst_ip,
            conn.dst_port as port,
            conn.protocol as protocol,
            conn.timestamp as timestamp
        ORDER BY conn.timestamp DESC
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            movements = []
            
            for record in results:
                port = record.get("port")
                service = {445: "SMB", 3389: "RDP", 22: "SSH", 135: "RPC", 139: "NetBIOS"}.get(port, "Unknown")
                
                movements.append({
                    "src_ip": record.get("src_ip"),
                    "dst_ip": record.get("dst_ip"),
                    "port": port,
                    "service": service,
                    "protocol": record.get("protocol"),
                    "timestamp": record.get("timestamp"),
                    "severity": "high"
                })
            
            logger.info(f"检测到 {len(movements)} 个横向移动事件")
            return movements
        except Exception as e:
            logger.error(f"横向移动检测失败: {str(e)}", exc_info=True)
            return []

    def find_data_exfiltration(self) -> List[Dict]:
        """检测数据外泄 - 大流量传输到外部IP"""
        query = """
        MATCH (src:IP)-[conn:CONNECTED_TO]->(dst:IP)
        WHERE src.ip_address =~ '^192\\.168\\..*'
          AND NOT dst.ip_address =~ '^192\\.168\\..*'
          AND conn.bytes_sent > 10485760
        RETURN 
            src.ip_address as src_ip,
            dst.ip_address as dst_ip,
            conn.dst_port as port,
            conn.bytes_sent as bytes_sent,
            conn.timestamp as timestamp
        ORDER BY conn.bytes_sent DESC
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            exfiltrations = []
            
            for record in results:
                bytes_sent = record.get("bytes_sent", 0)
                size_mb = round(bytes_sent / 1048576, 2)
                
                exfiltrations.append({
                    "src_ip": record.get("src_ip"),
                    "dst_ip": record.get("dst_ip"),
                    "port": record.get("port"),
                    "bytes_sent": bytes_sent,
                    "size_mb": size_mb,
                    "timestamp": record.get("timestamp"),
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
            p.process_id as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.start_time as timestamp
        ORDER BY p.start_time DESC
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
