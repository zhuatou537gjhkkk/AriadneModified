import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import hashlib

logger = logging.getLogger("FusionTrace.NetworkParser")


class NetworkParser:
    """
    网络数据解析器 (ETL - Transform)
    
    职责:
    1. 重建网络会话（Network Session）- 基于五元组
    2. 提取 IP 节点
    3. 提取 Domain 节点
    4. 提取 Connection 关系
    5. 关联进程与网络行为（用于时空关联）
    
    输出:
    - nodes: 节点列表 [{type, properties}, ...]
    - edges: 关系列表 [{type, source, target, properties}, ...]
    """

    def __init__(self):
        self.parsed_count = 0

    def parse(self, normalized_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        解析标准化后的网络事件
        
        Args:
            normalized_data: normalizer 输出的标准化数据
        
        Returns:
            {
                "nodes": [...],  # 节点列表
                "edges": [...],  # 关系列表
                "metadata": {...}  # 元数据
            }
        """
        try:
            # 只处理网络相关事件
            category = normalized_data.get("event_category")
            if category != "network":
                return None

            event_type = normalized_data.get("event_type")
            nodes = []
            edges = []

            # 根据事件类型分发处理
            if event_type in ["conn", "network_connect"]:
                # 网络连接事件
                conn_nodes, conn_edges = self._parse_connection(normalized_data)
                nodes.extend(conn_nodes)
                edges.extend(conn_edges)

            elif event_type == "dns":
                # DNS 查询事件
                dns_nodes, dns_edges = self._parse_dns(normalized_data)
                nodes.extend(dns_nodes)
                edges.extend(dns_edges)

            elif event_type == "http":
                # HTTP 请求事件
                http_nodes, http_edges = self._parse_http(normalized_data)
                nodes.extend(http_nodes)
                edges.extend(http_edges)

            if not nodes:
                return None

            self.parsed_count += 1
            if self.parsed_count % 1000 == 0:
                logger.info(f"[NetworkParser] 已解析 {self.parsed_count} 条网络事件")

            return {
                "nodes": nodes,
                "edges": edges,
                "metadata": {
                    "event_id": normalized_data.get("event_id"),
                    "timestamp": normalized_data.get("timestamp"),
                    "source": normalized_data.get("source"),
                }
            }

        except Exception as e:
            logger.error(f"网络事件解析异常: {str(e)}", exc_info=True)
            return None

    def _parse_connection(self, data: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        解析网络连接事件
        
        生成:
        - IP 节点（源IP、目标IP）
        - Host 节点（主机）
        - Process 节点（发起连接的进程，如果有）
        - CONNECTED_TO 边（源IP -> 目标IP）
        - INITIATED_BY 边（连接 -> 进程/主机）
        """
        nodes = []
        edges = []

        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")

        if not src_ip or not dst_ip:
            return nodes, edges

        # 1. 构建源IP节点
        src_ip_node = self._build_ip_node(src_ip)
        nodes.append(src_ip_node)

        # 2. 构建目标IP节点
        dst_ip_node = self._build_ip_node(dst_ip)
        nodes.append(dst_ip_node)

        # 3. 构建连接关系（源 -> 目标）
        connection_edge = {
            "type": "CONNECTED_TO",
            "source": src_ip_node["id"],
            "target": dst_ip_node["id"],
            "properties": {
                "timestamp": data.get("timestamp"),
                "src_port": data.get("src_port"),
                "dst_port": data.get("dst_port"),
                "protocol": data.get("protocol"),
                "connection_state": data.get("connection_state"),
                "duration": data.get("duration"),
                "bytes_sent": data.get("bytes_sent"),
                "bytes_received": data.get("bytes_received"),
                "event_id": data.get("event_id"),
                "raw_event_id": data.get("raw_event_id"),
            }
        }
        edges.append(connection_edge)

        # 4. 如果有关联主机信息，构建主机节点
        host_id = data.get("host_id")
        if host_id:
            host_node = self._build_host_node(data)
            nodes.append(host_node)

            # 建立主机与源IP的关联
            edges.append({
                "type": "HAS_IP",
                "source": host_node["id"],
                "target": src_ip_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                }
            })

        # 5. 如果有关联进程信息（Sysmon Event ID 3），构建进程节点
        process_id = data.get("process_id")
        if process_id:
            process_node = {
                "id": self._generate_process_node_id(
                    data.get("host_id"),
                    process_id,
                    data.get("timestamp")
                ),
                "type": "Process",
                "labels": ["Process"],
                "properties": {
                    "pid": process_id,
                    "process_name": data.get("process_name"),
                    "process_path": data.get("process_path"),
                    "host_id": host_id,
                }
            }
            nodes.append(process_node)

            # 进程发起连接
            edges.append({
                "type": "INITIATED_CONNECTION",
                "source": process_node["id"],
                "target": dst_ip_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                    "dst_port": data.get("dst_port"),
                    "protocol": data.get("protocol"),
                }
            })

        return nodes, edges

    def _parse_dns(self, data: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        解析 DNS 查询事件
        
        生成:
        - IP 节点（DNS服务器、应答IP）
        - Domain 节点（查询的域名）
        - Host 节点（发起查询的主机）
        - QUERIED 边（主机/IP -> 域名）
        - RESOLVED_TO 边（域名 -> IP）
        """
        nodes = []
        edges = []

        dns_query = data.get("dns_query")
        if not dns_query:
            return nodes, edges

        # 1. 构建域名节点
        domain_node = self._build_domain_node(dns_query)
        nodes.append(domain_node)

        # 2. 构建查询源IP节点
        src_ip = data.get("src_ip")
        if src_ip:
            src_ip_node = self._build_ip_node(src_ip)
            nodes.append(src_ip_node)

            # 构建查询关系
            edges.append({
                "type": "QUERIED_DOMAIN",
                "source": src_ip_node["id"],
                "target": domain_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                    "dns_query_type": data.get("dns_query_type"),
                    "dns_query_length": data.get("dns_query_length"),
                    "protocol": data.get("protocol"),
                    "event_id": data.get("event_id"),
                }
            })

        # 3. 构建DNS服务器IP节点
        dst_ip = data.get("dst_ip")
        if dst_ip:
            dns_server_node = self._build_ip_node(dst_ip)
            nodes.append(dns_server_node)

        # 4. 处理DNS应答（域名 -> IP）
        dns_answers = data.get("dns_answers")
        if dns_answers and isinstance(dns_answers, list):
            for answer in dns_answers:
                if self._is_valid_ip(answer):
                    answer_ip_node = self._build_ip_node(answer)
                    nodes.append(answer_ip_node)

                    # 构建解析关系
                    edges.append({
                        "type": "RESOLVED_TO",
                        "source": domain_node["id"],
                        "target": answer_ip_node["id"],
                        "properties": {
                            "timestamp": data.get("timestamp"),
                            "event_id": data.get("event_id"),
                        }
                    })

        # 5. 关联主机
        host_id = data.get("host_id")
        if host_id:
            host_node = self._build_host_node(data)
            nodes.append(host_node)

            # 主机查询域名
            edges.append({
                "type": "QUERIED_DOMAIN",
                "source": host_node["id"],
                "target": domain_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                }
            })

        return nodes, edges

    def _parse_http(self, data: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        解析 HTTP 请求事件
        
        生成:
        - IP 节点
        - Domain 节点（HTTP Host）
        - HTTP_REQUEST 边
        """
        nodes = []
        edges = []

        http_host = data.get("http_host")
        if not http_host:
            return nodes, edges

        # 1. 构建域名节点（HTTP Host）
        domain_node = self._build_domain_node(http_host)
        nodes.append(domain_node)

        # 2. 构建源IP和目标IP节点
        src_ip = data.get("src_ip")
        dst_ip = data.get("dst_ip")

        if src_ip:
            src_ip_node = self._build_ip_node(src_ip)
            nodes.append(src_ip_node)

        if dst_ip:
            dst_ip_node = self._build_ip_node(dst_ip)
            nodes.append(dst_ip_node)

            # HTTP请求关系
            if src_ip:
                edges.append({
                    "type": "HTTP_REQUEST",
                    "source": src_ip_node["id"],
                    "target": dst_ip_node["id"],
                    "properties": {
                        "timestamp": data.get("timestamp"),
                        "http_method": data.get("http_method"),
                        "http_host": http_host,
                        "http_uri": data.get("http_uri"),
                        "http_user_agent": data.get("http_user_agent"),
                        "http_status_code": data.get("http_status_code"),
                        "event_id": data.get("event_id"),
                    }
                })

            # 域名指向IP
            edges.append({
                "type": "POINTS_TO",
                "source": domain_node["id"],
                "target": dst_ip_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                }
            })

        return nodes, edges

    # ==========================================
    # 节点构建器
    # ==========================================

    def _build_ip_node(self, ip_address: str) -> Dict:
        """构建IP节点"""
        return {
            "id": self._generate_ip_node_id(ip_address),
            "type": "IP",
            "labels": ["IP"],
            "properties": {
                "ip_address": ip_address,
                "is_private": self._is_private_ip(ip_address),
            }
        }

    def _build_domain_node(self, domain: str) -> Dict:
        """构建域名节点"""
        return {
            "id": self._generate_domain_node_id(domain),
            "type": "Domain",
            "labels": ["Domain"],
            "properties": {
                "domain": domain,
                "is_suspicious": self._is_suspicious_domain(domain),
            }
        }

    def _build_host_node(self, data: Dict) -> Dict:
        """构建主机节点"""
        host_id = data.get("host_id")
        return {
            "id": self._generate_host_node_id(host_id),
            "type": "Host",
            "labels": ["Host"],
            "properties": {
                "host_id": host_id,
                "host_name": data.get("host_name"),
                "host_ip": data.get("host_ip"),
            }
        }

    # ==========================================
    # ID 生成器
    # ==========================================

    def _generate_ip_node_id(self, ip_address: str) -> str:
        """生成IP节点唯一ID"""
        return f"ip_{ip_address.replace('.', '_').replace(':', '_')}"

    def _generate_domain_node_id(self, domain: str) -> str:
        """生成域名节点唯一ID"""
        unique_str = f"domain_{domain.lower()}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    def _generate_host_node_id(self, host_id: str) -> str:
        """生成主机节点唯一ID"""
        return f"host_{host_id}"

    def _generate_process_node_id(
        self,
        host_id: str,
        process_id: int,
        timestamp: datetime
    ) -> str:
        """生成进程节点唯一ID（与ProcessParser保持一致）"""
        unique_str = f"process_{host_id}_{process_id}_{timestamp.isoformat()}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    # ==========================================
    # 辅助函数
    # ==========================================

    def _is_valid_ip(self, text: str) -> bool:
        """检查是否是有效的IP地址"""
        try:
            parts = text.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """判断是否是私有IP"""
        try:
            parts = [int(x) for x in ip.split(".")]
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8 (localhost)
            if parts[0] == 127:
                return True
            return False
        except:
            return False

    def _is_suspicious_domain(self, domain: str) -> bool:
        """
        简单的可疑域名检测（可扩展为威胁情报查询）
        """
        # 检查异常长的域名（可能是DNS隧道）
        if len(domain) > 100:
            return True
        
        # 检查是否包含过多的子域名级别
        if domain.count(".") > 5:
            return True
        
        # 检查是否包含随机字符串特征
        subdomain = domain.split(".")[0]
        if len(subdomain) > 30:
            return True
        
        return False


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

    parser = NetworkParser()

    print("=" * 70)
    print("FusionTrace Network Parser - 测试")
    print("=" * 70)

    # 测试用例1: 网络连接事件
    test_conn = {
        "event_id": "test_001",
        "event_category": "network",
        "event_type": "conn",
        "timestamp": datetime.now(timezone.utc),
        "source": "zeek",
        "src_ip": "192.168.1.100",
        "src_port": 49152,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "protocol": "tcp",
        "connection_state": "SF",
        "duration": 120.5,
        "bytes_sent": 1024,
        "bytes_received": 2048,
        "host_id": "victim-01",
        "host_name": "victim-01",
    }

    print("\n[测试 1] 网络连接事件")
    result = parser.parse(test_conn)
    print(json.dumps(result, indent=2, default=str))

    # 测试用例2: DNS查询事件
    test_dns = {
        "event_id": "test_002",
        "event_category": "network",
        "event_type": "dns",
        "timestamp": datetime.now(timezone.utc),
        "source": "zeek",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "udp",
        "dns_query": "malicious.com",
        "dns_query_type": "A",
        "dns_query_length": 13,
        "dns_answers": ["1.2.3.4", "5.6.7.8"],
    }

    print("\n[测试 2] DNS查询事件")
    result = parser.parse(test_dns)
    print(json.dumps(result, indent=2, default=str))

    # 测试用例3: HTTP请求事件
    test_http = {
        "event_id": "test_003",
        "event_category": "network",
        "event_type": "http",
        "timestamp": datetime.now(timezone.utc),
        "source": "zeek",
        "src_ip": "192.168.1.100",
        "dst_ip": "1.2.3.4",
        "dst_port": 80,
        "protocol": "tcp",
        "http_method": "GET",
        "http_host": "malicious.com",
        "http_uri": "/payload.exe",
        "http_user_agent": "Mozilla/5.0",
        "http_status_code": 200,
    }

    print("\n[测试 3] HTTP请求事件")
    result = parser.parse(test_http)
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 70)
    print(f"测试完成 - 解析总数: {parser.parsed_count}")
    print("=" * 70)
