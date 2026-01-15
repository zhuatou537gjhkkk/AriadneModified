"""
ProcessParser 模块

本模块定义 `ProcessParser`，用于将标准化后的进程与文件事件转换为图模型（节点和关系）。
职责包括构建进程、用户、文件等节点，以及生成进程间的 SPAWNED、EXECUTED_BY、
RUNS_IMAGE、CREATED/MODIFIED/DELETED 等关系。模块提供解析入口 `parse()`，以及若干
内部构建器方法用于生成节点 ID 和节点/关系的标准属性。

主要类与方法：
- `ProcessParser.parse(normalized_data)`：主入口，分发到 `_parse_process_event` 或
    `_parse_file_event`，返回 `{nodes, edges, metadata}`。
- `_parse_process_event`：处理进程创建/衍生事件，产生进程/父进程/用户/文件节点与关系。
- `_parse_file_event`：处理文件操作事件，产生文件节点并与进程建立 CREATED/MODIFIED/ACCESSED 关系。
- `_build_*` 系列方法：构建具体节点（Process/User/File）。
- `_generate_*_id` 系列方法：生成唯一 ID（基于主机、PID、时间戳或路径）。
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import hashlib

logger = logging.getLogger("FusionTrace.ProcessParser")


class ProcessParser:
    """
    进程数据解析器 (ETL - Transform)
    
    职责:
    1. 构建进程树（Process Tree）- 基于 PID/PPID 关系
    2. 提取进程节点（Process Node）
    3. 提取文件节点（File Node）
    4. 提取用户节点（User Node）
    5. 构建实体关系（SPAWNED, EXECUTED_BY, ACCESSED_FILE）
    
    输出:
    - nodes: 节点列表 [{type, properties}, ...]
    - edges: 关系列表 [{type, source, target, properties}, ...]
    """

    def __init__(self):
        self.parsed_count = 0

    def parse(self, normalized_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        解析标准化后的进程事件
        
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
            # 只处理进程和文件相关事件
            category = normalized_data.get("event_category")
            if category not in ["process", "file"]:
                return None

            nodes = []
            edges = []

            # 解析进程事件
            if category == "process":
                process_nodes, process_edges = self._parse_process_event(normalized_data)
                nodes.extend(process_nodes)
                edges.extend(process_edges)

            # 解析文件事件
            elif category == "file":
                file_nodes, file_edges = self._parse_file_event(normalized_data)
                nodes.extend(file_nodes)
                edges.extend(file_edges)

            if not nodes:
                return None

            self.parsed_count += 1
            if self.parsed_count % 1000 == 0:
                logger.info(f"[ProcessParser] 已解析 {self.parsed_count} 条进程/文件事件")

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
            logger.error(f"进程事件解析异常: {str(e)}", exc_info=True)
            return None

    def _parse_process_event(self, data: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        解析进程创建事件
        
        生成:
        - Process 节点（当前进程）
        - Process 节点（父进程，如果存在）
        - User 节点（执行用户）
        - File 节点（进程镜像文件）
        - SPAWNED 边（父进程 -> 子进程）
        - EXECUTED_BY 边（进程 -> 用户）
        - RUNS_IMAGE 边（进程 -> 文件）
        """
        nodes = []
        edges = []

        # 1. 构建当前进程节点
        process_id = data.get("process_id")
        if process_id:
            process_node = self._build_process_node(data)
            nodes.append(process_node)
            process_node_id = process_node["id"]

            # 2. 构建父进程节点（如果存在）
            parent_process_id = data.get("parent_process_id")
            if parent_process_id:
                parent_node = {
                    "id": self._generate_process_node_id(
                        data.get("host_id"),
                        parent_process_id
                    ),
                    "type": "Process",
                    "labels": ["Process"],
                    "properties": {
                        # 标识信息（统一格式）
                        "pid": parent_process_id,
                        "host_id": data.get("host_id"),
                        "host_name": data.get("host_name"),
                        "host_ip": data.get("host_ip"),  # 添加主机IP用于资产发现
                        # 其他字段暂置为None，等待后续事件补充
                        "process_name": None,
                        "process_path": None,
                        "command_line": None,
                        "working_directory": None,
                        "first_seen": data.get("timestamp"),
                        "last_seen": data.get("timestamp"),
                        "event_id": None,
                        "file_hash": None,
                    }
                }
                nodes.append(parent_node)

                # 构建 SPAWNED 关系（父 -> 子）
                edges.append({
                    "type": "SPAWNED",
                    "source": parent_node["id"],
                    "target": process_node_id,
                    "properties": {
                        "timestamp": data.get("timestamp"),
                        "event_id": data.get("event_id"),
                    }
                })

            # 3. 构建用户节点
            user_name = data.get("user_name")
            if user_name:
                user_node = self._build_user_node(data)
                nodes.append(user_node)

                # 构建 EXECUTED_BY 关系
                edges.append({
                    "type": "EXECUTED_BY",
                    "source": process_node_id,
                    "target": user_node["id"],
                    "properties": {
                        "timestamp": data.get("timestamp"),
                        "user_id": data.get("user_id"),
                        "effective_user_id": data.get("effective_user_id"),
                    }
                })

            # 4. 构建进程镜像文件节点
            process_path = data.get("process_path")
            if process_path:
                file_node = self._build_file_node(
                    file_path=process_path,
                    file_hash=data.get("file_hash"),
                    host_id=data.get("host_id")
                )
                nodes.append(file_node)

                # 构建 RUNS_IMAGE 关系
                edges.append({
                    "type": "RUNS_IMAGE",
                    "source": process_node_id,
                    "target": file_node["id"],
                    "properties": {
                        "timestamp": data.get("timestamp"),
                    }
                })

        return nodes, edges

    def _parse_file_event(self, data: Dict) -> Tuple[List[Dict], List[Dict]]:
        """
        解析文件操作事件
        
        生成:
        - File 节点
        - Process 节点（操作文件的进程）
        - CREATED/MODIFIED/DELETED 边
        """
        nodes = []
        edges = []

        file_path = data.get("file_path")
        if not file_path:
            return nodes, edges

        # 1. 构建文件节点
        file_node = self._build_file_node(
            file_path=file_path,
            file_hash=data.get("file_hash"),
            file_size=data.get("file_size"),
            file_owner=data.get("file_owner"),
            file_permissions=data.get("file_permissions"),
            host_id=data.get("host_id")
        )
        nodes.append(file_node)

        # 2. 如果有关联进程，构建进程节点和关系
        process_id = data.get("process_id")
        if process_id:
            process_node = {
                "id": self._generate_process_node_id(
                    data.get("host_id"),
                    process_id
                ),
                "type": "Process",
                "labels": ["Process"],
                "properties": {
                    # 标识信息（与NetworkParser一致）
                    "pid": process_id,
                    "host_id": data.get("host_id"),
                    "host_name": data.get("host_name"),
                    "host_ip": data.get("host_ip"),  # 添加主机IP用于资产发现
                    # 进程详细信息（如果可用）
                    "process_name": data.get("process_name"),
                    "process_path": data.get("process_path"),
                    "command_line": data.get("command_line"),
                    "working_directory": data.get("working_directory"),
                    # 时间信息
                    "first_seen": data.get("timestamp"),
                    "last_seen": data.get("timestamp"),
                    "event_id": data.get("event_id"),
                    "file_hash": data.get("file_hash"),
                }
            }
            nodes.append(process_node)

            # 根据事件类型构建不同的关系
            event_type = data.get("event_type")
            edge_type_map = {
                "file_create": "CREATED_FILE",
                "modification": "MODIFIED_FILE",
                "deleted": "DELETED_FILE",
                "accessed": "ACCESSED_FILE",
            }
            edge_type = edge_type_map.get(event_type, "ACCESSED_FILE")

            edges.append({
                "type": edge_type,
                "source": process_node["id"],
                "target": file_node["id"],
                "properties": {
                    "timestamp": data.get("timestamp"),
                    "event_id": data.get("event_id"),
                }
            })

        return nodes, edges

    # ==========================================
    # 节点构建器
    # ==========================================

    def _build_process_node(self, data: Dict) -> Dict:
        """构建进程节点（统一格式：ProcessParser与NetworkParser相容）"""
        process_id = data.get("process_id")
        host_id = data.get("host_id")
        timestamp = data.get("timestamp")

        return {
            "id": self._generate_process_node_id(host_id, process_id),
            "type": "Process",
            "labels": ["Process"],
            "properties": {
                # 标识信息（与NetworkParser一致的基础字段）
                "pid": process_id,
                "host_id": host_id,
                "host_name": data.get("host_name"),
                "host_ip": data.get("host_ip"),  # 添加主机IP用于资产发现
                # 进程详细信息（ProcessParser富集）
                "process_name": data.get("process_name"),
                "process_path": data.get("process_path"),
                "command_line": data.get("command_line"),
                "working_directory": data.get("working_directory"),
                # 时间与事件信息（用于生命周期追踪）
                "first_seen": timestamp,  # 首次观测此进程
                "last_seen": timestamp,   # 最后更新时间
                "event_id": data.get("event_id"),
                # 安全检测相关
                "file_hash": data.get("file_hash"),
            }
        }

    def _build_user_node(self, data: Dict) -> Dict:
        """构建用户节点"""
        user_name = data.get("user_name")
        host_id = data.get("host_id")

        return {
            "id": self._generate_user_node_id(user_name, host_id),
            "type": "User",
            "labels": ["User"],
            "properties": {
                "user_name": user_name,
                "user_id": data.get("user_id"),
                "effective_user_id": data.get("effective_user_id"),
                "host_id": host_id,
                "host_name": data.get("host_name"),
            }
        }

    def _build_file_node(
        self,
        file_path: str,
        file_hash: Optional[str] = None,
        file_size: Optional[int] = None,
        file_owner: Optional[str] = None,
        file_permissions: Optional[str] = None,
        host_id: Optional[str] = None
    ) -> Dict:
        """构建文件节点"""
        return {
            "id": self._generate_file_node_id(file_path, host_id),
            "type": "File",
            "labels": ["File"],
            "properties": {
                "file_path": file_path,
                "file_hash": file_hash,
                "file_size": file_size,
                "file_owner": file_owner,
                "file_permissions": file_permissions,
                "host_id": host_id,
            }
        }

    # ==========================================
    # ID 生成器（用于节点唯一标识）
    # ==========================================

    def _generate_process_node_id(
        self,
        host_id: str,
        process_id: int
    ) -> str:
        """
        生成进程节点唯一ID（全局去重，无时间戳）
        
        设计：不包含时间戳，确保同一进程在不同时刻对应同一节点。
        时间信息保存在节点属性（first_seen/last_seen）和边属性中。
        注意：如果进程PID被重用，将被视为同一节点（需要额外的生命周期管理）
        """
        unique_str = f"process_{host_id}_{process_id}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    def _generate_user_node_id(self, user_name: str, host_id: str) -> str:
        """生成用户节点唯一ID"""
        unique_str = f"user_{host_id}_{user_name}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    def _generate_file_node_id(self, file_path: str, host_id: str) -> str:
        """生成文件节点唯一ID"""
        unique_str = f"file_{host_id}_{file_path}"
        return hashlib.md5(unique_str.encode()).hexdigest()


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

    parser = ProcessParser()

    print("=" * 70)
    print("FusionTrace Process Parser - 测试")
    print("=" * 70)

    # 测试用例1: Windows 进程创建事件
    test_process = {
        "event_id": "test_001",
        "event_category": "process",
        "event_type": "process_create",
        "timestamp": datetime.now(timezone.utc),
        "source": "wazuh",
        "host_id": "agent_001",
        "host_name": "Windows11",
        "process_id": 4064,
        "parent_process_id": 7652,
        "process_name": "regsvr32.exe",
        "process_path": "C:\\Windows\\SysWOW64\\regsvr32.exe",
        "command_line": "/s /i C:\\AtomicRedTeam\\atomics\\T1218.010\\bin\\AllTheThingsx86.dll",
        "working_directory": "C:\\Users\\THECOT~1\\AppData\\Local\\Temp\\",
        "user_name": "Windows11\\Testuser",
        "user_id": "0x294325",
        "file_hash": "D9BE711BE2BF88096BB91C25DF775D90B964264AB25EC49CF04711D8C1F089F6",
    }

    print("\n[测试 1] 进程创建事件")
    result = parser.parse(test_process)
    print(json.dumps(result, indent=2, default=str))

    # 测试用例2: 文件修改事件
    test_file = {
        "event_id": "test_002",
        "event_category": "file",
        "event_type": "modification",
        "timestamp": datetime.now(timezone.utc),
        "source": "wazuh",
        "host_id": "agent_001",
        "host_name": "victim-01",
        "file_path": "/etc/passwd",
        "file_hash": "abc123def456",
        "file_size": 2048,
        "file_owner": "root",
        "file_permissions": "rw-r--r--",
        "process_id": 1234,
        "process_name": "vim",
        "process_path": "/usr/bin/vim",
    }

    print("\n[测试 2] 文件修改事件")
    result = parser.parse(test_file)
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 70)
    print(f"测试完成 - 解析总数: {parser.parsed_count}")
    print("=" * 70)
