"""
MITRE 映射模块

将事件或攻击链映射到 MITRE ATT&CK 的战术与技术，提供 ATT&CK 覆盖率统计、
TTP 提取与 APT 组织画像匹配的简化实现。模块既可基于单条事件进行映射（`map_event_to_mitre`），
也可聚合图数据库结果生成覆盖矩阵和 TTP 列表。

主要类与方法：
- `MITREMapper.map_event_to_mitre(event_data)`：根据规则标签与进程/命令行关键词映射战术/技术。
- `generate_attack_matrix(start_time, end_time)`：基于图数据库结果统计战术/技术覆盖率。
- `extract_ttps(attack_chain)`：从攻击链提取 TTP 特征。
- `match_apt_group(ttps)`：基于 TTP 与技术特征匹配 APT 画像（简化示例）。
"""

import logging
from typing import List, Dict, Any, Set
from app.etl.graph_sync import GraphSync

logger = logging.getLogger("FusionTrace.MITREMapper")


class MITREMapper:
    """
    MITRE ATT&CK 映射器
    
    职责:
    1. 将攻击行为映射到 ATT&CK 战术和技术
    2. 生成 ATT&CK 覆盖矩阵
    3. TTP（战术、技术、过程）提取
    4. APT 组织画像
    """

    # MITRE ATT&CK 战术映射（基于Wazuh规则组）
    TACTIC_MAPPING = {
        # 初始访问 (Initial Access)
        "web_attack": ["TA0001", "Initial Access"],
        "exploit": ["TA0001", "Initial Access"],
        "phishing": ["TA0001", "Initial Access"],
        
        # 执行 (Execution)
        "command_execution": ["TA0002", "Execution"],
        "powershell": ["TA0002", "Execution"],
        "script": ["TA0002", "Execution"],
        
        # 持久化 (Persistence)
        "persistence": ["TA0003", "Persistence"],
        "registry": ["TA0003", "Persistence"],
        "scheduled_task": ["TA0003", "Persistence"],
        
        # 权限提升 (Privilege Escalation)
        "privilege_escalation": ["TA0004", "Privilege Escalation"],
        "sudo": ["TA0004", "Privilege Escalation"],
        
        # 防御绕过 (Defense Evasion)
        "defense_evasion": ["TA0005", "Defense Evasion"],
        "obfuscation": ["TA0005", "Defense Evasion"],
        
        # 凭据访问 (Credential Access)
        "credential_access": ["TA0006", "Credential Access"],
        "password_dump": ["TA0006", "Credential Access"],
        
        # 发现 (Discovery)
        "discovery": ["TA0007", "Discovery"],
        "network_scan": ["TA0007", "Discovery"],
        "reconnaissance": ["TA0007", "Discovery"],
        
        # 横向移动 (Lateral Movement)
        "lateral_movement": ["TA0008", "Lateral Movement"],
        "remote_access": ["TA0008", "Lateral Movement"],
        
        # 收集 (Collection)
        "collection": ["TA0009", "Collection"],
        "data_staged": ["TA0009", "Collection"],
        
        # 命令与控制 (Command and Control)
        "c2": ["TA0011", "Command and Control"],
        "command_and_control": ["TA0011", "Command and Control"],
        "backdoor": ["TA0011", "Command and Control"],
        
        # 渗透 (Exfiltration)
        "exfiltration": ["TA0010", "Exfiltration"],
        "data_exfiltration": ["TA0010", "Exfiltration"],
        
        # 影响 (Impact)
        "impact": ["TA0040", "Impact"],
        "ransomware": ["TA0040", "Impact"],
        "data_destruction": ["TA0040", "Impact"],
    }

    # 技术ID映射（常见攻击技术）
    # 覆盖题目要求的：主机日志、主机行为监控、网络流量分析相关技术
    TECHNIQUE_MAPPING = {
        # T1059: Command and Scripting Interpreter (执行)
        "cmd.exe": "T1059.003",
        "powershell": "T1059.001",
        "bash": "T1059.004",
        "sh": "T1059.004",    # Unix sh shell
        "dash": "T1059.004",  # Debian Almquist Shell
        "zsh": "T1059.004",   # Z shell
        "python": "T1059.006",
        
        # T1218: System Binary Proxy Execution (防御规避)
        "regsvr32": "T1218.010",
        "rundll32": "T1218.011",
        "mshta": "T1218.005",
        
        # T1055: Process Injection (权限提升)
        "process_injection": "T1055",
        "inject": "T1055",
        
        # T1134: Access Token Manipulation (权限提升)
        "token": "T1134",
        "impersonate": "T1134",
        
        # T1003: OS Credential Dumping (凭据访问)
        "mimikatz": "T1003.001",
        "lsass": "T1003.001",
        "sam": "T1003.002",
        "procdump": "T1003.001",
        
        # T1110: Brute Force (凭据访问)
        "brute": "T1110",
        "hydra": "T1110",
        
        # T1021: Remote Services (横向移动)
        "rdp": "T1021.001",
        "ssh": "T1021.004",
        "smb": "T1021.002",
        "psexec": "T1021.002",
        "wmic": "T1021.003",
        
        # T1071: Application Layer Protocol (C2)
        "http": "T1071.001",
        "dns": "T1071.004",
        "beacon": "T1071.001",
        
        # T1573: Encrypted Channel (C2)
        "ssl": "T1573",
        "tls": "T1573",
        "encrypted": "T1573",
        
        # T1048: Exfiltration Over Alternative Protocol (数据外泄)
        "dns_tunnel": "T1048.003",
        "icmp_tunnel": "T1048",
        "exfil": "T1048",
        
        # T1041: Exfiltration Over C2 Channel (数据外泄)
        "exfiltration": "T1041",
        
        # T1505: Server Software Component (持久化)
        "webshell": "T1505.003",
        ".aspx": "T1505.003",
        ".jsp": "T1505.003",
        ".php": "T1505.003",
        
        # T1190: Exploit Public-Facing Application (初始访问)
        "exploit": "T1190",
        "cve-": "T1190",
        
        # T1566: Phishing (初始访问)
        "phishing": "T1566",
        "spearphish": "T1566",
        
        # T1053: Scheduled Task/Job (持久化)
        "cron": "T1053.003",
        "scheduled_task": "T1053.005",
        "schtasks": "T1053.005",
        "at.exe": "T1053.002",
        
        # T1547: Boot or Logon Autostart Execution (持久化)
        "registry_run": "T1547.001",
        "startup_folder": "T1547.001",
        "autorun": "T1547.001",
        
        # T1136: Create Account (持久化)
        "net user": "T1136.001",
        "useradd": "T1136.001",
        
        # T1082: System Information Discovery (发现)
        "systeminfo": "T1082",
        "uname": "T1082",
        "hostname": "T1082",
        
        # T1083: File and Directory Discovery (发现)
        "dir ": "T1083",
        "dir.exe": "T1083",
        "ls ": "T1083",
        "find ": "T1083",
        "find": "T1083",  # Linux find 命令（进程名）
        
        # T1057: Process Discovery (发现)
        "tasklist": "T1057",
        "ps aux": "T1057",
        "get-process": "T1057",
        
        # T1046: Network Service Scanning (发现)
        "nmap": "T1046",
        "masscan": "T1046",
        "portscan": "T1046",
        "netstat": "T1046",
        
        # T1005: Data from Local System (收集)
        "type ": "T1005",
        "cat ": "T1005",
        "cat": "T1005",  # Linux cat 命令（进程名）
        "head": "T1005",  # Linux head 命令
        "tail": "T1005",  # Linux tail 命令
        "copy ": "T1005",
        
        # T1113: Screen Capture (收集)
        "screenshot": "T1113",
        "screencapture": "T1113",
        
        # T1115: Clipboard Data (收集)
        "clipboard": "T1115",
        "xclip": "T1115",
        
        # T1036: Masquerading (防御规避)
        "masquerade": "T1036",
        "rename": "T1036",
        
        # T1027: Obfuscated Files (防御规避)
        "obfuscate": "T1027",
        "-enc": "T1027",
        "base64": "T1027",
        
        # T1070: Indicator Removal (防御规避)
        "del ": "T1070.004",
        "rm ": "T1070.004",
        "rm": "T1070.004",  # Linux rm 命令（进程名）
        "shred": "T1070.004",  # Linux shred 命令
        "wevtutil": "T1070.001",
        
        # T1486: Data Encrypted for Impact (影响)
        "ransomware": "T1486",
        "encrypt": "T1486",
        ".locked": "T1486",
        
        # T1489: Service Stop (影响)
        "sc stop": "T1489",
        "net stop": "T1489",
        "systemctl stop": "T1489",
        
        # T1490: Inhibit System Recovery (影响)
        "vssadmin": "T1490",
        "bcdedit": "T1490",
        "wbadmin": "T1490",
    }

    def __init__(self, graph_sync: GraphSync = None):
        """
        初始化 MITRE 映射器
        
        Args:
            graph_sync: GraphSync 实例
        """
        self.graph_sync = graph_sync or GraphSync()

    def map_event_to_mitre(self, event_data: Dict) -> Dict[str, Any]:
        """
        将单个事件映射到 MITRE ATT&CK
        
        Args:
            event_data: 事件数据
                {
                    "rule_tags": [...],
                    "process_name": "...",
                    "command_line": "...",
                    ...
                }
        
        Returns:
            MITRE 映射结果
        """
        tactics = set()
        techniques = set()

        # 1. 从规则标签映射战术
        rule_tags = event_data.get("rule_tags", [])
        for tag in rule_tags:
            if tag in self.TACTIC_MAPPING:
                tactic_id, tactic_name = self.TACTIC_MAPPING[tag]
                tactics.add((tactic_id, tactic_name))

        # 2. 从进程名称和命令行映射技术（安全处理 None）
        process_name = str(event_data.get("process_name") or "").lower()
        command_line = str(event_data.get("command_line") or "").lower()

        for keyword, technique_id in self.TECHNIQUE_MAPPING.items():
            if keyword in process_name or keyword in command_line:
                techniques.add(technique_id)

        return {
            "tactics": [{"id": t[0], "name": t[1]} for t in tactics],
            "techniques": list(techniques),
            "confidence": self._calculate_confidence(len(tactics), len(techniques))
        }

    def _calculate_confidence(self, tactic_count: int, technique_count: int) -> float:
        """
        计算映射置信度
        
        基于匹配到的战术和技术数量
        """
        score = (tactic_count * 0.4 + technique_count * 0.6) / 3
        return min(score, 1.0)

    def generate_attack_matrix(
        self,
        start_time: str = None,
        end_time: str = None
    ) -> Dict[str, Any]:
        """
        生成 ATT&CK 覆盖矩阵
        
        统计时间范围内检测到的所有战术和技术
        
        Returns:
            {
                "tactics": {...},
                "techniques": {...},
                "coverage": float
            }
        """
        query = """
        // 查找所有进程事件
        MATCH (p:Process)
        WHERE ($start_time IS NULL OR p.first_seen >= $start_time)
          AND ($end_time IS NULL OR p.first_seen <= $end_time)
        
        // 查找关联的规则标签
        OPTIONAL MATCH (h:Host {host_id: p.host_id})
        
        RETURN 
            p.process_name as process,
            p.command_line as command,
            p.first_seen as timestamp
        LIMIT 1000
        """

        params = {
            "start_time": start_time,
            "end_time": end_time
        }

        try:
            results = self.graph_sync.execute_query(query, params)
            
            all_tactics = set()
            all_techniques = set()
            technique_counts = {}

            for record in results:
                mitre_mapping = self.map_event_to_mitre({
                    "process_name": str(record.get("process") or ""),
                    "command_line": str(record.get("command") or "")
                })
                
                # 统计战术
                for tactic in mitre_mapping.get("tactics", []):
                    all_tactics.add(tactic["id"])
                
                # 统计技术
                for technique in mitre_mapping.get("techniques", []):
                    all_techniques.add(technique)
                    technique_counts[technique] = technique_counts.get(technique, 0) + 1

            # 计算覆盖率（假设 ATT&CK 有14个战术，约200个技术）
            tactic_coverage = len(all_tactics) / 14.0
            technique_coverage = len(all_techniques) / 200.0

            return {
                "tactics": {
                    "detected": list(all_tactics),
                    "count": len(all_tactics),
                    "coverage": tactic_coverage
                },
                "techniques": {
                    "detected": list(all_techniques),
                    "count": len(all_techniques),
                    "coverage": technique_coverage,
                    "top_techniques": sorted(
                        technique_counts.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]
                },
                "total_events": len(results)
            }

        except Exception as e:
            logger.error(f"生成 ATT&CK 矩阵失败: {str(e)}", exc_info=True)
            return {}

    def extract_ttps(
        self,
        attack_chain: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        从攻击链提取 TTP（战术、技术、过程）
        
        Args:
            attack_chain: 攻击链数据（来自 ChainBuilder）
        
        Returns:
            TTP 特征
        """
        ttps = {
            "tactics": set(),
            "techniques": set(),
            "procedures": []
        }

        chains = attack_chain.get("chains", [])
        
        for chain in chains:
            if not isinstance(chain, dict):
                continue
            
            # 支持新的多节点链结构
            chain_nodes = chain.get("chain", [])
            if chain_nodes:
                # 新格式：chain 是节点数组
                for node in chain_nodes:
                    mitre_node = self.map_event_to_mitre({
                        "process_name": str(node.get("name") or ""),
                        "command_line": str(node.get("command") or "")
                    })
                    
                    for tactic in mitre_node.get("tactics", []):
                        ttps["tactics"].add(tactic["id"])
                    
                    for technique in mitre_node.get("techniques", []):
                        ttps["techniques"].add(technique)
                    
                    if mitre_node.get("techniques"):
                        ttps["procedures"].append({
                            "process": node.get("name"),
                            "command": node.get("command"),
                            "techniques": mitre_node.get("techniques", []),
                            "timestamp": node.get("time")
                        })
            else:
                # 向后兼容旧格式（两节点链）
                parent = chain.get("parent", {})
                child = chain.get("child", {})
                
                # 分析父进程
                if parent:
                    mitre_parent = self.map_event_to_mitre({
                        "process_name": str(parent.get("name") or ""),
                        "command_line": str(parent.get("command") or "")
                    })
                    
                    for tactic in mitre_parent.get("tactics", []):
                        ttps["tactics"].add(tactic["id"])
                    
                    for technique in mitre_parent.get("techniques", []):
                        ttps["techniques"].add(technique)
                    
                    if mitre_parent.get("techniques"):
                        ttps["procedures"].append({
                            "process": parent.get("name"),
                            "command": parent.get("command"),
                            "techniques": mitre_parent.get("techniques", []),
                            "timestamp": parent.get("time")
                        })
                
                # 分析子进程
                if child:
                    mitre_child = self.map_event_to_mitre({
                        "process_name": str(child.get("name") or ""),
                        "command_line": str(child.get("command") or "")
                    })
                    
                    for tactic in mitre_child.get("tactics", []):
                        ttps["tactics"].add(tactic["id"])
                    
                    for technique in mitre_child.get("techniques", []):
                        ttps["techniques"].add(technique)
                    
                    if mitre_child.get("techniques"):
                        ttps["procedures"].append({
                            "process": child.get("name"),
                            "command": child.get("command"),
                            "techniques": mitre_child.get("techniques", []),
                            "timestamp": child.get("time")
                        })

        return {
            "tactics": list(ttps["tactics"]),
            "techniques": list(ttps["techniques"]),
            "procedures": ttps["procedures"],
            "ttp_count": len(ttps["tactics"]) + len(ttps["techniques"])
        }

    def match_apt_group(self, ttps: Dict[str, Any]) -> List[Dict]:
        """
        APT 组织画像匹配
        
        基于 TTP 特征匹配已知的 APT 组织
        
        Args:
            ttps: TTP 特征数据
        
        Returns:
            匹配的 APT 组织列表
        """
        # APT 组织特征库（简化版本，实际应该从数据库或配置文件加载）
        apt_profiles = {
            "APT28": {
                "name": "APT28 (Fancy Bear)",
                "country": "Russia",
                "signature_techniques": ["T1059.001", "T1021.001", "T1071.001", "T1082", "T1083"],
                "signature_tools": ["mimikatz", "powershell"]
            },
            "APT29": {
                "name": "APT29 (Cozy Bear)",
                "country": "Russia",
                "signature_techniques": ["T1059.001", "T1218.011", "T1071.001", "T1005"],
                "signature_tools": ["powershell", "rundll32"]
            },
            "APT41": {
                "name": "APT41",
                "country": "China",
                "signature_techniques": ["T1505.003", "T1059.003", "T1071.001", "T1021.004"],
                "signature_tools": ["webshell", "cmd", "ssh"]
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "country": "North Korea",
                "signature_techniques": ["T1059.001", "T1003.001", "T1048.003"],
                "signature_tools": ["mimikatz", "dns_tunnel"]
            },
            # 添加 Linux 攻击相关的 APT 组织
            "Turla": {
                "name": "Turla (Snake)",
                "country": "Russia",
                "signature_techniques": ["T1059.004", "T1021.004", "T1083", "T1082", "T1005"],
                "signature_tools": ["bash", "ssh", "find", "cat"]
            },
            "TeamTNT": {
                "name": "TeamTNT",
                "country": "Unknown",
                "signature_techniques": ["T1059.004", "T1046", "T1082", "T1070.004", "T1005"],
                "signature_tools": ["bash", "nmap", "rm", "cat"]
            },
            "Rocke": {
                "name": "Rocke Group",
                "country": "China",
                "signature_techniques": ["T1059.004", "T1053.003", "T1082", "T1083"],
                "signature_tools": ["bash", "cron", "curl", "wget"]
            }
        }

        detected_techniques = set(ttps.get("techniques", []))
        matches = []
        
        # 定义通用技术（几乎所有攻击都会用到，权重降低）
        common_techniques_pool = {
            "T1059.004",  # Unix Shell - 太通用
            "T1059.001",  # PowerShell - Windows 常见
            "T1082",      # System Information Discovery - 侦察基础
            "T1083",      # File and Directory Discovery - 侦察基础
            "T1005",      # Data from Local System - 通用收集
        }
        
        # 定义独特技术（匹配到这些才更有说服力）
        unique_techniques_pool = {
            "T1003.001",  # LSASS Memory - 特定凭据窃取
            "T1218.011",  # Rundll32 - 特定规避技术
            "T1505.003",  # Web Shell - 特定持久化
            "T1048.003",  # DNS Tunnel Exfil - 特定外泄
            "T1053.003",  # Cron - 特定持久化
        }

        for apt_id, profile in apt_profiles.items():
            signature_techniques = set(profile["signature_techniques"])
            
            # 计算匹配度
            matched_techniques = detected_techniques & signature_techniques
            if matched_techniques:
                # 基础匹配分数
                base_score = len(matched_techniques) / len(signature_techniques)
                
                # 计算通用技术占比（通用技术越多，惩罚越大）
                common_matched = matched_techniques & common_techniques_pool
                common_ratio = len(common_matched) / len(matched_techniques) if matched_techniques else 0
                
                # 计算独特技术加成
                unique_matched = matched_techniques & unique_techniques_pool
                unique_bonus = len(unique_matched) * 0.05  # 每个独特技术加 5%
                
                # 应用惩罚和加成
                # 如果全是通用技术，最多只能得到 70% 分数
                # 公式：基础分 * (1 - 通用占比 * 0.3) + 独特加成
                adjusted_score = base_score * (1 - common_ratio * 0.3) + unique_bonus
                
                # 设置上限为 85%（因为没有 100% 确定的归因）
                final_score = min(adjusted_score, 0.85)
                
                # 确定置信度等级
                if final_score > 0.7:
                    confidence = "High"
                elif final_score > 0.5:
                    confidence = "Medium"
                elif final_score > 0.3:
                    confidence = "Low"
                else:
                    confidence = "Very Low"
                
                matches.append({
                    "apt_id": apt_id,
                    "apt_name": profile["name"],
                    "country": profile["country"],
                    "match_score": final_score,
                    "matched_techniques": list(matched_techniques),
                    "confidence": confidence
                })

        # 按匹配度排序
        matches.sort(key=lambda x: x["match_score"], reverse=True)
        
        if matches:
            logger.info(f"匹配到 {len(matches)} 个可能的 APT 组织，最高匹配: {matches[0]['apt_name']} ({matches[0]['match_score']:.1%})")
        
        return matches

    def generate_mitre_report(
        self,
        attack_chain: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        生成完整的 MITRE 分析报告
        
        Args:
            attack_chain: 攻击链数据
        
        Returns:
            完整报告
        """
        # 1. 提取 TTP
        ttps = self.extract_ttps(attack_chain)
        
        # 2. 匹配 APT 组织
        apt_matches = self.match_apt_group(ttps)
        
        # 3. 生成战术时间线
        tactic_timeline = self._generate_tactic_timeline(ttps)

        report = {
            "summary": {
                "total_tactics": len(ttps["tactics"]),
                "total_techniques": len(ttps["techniques"]),
                "total_procedures": len(ttps["procedures"]),
            },
            "ttps": ttps,
            "apt_attribution": apt_matches,
            "tactic_timeline": tactic_timeline,
            "recommendations": self._generate_recommendations(ttps, apt_matches)
        }

        return report

    def _generate_tactic_timeline(self, ttps: Dict) -> List[Dict]:
        """
        生成战术时间线（Kill Chain）
        按时间戳排序，处理None值的情况
        """
        procedures = ttps.get("procedures", [])
        
        # 按时间排序，使用安全的排序方式处理None值
        # 将None值排到最后
        timeline = sorted(
            procedures,
            key=lambda x: (x.get("timestamp") is None, x.get("timestamp", ""))
        )
        
        return timeline

    def _generate_recommendations(
        self,
        ttps: Dict,
        apt_matches: List[Dict]
    ) -> List[str]:
        """
        生成防御建议
        """
        recommendations = []

        # 基于检测到的技术生成建议
        techniques = ttps.get("techniques", [])
        
        if "T1059.001" in techniques:  # PowerShell
            recommendations.append("启用 PowerShell 日志记录和脚本块日志")
            recommendations.append("限制 PowerShell 执行策略")
        
        if "T1003.001" in techniques:  # LSASS Dump
            recommendations.append("启用 Credential Guard")
            recommendations.append("监控 LSASS 进程访问")
        
        if "T1071.004" in techniques:  # DNS Tunneling
            recommendations.append("监控异常 DNS 查询（长域名、高频率）")
            recommendations.append("部署 DNS 防火墙")
        
        if "T1505.003" in techniques:  # WebShell
            recommendations.append("定期扫描 Web 目录")
            recommendations.append("启用 Web 应用防火墙（WAF）")

        # 基于 APT 匹配生成建议
        if apt_matches:
            top_apt = apt_matches[0]
            recommendations.append(
                f"检测到与 {top_apt['apt_name']} 相似的 TTP，"
                f"建议查阅该组织的最新威胁情报"
            )

        return recommendations


# ==========================================
# 测试入口
# ==========================================
if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    mapper = MITREMapper()

    print("=" * 70)
    print("FusionTrace MITREMapper - 测试")
    print("=" * 70)

    # 测试1: 单个事件映射
    print("\n[测试 1] 事件映射到 MITRE")
    test_event = {
        "rule_tags": ["powershell", "command_execution"],
        "process_name": "powershell.exe",
        "command_line": "powershell -enc base64_encoded_command"
    }
    mitre_mapping = mapper.map_event_to_mitre(test_event)
    print(json.dumps(mitre_mapping, indent=2))

    # 测试2: TTP 提取
    print("\n[测试 2] TTP 提取")
    test_chain = {
        "chains": [{
            "chains": [
                {
                    "command_line": "powershell -enc ...",
                    "process_name": "powershell.exe",
                    "when": "2026-01-12T10:00:00"
                },
                {
                    "command_line": "mimikatz.exe",
                    "process_name": "mimikatz.exe",
                    "when": "2026-01-12T10:05:00"
                }
            ]
        }]
    }
    ttps = mapper.extract_ttps(test_chain)
    print(json.dumps(ttps, indent=2, default=str))

    # 测试3: APT 匹配
    print("\n[测试 3] APT 组织匹配")
    apt_matches = mapper.match_apt_group(ttps)
    print(json.dumps(apt_matches, indent=2))

    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
