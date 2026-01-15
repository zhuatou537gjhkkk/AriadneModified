#!/bin/bash

# ---------------------------------------------------------
# 功能: 配置 Linux Auditd 规则并覆盖 Wazuh Agent 配置文件
# 前置条件: 
#   1. 必须先运行 install.sh 安装 wazuh-agent
# 使用方法: sudo ./configure_agent.sh <Manager_IP> <Agent_Name>
# 示例: sudo ./configure_agent.sh 172.31.65.2 node3
# ---------------------------------------------------------

if [ "$#" -ne 2 ]; then
    echo "用法: sudo $0 <Manager_IP> <Agent_Name>"
    echo "示例: sudo $0 172.31.65.2 node3"
    exit 1
fi

MANAGER_IP=$1
AGENT_NAME=$2

# 检查是否以 root 运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本"
  exit 1
fi

# ---------------------------------------------------------
# 定义路径变量 
# ---------------------------------------------------------
# 获取脚本当前所在目录的绝对路径
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# 定义配置文件的存放路径 (相对于脚本位置)
CONFIG_DIR="$SCRIPT_DIR/../../config/sensor-agent"

echo "开始配置 Agent 环境: $AGENT_NAME (Manager: $MANAGER_IP)"
echo "配置文件目录: $CONFIG_DIR"

# ---------------------------------------------------------
# 1. 检查必要文件
# ---------------------------------------------------------
if [ ! -f "$CONFIG_DIR/audit.rules" ]; then
    echo "错误: 在 $CONFIG_DIR 下未找到 audit.rules 规则文件"
    exit 1
fi

if [ ! -f "$CONFIG_DIR/ossec.conf" ]; then
    echo "错误: 在 $CONFIG_DIR 下未找到 ossec.conf 模板文件"
    exit 1
fi

TARGET_CONF="/var/ossec/etc/ossec.conf"
if [ ! -f "$TARGET_CONF" ]; then
    echo "错误: 未找到目标配置文件 $TARGET_CONF"
    echo "请先运行 install.sh 安装 Wazuh Agent"
    exit 1
fi

# ---------------------------------------------------------
# 2. 配置并加载 Linux Auditd
# ---------------------------------------------------------
echo "配置 Linux Auditd..."

# 确保 auditd 工具已安装
if ! command -v auditctl &> /dev/null; then
    echo "      正在补装 auditd..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y auditd
    elif command -v yum &> /dev/null; then
        yum install -y auditd
    fi
fi

# 部署规则文件
if [ -d "/etc/audit/rules.d" ]; then
    cp "$CONFIG_DIR/audit.rules" /etc/audit/rules.d/audit.rules
    # 清理可能存在的旧文件避免冲突
    rm -f /etc/audit/audit.rules
    # 重新生成主规则文件
    aug enreap 2>/dev/null || true 
else
    cp "$CONFIG_DIR/audit.rules" /etc/audit/audit.rules
fi

# 加载规则
echo " 加载 Auditd 规则"
service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || auditctl -R /etc/audit/rules.d/audit.rules

# ---------------------------------------------------------
# 3. 应用 Wazuh 配置文件
# ---------------------------------------------------------
echo "应用 Wazuh 配置文件"

# 备份原文件
cp "$TARGET_CONF" "${TARGET_CONF}.bak_$(date +%s)"

# 复制新配置模板
cp "$CONFIG_DIR/ossec.conf" "$TARGET_CONF"

# 替换占位符 (修改 IP 和 Name)
sed -i "s/MANAGER_IP_PLACEHOLDER/$MANAGER_IP/g" "$TARGET_CONF"
sed -i "s/AGENT_NAME_PLACEHOLDER/$AGENT_NAME/g" "$TARGET_CONF"

echo "      配置文件已更新"

# ---------------------------------------------------------
# 4. 重启服务使配置生效
# ---------------------------------------------------------
echo "重启 Wazuh Agent..."
systemctl restart wazuh-agent

echo "配置完成"
echo "- Auditd 规则已加载"
echo "- Wazuh Agent 已指向 $MANAGER_IP 并重命名为 $AGENT_NAME"