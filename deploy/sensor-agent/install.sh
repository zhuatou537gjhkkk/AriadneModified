#!/bin/bash

# 1. 自动获取脚本参数作为主机名 (比如 node3)
AGENT_NAME=$1

# 检查有没有传参数
if [ -z "$AGENT_NAME" ]; then
    echo "错误: 必须指定 Agent 名字"
    echo "用法: sudo ./install.sh node3"
    exit 1
fi

MANAGER_IP="172.31.65.2"  # Node 1 的内网 IP (走内网不费流量)

echo "开始安装 Agent: [$AGENT_NAME] (连接 Manager: $MANAGER_IP)"

# 2. 添加 Wazuh 官方源 (GPG Key)
echo "配置软件源"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list > /dev/null
apt-get update -y

# 3. 安装并自动配置
echo "下载并安装 Agent"
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y wazuh-agent

# 4. 启动服务
echo "启动服务"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "安装完成"