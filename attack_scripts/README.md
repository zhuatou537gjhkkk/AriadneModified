# FusionTrace 攻击模拟脚本

本目录包含用于 FusionTrace 安全检测系统演示的攻击模拟脚本。

> ⚠️ **警告**：这些脚本仅用于授权的内网测试环境，请勿在未授权的系统上使用！

## 实验环境架构

```
┌─────────────────┐      SSH      ┌─────────────────┐      Agent      ┌─────────────────┐
│   服务器 C      │  ─────────►  │   服务器 B      │  ───────────►  │   服务器 A      │
│   (攻击机)      │              │   (靶机)        │                │   (分析平台)    │
│                 │              │                 │                │                 │
│ 运行攻击脚本    │              │ Wazuh Agent     │                │ Wazuh Manager   │
│                 │              │ (Auditd监控)    │                │ Zeek            │
│                 │              │                 │                │ FusionTrace     │
└─────────────────┘              └─────────────────┘                └─────────────────┘
```

## 脚本说明

### 1. comprehensive_attack.py - 全面攻击模拟

完整的 APT 攻击链模拟，覆盖 MITRE ATT&CK 11 个战术阶段。

**特点**：
- 覆盖完整攻击生命周期
- 产生丰富的攻击日志
- 支持多种攻击模式

**覆盖的 ATT&CK 战术**：
| 阶段 | 战术 | 技术ID |
|------|------|--------|
| 1 | 初始访问 | T1078, T1110 |
| 2 | 执行 | T1059 |
| 3 | 发现 | T1082, T1016, T1033 |
| 4 | 凭据访问 | T1552, T1003 |
| 5 | 权限提升 | T1548 |
| 6 | 持久化 | T1053, T1546 |
| 7 | 防御规避 | T1070 |
| 8 | 横向移动 | T1021, T1018 |
| 9 | 收集 | T1560, T1005 |
| 10 | C2 通信 | T1071, T1572 |
| 11 | 数据外泄 | T1048 |

**使用方法**：
```bash
# 完整攻击链
python comprehensive_attack.py --victim <IP> --user <用户> --password '<密码>' --mode full

# 快速演示
python comprehensive_attack.py --victim <IP> --user <用户> --password '<密码>' --mode quick

# 隐蔽攻击
python comprehensive_attack.py --victim <IP> --user <用户> --password '<密码>' --mode stealth

# 分步演示（每步暂停）
python comprehensive_attack.py --victim <IP> --user <用户> --password '<密码>' --mode demo
```

**参数说明**：
| 参数 | 说明 | 必需 |
|------|------|------|
| `--victim` | 靶机 IP 地址 | ✅ |
| `--user` | SSH 用户名 | ✅ |
| `--password` | SSH 密码 | ✅ (与 --key 二选一) |
| `--key` | SSH 私钥文件路径 | ✅ (与 --password 二选一) |
| `--port` | SSH 端口 (默认: 22) | ❌ |
| `--mode` | 攻击模式: full/quick/stealth/demo | ❌ |
| `--interval` | 攻击阶段间隔秒数 (默认: 3) | ❌ |
| `--skip-cleanup` | 跳过清理步骤 | ❌ |

---

### 2. chain_attack.py - 长攻击链生成

专门设计用于产生**深层嵌套的进程调用关系**，在 FusionTrace 中显示长攻击链。

**特点**：
- 产生 4-5 层深度的进程链
- 脚本嵌套调用，形成真正的父子关系
- 适合演示攻击链溯源功能

**攻击链结构**：
```
攻击链 1 - 侦察 (5层):
    bash → python3 → bash → bash → bash
           │           │       │       └── cat, head
           │           │       └── find
           │           └── uname, ip
           └── subprocess.call()

攻击链 2 - 持久化 (4层):
    bash → python3 → bash → bash
                       │       └── touch, history
                       └── chmod, crontab

攻击链 3 - 数据外泄 (5层):
    bash → python3 → bash → bash → bash
                       │       │       └── curl, nslookup
                       │       └── base64, md5sum
                       └── tar
```

**使用方法**：
```bash
python chain_attack.py --victim <IP> --user <用户> --password '<密码>'
```

**参数说明**：
| 参数 | 说明 | 必需 |
|------|------|------|
| `--victim` | 靶机 IP 地址 | ✅ |
| `--user` | SSH 用户名 | ✅ |
| `--password` | SSH 密码 | ✅ |
| `--port` | SSH 端口 (默认: 22) | ❌ |

---

## 快速开始

### 1. 安装依赖

```bash
cd attack_scripts
pip install -r requirements.txt
```

### 2. 运行攻击脚本

**示例 1**：运行全面攻击
```bash
python comprehensive_attack.py --victim 172.31.65.4 --user root --password 'Bupt2023' --mode full
```

**示例 2**：生成长攻击链
```bash
python chain_attack.py --victim 172.31.65.4 --user root --password 'Bupt2023'
```

### 3. 查看结果

1. 等待 Wazuh Agent 采集日志（约 1-2 分钟）
2. 打开 FusionTrace 前端界面
3. 在「溯源画布」页面查看攻击链

---

## 预期效果对比

| 脚本 | 攻击链长度 | 特点 |
|------|-----------|------|
| comprehensive_attack.py | 2 节点 | 覆盖全面，多条短链 |
| chain_attack.py | 4-5 节点 | 深层嵌套，少量长链 |

**建议**：两个脚本配合使用，既能展示全面的攻击覆盖，又能展示深层的攻击链溯源。

---

## 注意事项

1. **仅限授权环境**：请确保在授权的内网测试环境中使用
2. **靶机配置**：确保靶机已安装并配置好 Wazuh Agent
3. **Auditd 规则**：确保靶机的 Auditd 已配置 execve 监控规则
4. **网络连通性**：确保攻击机可以 SSH 连接到靶机
5. **日志延迟**：执行攻击后需等待 1-2 分钟让日志同步到 Wazuh Manager

---

## 文件结构

```
attack_scripts/
├── README.md                  # 本说明文件
├── requirements.txt           # Python 依赖
├── comprehensive_attack.py    # 全面攻击模拟脚本
└── chain_attack.py           # 长攻击链生成脚本
```
