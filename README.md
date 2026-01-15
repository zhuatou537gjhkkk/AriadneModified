# <img src="./img/logo.png" height="30"> Ariadne：基于多源数据的恶意攻击行为溯源分析系统

![系统展示](./img/name.png)

## 📖 项目简介

Ariadne 是一个综合性的安全威胁溯源分析平台，通过整合主机日志（Wazuh）、网络流量（Zeek）等多源数据，利用图数据库（Neo4j）构建攻击关系图谱，实现对 APT 攻击、横向移动等复杂攻击行为的自动化溯源分析。

### 核心功能

- 🔍 **多源数据采集** - 集成 Wazuh Agent 和 Zeek 实现主机与网络流量的全面监控
- 📊 **图谱化分析** - 基于 Neo4j 构建攻击链图谱，直观展示攻击路径
- 🎯 **威胁溯源** - 自动关联分析，追踪攻击来源和传播路径
- 📈 **实时可视化** - 基于 ECharts 的动态图表展示威胁态势
- 🧪 **攻击模拟** - 内置多种攻击场景模拟器，支持系统测试验证

## ⚙️ 系统架构

![系统架构图](./img/architecture.png)

## 🏗️ 技术组成

### 后端技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| **Python** | 3.12 | 主要开发语言 |
| **FastAPI** | 0.95+ | Web 框架 |
| **Uvicorn** | 0.22+ | ASGI 服务器 |
| **Neo4j** | 5.8+ | 图数据库 |
| **Pydantic** | 1.10+ | 数据验证 |

### 前端技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| **React** | 19 | UI 框架 |
| **Vite** | 7 | 构建工具 |
| **Ant Design** | 6 | 组件库 |
| **ECharts** | 6 | 数据可视化 |
| **Axios** | 1.13+ | HTTP 客户端 |

### 数据采集与处理

| 组件 | 版本 | 用途 |
|------|------|------|
| **Auditd** | 3.0.7 | 主机行为检测 |
| **Wazuh** | 4.7.2 | 主机入侵检测 |
| **Zeek** | - | 网络流量分析 |
| **Logstash** | 8.10.2 | 日志聚合处理 |

## 🚀 快速开始

### 环境要求

- **操作系统**: Linux (推荐 Ubuntu 20.04+)
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Conda**: 用于 Python 环境管理

### 服务端一键部署

> 注意：请确认已经配置好客户端环境，具体配置可见[操作手册](./操作手册.md)。

```bash
# 1. 启动 Neo4j 图数据库
docker run --restart always --publish=7474:7474 --publish=7687:7687 \
    --env NEO4J_AUTH=neo4j/ariadne_neo4j \
    --volume=/home/Ariadne/data/neo4j_data:/data neo4j

# 2. 启动 Wazuh Manager
cd /home/Ariadne/deploy/wazuh_server && docker-compose up -d

# 3. 启动 Logstash-Zeek 日志收集器
docker run -d --name logstash-zeek --restart always -p 5044:5044 \
    --user root \
    -v /home/Ariadne/config/logstash_zeek/:/usr/share/logstash/pipeline/ \
    -v /home/Ariadne/data/zeek/:/home/Ariadne/data/zeek/ \
    logstash:8.10.2

# 4. 配置 Python 环境
cd /home/Ariadne
conda create -n ariadne python=3.12
conda activate ariadne
pip install -r requirements.txt
conda install -c conda-forge nodejs

# 5. 启动后端服务
cd /home/Ariadne/src/backend
nohup python main.py > backend.log 2>&1 &

# 6. 启动前端服务
cd /home/Ariadne/src/frontend
npm install
npm run dev
```

### 访问系统

部署完成后，通过以下地址访问：

- **Ariadne 主界面**: http://localhost:5173
- **Neo4j 管理界面**: http://localhost:7474
- **Wazuh Dashboard**: https://localhost:443


## 📂 项目结构

```
Ariadne/
├── config/                    # 配置文件
│   ├── logstash_zeek/        # Logstash 配置
│   └── wazuh/                # Wazuh 配置
├── data/                     # 数据存储
│   ├── logs/                 # 日志数据
│   └── neo4j_data/          # 图数据库数据
├── deploy/                   # 部署脚本
│   ├── sensor-agent/        # Agent 安装
│   ├── sensor-network/      # 网络传感器
│   └── wazuh_server/        # Wazuh 服务端
├── src/                      # 源代码
│   ├── backend/             # 后端服务
│   │   ├── app/
│   │   │   ├── analysis/   # 分析引擎
│   │   │   ├── api/        # API 接口
│   │   │   ├── core/       # 核心配置
│   │   │   ├── enrichment/ # 威胁情报
│   │   │   └── etl/        # 数据处理
│   │   ├── main.py         # 入口文件
│   │   └── test/           # 测试工具
│   └── frontend/            # 前端应用
│       └── src/
│           ├── components/  # React 组件
│           ├── services/    # API 服务
│           └── utils/       # 工具函数
├── img/                      # 图片资源
├── requirements.txt          # Python 依赖
└── 操作手册.md               # 详细操作手册
```

## 🧪 测试工具

系统内置多种攻击场景模拟器，用于测试验证：

```bash
cd /home/Ariadne/src/backend/test

# 完整攻击链测试
python advanced_log_simulator.py full_chain 3

# 压力测试
python advanced_log_simulator.py stress 1 60 100

# 横向移动测试
python advanced_log_simulator.py lateral 10 3
```


## 🔧 主要模块

### 分析引擎 (Analysis Pipeline)

- **攻击链构建** - 基于 MITRE ATT&CK 框架识别攻击技战术
- **图算法分析** - 利用最短路径、社区发现等算法分析攻击路径
- **威胁情报匹配** - 关联外部威胁情报，识别已知攻击组织

### ETL 数据处理

- **多源数据采集** - 实时采集 Wazuh 和 Zeek 日志
- **数据规范化** - 统一不同数据源的字段格式
- **图谱同步** - 自动将事件数据同步到 Neo4j 图数据库

### API 接口

- RESTful API 设计
- WebSocket 实时推送
- 完整的 API 文档（Swagger UI）

## 📊 监控指标

系统支持以下监控维度：

- ⚡ EPS (Events Per Second) - 事件处理速率
- 🎯 告警统计 - 按严重程度分类统计
- 🌐 网络连接分析 - 异常连接检测
- 🖥️ 主机行为分析 - 进程、文件操作监控
- 🔗 攻击链图谱 - 可视化攻击传播路径


## 🤝 贡献

欢迎提交 Issue 和 Pull Request！


## 📄 许可证

Copyright (c) 2026 [Your Name/Organization]
本项目采用 [MIT License](LICENSE) 开源协议。
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> 本项目使用的开源组件可能有不同的许可证，使用时请注意遵守。


### 免责声明

本项目仅供学习研究使用，作者不对使用本软件造成的任何损失负责。在生产环境使用前，请进行充分的安全评估和测试。

