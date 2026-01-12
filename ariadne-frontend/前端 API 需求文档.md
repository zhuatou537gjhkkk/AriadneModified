# 前端 API 需求文档

版本: v1.0

对接方: 前端开发组 -> 后端开发组

协议: HTTP/HTTPS

数据格式: JSON

## 1. 通用说明

- **Base URL**: `/api/v1` (建议)
- **鉴权**: 所有接口需在 Header 中携带 Token (如 `Authorization: Bearer <token>`)。
- **状态码**: 200 表示成功，4xx/5xx 表示异常。

------

## 2. 态势总览 (Dashboard)

此页面主要用于展示宏观数据，要求数据响应速度快。

### 2.1 获取核心统计指标

用于填充页面顶部的四个统计卡片。

- **接口地址**: `GET /dashboard/summary`

- **响应示例**:

  ```JSON
  {
    "active_threats": 20,       // 活跃威胁源
    "intercepted_today": 903,   // 今日拦截
    "throughput_eps": 4600,     // 数据吞吐 (EPS)
    "time_sync_offset": 12      // 时间同步偏差 (ms)
  }
  ```

### 2.2 获取流量趋势数据

用于渲染 `TrafficTrend` 组件中的折线图。

- **接口地址**: `GET /dashboard/traffic-trend`

- **参数**: `range` (可选，如 "1h", "24h")

- **响应示例**:

  ```JSON
  {
    "categories": ["10:00", "10:05", "10:10", "10:15", "10:20", "10:25", "10:30"],
    "series": {
      "zeek_network": [120, 132, 101, 134, 290, 230, 210], // 对应 Zeek (Network)
      "auditd_endpoint": [220, 182, 191, 234, 290, 330, 310] // 对应 Auditd (Endpoint)
    }
  }
  ```

### 2.3 获取全网拓扑数据

用于渲染 `TopologyGraph` 组件。

- **接口地址**: `GET /dashboard/topology`

- **响应示例**:

  ```JSON
  {
    "nodes": [
      { "name": "Analysis Center", "category": "Server", "status": "online" },
      { "name": "Victim-03 (Admin)", "category": "Compromised", "status": "compromised" }
    ],
    "links": [
      { "source": "Analysis Center", "target": "Zeek Sensor" },
      { "source": "Victim-03 (Admin)", "target": "Zeek Sensor", "type": "tunnel" } // 隐蔽信道
    ]
  }
  ```

### 2.4 获取实时告警列表

用于渲染 Dashboard 右侧的告警列表。

- **接口地址**: `GET /alerts/latest`

- **参数**: `limit` (默认 5)

- **响应示例**:

  ```JSON
  [
    {
      "id": "alert-001",
      "title": "DNS Tunnel Detection",
      "source": "Zeek",
      "time": "10:01:05",
      "level": "High",     // 对应前端颜色渲染逻辑
      "clickable": true    // 是否支持点击钻取分析
    },
    {
      "title": "Suspicious Process Spawning",
      "source": "Auditd",
      "time": "10:01:02",
      "level": "Medium"
    }
  ]
  ```

------

## 3. 溯源画布 (Investigation)

此模块交互性最强，需要完整的图谱数据和时序数据。

### 3.1 获取攻击图谱数据

用于渲染 `AttackGraph` 组件。请严格遵循 ECharts Graph 数据格式。

- **接口地址**: `GET /investigation/graph`

- **参数**: `alert_id` (关联的告警ID) 或 `time_window`

- **响应示例**:

  ```JSON
  {
    "nodes": [
      {
        "id": "192.168.1.5",
        "name": "192.168.1.5",
        "category": "IP",
        "symbolSize": 50,
        "details": "受害主机 | Agent在线"
      },
      {
        "id": "powershell.exe",
        "name": "powershell.exe",
        "category": "Process",
        "details": "Args: -enc W3... | 内存注入风险"
      }
    ],
    "links": [
      { "source": "192.168.1.5", "target": "cmd.exe", "value": "SPAWNED" },
      { "source": "powershell.exe", "target": "114.114.114.114", "value": "C2_CONNECT" }
    ]
  }
  ```

### 3.2 获取攻击叙事线 (Timeline)

用于渲染“攻击叙事线 (STORYLINE)”卡片。

- **接口地址**: `GET /investigation/storyline`

- **响应示例**:

  ```JSON
  [
    { "time": "09:59:00", "content": "正常业务流量基线建立完毕", "highlight": false },
    { "time": "10:00:01", "content": "检测到 WebShell 访问 (192.168.1.5)", "highlight": true, "severity": "high" },
    { "time": "10:00:10", "content": "建立非法 C2 连接", "highlight": true, "severity": "critical" }
  ]
  ```

### 3.3 威胁深度分析 (熵值检测)

当用户点击特定告警（如 DNS Tunnel）时，右侧抽屉弹出的详细分析图表。

- **接口地址**: `GET /analysis/entropy`

- **参数**: `alert_id`

- **响应示例**:

  ```JSON
  {
    "packets": ["Pkt-1", "Pkt-2", "Pkt-3", "Pkt-4", "Pkt-5"], // X轴
    "values": [3.2, 3.5, 3.1, 7.8, 7.9],                       // Y轴数据
    "threshold": 5.0                                           // 阈值线
  }
  ```

------

## 4. 资产与探针 (Sensors)

### 4.1 获取资产列表

用于渲染资产管理表格 中的 `assetData`。

- **接口地址**: `GET /assets`

- **响应示例**:

  ```JSON
  [
    {
      "id": "1",
      "name": "Node-01 (Analysis)",
      "ip": "192.168.1.2",
      "role": "Server",
      "auditd_enabled": true,
      "zeek_enabled": true,
      "status": "Online"
    },
    {
      "id": "3",
      "name": "Node-03 (Agent)",
      "ip": "192.168.1.5",
      "role": "Victim",
      "auditd_enabled": false,
      "zeek_enabled": false,
      "status": "Compromised"
    }
  ]
  ```

### 4.2 控制探针开关

当用户点击表格中的 Switch 开关时调用。

- **接口地址**: `POST /assets/{id}/config`

- **请求体**:

  ```JSON
  {
    "module": "auditd", // 或 "zeek"
    "enabled": true
  }
  ```

- **响应**: `200 OK`

------

## 5. 情报与归因 (Attribution)

### 5.1 获取 APT 组织信息

用于展示 APT28 画像及进度条，以及带有颜色标记的证据链。

- **接口地址**: `GET /attribution/intelligence`

- **响应示例**:

  ```JSON
  {
    "name": "Fancy Bear",         // 前端字段已更新，原文档为 actor_name
    "code": "APT28",              // 前端字段已更新，原文档为 actor_code
    "confidence": 92,             // 前端字段已更新，原文档为 confidence_score
    "evidence": [                 // 证据链数组
      {
        "content": "检测到已知 C2 域名",
        "color": "red"            // 用于前端渲染时间轴节点的颜色 (red/blue/green)
      },
      {
        "content": "UTC+3 作息规律",
        "color": "blue"
      },
      {
        "content": "样本特征匹配 X-Agent 变种",
        "color": "green"
      }
    ]
  }
  ```



## 6. 战术分析 (ATT&CK)

### 6.1 获取战术命中高亮

用于获取当前分析出的攻击技术列表，前端将根据返回的技术名称高亮对应的矩阵单元格。

- **接口地址**: `GET /attack/highlights`

- **响应示例**:

  ```JSON
  [
    "Command and Scripting Interpreter",
    "Process Injection",
    "Obfuscated Files",
    "Encrypted Channel"
  ]
  ```

