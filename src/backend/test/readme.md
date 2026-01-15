advanced_log_simulate.py文件使用方法
# 1. 完整攻击链（默认）- 模拟 APT 攻击全流程
python advanced_log_simulator.py full_chain 3

# 2. 压力测试 - 生成大量日志测试系统性能
python advanced_log_simulator.py stress 1 60 100  # 60秒, 100 EPS

# 3. 资产发现测试 - 模拟新主机上线
python advanced_log_simulator.py discovery 5 5    # 5台新主机, 5秒间隔

# 4. 横向移动专项测试
python advanced_log_simulator.py lateral 10 3    # 10次横向移动

# 5. 演示模式 - 逐步展示各种攻击技术
python advanced_log_simulator.py demo 5