import asyncio
import json
import os
import logging
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime, timezone
from app.core.config import settings

# 初始化日志记录器
logger = logging.getLogger("FusionTrace.Collector")


class CollectorMetrics:
    """采集器性能指标统计"""
    def __init__(self):
        self.total_collected = 0
        self.parse_errors = 0
        self.queue_overflow_warnings = 0
        self.last_log_time = datetime.now(timezone.utc)
    
    def log_stats(self):
        """定期输出统计信息"""
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_log_time).total_seconds()
        if elapsed >= 60:  # 每分钟输出一次
            rate = self.total_collected / elapsed if elapsed > 0 else 0
            logger.info(
                f"[STATS] 采集统计 - 总量: {self.total_collected}, "
                f"速率: {rate:.2f}/s, "
                f"解析错误: {self.parse_errors}"
            )
            self.last_log_time = now


class LogCollector:
    """
    FusionTrace 日志采集器 (ETL - Extract)
    
    职责:
    1. 实时监听 Wazuh 和 Zeek 的 JSON 日志文件
    2. 统一封装为标准格式 (source + raw + timestamp)
    3. 处理日志轮转、文件缺失等异常场景
    4. 提供背压控制，防止内存溢出
    
    前提:
    - Zeek 必须配置为 JSON 输出模式 (LogAscii::use_json = T)
    - 所有节点必须完成 NTP 时间同步
    
    数据流:
    文件 -> _tail_file_generator -> _process_json_line -> queue -> stream()
    """

    def __init__(self, max_queue_size: int = 10000, read_from_start: bool = False):
        """
        Args:
            max_queue_size: 队列大小
            read_from_start: 是否从文件开头读取（测试模式用）
        """
        self.running = False
        self.queue = asyncio.Queue(maxsize=max_queue_size)
        self.metrics = CollectorMetrics()
        self._monitor_task = None
        self.read_from_start = read_from_start

    async def _tail_file_generator(self, file_path: str) -> AsyncGenerator[str, None]:
        """
        [底层核心] 通用文件流生成器
        只负责：打开文件、实时读取新行、处理日志轮转。
        """
        file_name = os.path.basename(file_path)
        logger.info(f"开始监听文件: {file_name}")

        # 1. 等待文件创建
        while not os.path.exists(file_path):
            logger.warning(f"文件未找到，5秒后重试: {file_path}")
            await asyncio.sleep(5)

        current_file = open(file_path, 'r', encoding='utf-8', errors='ignore')
        
        # 根据模式决定读取位置
        if self.read_from_start:
            # 测试模式：从文件开头读取
            current_file.seek(0, 0)
            logger.info(f"[测试模式] 从文件开头读取: {file_name}")
        else:
            # 生产模式：只采集启动后的新数据，防止读取历史积压数据
            current_file.seek(0, 2)
            logger.info(f"[生产模式] 从文件末尾开始监听: {file_name}")

        current_inode = os.fstat(current_file.fileno()).st_ino

        try:
            while self.running:
                # 尝试读取一行
                line = current_file.readline()

                if line:
                    yield line
                    continue  # 读到数据后不 sleep，立即尝试读下一行，保证高吞吐

                # --- EOF: 处理轮转检测 ---
                try:
                    if os.path.exists(file_path):
                        new_inode = os.stat(file_path).st_ino
                        if new_inode != current_inode:
                            logger.info(f"检测到日志轮转: {file_name}")
                            current_file.close()
                            # 打开新文件
                            current_file = open(file_path, 'r', encoding='utf-8', errors='ignore')
                            current_inode = new_inode
                            # 新文件从头开始读
                            continue
                except FileNotFoundError:
                    pass  # 文件可能短暂消失

                # 无数据且无轮转，短暂休眠释放 CPU
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"文件监听异常 [{file_name}]: {e}")
        finally:
            current_file.close()
            logger.info(f"停止监听文件: {file_name}")

    async def _process_json_line(self, line: str, source: str, sub_type: Optional[str]):
        """
        统一的 JSON 解析逻辑
        
        Args:
            line: 原始日志行
            source: 数据源标识 (wazuh/zeek)
            sub_type: 子类型 (Zeek的conn/dns/http等，Wazuh为None)
        """
        try:
            line = line.strip()
            if not line or line.startswith('#'):  # 跳过空行和Zeek注释行
                return

            # 核心解析
            raw_data = json.loads(line)

            # 基础验证：确保有基本的时间戳字段
            if source == "zeek" and "ts" not in raw_data:
                logger.warning(f"[Zeek] 缺少时间戳字段，跳过: {line[:50]}")
                self.metrics.parse_errors += 1
                return
            elif source == "wazuh" and "timestamp" not in raw_data:
                logger.warning(f"[Wazuh] 缺少时间戳字段，跳过: {line[:50]}")
                self.metrics.parse_errors += 1
                return

            # 封装标准化消息
            payload = {
                "source": source,
                "sub_type": sub_type,
                "timestamp_collected": datetime.now(timezone.utc).isoformat(),  # 采集时间（UTC）
                "raw": raw_data
            }
            
            # 入队（带背压控制）
            if self.queue.qsize() > self.queue.maxsize * 0.8:
                logger.warning(
                    f"[WARNING] 队列接近饱和: {self.queue.qsize()}/{self.queue.maxsize}, "
                    f"下游处理可能过慢"
                )
                self.metrics.queue_overflow_warnings += 1
            
            await self.queue.put(payload)
            self.metrics.total_collected += 1

        except json.JSONDecodeError as e:
            # 仅记录前50字符用于调试，防止日志刷屏
            logger.debug(f"[{source}] 忽略非 JSON 行: {line[:50]}... (Error: {e})")
            self.metrics.parse_errors += 1
        except asyncio.QueueFull:
            logger.error(f"[ERROR] [{source}] 队列已满，丢弃数据！考虑增加 max_queue_size")
            self.metrics.parse_errors += 1
        except Exception as e:
            logger.error(f"[{source}] 处理异常: {e}", exc_info=True)
            self.metrics.parse_errors += 1

    # ==========================================
    # 业务采集任务
    # ==========================================

    async def collect_wazuh(self):
        """采集 Wazuh Alerts"""
        path = settings.LOG_PATH_WAZUH

        async for line in self._tail_file_generator(path):
            await self._process_json_line(line, source="wazuh", sub_type=None)

    async def collect_zeek_single(self, filename: str):
        """采集单个 Zeek 日志 (conn.log, dns.log 等)"""
        path = os.path.join(settings.LOG_DIR_ZEEK, filename)
        sub_type = filename.split('.')[0]  # 从文件名提取类型, e.g. "conn"

        async for line in self._tail_file_generator(path):
            await self._process_json_line(line, source="zeek", sub_type=sub_type)

    async def collect_zeek(self):
        """管理所有 Zeek 文件的采集任务"""
        tasks = []
        for log_file in settings.ZEEK_FILES_TO_WATCH:
            tasks.append(
                asyncio.create_task(self.collect_zeek_single(log_file))
            )
        await asyncio.gather(*tasks)

    # ==========================================
    # 生命周期控制
    # ==========================================

    async def _monitor_loop(self):
        """后台监控任务：定期输出性能指标"""
        while self.running:
            await asyncio.sleep(60)
            self.metrics.log_stats()

    async def start(self):
        """启动采集引擎（所有数据源并行采集）"""
        self.running = True
        logger.info("=" * 60)
        logger.info(">>> FusionTrace 数据采集引擎启动 <<<")
        logger.info(f"模式: JSON | 队列大小: {self.queue.maxsize}")
        logger.info(f"Wazuh路径: {settings.LOG_PATH_WAZUH}")
        logger.info(f"Zeek目录: {settings.LOG_DIR_ZEEK}")
        logger.info(f"监控文件: {settings.ZEEK_FILES_TO_WATCH}")
        logger.info("=" * 60)

        # 启动监控任务
        self._monitor_task = asyncio.create_task(self._monitor_loop())

        try:
            await asyncio.gather(
                self.collect_wazuh(),
                self.collect_zeek()
            )
        except Exception as e:
            logger.error(f"采集引擎异常: {e}", exc_info=True)
            raise

    async def stream(self) -> AsyncGenerator[Dict[str, Any], None]:
        """下游消费接口"""
        while True:
            data = await self.queue.get()
            yield data
            self.queue.task_done()

    def stop(self):
        """停止采集引擎"""
        self.running = False
        if self._monitor_task:
            self._monitor_task.cancel()
        
        # 输出最终统计
        logger.info("=" * 60)
        logger.info(">>> 采集引擎已停止 <<<")
        logger.info(f"最终统计 - 总采集: {self.metrics.total_collected}, "
                   f"错误: {self.metrics.parse_errors}")
        logger.info("=" * 60)


# --- 调试入口 ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


    async def main():
        collector = LogCollector()
        asyncio.create_task(collector.start())

        try:
            async for msg in collector.stream():
                # 打印结构化数据预览
                src = msg['source']
                sub = f"({msg['sub_type']})" if msg['sub_type'] else ""

                # 尝试打印几个关键字段证明 JSON 解析成功
                content = ""
                if src == 'zeek':
                    # Zeek JSON 常见字段
                    content = f"ID:{msg['raw'].get('uid', '?')} Proto:{msg['raw'].get('proto', '?')}"
                elif src == 'wazuh':
                    # Wazuh JSON 常见字段
                    content = f"Rule:{msg['raw'].get('rule', {}).get('id', '?')} Agent:{msg['raw'].get('agent', {}).get('name', '?')}"

                print(f"Received [{src}{sub}]: {content}")
        except KeyboardInterrupt:
            collector.stop()


    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass