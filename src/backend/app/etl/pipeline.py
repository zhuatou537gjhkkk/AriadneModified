import logging
import asyncio
from typing import Optional
from app.etl.collector import LogCollector
from app.etl.normalizer import LogNormalizer
from app.etl.parser_process import ProcessParser
from app.etl.parser_network import NetworkParser
from app.etl.graph_sync import GraphSync

logger = logging.getLogger("FusionTrace.Pipeline")


class ETLPipeline:
    """
    FusionTrace ETL 完整流水线
    
    数据流:
    Raw Logs (Wazuh/Zeek)
      ↓ [Collector]
    Structured JSON
      ↓ [Normalizer]
    Standardized Dict
      ↓ [Parser]
    Graph Nodes & Edges
      ↓ [GraphSync]
    Neo4j Graph Database
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        batch_size: int = 100,
        flush_interval: int = 5,
        test_mode: bool = False
    ):
        """
        初始化 ETL 流水线
        
        Args:
            max_queue_size: 采集队列大小
            batch_size: 批量写入大小
            flush_interval: 刷新间隔（秒）
            test_mode: 测试模式（从文件开头读取）
        """
        # 初始化各模块
        self.collector = LogCollector(
            max_queue_size=max_queue_size,
            read_from_start=test_mode
        )
        self.normalizer = LogNormalizer()
        self.process_parser = ProcessParser()
        self.network_parser = NetworkParser()
        self.graph_sync = GraphSync()
        
        # 配置参数
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        # 统计信息
        self.stats = {
            "collected": 0,
            "normalized": 0,
            "parsed": 0,
            "synced": 0,
            "errors": {
                "normalize": 0,
                "parse": 0,
                "sync": 0,
            }
        }
        
        self.running = False
        self._batch_buffer = []

    async def start(self):
        """启动 ETL 流水线"""
        self.running = True
        logger.info("=" * 70)
        logger.info(">>> FusionTrace ETL Pipeline 启动 <<<")
        logger.info("=" * 70)

        # 初始化数据库约束和索引
        logger.info("初始化 Neo4j 约束和索引...")
        self.graph_sync.create_constraints()
        self.graph_sync.create_indexes()

        # 启动采集任务
        collector_task = asyncio.create_task(self.collector.start())
        
        # 启动处理任务
        processor_task = asyncio.create_task(self._process_loop())
        
        # 启动定时刷新任务
        flush_task = asyncio.create_task(self._flush_loop())

        try:
            await asyncio.gather(collector_task, processor_task, flush_task)
        except Exception as e:
            logger.error(f"Pipeline 异常: {str(e)}", exc_info=True)
        finally:
            self.stop()

    async def _process_loop(self):
        """主处理循环"""
        logger.info("处理循环已启动")
        
        async for raw_message in self.collector.stream():
            try:
                # 统计
                self.stats["collected"] += 1

                # Step 1: Normalize
                normalized = self.normalizer.normalize(raw_message)
                if not normalized:
                    self.stats["errors"]["normalize"] += 1
                    continue
                
                self.stats["normalized"] += 1

                # Step 2: Parse
                graph_data = await self._parse(normalized)
                if not graph_data:
                    self.stats["errors"]["parse"] += 1
                    continue
                
                self.stats["parsed"] += 1

                # Step 3: Buffer for batch sync
                self._batch_buffer.append(graph_data)

                # 批量写入
                if len(self._batch_buffer) >= self.batch_size:
                    await self._flush_batch()

                # 定期输出统计
                if self.stats["collected"] % 1000 == 0:
                    self._log_stats()

            except Exception as e:
                logger.error(f"处理异常: {str(e)}", exc_info=True)

    async def _parse(self, normalized_data: dict) -> Optional[dict]:
        """
        根据事件类型选择 Parser
        """
        category = normalized_data.get("event_category")
        
        if category in ["process", "file"]:
            return self.process_parser.parse(normalized_data)
        elif category == "network":
            return self.network_parser.parse(normalized_data)
        else:
            return None

    async def _flush_batch(self):
        """刷新批量缓冲区到 Neo4j"""
        if not self._batch_buffer:
            return

        try:
            # 批量同步
            success_count = await asyncio.to_thread(
                self.graph_sync.batch_sync,
                self._batch_buffer
            )
            
            self.stats["synced"] += success_count
            self.stats["errors"]["sync"] += len(self._batch_buffer) - success_count
            
            # 清空缓冲区
            self._batch_buffer.clear()
            
        except Exception as e:
            logger.error(f"批量刷新失败: {str(e)}", exc_info=True)
            self.stats["errors"]["sync"] += len(self._batch_buffer)
            self._batch_buffer.clear()

    async def _flush_loop(self):
        """定时刷新循环"""
        while self.running:
            await asyncio.sleep(self.flush_interval)
            await self._flush_batch()

    def _log_stats(self):
        """输出统计信息"""
        logger.info("=" * 70)
        logger.info("ETL Pipeline 统计:")
        logger.info(f"  已采集: {self.stats['collected']}")
        logger.info(f"  已标准化: {self.stats['normalized']}")
        logger.info(f"  已解析: {self.stats['parsed']}")
        logger.info(f"  已同步到图库: {self.stats['synced']}")
        logger.info(f"  错误统计:")
        logger.info(f"    - 标准化错误: {self.stats['errors']['normalize']}")
        logger.info(f"    - 解析错误: {self.stats['errors']['parse']}")
        logger.info(f"    - 同步错误: {self.stats['errors']['sync']}")
        logger.info("=" * 70)

    def stop(self):
        """停止 ETL 流水线"""
        self.running = False
        
        # 刷新剩余数据
        if self._batch_buffer:
            logger.info("刷新剩余数据...")
            asyncio.create_task(self._flush_batch())
        
        # 停止采集器
        self.collector.stop()
        
        # 关闭数据库连接
        self.graph_sync.close()
        
        # 最终统计
        self._log_stats()
        
        logger.info("=" * 70)
        logger.info(">>> ETL Pipeline 已停止 <<<")
        logger.info("=" * 70)

    def get_graph_stats(self) -> dict:
        """获取图数据库统计"""
        return self.graph_sync.get_stats()


# ==========================================
# 主入口
# ==========================================
async def main():
    """主函数"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 生产模式：从文件末尾监听新增日志
    pipeline = ETLPipeline(
        max_queue_size=10000,
        batch_size=100,
        flush_interval=5,
        test_mode=False  # 生产模式，只监听新增数据
    )

    try:
        await pipeline.start()
    except KeyboardInterrupt:
        logger.info("收到停止信号...")
        pipeline.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
