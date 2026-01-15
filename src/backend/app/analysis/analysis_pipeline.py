"""
AnalysisPipeline 模块

在数据入库后对图数据进行综合分析，整合攻击链构建、攻击模式检测、MITRE 映射、
情报增强和归因分析，生成 JSON 和文本摘要报告。是检测结果整理与展示的上游管道。

主要类与方法：
- `AnalysisPipeline.analyze(time_range_hours)`：执行完整分析流程并返回报告字典。
- `_save_report(report)`：将分析结果保存为 JSON 与文本摘要，并更新 latest 文件。
- `quick_analysis`：针对单个可疑指标（IP/进程）执行快速追溯与情报查询。

依赖组件：`ChainBuilder`, `GraphAlgorithms`, `MITREMapper`, `ThreatIntelligence`, `Attribution`。
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any
from pathlib import Path
from app.analysis.chain_builder import ChainBuilder
from app.analysis.graph_algo import GraphAlgorithms
from app.analysis.mitre_mapper import MITREMapper
from app.enrichment.threat_intel import ThreatIntelligence
from app.enrichment.attribution import Attribution

logger = logging.getLogger("FusionTrace.AnalysisPipeline")

# 输出目录
OUTPUT_DIR = Path("/home/Ariadne/data/output")  # Linux部署用
# OUTPUT_DIR = Path("D:/Projects/Python/Courses/Ariadne/data/output")  # Windows本地测试用


class AnalysisPipeline:
    """
    分析流水线 - 对已入库的图数据进行分析
    
    流程:
    1. 攻击链构建（时空关联）
    2. 攻击模式匹配
    3. MITRE ATT&CK 映射
    4. 威胁情报增强
    5. 攻击归因
    """

    def __init__(self):
        self.chain_builder = ChainBuilder()
        self.graph_algo = GraphAlgorithms()
        self.mitre_mapper = MITREMapper()
        self.threat_intel = ThreatIntelligence()
        self.attribution = Attribution()

    def analyze(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """
        执行完整分析
        
        Args:
            time_range_hours: 分析时间范围（小时）
        
        Returns:
            完整分析报告
        """
        logger.info(f"开始分析最近 {time_range_hours} 小时的数据...")

        report = {
            "analysis_time": datetime.now().isoformat(),
            "time_range_hours": time_range_hours,
        }

        # 1. 攻击链构建
        logger.info("步骤 1: 构建攻击链...")
        attack_chains = self.chain_builder.build_attack_chain(
            time_range_hours=time_range_hours
        )
        report["attack_chains"] = attack_chains

        # 2. 攻击模式检测
        logger.info("步骤 2: 检测攻击模式...")
        patterns = {
            "reverse_shell": self.graph_algo.find_attack_patterns("reverse_shell"),
            "credential_dump": self.graph_algo.find_attack_patterns("credential_dump"),
            "lateral_movement": self.graph_algo.find_attack_patterns("lateral_movement"),
            "webshell": self.graph_algo.find_attack_patterns("webshell"),
        }
        report["attack_patterns"] = patterns

        # 3. 横向移动检测
        logger.info("步骤 3: 检测横向移动...")
        lateral_movement = self.chain_builder.find_lateral_movement(time_range_hours)
        report["lateral_movement"] = lateral_movement

        # 4. 数据外泄检测
        logger.info("步骤 4: 检测数据外泄...")
        data_exfiltration = self.chain_builder.find_data_exfiltration()
        report["data_exfiltration"] = data_exfiltration

        # 5. 持久化机制检测
        logger.info("步骤 5: 检测持久化机制...")
        persistence = self.chain_builder.find_persistence_mechanisms()
        report["persistence"] = persistence

        # 6. MITRE ATT&CK 映射
        logger.info("步骤 6: 生成 MITRE ATT&CK 报告...")
        mitre_report = self.mitre_mapper.generate_mitre_report(attack_chains)
        report["mitre_analysis"] = mitre_report

        # 7. 攻击归因
        logger.info("步骤 7: 执行攻击归因...")
        # 提取 IOC
        iocs = self._extract_iocs(attack_chains, patterns)
        attribution_report = self.attribution.attribute_attack(attack_chains, iocs)
        report["attribution"] = attribution_report

        logger.info("分析完成！")
        
        # 保存报告到文件
        self._save_report(report)
        
        return report

    def _save_report(self, report: Dict[str, Any]) -> None:
        """保存分析报告到文件"""
        try:
            # 创建输出目录
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            
            # 生成时间戳文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 1. 保存完整 JSON 报告
            json_file = OUTPUT_DIR / f"analysis_report_{timestamp}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"完整报告已保存: {json_file}")
            
            # 2. 保存摘要报告（文本格式）
            summary_file = OUTPUT_DIR / f"analysis_summary_{timestamp}.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("FusionTrace 分析报告摘要\n")
                f.write("=" * 70 + "\n")
                f.write(f"分析时间: {report.get('analysis_time')}\n")
                f.write(f"时间范围: {report.get('time_range_hours')} 小时\n\n")
                
                # 攻击链
                f.write("【攻击链分析】\n")
                chains = report.get('attack_chains', {})
                f.write(f"  检测到攻击链: {chains.get('total_count', 0)} 条\n")
                f.write(f"  可疑IP: {len(chains.get('suspicious_ips', []))} 个\n")
                f.write(f"  可疑进程: {len(chains.get('suspicious_processes', []))} 个\n\n")
                
                # 攻击模式
                f.write("【攻击模式检测】\n")
                patterns = report.get('attack_patterns', {})
                for pattern_type, results in patterns.items():
                    f.write(f"  {pattern_type}: {len(results)} 个\n")
                f.write("\n")
                
                # 横向移动
                f.write("【横向移动】\n")
                lateral = report.get('lateral_movement', [])
                f.write(f"  检测到: {len(lateral)} 个\n")
                if lateral:
                    for lm in lateral[:5]:  # 显示前5个
                        f.write(f"    - {lm.get('src_ip')} -> {lm.get('dst_ip')}:{lm.get('port')} ({lm.get('service')})\n")
                f.write("\n")
                
                # 数据外泄
                f.write("【数据外泄】\n")
                exfil = report.get('data_exfiltration', [])
                f.write(f"  检测到: {len(exfil)} 个\n")
                if exfil:
                    for ex in exfil[:5]:
                        f.write(f"    - {ex.get('src_ip')} -> {ex.get('dst_ip')} ({ex.get('size_mb')} MB)\n")
                f.write("\n")
                
                # 持久化
                f.write("【持久化机制】\n")
                persist = report.get('persistence', [])
                f.write(f"  检测到: {len(persist)} 个\n")
                if persist:
                    for p in persist[:5]:
                        f.write(f"    - {p.get('mechanism')}: {p.get('process_name')}\n")
                f.write("\n")
                
                # MITRE ATT&CK
                f.write("【MITRE ATT&CK 分析】\n")
                mitre = report.get('mitre_analysis', {})
                if mitre:
                    summary = mitre.get('summary', {})
                    f.write(f"  战术: {summary.get('total_tactics', 0)} 个\n")
                    f.write(f"  技术: {summary.get('total_techniques', 0)} 个\n")
                    f.write(f"  过程: {summary.get('total_procedures', 0)} 个\n")
                    
                    ttps = mitre.get('ttps', {})
                    if ttps.get('tactics'):
                        f.write(f"  检测到的战术: {', '.join(ttps.get('tactics', []))}\n")
                    if ttps.get('techniques'):
                        f.write(f"  检测到的技术: {', '.join(ttps.get('techniques', [])[:10])}\n")
                f.write("\n")
                
                # 攻击归因
                f.write("【攻击归因】\n")
                attribution = report.get('attribution', {})
                if attribution:
                    apt_candidates = attribution.get('apt_candidates', [])
                    if apt_candidates:
                        top_apt = apt_candidates[0]
                        f.write(f"  最可能的组织: {top_apt.get('apt_name')}\n")
                        f.write(f"  置信度: {top_apt.get('confidence')}\n")
                        f.write(f"  匹配分数: {top_apt.get('match_score', 0):.2f}\n")
                    else:
                        f.write("  未匹配到已知APT组织\n")
                f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write("详细报告请查看 JSON 文件\n")
                f.write("=" * 70 + "\n")
            
            logger.info(f"摘要报告已保存: {summary_file}")
            
            # 3. 保存最新报告链接（方便查看）
            latest_json = OUTPUT_DIR / "latest_report.json"
            latest_summary = OUTPUT_DIR / "latest_summary.txt"
            
            import shutil
            shutil.copy2(json_file, latest_json)
            shutil.copy2(summary_file, latest_summary)
            logger.info(f"最新报告已更新: {latest_json}, {latest_summary}")
            
        except Exception as e:
            logger.error(f"保存报告失败: {str(e)}", exc_info=True)

    def _extract_iocs(self, attack_chains: Dict, patterns: Dict) -> list:
        """从分析结果中提取 IOC"""
        iocs = []
        
        # 从攻击链中提取（简化实现）
        # 实际应该从 Neo4j 查询相关的 IP、域名、文件哈希
        
        return iocs

    def quick_analysis(self, suspicious_ip: str = None, suspicious_process: str = None):
        """
        快速分析 - 针对可疑指标
        
        Args:
            suspicious_ip: 可疑 IP
            suspicious_process: 可疑进程名
        """
        logger.info("执行快速分析...")
        
        result = {}
        
        if suspicious_ip:
            # 从 IP 追溯攻击链
            chain = self.chain_builder.build_attack_chain(suspicious_ip=suspicious_ip)
            result["ip_based_chain"] = chain
            
            # IP 情报查询
            intel = self.threat_intel.enrich_ip(suspicious_ip)
            result["ip_intelligence"] = intel
        
        if suspicious_process:
            # 从进程追溯攻击链
            chain = self.chain_builder.build_attack_chain(suspicious_process=suspicious_process)
            result["process_based_chain"] = chain
        
        return result


# ==========================================
# 测试/单独运行
# ==========================================
if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    pipeline = AnalysisPipeline()

    print("=" * 70)
    print("FusionTrace Analysis Pipeline")
    print("=" * 70)

    # 执行完整分析
    report = pipeline.analyze(time_range_hours=24)
    
    # 输出摘要
    print("\n分析摘要:")
    print(f"  攻击链: {report['attack_chains'].get('total_count', 0)} 条")
    print(f"  横向移动: {len(report.get('lateral_movement', []))} 个")
    print(f"  数据外泄: {len(report.get('data_exfiltration', []))} 个")
    
    if report.get('mitre_analysis'):
        mitre = report['mitre_analysis'].get('summary', {})
        print(f"  MITRE 战术: {mitre.get('total_tactics', 0)} 个")
        print(f"  MITRE 技术: {mitre.get('total_techniques', 0)} 个")
    
    if report.get('attribution', {}).get('apt_candidates'):
        apt = report['attribution']['apt_candidates'][0]
        print(f"  归因结果: {apt.get('apt_name')} (置信度: {apt.get('confidence')})")

    print("\n" + "=" * 70)
    print("报告已保存到:")
    print(f"  完整报告: {OUTPUT_DIR / 'latest_report.json'}")
    print(f"  摘要报告: {OUTPUT_DIR / 'latest_summary.txt'}")
    print("=" * 70)
