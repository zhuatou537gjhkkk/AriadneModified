"""
Attribution 模块

实现基于 TTP（战术/技术/过程）特征和情报数据的攻击归因分析。模块会
提取 TTP、匹配已知 APT 画像、进行基础设施情报增强并计算综合归因评分，
最终返回结构化的归因报告与建议。

主要类与方法：
- `Attribution.attribute_attack(attack_chain, iocs)`：主入口，返回归因分析报告。
- `_analyze_infrastructure` / `_analyze_tactic_preferences` / `_analyze_tools`：用于构建归因证据链的子方法。
- `_calculate_attribution_score` / `_get_confidence_level`：评分与置信度评估逻辑。
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.analysis.mitre_mapper import MITREMapper
from app.enrichment.threat_intel import ThreatIntelligence

logger = logging.getLogger("FusionTrace.Attribution")


class Attribution:
    """
    攻击归因模块
    
    职责:
    1. APT 组织画像
    2. 基于 TTP 特征的归因分析
    3. 基础设施关联
    4. 历史攻击关联
    5. 生成归因报告
    """

    def __init__(self):
        """初始化归因模块"""
        self.mitre_mapper = MITREMapper()
        self.threat_intel = ThreatIntelligence()

    def attribute_attack(
        self,
        attack_chain: Dict[str, Any],
        iocs: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        攻击归因分析
        
        Args:
            attack_chain: 攻击链数据（来自 ChainBuilder）
            iocs: IOC 指标列表（IP、域名、文件哈希）
        
        Returns:
            归因分析报告
        """
        logger.info("开始攻击归因分析...")

        # 1. 提取 TTP 特征
        ttps = self.mitre_mapper.extract_ttps(attack_chain)
        
        # 2. 匹配 APT 组织
        apt_matches = self.mitre_mapper.match_apt_group(ttps)
        
        # 3. 基础设施关联
        infrastructure_intel = self._analyze_infrastructure(iocs or [])
        
        # 4. 战术偏好分析
        tactic_preferences = self._analyze_tactic_preferences(ttps)
        
        # 5. 工具特征分析
        tool_signatures = self._analyze_tools(attack_chain)
        
        # 6. 综合归因评分
        attribution_score = self._calculate_attribution_score(
            apt_matches,
            infrastructure_intel,
            ttps
        )

        report = {
            "attribution_summary": {
                "confidence_level": self._get_confidence_level(attribution_score),
                "attribution_score": attribution_score,
                "primary_suspect": apt_matches[0] if apt_matches else None,
                "analysis_time": datetime.now().isoformat()
            },
            "apt_candidates": apt_matches[:5],  # Top 5
            "ttp_profile": {
                "tactics": ttps.get("tactics", []),
                "techniques": ttps.get("techniques", []),
                "tactic_preferences": tactic_preferences
            },
            "infrastructure_analysis": infrastructure_intel,
            "tool_signatures": tool_signatures,
            "historical_correlation": self._find_historical_correlation(ttps),
            "recommendations": self._generate_attribution_recommendations(apt_matches)
        }

        logger.info(f"归因分析完成，置信度: {report['attribution_summary']['confidence_level']}")
        
        return report

    def _analyze_infrastructure(self, iocs: List[Dict]) -> Dict[str, Any]:
        """
        基础设施分析
        
        分析攻击者使用的 IP、域名、服务器等基础设施
        """
        infrastructure = {
            "ips": [],
            "domains": [],
            "c2_servers": [],
            "geolocation": {},
            "hosting_providers": set()
        }

        # 情报增强
        enriched_iocs = self.threat_intel.batch_enrich(iocs)

        for ioc in enriched_iocs:
            intel = ioc.get("intelligence", {})
            ioc_type = ioc.get("type")
            
            if ioc_type == "ip":
                infrastructure["ips"].append({
                    "value": ioc.get("value"),
                    "is_malicious": intel.get("is_malicious"),
                    "threat_score": intel.get("threat_score"),
                    "country": intel.get("geolocation", {}).get("country"),
                    "isp": intel.get("geolocation", {}).get("isp")
                })
                
                # 统计地理位置
                country = intel.get("geolocation", {}).get("country")
                if country:
                    infrastructure["geolocation"][country] = \
                        infrastructure["geolocation"].get(country, 0) + 1
                
                # 识别 C2 服务器
                if intel.get("is_malicious") and intel.get("threat_score", 0) > 70:
                    infrastructure["c2_servers"].append(ioc.get("value"))
            
            elif ioc_type == "domain":
                infrastructure["domains"].append({
                    "value": ioc.get("value"),
                    "is_malicious": intel.get("is_malicious"),
                    "threat_score": intel.get("threat_score"),
                    "is_dga": intel.get("is_dga"),
                    "tags": intel.get("tags", [])
                })

        infrastructure["hosting_providers"] = list(infrastructure["hosting_providers"])
        
        return infrastructure

    def _analyze_tactic_preferences(self, ttps: Dict) -> Dict[str, float]:
        """
        分析战术偏好
        
        统计攻击者在各个战术阶段的活跃程度
        """
        tactic_names = {
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration",
            "TA0011": "Command and Control",
            "TA0040": "Impact"
        }

        detected_tactics = ttps.get("tactics", [])
        total_count = len(detected_tactics)

        preferences = {}
        for tactic_id in detected_tactics:
            tactic_name = tactic_names.get(tactic_id, "Unknown")
            preferences[tactic_name] = preferences.get(tactic_name, 0) + 1

        # 转换为百分比
        if total_count > 0:
            preferences = {k: v / total_count for k, v in preferences.items()}

        return preferences

    def _analyze_tools(self, attack_chain: Dict) -> List[Dict]:
        """
        分析攻击工具特征
        
        识别使用的攻击工具、脚本、恶意软件
        """
        tools = []
        seen_tools = set()

        chains = attack_chain.get("chains", [])
        
        for chain in chains:
            if isinstance(chain, dict):
                # 支持新的多节点链结构
                chain_nodes = chain.get("chain", [])
                if chain_nodes:
                    # 新格式：chain 是节点数组
                    processes = chain_nodes
                else:
                    # 向后兼容旧格式：从 parent 和 child 提取
                    processes = []
                    parent = chain.get("parent")
                    child = chain.get("child")
                    if parent:
                        processes.append(parent)
                    if child:
                        processes.append(child)
                
                for proc in processes:
                    if isinstance(proc, dict):
                        process_name = (proc.get("name") or "").lower()
                        command = (proc.get("command") or "").lower()
                        
                        # 识别常见攻击工具
                        tool_patterns = {
                            "mimikatz": "Credential Dumping",
                            "powershell": "Script Execution",
                            "psexec": "Lateral Movement",
                            "netcat": "Reverse Shell",
                            "meterpreter": "Post-Exploitation",
                            "cobalt": "C2 Framework",
                            "empire": "Post-Exploitation Framework",
                            "bloodhound": "AD Enumeration"
                        }
                        
                        for tool, category in tool_patterns.items():
                            if tool in process_name or tool in command:
                                if tool not in seen_tools:
                                    tools.append({
                                        "tool": tool,
                                        "category": category,
                                        "process": proc.get("process_name"),
                                        "timestamp": proc.get("when")
                                    })
                                    seen_tools.add(tool)

        return tools

    def _calculate_attribution_score(
        self,
        apt_matches: List[Dict],
        infrastructure: Dict,
        ttps: Dict
    ) -> float:
        """
        计算归因置信度评分（0-100）
        
        评分因素:
        1. APT 匹配度 (40%)
        2. 基础设施情报 (30%)
        3. TTP 完整性 (30%)
        """
        score = 0.0

        # 1. APT 匹配评分
        if apt_matches:
            top_match = apt_matches[0]
            apt_score = top_match.get("match_score", 0) * 40
            score += apt_score

        # 2. 基础设施评分
        c2_count = len(infrastructure.get("c2_servers", []))
        malicious_ip_count = sum(
            1 for ip in infrastructure.get("ips", [])
            if ip.get("is_malicious")
        )
        if malicious_ip_count > 0:
            infra_score = min((c2_count * 10 + malicious_ip_count * 5), 30)
            score += infra_score

        # 3. TTP 完整性评分
        tactic_count = len(ttps.get("tactics", []))
        technique_count = len(ttps.get("techniques", []))
        ttp_completeness = min((tactic_count * 3 + technique_count), 30)
        score += ttp_completeness

        return min(score, 100.0)

    def _get_confidence_level(self, score: float) -> str:
        """
        根据评分获取置信度级别
        """
        if score >= 80:
            return "High"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "Low"
        else:
            return "Very Low"

    def _find_historical_correlation(self, ttps: Dict) -> List[Dict]:
        """
        历史攻击关联
        
        查找使用相似 TTP 的历史攻击
        """
        # 这里简化处理，实际应该查询历史数据库
        return [
            {
                "attack_id": "ATK-2025-001",
                "date": "2025-12-15",
                "similarity_score": 0.85,
                "common_techniques": ["T1059.001", "T1003.001"]
            }
        ]

    def _generate_attribution_recommendations(
        self,
        apt_matches: List[Dict]
    ) -> List[str]:
        """
        生成归因建议
        """
        recommendations = []

        if not apt_matches:
            recommendations.append("未能明确归因到特定 APT 组织，建议收集更多 IOC 和 TTP 信息")
            return recommendations

        top_apt = apt_matches[0]
        confidence = top_apt.get("confidence")

        if confidence == "High":
            recommendations.append(
                f"高置信度归因到 {top_apt['apt_name']}，"
                f"建议查阅该组织的最新威胁情报和防御策略"
            )
            recommendations.append(
                f"重点关注该组织常用的技术: {', '.join(top_apt.get('matched_techniques', []))}"
            )
        elif confidence == "Medium":
            recommendations.append(
                f"中等置信度归因到 {top_apt['apt_name']}，"
                f"建议进一步收集证据以提高归因准确性"
            )
        else:
            recommendations.append(
                f"低置信度归因，TTP 特征与 {top_apt['apt_name']} 部分匹配，"
                f"但需要更多证据支持"
            )

        recommendations.append("建议共享 IOC 到威胁情报社区，获取更多关联信息")
        recommendations.append("建议进行攻击溯源演练，验证归因结论")

        return recommendations

    def generate_apt_profile(self, apt_name: str) -> Dict[str, Any]:
        """
        生成 APT 组织画像
        
        Args:
            apt_name: APT 组织名称
        
        Returns:
            组织画像
        """
        # APT 组织数据库（简化版）
        apt_database = {
            "APT28": {
                "name": "APT28 (Fancy Bear)",
                "aliases": ["Sofacy", "Sednit", "STRONTIUM"],
                "country": "Russia",
                "active_since": "2004",
                "targets": ["Government", "Military", "Energy"],
                "signature_ttps": {
                    "tactics": ["Initial Access", "Execution", "Persistence"],
                    "techniques": ["T1059.001", "T1021.001", "T1071.001"],
                    "tools": ["X-Agent", "Komplex", "Zebrocy"]
                },
                "infrastructure": {
                    "typical_hosting": ["Bullet-proof hosting", "Compromised infrastructure"],
                    "typical_domains": ["Look-alike domains", "Typosquatting"]
                },
                "references": [
                    "https://attack.mitre.org/groups/G0007/",
                    "https://www.fireeye.com/current-threats/apt-groups.html"
                ]
            }
        }

        profile = apt_database.get(apt_name)
        
        if not profile:
            return {
                "error": f"APT 组织 {apt_name} 未在数据库中找到",
                "suggestions": list(apt_database.keys())
            }

        return profile


# ==========================================
# 测试入口
# ==========================================
if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    attribution = Attribution()

    print("=" * 70)
    print("FusionTrace Attribution - 测试")
    print("=" * 70)

    # 测试1: APT 组织画像
    print("\n[测试 1] APT28 组织画像")
    profile = attribution.generate_apt_profile("APT28")
    print(json.dumps(profile, indent=2))

    # 测试2: 攻击归因
    print("\n[测试 2] 攻击归因分析")
    test_chain = {
        "chains": [{
            "chains": [
                {
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc ...",
                    "when": "2026-01-12T10:00:00"
                },
                {
                    "process_name": "mimikatz.exe",
                    "command_line": "mimikatz.exe",
                    "when": "2026-01-12T10:05:00"
                }
            ]
        }]
    }
    test_iocs = [
        {"type": "ip", "value": "1.1.1.1"},
        {"type": "domain", "value": "malicious.com"}
    ]
    
    attribution_report = attribution.attribute_attack(test_chain, test_iocs)
    print(json.dumps(attribution_report, indent=2, default=str))

    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
