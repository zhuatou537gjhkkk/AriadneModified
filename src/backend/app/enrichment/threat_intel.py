"""
ThreatIntelligence 模块

提供对 IP、域名与文件哈希的外部情报查询与本地简单分析（如 DGA 检测），并带有
本地缓存机制以减少重复调用。模块包含示例的第三方 API 调用封装（AbuseIPDB、VirusTotal、AlienVault），
以及批量增强接口 `batch_enrich`。

主要类与方法：
- `ThreatIntelligence.enrich_ip(ip)` / `enrich_domain(domain)` / `enrich_file_hash(hash)`：单个指标情报增强。
- `batch_enrich(indicators)`：对多个 IOC 批量增强。
- `_query_*`：示例性的第三方 API 查询封装（需要配置 API key）。
- 本地方法如 `_detect_dga`、缓存管理 `_get_cache` / `_set_cache`。
"""

import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger("FusionTrace.ThreatIntel")


class ThreatIntelligence:
    """
    威胁情报模块
    
    职责:
    1. IP 信誉查询
    2. 域名信誉查询
    3. 文件哈希查询
    4. 缓存管理
    5. 多源情报聚合
    """

    def __init__(self, cache_ttl_hours: int = 24):
        """
        初始化威胁情报模块
        
        Args:
            cache_ttl_hours: 缓存过期时间（小时）
        """
        self.cache = {}
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        
        # API 配置（实际使用时需要配置真实的 API Key）
        self.abuseipdb_api_key = ""
        self.virustotal_api_key = ""
        self.alienvault_api_key = ""

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        IP 地址情报增强
        
        查询:
        1. 是否是已知恶意IP
        2. 地理位置
        3. ASN 信息
        4. 历史攻击记录
        
        Args:
            ip_address: IP地址
        
        Returns:
            情报数据
        """
        # 检查缓存
        cache_key = f"ip_{ip_address}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        intel = {
            "ip_address": ip_address,
            "is_malicious": False,
            "threat_score": 0,
            "sources": [],
            "tags": [],
            "geolocation": {},
            "last_updated": datetime.now().isoformat()
        }

        # 1. AbuseIPDB 查询
        abuse_data = self._query_abuseipdb(ip_address)
        if abuse_data:
            intel["is_malicious"] = abuse_data.get("abuseConfidenceScore", 0) > 75
            intel["threat_score"] = abuse_data.get("abuseConfidenceScore", 0)
            intel["sources"].append("AbuseIPDB")
            intel["tags"].extend(abuse_data.get("usageType", []))
            intel["geolocation"] = {
                "country": abuse_data.get("countryCode"),
                "isp": abuse_data.get("isp")
            }

        # 2. VirusTotal 查询
        vt_data = self._query_virustotal_ip(ip_address)
        if vt_data:
            intel["sources"].append("VirusTotal")
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 3:
                intel["is_malicious"] = True
                intel["threat_score"] = max(intel["threat_score"], malicious_count * 10)

        # 3. AlienVault OTX 查询
        otx_data = self._query_alienvault_ip(ip_address)
        if otx_data:
            intel["sources"].append("AlienVault OTX")
            if otx_data.get("pulse_info", {}).get("count", 0) > 0:
                intel["is_malicious"] = True
                intel["tags"].extend(otx_data.get("tags", []))

        # 保存缓存
        self._set_cache(cache_key, intel)

        return intel

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        域名情报增强
        
        查询:
        1. 是否是钓鱼域名
        2. DGA（域名生成算法）检测
        3. 域名年龄
        4. SSL 证书信息
        """
        cache_key = f"domain_{domain}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        intel = {
            "domain": domain,
            "is_malicious": False,
            "threat_score": 0,
            "sources": [],
            "tags": [],
            "registration_date": None,
            "last_updated": datetime.now().isoformat()
        }

        # 1. VirusTotal 域名查询
        vt_data = self._query_virustotal_domain(domain)
        if vt_data:
            intel["sources"].append("VirusTotal")
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 3:
                intel["is_malicious"] = True
                intel["threat_score"] = malicious_count * 10

        # 2. 域名特征分析（本地检测）
        intel["is_dga"] = self._detect_dga(domain)
        if intel["is_dga"]:
            intel["tags"].append("DGA")
            intel["threat_score"] += 50

        # 3. 新注册域名检测（通常用于钓鱼）
        intel["is_newly_registered"] = self._is_newly_registered(domain)
        if intel["is_newly_registered"]:
            intel["tags"].append("NewlyRegistered")
            intel["threat_score"] += 30

        self._set_cache(cache_key, intel)
        return intel

    def enrich_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        文件哈希情报增强
        
        查询:
        1. 是否是已知恶意文件
        2. 文件类型
        3. 关联的恶意软件家族
        """
        cache_key = f"hash_{file_hash}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        intel = {
            "file_hash": file_hash,
            "is_malicious": False,
            "threat_score": 0,
            "sources": [],
            "malware_family": None,
            "file_type": None,
            "last_updated": datetime.now().isoformat()
        }

        # VirusTotal 文件查询
        vt_data = self._query_virustotal_file(file_hash)
        if vt_data:
            intel["sources"].append("VirusTotal")
            attrs = vt_data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 5:
                intel["is_malicious"] = True
                intel["threat_score"] = min(malicious_count * 10, 100)
            
            intel["file_type"] = attrs.get("type_description")
            intel["malware_family"] = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")

        self._set_cache(cache_key, intel)
        return intel

    def batch_enrich(self, indicators: List[Dict]) -> List[Dict]:
        """
        批量情报增强
        
        Args:
            indicators: 指标列表
                [
                    {"type": "ip", "value": "1.1.1.1"},
                    {"type": "domain", "value": "malicious.com"},
                    {"type": "hash", "value": "abc123..."}
                ]
        
        Returns:
            增强后的指标列表
        """
        enriched = []
        
        for indicator in indicators:
            ioc_type = indicator.get("type")
            ioc_value = indicator.get("value")
            
            if ioc_type == "ip":
                intel = self.enrich_ip(ioc_value)
            elif ioc_type == "domain":
                intel = self.enrich_domain(ioc_value)
            elif ioc_type == "hash":
                intel = self.enrich_file_hash(ioc_value)
            else:
                intel = {}
            
            enriched.append({
                **indicator,
                "intelligence": intel
            })
        
        return enriched

    # ==========================================
    # API 查询方法（示例实现）
    # ==========================================

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """查询 AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get("data")
        except Exception as e:
            logger.debug(f"AbuseIPDB 查询失败: {str(e)}")
        
        return None

    def _query_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """查询 VirusTotal IP"""
        if not self.virustotal_api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"VirusTotal IP 查询失败: {str(e)}")
        
        return None

    def _query_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """查询 VirusTotal 域名"""
        if not self.virustotal_api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"VirusTotal Domain 查询失败: {str(e)}")
        
        return None

    def _query_virustotal_file(self, file_hash: str) -> Optional[Dict]:
        """查询 VirusTotal 文件"""
        if not self.virustotal_api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.virustotal_api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"VirusTotal File 查询失败: {str(e)}")
        
        return None

    def _query_alienvault_ip(self, ip: str) -> Optional[Dict]:
        """查询 AlienVault OTX"""
        if not self.alienvault_api_key:
            return None

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.alienvault_api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"AlienVault 查询失败: {str(e)}")
        
        return None

    # ==========================================
    # 本地检测方法
    # ==========================================

    def _detect_dga(self, domain: str) -> bool:
        """
        DGA（域名生成算法）检测
        
        特征:
        1. 高熵值
        2. 随机字符串
        3. 缺少元音字母
        """
        subdomain = domain.split(".")[0]
        
        # 检查长度（DGA 通常很长）
        if len(subdomain) > 20:
            return True
        
        # 检查元音比例
        vowels = "aeiou"
        vowel_count = sum(1 for c in subdomain.lower() if c in vowels)
        vowel_ratio = vowel_count / len(subdomain) if subdomain else 0
        
        if vowel_ratio < 0.2:  # 元音比例过低
            return True
        
        # 检查数字比例
        digit_count = sum(1 for c in subdomain if c.isdigit())
        digit_ratio = digit_count / len(subdomain) if subdomain else 0
        
        if digit_ratio > 0.3:  # 数字比例过高
            return True
        
        return False

    def _is_newly_registered(self, domain: str) -> bool:
        """
        检测是否是新注册域名（简化实现）
        
        实际应该查询 WHOIS 数据库
        """
        # 这里简化处理，实际应该查询 WHOIS
        return False

    # ==========================================
    # 缓存管理
    # ==========================================

    def _get_cache(self, key: str) -> Optional[Dict]:
        """获取缓存"""
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.cache_ttl:
                return data
            else:
                del self.cache[key]
        return None

    def _set_cache(self, key: str, value: Dict):
        """设置缓存"""
        self.cache[key] = (value, datetime.now())

    def clear_cache(self):
        """清空缓存"""
        self.cache.clear()
        logger.info("威胁情报缓存已清空")


# ==========================================
# 测试入口
# ==========================================
if __name__ == "__main__":
    import json

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    intel = ThreatIntelligence()

    print("=" * 70)
    print("FusionTrace ThreatIntelligence - 测试")
    print("=" * 70)

    # 测试1: IP 情报查询
    print("\n[测试 1] IP 情报查询")
    ip_intel = intel.enrich_ip("1.1.1.1")
    print(json.dumps(ip_intel, indent=2))

    # 测试2: 域名情报查询
    print("\n[测试 2] 域名情报查询")
    domain_intel = intel.enrich_domain("malicious.com")
    print(json.dumps(domain_intel, indent=2))

    # 测试3: DGA 检测
    print("\n[测试 3] DGA 检测")
    test_domains = [
        "google.com",  # 正常域名
        "dGVzdGRhdGF0ZXN0ZGF0YXRlc3RkYXRh.com",  # 疑似 DGA
        "abc123def456ghi789.com"  # 疑似 DGA
    ]
    for domain in test_domains:
        is_dga = intel._detect_dga(domain)
        print(f"{domain}: {'DGA' if is_dga else 'Normal'}")

    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
