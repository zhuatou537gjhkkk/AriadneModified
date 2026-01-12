"""
图算法分析 - 攻击模式匹配
"""
import logging
from typing import List, Dict, Any
from app.etl.graph_sync import GraphSync

logger = logging.getLogger("FusionTrace.GraphAlgo")


class GraphAlgorithms:
    """图算法 - 攻击模式检测"""

    def __init__(self, graph_sync: GraphSync = None):
        self.graph_sync = graph_sync or GraphSync()

    def find_attack_patterns(self, pattern_type: str) -> List[Dict]:
        """
        查找攻击模式
        
        Args:
            pattern_type: 攻击模式类型
                - reverse_shell: 反弹Shell
                - credential_dump: 凭据转储
                - lateral_movement: 横向移动
                - webshell: WebShell
        """
        if pattern_type == "reverse_shell":
            return self._find_reverse_shell()
        elif pattern_type == "credential_dump":
            return self._find_credential_dump()
        elif pattern_type == "lateral_movement":
            return self._find_lateral_movement()
        elif pattern_type == "webshell":
            return self._find_webshell()
        else:
            logger.warning(f"未知的攻击模式: {pattern_type}")
            return []

    def _find_reverse_shell(self) -> List[Dict]:
        """检测反弹Shell模式: 进程创建 -> 网络连接到外部"""
        query = """
        MATCH (parent:Process)-[:SPAWNED]->(shell:Process)
        WHERE shell.process_name IN ['nc.exe', 'cmd.exe', 'bash', 'sh']
          AND (shell.command_line CONTAINS '4444' 
               OR shell.command_line CONTAINS 'nc.exe -e'
               OR shell.command_line CONTAINS '/bin/bash -i')
        RETURN 
            parent.process_id as parent_pid,
            parent.process_name as parent_name,
            shell.process_id as shell_pid,
            shell.process_name as shell_name,
            shell.command_line as command,
            shell.host_id as host_id,
            shell.start_time as timestamp
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            patterns = []
            
            for record in results:
                patterns.append({
                    "pattern_type": "reverse_shell",
                    "severity": "critical",
                    "parent_process": f"{record.get('parent_name')} (PID: {record.get('parent_pid')})",
                    "shell_process": f"{record.get('shell_name')} (PID: {record.get('shell_pid')})",
                    "command_line": record.get('command'),
                    "host_id": record.get('host_id'),
                    "timestamp": record.get('timestamp'),
                    "description": "检测到反弹Shell行为"
                })
            
            logger.info(f"检测到 {len(patterns)} 个反弹Shell模式")
            return patterns
        except Exception as e:
            logger.error(f"反弹Shell检测失败: {str(e)}", exc_info=True)
            return []

    def _find_credential_dump(self) -> List[Dict]:
        """检测凭据转储: mimikatz, lsass访问"""
        query = """
        MATCH (p:Process)
        WHERE p.process_name IN ['mimikatz.exe', 'procdump.exe', 'dumpert.exe']
           OR p.command_line CONTAINS 'lsass'
           OR p.command_line CONTAINS 'sekurlsa'
           OR p.command_line CONTAINS 'privilege::debug'
        RETURN 
            p.process_id as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.start_time as timestamp
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            patterns = []
            
            for record in results:
                patterns.append({
                    "pattern_type": "credential_dump",
                    "severity": "critical",
                    "process": f"{record.get('name')} (PID: {record.get('pid')})",
                    "command_line": record.get('command'),
                    "host_id": record.get('host_id'),
                    "timestamp": record.get('timestamp'),
                    "description": "检测到凭据窃取行为"
                })
            
            logger.info(f"检测到 {len(patterns)} 个凭据转储模式")
            return patterns
        except Exception as e:
            logger.error(f"凭据转储检测失败: {str(e)}", exc_info=True)
            return []

    def _find_lateral_movement(self) -> List[Dict]:
        """检测横向移动: PsExec, WMI, PowerShell远程"""
        query = """
        MATCH (p:Process)
        WHERE p.process_name IN ['psexec.exe', 'wmic.exe', 'winrs.exe']
           OR (p.process_name = 'powershell.exe' AND p.command_line CONTAINS 'Invoke-Command')
           OR p.command_line CONTAINS 'psexec'
        RETURN 
            p.process_id as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.start_time as timestamp
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            patterns = []
            
            for record in results:
                patterns.append({
                    "pattern_type": "lateral_movement",
                    "severity": "high",
                    "process": f"{record.get('name')} (PID: {record.get('pid')})",
                    "command_line": record.get('command'),
                    "host_id": record.get('host_id'),
                    "timestamp": record.get('timestamp'),
                    "description": "检测到横向移动工具"
                })
            
            logger.info(f"检测到 {len(patterns)} 个横向移动模式")
            return patterns
        except Exception as e:
            logger.error(f"横向移动检测失败: {str(e)}", exc_info=True)
            return []

    def _find_webshell(self) -> List[Dict]:
        """检测WebShell: Web进程衍生Shell"""
        query = """
        MATCH (web:Process)-[:SPAWNED]->(shell:Process)
        WHERE web.process_name IN ['w3wp.exe', 'httpd', 'apache2', 'nginx', 'tomcat']
          AND shell.process_name IN ['cmd.exe', 'powershell.exe', 'bash', 'sh']
        RETURN 
            web.process_id as web_pid,
            web.process_name as web_name,
            shell.process_id as shell_pid,
            shell.process_name as shell_name,
            shell.command_line as command,
            shell.host_id as host_id,
            shell.start_time as timestamp
        LIMIT 50
        """
        
        try:
            results = self.graph_sync.execute_query(query, {})
            patterns = []
            
            for record in results:
                patterns.append({
                    "pattern_type": "webshell",
                    "severity": "critical",
                    "web_process": f"{record.get('web_name')} (PID: {record.get('web_pid')})",
                    "shell_process": f"{record.get('shell_name')} (PID: {record.get('shell_pid')})",
                    "command_line": record.get('command'),
                    "host_id": record.get('host_id'),
                    "timestamp": record.get('timestamp'),
                    "description": "检测到WebShell后门"
                })
            
            logger.info(f"检测到 {len(patterns)} 个WebShell模式")
            return patterns
        except Exception as e:
            logger.error(f"WebShell检测失败: {str(e)}", exc_info=True)
            return []


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    algo = GraphAlgorithms()
    
    print("=" * 70)
    print("测试攻击模式检测")
    print("=" * 70)
    
    patterns = [
        "reverse_shell",
        "credential_dump",
        "lateral_movement",
        "webshell"
    ]
    
    for pattern in patterns:
        results = algo.find_attack_patterns(pattern)
        print(f"\n{pattern}: {len(results)} 个")
