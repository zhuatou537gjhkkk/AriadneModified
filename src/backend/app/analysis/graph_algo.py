"""
图算法与模式检测模块

提供一组基于图查询的攻击模式检测方法（例如反弹 Shell、凭据转储、横向移动、WebShell）。
使用 `GraphSync.execute_query` 执行 Cypher 查询并将结果转换为结构化的检测记录。

主要类与方法：
- `GraphAlgorithms.find_attack_patterns(pattern_type)`：根据类型分发到具体检测方法。
- `_find_reverse_shell` / `_find_credential_dump` / `_find_lateral_movement` / `_find_webshell`
 ：实现具体的 Cypher 查询与结果解析逻辑。
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
            parent.pid as parent_pid,
            parent.process_name as parent_name,
            shell.pid as shell_pid,
            shell.process_name as shell_name,
            shell.command_line as command,
            shell.host_id as host_id,
            shell.first_seen as timestamp
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
        WHERE toLower(p.process_name) IN ['mimikatz.exe', 'procdump.exe', 'dumpert.exe', 'procdump64.exe']
           OR toLower(p.command_line) CONTAINS 'lsass'
           OR toLower(p.command_line) CONTAINS 'sekurlsa'
           OR toLower(p.command_line) CONTAINS 'privilege::debug'
           OR toLower(p.command_line) CONTAINS 'mimikatz'
        RETURN 
            p.pid as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.first_seen as timestamp
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
        WHERE toLower(p.process_name) IN ['psexec.exe', 'psexec64.exe', 'psexesvc.exe', 'wmic.exe', 'winrs.exe']
           OR (toLower(p.process_name) = 'powershell.exe' AND toLower(p.command_line) CONTAINS 'invoke-command')
           OR toLower(p.command_line) CONTAINS 'psexec'
           OR toLower(p.command_line) CONTAINS '\\\\192.'
           OR toLower(p.command_line) CONTAINS '/node:'
        RETURN 
            p.pid as pid,
            p.process_name as name,
            p.command_line as command,
            p.host_id as host_id,
            p.first_seen as timestamp
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
            web.pid as web_pid,
            web.process_name as web_name,
            shell.pid as shell_pid,
            shell.process_name as shell_name,
            shell.command_line as command,
            shell.host_id as host_id,
            shell.first_seen as timestamp
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
