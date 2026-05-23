"""
EnvGuard-CLI 密钥扫描引擎模块

负责扫描文件和目录中的硬编码密钥、凭证和敏感信息。
支持 15+ 种文件类型，使用 80+ 内置正则规则进行匹配。
"""

import os
import re
import fnmatch
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from envguard.rules import (
    Rule,
    RuleCategory,
    Severity,
    get_all_rules,
    get_rule_by_name,
)


# 支持的文件扩展名
SUPPORTED_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
    ".rb", ".php", ".yml", ".yaml", ".json", ".toml", ".ini",
    ".cfg", ".env", ".sh", ".bash", ".zsh", ".fish",
    ".tf", ".hcl", ".properties", ".xml", ".gradle",
    ".cs", ".cpp", ".c", ".h", ".hpp",
    ".pem", ".key", ".p12", ".pfx", ".cert", ".crt", ".cer",
}

# 默认排除的目录
DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "__pycache__", "node_modules",
    "venv", ".venv", "env", ".env", "virtualenv",
    ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
    "dist", "build", ".gradle", "target", "vendor",
    ".idea", ".vscode", ".DS_Store",
}

# 二进制文件扩展名（跳过扫描）
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".class", ".o", ".obj",
}


@dataclass
class ScanMatch:
    """单条扫描匹配结果"""
    rule_name: str
    rule_category: RuleCategory
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    description: str

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "rule_name": self.rule_name,
            "rule_category": self.rule_category.value,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "matched_text": self.matched_text,
            "description": self.description,
        }


@dataclass
class ScanResult:
    """扫描结果汇总"""
    matches: List[ScanMatch] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    scan_duration: float = 0.0

    @property
    def total_findings(self) -> int:
        """总发现数"""
        return len(self.matches)

    @property
    def critical_count(self) -> int:
        """CRITICAL 级别发现数"""
        return sum(1 for m in self.matches if m.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """HIGH 级别发现数"""
        return sum(1 for m in self.matches if m.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """MEDIUM 级别发现数"""
        return sum(1 for m in self.matches if m.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """LOW 级别发现数"""
        return sum(1 for m in self.matches if m.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """INFO 级别发现数"""
        return sum(1 for m in self.matches if m.severity == Severity.INFO)

    def get_by_severity(self, severity: Severity) -> List[ScanMatch]:
        """按严重等级筛选匹配结果"""
        return [m for m in self.matches if m.severity == severity]

    def get_by_file(self, file_path: str) -> List[ScanMatch]:
        """按文件路径筛选匹配结果"""
        return [m for m in self.matches if m.file_path == file_path]

    def get_by_category(self, category: RuleCategory) -> List[ScanMatch]:
        """按分类筛选匹配结果"""
        return [m for m in self.matches if m.rule_category == category]

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "summary": {
                "total_findings": self.total_findings,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "by_severity": {
                    "CRITICAL": self.critical_count,
                    "HIGH": self.high_count,
                    "MEDIUM": self.medium_count,
                    "LOW": self.low_count,
                    "INFO": self.info_count,
                },
                "scan_duration_seconds": round(self.scan_duration, 3),
                "errors": self.errors,
            },
            "findings": [m.to_dict() for m in self.matches],
        }


class Scanner:
    """
    密钥扫描引擎。

    扫描文件和目录，使用正则规则检测硬编码的密钥和凭证。

    Attributes:
        rules: 扫描规则列表
        exclude_dirs: 排除的目录集合
        ignore_patterns: 忽略的文件 glob 模式
        min_severity: 最低严重等级过滤
        max_file_size: 单文件最大扫描大小（字节）
        progress_callback: 扫描进度回调函数
    """

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        exclude_dirs: Optional[Set[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
        min_severity: Optional[Severity] = None,
        max_file_size: int = 1024 * 1024,  # 1MB
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> None:
        """
        初始化扫描器。

        Args:
            rules: 自定义规则列表，为 None 时使用全部内置规则
            exclude_dirs: 排除的目录名集合
            ignore_patterns: 忽略的文件 glob 模式列表
            min_severity: 最低报告严重等级
            max_file_size: 单文件最大扫描字节数
            progress_callback: 进度回调 (current_file, files_done, total_files)
        """
        self.rules = rules if rules is not None else get_all_rules()
        self.exclude_dirs = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
        self.ignore_patterns = ignore_patterns if ignore_patterns is not None else []
        self.min_severity = min_severity
        self.max_file_size = max_file_size
        self.progress_callback = progress_callback

    def _severity_passes(self, severity: Severity) -> bool:
        """
        检查严重等级是否通过最低等级过滤。

        Args:
            severity: 待检查的严重等级

        Returns:
            是否通过过滤
        """
        if self.min_severity is None:
            return True
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return severity_order.index(severity) >= severity_order.index(self.min_severity)

    def _should_scan_file(self, file_path: str) -> bool:
        """
        判断文件是否应该被扫描。

        Args:
            file_path: 文件绝对路径

        Returns:
            是否应该扫描
        """
        # 检查忽略模式
        basename = os.path.basename(file_path)
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(file_path, pattern):
                return False

        # 检查文件扩展名
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        # 跳过二进制文件
        if ext in BINARY_EXTENSIONS:
            return False

        # .env 文件总是扫描
        if basename.startswith(".env") or ext == ".env":
            return True

        # 检查是否在支持的扩展名列表中
        return ext in SUPPORTED_EXTENSIONS

    def _should_scan_dir(self, dir_path: str) -> bool:
        """
        判断目录是否应该被扫描。

        Args:
            dir_path: 目录路径

        Returns:
            是否应该扫描
        """
        dir_name = os.path.basename(dir_path)
        return dir_name not in self.exclude_dirs

    def _read_file(self, file_path: str) -> Optional[str]:
        """
        安全读取文件内容。

        Args:
            file_path: 文件路径

        Returns:
            文件内容字符串，读取失败返回 None
        """
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return None
            if file_size == 0:
                return None

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except (OSError, IOError, PermissionError):
            return None

    def _scan_content(
        self,
        content: str,
        file_path: str,
    ) -> List[ScanMatch]:
        """
        扫描文件内容。

        Args:
            content: 文件文本内容
            file_path: 文件路径

        Returns:
            匹配结果列表
        """
        matches: List[ScanMatch] = []
        lines = content.splitlines()

        for rule in self.rules:
            if not self._severity_passes(rule.severity):
                continue

            for line_idx, line in enumerate(lines):
                rule_matches = rule.matches(line)
                for match in rule_matches:
                    matched_text = match.group(0)
                    # 跳过过短的匹配（减少误报）
                    if len(matched_text) < 8:
                        continue
                    # 跳过纯注释行中的示例值
                    stripped = line.strip()
                    if stripped.startswith("#") and any(
                        kw in stripped.lower()
                        for kw in ["example", "your-", "xxx", "changeme", "placeholder"]
                    ):
                        continue

                    scan_match = ScanMatch(
                        rule_name=rule.name,
                        rule_category=rule.category,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_idx + 1,
                        line_content=line,
                        matched_text=matched_text,
                        description=rule.description,
                    )
                    matches.append(scan_match)

        return matches

    def scan_file(self, file_path: str) -> List[ScanMatch]:
        """
        扫描单个文件。

        Args:
            file_path: 文件路径

        Returns:
            匹配结果列表
        """
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            return []

        if not self._should_scan_file(abs_path):
            return []

        content = self._read_file(abs_path)
        if content is None:
            return []

        return self._scan_content(content, abs_path)

    def scan_directory(self, dir_path: str) -> ScanResult:
        """
        递归扫描目录。

        Args:
            dir_path: 目录路径

        Returns:
            扫描结果汇总
        """
        import time

        start_time = time.time()
        result = ScanResult()
        abs_dir = os.path.abspath(dir_path)

        if not os.path.isdir(abs_dir):
            result.errors.append(f"目录不存在: {abs_dir}")
            return result

        # 收集所有待扫描文件
        all_files: List[str] = []
        for root, dirs, files in os.walk(abs_dir):
            # 过滤排除目录（原地修改 dirs 影响 os.walk 遍历）
            dirs[:] = [d for d in dirs if self._should_scan_dir(os.path.join(root, d))]

            for filename in files:
                file_path = os.path.join(root, filename)
                if self._should_scan_file(file_path):
                    all_files.append(file_path)

        total_files = len(all_files)

        # 逐文件扫描
        for idx, file_path in enumerate(all_files):
            if self.progress_callback:
                self.progress_callback(file_path, idx + 1, total_files)

            try:
                content = self._read_file(file_path)
                if content is None:
                    result.files_skipped += 1
                    continue

                matches = self._scan_content(content, file_path)
                result.matches.extend(matches)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"扫描 {file_path} 时出错: {str(e)}")
                result.files_skipped += 1

        result.scan_duration = time.time() - start_time
        return result

    def scan(self, path: str) -> ScanResult:
        """
        扫描文件或目录（自动判断）。

        Args:
            path: 文件或目录路径

        Returns:
            扫描结果汇总
        """
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path):
            import time
            start_time = time.time()
            result = ScanResult()
            matches = self.scan_file(abs_path)
            result.matches = matches
            result.files_scanned = 1 if matches or os.path.isfile(abs_path) else 0
            result.scan_duration = time.time() - start_time
            return result
        elif os.path.isdir(abs_path):
            return self.scan_directory(abs_path)
        else:
            result = ScanResult()
            result.errors.append(f"路径不存在: {abs_path}")
            return result
