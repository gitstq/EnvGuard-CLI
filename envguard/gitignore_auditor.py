"""
EnvGuard-CLI .gitignore 安全审计模块

检查 .gitignore 文件的安全配置，包括：
- 是否包含 .env 相关规则
- 是否忽略了敏感文件类型
- 是否意外忽略了必要文件
- 提供改进建议
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class AuditSeverity(Enum):
    """审计严重等级"""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    OK = "OK"


@dataclass
class AuditFinding:
    """单条审计发现"""
    severity: AuditSeverity
    category: str
    message: str
    suggestion: str
    current_rule: Optional[str] = None
    recommended_rule: Optional[str] = None

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "suggestion": self.suggestion,
            "current_rule": self.current_rule,
            "recommended_rule": self.recommended_rule,
        }


@dataclass
class AuditResult:
    """审计结果汇总"""
    findings: List[AuditFinding] = field(default_factory=list)
    gitignore_exists: bool = False
    gitignore_path: str = ""
    rules_count: int = 0
    has_env_rules: bool = False
    has_sensitive_rules: bool = False
    has_essential_rules: bool = False

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.INFO)

    @property
    def ok_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == AuditSeverity.OK)

    @property
    def is_secure(self) -> bool:
        """是否通过安全审计（无 ERROR 和 WARNING）"""
        return self.error_count == 0 and self.warning_count == 0

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "summary": {
                "gitignore_exists": self.gitignore_exists,
                "gitignore_path": self.gitignore_path,
                "rules_count": self.rules_count,
                "has_env_rules": self.has_env_rules,
                "has_sensitive_rules": self.has_sensitive_rules,
                "has_essential_rules": self.has_essential_rules,
                "is_secure": self.is_secure,
                "by_severity": {
                    "ERROR": self.error_count,
                    "WARNING": self.warning_count,
                    "INFO": self.info_count,
                    "OK": self.ok_count,
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class GitignoreAuditor:
    """
    .gitignore 安全审计器。

    审计 .gitignore 文件的安全配置，检查是否正确忽略了
    敏感文件并保留了必要文件。
    """

    # 必须忽略的 .env 相关模式
    REQUIRED_ENV_PATTERNS: List[str] = [
        ".env",
        ".env.local",
        ".env.development.local",
        ".env.test.local",
        ".env.production.local",
        ".env.*.local",
    ]

    # 建议忽略的敏感文件模式
    RECOMMENDED_SENSITIVE_PATTERNS: List[Tuple[str, str]] = [
        ("*.pem", "PEM 格式证书/私钥文件"),
        ("*.key", "密钥文件"),
        ("*.p12", "PKCS#12 证书文件"),
        ("*.pfx", "PFX 证书文件"),
        ("*.jks", "Java KeyStore 文件"),
        ("*.keystore", "密钥库文件"),
        ("*.cert", "证书文件"),
        ("id_rsa*", "SSH RSA 私钥"),
        ("id_dsa*", "SSH DSA 私钥"),
        ("id_ecdsa*", "SSH ECDSA 私钥"),
        ("id_ed25519*", "SSH Ed25519 私钥"),
        ("*.credentials", "凭证文件"),
        ("*.secret", "密钥文件"),
        ("*credentials.json", "Google Cloud 凭证文件"),
        ("*service-account*.json", "服务账号凭证文件"),
    ]

    # 常见的意外忽略模式（不应被忽略的文件）
    UNEXPECTED_IGNORE_PATTERNS: List[Tuple[str, str]] = [
        ("*.py", "Python 源文件（不应全局忽略）"),
        ("*.js", "JavaScript 源文件（不应全局忽略）"),
        ("*.ts", "TypeScript 源文件（不应全局忽略）"),
        ("*.go", "Go 源文件（不应全局忽略）"),
        ("*.rs", "Rust 源文件（不应全局忽略）"),
        ("src/", "源代码目录"),
        ("*.json", "JSON 配置文件（不应全局忽略）"),
        ("*.yml", "YAML 配置文件（不应全局忽略）"),
        ("*.yaml", "YAML 配置文件（不应全局忽略）"),
        ("*.toml", "TOML 配置文件（不应全局忽略）"),
        ("README*", "README 文件"),
        ("LICENSE*", "许可证文件"),
        ("Dockerfile", "Docker 配置文件"),
        ("Makefile", "构建文件"),
    ]

    # 建议包含的基础规则
    RECOMMENDED_BASE_PATTERNS: List[Tuple[str, str]] = [
        ("__pycache__/", "Python 字节码缓存"),
        ("*.py[cod]", "Python 编译文件"),
        ("node_modules/", "Node.js 依赖目录"),
        (".DS_Store", "macOS 系统文件"),
        ("Thumbs.db", "Windows 缩略图缓存"),
        ("*.log", "日志文件"),
        (".venv/", "Python 虚拟环境"),
        ("venv/", "Python 虚拟环境"),
    ]

    def __init__(self, project_path: str = ".") -> None:
        """
        初始化审计器。

        Args:
            project_path: 项目根目录路径
        """
        self.project_path = os.path.abspath(project_path)
        self.gitignore_path = os.path.join(self.project_path, ".gitignore")

    def _parse_gitignore(self) -> List[str]:
        """
        解析 .gitignore 文件内容。

        Returns:
            .gitignore 中的规则列表（已去除注释和空行）
        """
        if not os.path.isfile(self.gitignore_path):
            return []

        rules: List[str] = []
        try:
            with open(self.gitignore_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    # 跳过空行和注释
                    if not line or line.startswith("#"):
                        continue
                    rules.append(line)
        except (OSError, IOError, PermissionError):
            pass

        return rules

    def _pattern_matches(self, pattern: str, rules: List[str]) -> bool:
        """
        检查规则列表中是否包含匹配的模式。

        Args:
            pattern: 待匹配的模式
            rules: 规则列表

        Returns:
            是否匹配
        """
        import fnmatch
        for rule in rules:
            if rule == pattern or fnmatch.fnmatch(pattern, rule):
                return True
        return False

    def _pattern_covered(self, pattern: str, rules: List[str]) -> bool:
        """
        检查某个模式是否被现有规则覆盖。

        Args:
            pattern: 待检查的模式
            rules: 现有规则列表

        Returns:
            是否被覆盖
        """
        import fnmatch

        # 精确匹配
        if pattern in rules:
            return True

        # 通配符匹配
        for rule in rules:
            if fnmatch.fnmatch(pattern, rule):
                return True

        # 检查目录级别覆盖（如 .env 被 .env.* 覆盖）
        if "." in pattern:
            parts = pattern.split(".")
            if len(parts) > 1:
                base_pattern = parts[0] + ".*"
                if base_pattern in rules:
                    return True

        return False

    def audit(self) -> AuditResult:
        """
        执行 .gitignore 安全审计。

        Returns:
            审计结果
        """
        result = AuditResult()
        result.gitignore_path = self.gitignore_path

        # 检查 .gitignore 是否存在
        if not os.path.isfile(self.gitignore_path):
            result.gitignore_exists = False
            result.findings.append(AuditFinding(
                severity=AuditSeverity.ERROR,
                category="missing_file",
                message="项目根目录下未找到 .gitignore 文件",
                suggestion="立即创建 .gitignore 文件并添加基本规则",
                recommended_rule=".env\n__pycache__/\n*.py[cod]\nnode_modules/\n",
            ))
            return result

        result.gitignore_exists = True
        rules = self._parse_gitignore()
        result.rules_count = len(rules)

        # ---- 检查 .env 相关规则 ----
        env_rules_found: List[str] = []
        env_rules_missing: List[str] = []

        for pattern in self.REQUIRED_ENV_PATTERNS:
            if self._pattern_covered(pattern, rules):
                env_rules_found.append(pattern)
            else:
                env_rules_missing.append(pattern)

        result.has_env_rules = len(env_rules_found) > 0

        if not env_rules_missing:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.OK,
                category="env_rules",
                message="所有必要的 .env 规则均已配置",
                suggestion="",
            ))
        else:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.ERROR,
                category="env_rules",
                message=f"缺少 {len(env_rules_missing)} 个 .env 忽略规则: {', '.join(env_rules_missing)}",
                suggestion="将以下规则添加到 .gitignore",
                recommended_rule="\n".join(env_rules_missing),
            ))

        # ---- 检查敏感文件规则 ----
        sensitive_found: List[str] = []
        sensitive_missing: List[str] = []

        for pattern, desc in self.RECOMMENDED_SENSITIVE_PATTERNS:
            if self._pattern_covered(pattern, rules):
                sensitive_found.append(pattern)
            else:
                sensitive_missing.append(pattern)

        result.has_sensitive_rules = len(sensitive_found) > 0

        if sensitive_missing:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.WARNING,
                category="sensitive_files",
                message=f"建议添加 {len(sensitive_missing)} 个敏感文件忽略规则",
                suggestion="以下文件类型可能包含密钥/证书，建议忽略",
                recommended_rule="\n".join(sensitive_missing),
            ))
        else:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.OK,
                category="sensitive_files",
                message="敏感文件忽略规则配置完善",
                suggestion="",
            ))

        # ---- 检查意外忽略 ----
        for pattern, desc in self.UNEXPECTED_IGNORE_PATTERNS:
            if pattern in rules:
                result.findings.append(AuditFinding(
                    severity=AuditSeverity.ERROR,
                    category="unexpected_ignore",
                    message=f"检测到可能意外忽略的规则: '{pattern}' ({desc})",
                    suggestion=f"请确认是否真的需要忽略 {desc}",
                    current_rule=pattern,
                ))

        # ---- 检查基础规则 ----
        base_found: List[str] = []
        base_missing: List[str] = []

        for pattern, desc in self.RECOMMENDED_BASE_PATTERNS:
            if self._pattern_covered(pattern, rules):
                base_found.append(pattern)
            else:
                base_missing.append(pattern)

        result.has_essential_rules = len(base_found) > 0

        if base_missing:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.INFO,
                category="base_rules",
                message=f"建议添加 {len(base_missing)} 个基础忽略规则",
                suggestion="以下规则有助于保持仓库整洁",
                recommended_rule="\n".join(base_missing),
            ))

        # ---- 检查 .env 文件是否已被跟踪 ----
        for env_file in [".env", ".env.local"]:
            env_path = os.path.join(self.project_path, env_file)
            if os.path.isfile(env_path):
                if env_file not in rules and not self._pattern_covered(env_file, rules):
                    result.findings.append(AuditFinding(
                        severity=AuditSeverity.ERROR,
                        category="tracked_env",
                        message=f"检测到 {env_file} 文件存在但未被 .gitignore 忽略",
                        suggestion=f"将 {env_file} 添加到 .gitignore，并从 Git 历史中移除",
                        recommended_rule=env_file,
                    ))

        # ---- 检查否定规则安全性 ----
        negation_rules = [r for r in rules if r.startswith("!")]
        for rule in negation_rules:
            negated_pattern = rule[1:]
            if any(
                sensitive in negated_pattern.lower()
                for sensitive in [".env", ".key", ".pem", ".secret", "credential"]
            ):
                result.findings.append(AuditFinding(
                    severity=AuditSeverity.WARNING,
                    category="negation_rule",
                    message=f"检测到敏感文件的否定规则: '{rule}'",
                    suggestion="否定规则将导致被忽略的敏感文件重新被跟踪，请确认是否安全",
                    current_rule=rule,
                ))

        # 如果没有发现任何问题
        if result.is_secure and result.findings:
            pass  # 已有 OK 发现
        elif not result.findings:
            result.findings.append(AuditFinding(
                severity=AuditSeverity.OK,
                category="general",
                message=".gitignore 配置安全",
                suggestion="",
            ))

        return result
