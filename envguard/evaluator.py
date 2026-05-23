"""
EnvGuard-CLI 密钥强度评估器模块

负责评估发现的密钥/凭证的强度，包括长度分析、
熵值计算、类型识别和风险等级划分。
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from envguard.rules import RuleCategory, Severity
from envguard.scanner import ScanMatch


@dataclass
class KeyEvaluation:
    """单条密钥评估结果"""
    matched_text: str
    rule_name: str
    rule_category: RuleCategory
    severity: Severity
    length: int
    entropy: float
    key_type: str
    risk_level: Severity
    risk_reasons: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "matched_text": self.matched_text,
            "rule_name": self.rule_name,
            "rule_category": self.rule_category.value,
            "original_severity": self.severity.value,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "key_type": self.key_type,
            "risk_level": self.risk_level.value,
            "risk_reasons": self.risk_reasons,
            "suggestions": self.suggestions,
        }


@dataclass
class SecurityScore:
    """整体安全评分"""
    score: int  # 0-100
    grade: str  # A, B, C, D, F
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    average_entropy: float
    summary: str

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "score": self.score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "by_severity": {
                "CRITICAL": self.critical_count,
                "HIGH": self.high_count,
                "MEDIUM": self.medium_count,
                "LOW": self.low_count,
                "INFO": self.info_count,
            },
            "average_entropy": round(self.average_entropy, 4),
            "summary": self.summary,
        }


class KeyType(Enum):
    """密钥类型枚举"""
    API_KEY = "API Key"
    TOKEN = "Token"
    SECRET = "Secret"
    CONNECTION_STRING = "Connection String"
    PRIVATE_KEY = "Private Key"
    HIGH_ENTROPY = "High Entropy String"
    PASSWORD = "Password"
    UNKNOWN = "Unknown"


class Evaluator:
    """
    密钥强度评估器。

    对扫描发现的密钥/凭证进行强度评估，包括：
    - 长度分析
    - Shannon 熵值计算
    - 密钥类型识别
    - 风险等级评估
    - 整体安全评分
    """

    # 密钥长度阈值
    LENGTH_THRESHOLDS = {
        "very_short": 8,
        "short": 16,
        "medium": 24,
        "long": 32,
        "very_long": 64,
    }

    # 熵值阈值
    ENTROPY_THRESHOLDS = {
        "very_low": 2.0,
        "low": 3.0,
        "medium": 4.0,
        "high": 5.0,
        "very_high": 6.0,
    }

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        计算 Shannon 信息熵。

        Args:
            text: 输入文本

        Returns:
            Shannon 熵值（bits per character）
        """
        if not text:
            return 0.0

        # 过滤掉非字符内容，保留有意义部分
        filtered = re.sub(r'[^A-Za-z0-9+/=_\-.]', '', text)
        if not filtered:
            return 0.0

        length = len(filtered)
        if length == 0:
            return 0.0

        counter = Counter(filtered)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def identify_key_type(match: ScanMatch) -> str:
        """
        识别密钥类型。

        Args:
            match: 扫描匹配结果

        Returns:
            密钥类型描述字符串
        """
        category_map = {
            RuleCategory.API_KEY: KeyType.API_KEY,
            RuleCategory.TOKEN: KeyType.TOKEN,
            RuleCategory.SECRET: KeyType.SECRET,
            RuleCategory.CONNECTION_STRING: KeyType.CONNECTION_STRING,
            RuleCategory.PRIVATE_KEY: KeyType.PRIVATE_KEY,
            RuleCategory.HIGH_ENTROPY: KeyType.HIGH_ENTROPY,
            RuleCategory.OTHER: KeyType.UNKNOWN,
        }
        key_type = category_map.get(match.rule_category, KeyType.UNKNOWN)

        # 根据规则名称进一步细化
        rule_name_lower = match.rule_name.lower()
        if "password" in rule_name_lower or "passwd" in rule_name_lower:
            key_type = KeyType.PASSWORD
        elif "private key" in rule_name_lower:
            key_type = KeyType.PRIVATE_KEY
        elif "connection" in rule_name_lower or "database" in rule_name_lower:
            key_type = KeyType.CONNECTION_STRING

        return key_type.value

    @staticmethod
    def _classify_length(length: int) -> str:
        """
        根据长度分类。

        Args:
            length: 密钥长度

        Returns:
            长度分类描述
        """
        thresholds = Evaluator.LENGTH_THRESHOLDS
        if length < thresholds["very_short"]:
            return "very_short"
        elif length < thresholds["short"]:
            return "short"
        elif length < thresholds["medium"]:
            return "medium"
        elif length < thresholds["long"]:
            return "long"
        elif length < thresholds["very_long"]:
            return "very_long"
        else:
            return "extremely_long"

    @staticmethod
    def _classify_entropy(entropy: float) -> str:
        """
        根据熵值分类。

        Args:
            entropy: Shannon 熵值

        Returns:
            熵值分类描述
        """
        thresholds = Evaluator.ENTROPY_THRESHOLDS
        if entropy < thresholds["very_low"]:
            return "very_low"
        elif entropy < thresholds["low"]:
            return "low"
        elif entropy < thresholds["medium"]:
            return "medium"
        elif entropy < thresholds["high"]:
            return "high"
        elif entropy < thresholds["very_high"]:
            return "very_high"
        else:
            return "extremely_high"

    def evaluate_match(self, match: ScanMatch) -> KeyEvaluation:
        """
        评估单条密钥匹配的强度。

        Args:
            match: 扫描匹配结果

        Returns:
            密钥评估结果
        """
        matched_text = match.matched_text
        length = len(matched_text)
        entropy = self.calculate_shannon_entropy(matched_text)
        key_type = self.identify_key_type(match)

        risk_reasons: List[str] = []
        suggestions: List[str] = []

        # 初始风险等级基于规则默认严重等级
        risk_level = match.severity

        # 长度评估
        length_class = self._classify_length(length)
        if length_class in ("very_short", "short"):
            risk_reasons.append(f"密钥长度过短 ({length} 字符)，容易被暴力破解")
            suggestions.append("建议使用至少 32 字符的密钥")
            # 短密钥提升风险等级
            if risk_level.value in ("LOW", "INFO"):
                risk_level = Severity.MEDIUM
        elif length_class == "medium":
            risk_reasons.append(f"密钥长度中等 ({length} 字符)")
            suggestions.append("建议增加密钥长度至 32 字符以上")
        elif length_class in ("very_long", "extremely_long"):
            risk_reasons.append(f"密钥长度充足 ({length} 字符)")

        # 熵值评估
        entropy_class = self._classify_entropy(entropy)
        if entropy_class in ("very_low", "low"):
            risk_reasons.append(f"熵值过低 ({entropy:.2f})，密钥随机性不足")
            suggestions.append("建议使用密码学安全的随机生成器创建密钥")
            if risk_level.value in ("LOW", "INFO", "MEDIUM"):
                risk_level = Severity.MEDIUM
        elif entropy_class == "medium":
            risk_reasons.append(f"熵值中等 ({entropy:.2f})")
        elif entropy_class in ("high", "very_high", "extremely_high"):
            risk_reasons.append(f"熵值良好 ({entropy:.2f})")

        # 类型特殊评估
        if key_type == KeyType.PRIVATE_KEY.value:
            risk_reasons.append("私钥泄露可能导致严重安全后果")
            suggestions.append("立即轮换私钥并撤销旧密钥")
            risk_level = Severity.CRITICAL
        elif key_type == KeyType.CONNECTION_STRING.value:
            risk_reasons.append("连接字符串包含数据库凭证")
            suggestions.append("使用环境变量或密钥管理服务替代硬编码")
        elif key_type == KeyType.PASSWORD.value:
            risk_reasons.append("密码明文存储存在安全风险")
            suggestions.append("使用密码哈希替代明文存储")

        # 通用建议
        suggestions.append("使用密钥管理服务 (如 AWS Secrets Manager, HashiCorp Vault)")
        suggestions.append("确保 .env 文件已添加到 .gitignore")

        return KeyEvaluation(
            matched_text=matched_text,
            rule_name=match.rule_name,
            rule_category=match.rule_category,
            severity=match.severity,
            length=length,
            entropy=entropy,
            key_type=key_type,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            suggestions=suggestions,
        )

    def evaluate_matches(self, matches: List[ScanMatch]) -> List[KeyEvaluation]:
        """
        批量评估密钥匹配。

        Args:
            matches: 扫描匹配结果列表

        Returns:
            密钥评估结果列表
        """
        return [self.evaluate_match(match) for match in matches]

    def calculate_security_score(
        self,
        matches: List[ScanMatch],
        evaluations: Optional[List[KeyEvaluation]] = None,
    ) -> SecurityScore:
        """
        计算整体安全评分。

        评分规则:
        - 基础分 100 分
        - CRITICAL: 每个 -20 分
        - HIGH: 每个 -10 分
        - MEDIUM: 每个 -5 分
        - LOW: 每个 -2 分
        - INFO: 每个 -1 分
        - 最低 0 分

        等级:
        - A: 90-100
        - B: 75-89
        - C: 60-74
        - D: 40-59
        - F: 0-39

        Args:
            matches: 扫描匹配结果列表
            evaluations: 可选的评估结果列表

        Returns:
            安全评分结果
        """
        if evaluations is None:
            evaluations = self.evaluate_matches(matches)

        score = 100
        deductions = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }

        severity_counts: Dict[Severity, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }

        for match in matches:
            severity_counts[match.severity] += 1
            score -= deductions.get(match.severity, 1)

        score = max(0, min(100, score))

        # 计算等级
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        # 平均熵值
        if evaluations:
            average_entropy = sum(e.entropy for e in evaluations) / len(evaluations)
        else:
            average_entropy = 0.0

        # 生成摘要
        total = len(matches)
        if total == 0:
            summary = "未发现安全问题，安全状况良好。"
        elif score >= 75:
            summary = (
                f"发现 {total} 个潜在安全问题，整体安全状况较好。"
                f"建议处理 {severity_counts[Severity.HIGH] + severity_counts[Severity.CRITICAL]} 个高危项。"
            )
        elif score >= 40:
            summary = (
                f"发现 {total} 个安全问题，其中包含高危项。"
                f"建议立即处理 {severity_counts[Severity.CRITICAL]} 个严重问题和"
                f" {severity_counts[Severity.HIGH]} 个高危问题。"
            )
        else:
            summary = (
                f"发现 {total} 个安全问题，安全状况堪忧！"
                f"请立即处理所有严重和高危问题。"
            )

        return SecurityScore(
            score=score,
            grade=grade,
            total_findings=total,
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
            average_entropy=average_entropy,
            summary=summary,
        )
