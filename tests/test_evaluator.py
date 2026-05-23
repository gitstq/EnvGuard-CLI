"""
EnvGuard-CLI 密钥强度评估器单元测试
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from envguard.rules import RuleCategory, Severity
from envguard.scanner import ScanMatch
from envguard.evaluator import Evaluator, SecurityScore


class TestShannonEntropy(unittest.TestCase):
    """Shannon 熵值计算测试"""

    def setUp(self) -> None:
        self.evaluator = Evaluator()

    def test_empty_string_entropy(self) -> None:
        """测试空字符串熵值"""
        entropy = self.evaluator.calculate_shannon_entropy("")
        self.assertEqual(entropy, 0.0)

    def test_uniform_string_entropy(self) -> None:
        """测试均匀字符串熵值"""
        entropy = self.evaluator.calculate_shannon_entropy("aaaaaa")
        self.assertEqual(entropy, 0.0)

    def test_high_entropy_string(self) -> None:
        """测试高熵字符串"""
        entropy = self.evaluator.calculate_shannon_entropy(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )
        self.assertGreater(entropy, 5.0)

    def test_medium_entropy_string(self) -> None:
        """测试中等熵字符串"""
        entropy = self.evaluator.calculate_shannon_entropy("hello world 12345")
        self.assertGreater(entropy, 2.0)
        self.assertLess(entropy, 5.0)

    def test_binary_like_string(self) -> None:
        """测试类二进制字符串"""
        entropy = self.evaluator.calculate_shannon_entropy("0101010101010101")
        self.assertLess(entropy, 2.0)

    def test_real_api_key_entropy(self) -> None:
        """测试真实 API Key 熵值"""
        entropy = self.evaluator.calculate_shannon_entropy(
            "AKIAIOSFODNN7EXAMPLE"
        )
        self.assertGreater(entropy, 2.0)


class TestKeyTypeIdentification(unittest.TestCase):
    """密钥类型识别测试"""

    def setUp(self) -> None:
        self.evaluator = Evaluator()

    def _make_match(self, rule_name: str, category: RuleCategory) -> ScanMatch:
        """创建测试用 ScanMatch"""
        return ScanMatch(
            rule_name=rule_name,
            rule_category=category,
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=1,
            line_content="test",
            matched_text="test_value",
            description="test description",
        )

    def test_api_key_type(self) -> None:
        """测试 API Key 类型识别"""
        match = self._make_match("AWS Access Key ID", RuleCategory.API_KEY)
        key_type = self.evaluator.identify_key_type(match)
        self.assertEqual(key_type, "API Key")

    def test_token_type(self) -> None:
        """测试 Token 类型识别"""
        match = self._make_match("GitHub Personal Access Token", RuleCategory.TOKEN)
        key_type = self.evaluator.identify_key_type(match)
        self.assertEqual(key_type, "Token")

    def test_private_key_type(self) -> None:
        """测试私钥类型识别"""
        match = self._make_match("RSA Private Key", RuleCategory.PRIVATE_KEY)
        key_type = self.evaluator.identify_key_type(match)
        self.assertEqual(key_type, "Private Key")

    def test_connection_string_type(self) -> None:
        """测试连接串类型识别"""
        match = self._make_match("MySQL Connection String", RuleCategory.CONNECTION_STRING)
        key_type = self.evaluator.identify_key_type(match)
        self.assertEqual(key_type, "Connection String")

    def test_password_type(self) -> None:
        """测试密码类型识别"""
        match = self._make_match("Generic Password Assignment", RuleCategory.SECRET)
        key_type = self.evaluator.identify_key_type(match)
        self.assertEqual(key_type, "Password")


class TestMatchEvaluation(unittest.TestCase):
    """单条密钥评估测试"""

    def setUp(self) -> None:
        self.evaluator = Evaluator()

    def _make_match(
        self,
        rule_name: str = "Test Rule",
        category: RuleCategory = RuleCategory.API_KEY,
        severity: Severity = Severity.HIGH,
        matched_text: str = "test_key_value_12345",
    ) -> ScanMatch:
        """创建测试用 ScanMatch"""
        return ScanMatch(
            rule_name=rule_name,
            rule_category=category,
            severity=severity,
            file_path="/test/file.py",
            line_number=1,
            line_content="test",
            matched_text=matched_text,
            description="test description",
        )

    def test_evaluation_has_required_fields(self) -> None:
        """测试评估结果包含必要字段"""
        match = self._make_match()
        evaluation = self.evaluator.evaluate_match(match)
        self.assertIsNotNone(evaluation.matched_text)
        self.assertIsNotNone(evaluation.rule_name)
        self.assertGreater(evaluation.length, 0)
        self.assertGreaterEqual(evaluation.entropy, 0.0)
        self.assertIsNotNone(evaluation.key_type)
        self.assertIsNotNone(evaluation.risk_level)
        self.assertIsInstance(evaluation.risk_reasons, list)
        self.assertIsInstance(evaluation.suggestions, list)

    def test_short_key_higher_risk(self) -> None:
        """测试短密钥风险提升"""
        match = self._make_match(matched_text="short", severity=Severity.LOW)
        evaluation = self.evaluator.evaluate_match(match)
        self.assertIn(evaluation.risk_level, [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])

    def test_private_key_critical_risk(self) -> None:
        """测试私钥始终为 CRITICAL"""
        match = self._make_match(
            rule_name="RSA Private Key",
            category=RuleCategory.PRIVATE_KEY,
            severity=Severity.CRITICAL,
        )
        evaluation = self.evaluator.evaluate_match(match)
        self.assertEqual(evaluation.risk_level, Severity.CRITICAL)

    def test_evaluation_to_dict(self) -> None:
        """测试评估结果序列化"""
        match = self._make_match()
        evaluation = self.evaluator.evaluate_match(match)
        data = evaluation.to_dict()
        self.assertIn("matched_text", data)
        self.assertIn("entropy", data)
        self.assertIn("risk_level", data)
        self.assertIn("suggestions", data)


class TestSecurityScore(unittest.TestCase):
    """安全评分测试"""

    def setUp(self) -> None:
        self.evaluator = Evaluator()

    def _make_match(
        self,
        severity: Severity = Severity.HIGH,
    ) -> ScanMatch:
        """创建测试用 ScanMatch"""
        return ScanMatch(
            rule_name="Test Rule",
            rule_category=RuleCategory.API_KEY,
            severity=severity,
            file_path="/test/file.py",
            line_number=1,
            line_content="test",
            matched_text="test_key_value_1234567890",
            description="test description",
        )

    def test_no_findings_perfect_score(self) -> None:
        """测试无发现时满分"""
        score = self.evaluator.calculate_security_score([])
        self.assertEqual(score.score, 100)
        self.assertEqual(score.grade, "A")

    def test_critical_finding_reduces_score(self) -> None:
        """测试 CRITICAL 发现降低评分"""
        matches = [self._make_match(Severity.CRITICAL)]
        score = self.evaluator.calculate_security_score(matches)
        self.assertLess(score.score, 100)
        self.assertEqual(score.critical_count, 1)

    def test_multiple_findings_score(self) -> None:
        """测试多发现评分"""
        matches = [
            self._make_match(Severity.CRITICAL),
            self._make_match(Severity.HIGH),
            self._make_match(Severity.MEDIUM),
        ]
        score = self.evaluator.calculate_security_score(matches)
        self.assertEqual(score.score, 65)  # 100 - 20 - 10 - 5
        self.assertEqual(score.grade, "C")

    def test_score_never_negative(self) -> None:
        """测试评分不会为负"""
        matches = [self._make_match(Severity.CRITICAL) for _ in range(20)]
        score = self.evaluator.calculate_security_score(matches)
        self.assertGreaterEqual(score.score, 0)

    def test_score_grade_boundaries(self) -> None:
        """测试评分等级边界"""
        # A: 90-100
        score_a = self.evaluator.calculate_security_score([])
        self.assertEqual(score_a.grade, "A")

        # B: 75-89
        matches_b = [self._make_match(Severity.HIGH) for _ in range(2)]
        score_b = self.evaluator.calculate_security_score(matches_b)
        self.assertIn(score_b.grade, ["A", "B"])

        # F: 0-39
        matches_f = [self._make_match(Severity.CRITICAL) for _ in range(4)]
        score_f = self.evaluator.calculate_security_score(matches_f)
        self.assertIn(score_f.grade, ["C", "D", "F"])

    def test_security_score_to_dict(self) -> None:
        """测试安全评分序列化"""
        score = self.evaluator.calculate_security_score([])
        data = score.to_dict()
        self.assertIn("score", data)
        self.assertIn("grade", data)
        self.assertIn("summary", data)
        self.assertIn("by_severity", data)

    def test_summary_generation(self) -> None:
        """测试摘要生成"""
        score_clean = self.evaluator.calculate_security_score([])
        self.assertIn("未发现", score_clean.summary)

        score_dirty = self.evaluator.calculate_security_score(
            [self._make_match(Severity.CRITICAL)]
        )
        self.assertIn("发现", score_dirty.summary)


class TestLengthClassification(unittest.TestCase):
    """长度分类测试"""

    def test_very_short(self) -> None:
        result = Evaluator._classify_length(5)
        self.assertEqual(result, "very_short")

    def test_short(self) -> None:
        result = Evaluator._classify_length(12)
        self.assertEqual(result, "short")

    def test_medium(self) -> None:
        result = Evaluator._classify_length(20)
        self.assertEqual(result, "medium")

    def test_long(self) -> None:
        result = Evaluator._classify_length(30)
        self.assertEqual(result, "long")

    def test_very_long(self) -> None:
        result = Evaluator._classify_length(50)
        self.assertEqual(result, "very_long")

    def test_extremely_long(self) -> None:
        result = Evaluator._classify_length(100)
        self.assertEqual(result, "extremely_long")


class TestEntropyClassification(unittest.TestCase):
    """熵值分类测试"""

    def test_very_low(self) -> None:
        result = Evaluator._classify_entropy(1.0)
        self.assertEqual(result, "very_low")

    def test_low(self) -> None:
        result = Evaluator._classify_entropy(2.5)
        self.assertEqual(result, "low")

    def test_medium(self) -> None:
        result = Evaluator._classify_entropy(3.5)
        self.assertEqual(result, "medium")

    def test_high(self) -> None:
        result = Evaluator._classify_entropy(4.5)
        self.assertEqual(result, "high")

    def test_very_high(self) -> None:
        result = Evaluator._classify_entropy(5.5)
        self.assertEqual(result, "very_high")

    def test_extremely_high(self) -> None:
        result = Evaluator._classify_entropy(7.0)
        self.assertEqual(result, "extremely_high")


if __name__ == "__main__":
    unittest.main()
