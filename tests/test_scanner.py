"""
EnvGuard-CLI 扫描引擎单元测试
"""

import os
import sys
import tempfile
import unittest

# 确保可以导入 envguard 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from envguard.rules import (
    RuleCategory,
    Severity,
    get_all_rules,
    get_rules_by_category,
    get_rules_by_severity,
    get_rule_by_name,
    get_rule_summary,
)
from envguard.scanner import Scanner, ScanMatch, ScanResult, SUPPORTED_EXTENSIONS


class TestRules(unittest.TestCase):
    """规则模块测试"""

    def test_get_all_rules_returns_list(self) -> None:
        """测试获取所有规则"""
        rules = get_all_rules()
        self.assertIsInstance(rules, list)
        self.assertGreaterEqual(len(rules), 80, "应至少有 80 条规则")

    def test_rule_has_required_fields(self) -> None:
        """测试规则包含必要字段"""
        rules = get_all_rules()
        for rule in rules:
            self.assertIsNotNone(rule.name)
            self.assertIsNotNone(rule.pattern)
            self.assertIsNotNone(rule.category)
            self.assertIsNotNone(rule.severity)
            self.assertIsNotNone(rule.description)

    def test_get_rules_by_category(self) -> None:
        """测试按分类获取规则"""
        for category in RuleCategory:
            rules = get_rules_by_category(category)
            self.assertIsInstance(rules, list)
            for rule in rules:
                self.assertEqual(rule.category, category)

    def test_get_rules_by_severity(self) -> None:
        """测试按严重等级获取规则"""
        for severity in Severity:
            rules = get_rules_by_severity(severity)
            self.assertIsInstance(rules, list)
            for rule in rules:
                self.assertEqual(rule.severity, severity)

    def test_get_rule_by_name(self) -> None:
        """测试按名称获取规则"""
        rules = get_all_rules()
        if rules:
            rule = get_rule_by_name(rules[0].name)
            self.assertIsNotNone(rule)
            self.assertEqual(rule.name, rules[0].name)

    def test_get_rule_by_name_not_found(self) -> None:
        """测试获取不存在的规则"""
        rule = get_rule_by_name("nonexistent_rule_name")
        self.assertIsNone(rule)

    def test_get_rule_summary(self) -> None:
        """测试规则摘要"""
        summary = get_rule_summary()
        self.assertIn("total", summary)
        self.assertGreater(summary["total"], 0)

    def test_aws_access_key_pattern(self) -> None:
        """测试 AWS Access Key ID 正则"""
        rule = get_rule_by_name("AWS Access Key ID")
        self.assertIsNotNone(rule)
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        self.assertTrue(rule.pattern.search(aws_key))
        aws_key2 = "ASIA" + "QFFFFFFFFFFFFFFF"
        self.assertTrue(rule.pattern.search(aws_key2))

    def test_github_token_pattern(self) -> None:
        """测试 GitHub Token 正则"""
        rule = get_rule_by_name("GitHub Personal Access Token")
        self.assertIsNotNone(rule)
        gh_token = "ghp_" + "fakeToken1234567890abcdefghijklmnopq"
        self.assertTrue(rule.pattern.search(gh_token))

    def test_google_api_key_pattern(self) -> None:
        """测试 Google API Key 正则"""
        rule = get_rule_by_name("Google API Key")
        self.assertIsNotNone(rule)
        g_key = "AIza" + "SyFake00000000000000000000000000000000"
        self.assertTrue(rule.pattern.search(g_key))

    def test_stripe_secret_key_pattern(self) -> None:
        """测试 Stripe Secret Key 正则"""
        rule = get_rule_by_name("Stripe Secret Key")
        self.assertIsNotNone(rule)
        sk = "sk_live_" + "51XXXXXXXXXXXXXXXfake000000000000"
        self.assertTrue(rule.pattern.search(sk))

    def test_jwt_pattern(self) -> None:
        """测试 JWT Token 正则"""
        rule = get_rule_by_name("JWT Token")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456"
        ))

    def test_rsa_private_key_pattern(self) -> None:
        """测试 RSA 私钥正则"""
        rule = get_rule_by_name("RSA Private Key")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search("-----BEGIN RSA PRIVATE KEY-----"))

    def test_mysql_connection_string_pattern(self) -> None:
        """测试 MySQL 连接串正则"""
        rule = get_rule_by_name("MySQL Connection String")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search("mysql://user:password@localhost:3306/mydb"))

    def test_postgresql_connection_string_pattern(self) -> None:
        """测试 PostgreSQL 连接串正则"""
        rule = get_rule_by_name("PostgreSQL Connection String")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search("postgresql://user:password@localhost:5432/mydb"))

    def test_mongodb_connection_string_pattern(self) -> None:
        """测试 MongoDB 连接串正则"""
        rule = get_rule_by_name("MongoDB Connection String")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search("mongodb://user:password@localhost:27017/mydb"))

    def test_slack_token_pattern(self) -> None:
        """测试 Slack Token 正则"""
        rule = get_rule_by_name("Slack Token (xoxb)")
        self.assertIsNotNone(rule)
        slack_tok = "xoxb-" + "0000000000000" + "-" + "A" * 24
        self.assertTrue(rule.pattern.search(slack_tok))

    def test_discord_bot_token_pattern(self) -> None:
        """测试 Discord Bot Token 正则"""
        rule = get_rule_by_name("Discord Bot Token")
        self.assertIsNotNone(rule)
        dc_tok = "MTIzNDU2Nzg5MDEyMzQ1Njc" + ".fakefake" + "." + "f" * 36
        self.assertTrue(rule.pattern.search(dc_tok))

    def test_telegram_bot_token_pattern(self) -> None:
        """测试 Telegram Bot Token 正则"""
        rule = get_rule_by_name("Telegram Bot Token")
        self.assertIsNotNone(rule)
        tg_tok = "123456789" + ":" + "ABCdefGHIjklMNOpqrsTUVwxyz_fake"
        self.assertTrue(rule.pattern.search(tg_tok))

    def test_sendgrid_api_key_pattern(self) -> None:
        """测试 SendGrid API Key 正则"""
        rule = get_rule_by_name("SendGrid API Key")
        self.assertIsNotNone(rule)
        sg_key = "SG." + "a" * 22 + "." + "b" * 23
        self.assertTrue(rule.pattern.search(sg_key))

    def test_openai_api_key_pattern(self) -> None:
        """测试 OpenAI API Key 正则"""
        rule = get_rule_by_name("OpenAI Project API Key")
        self.assertIsNotNone(rule)
        oai_key = "sk-proj-" + "a" * 22
        self.assertTrue(rule.pattern.search(oai_key))

    def test_anthropic_api_key_pattern(self) -> None:
        """测试 Anthropic API Key 正则"""
        rule = get_rule_by_name("Anthropic API Key")
        self.assertIsNotNone(rule)
        ant_key = "sk-ant-" + "api03-" + "a" * 40
        self.assertTrue(rule.pattern.search(ant_key))

    def test_gitlab_token_pattern(self) -> None:
        """测试 GitLab Token 正则"""
        rule = get_rule_by_name("GitLab Token")
        self.assertIsNotNone(rule)
        gl_tok = "glpat-" + "a" * 36
        self.assertTrue(rule.pattern.search(gl_tok))

    def test_alibaba_cloud_key_pattern(self) -> None:
        """测试阿里云 Access Key 正则"""
        rule = get_rule_by_name("Alibaba Cloud Access Key")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.pattern.search("LTAI5tExampleKey12345"))


class TestSupportedExtensions(unittest.TestCase):
    """支持的文件扩展名测试"""

    def test_python_supported(self) -> None:
        """测试 Python 文件在支持列表中"""
        self.assertIn(".py", SUPPORTED_EXTENSIONS)

    def test_javascript_supported(self) -> None:
        """测试 JavaScript 文件在支持列表中"""
        self.assertIn(".js", SUPPORTED_EXTENSIONS)

    def test_env_file_supported(self) -> None:
        """测试 .env 文件在支持列表中"""
        self.assertIn(".env", SUPPORTED_EXTENSIONS)

    def test_yaml_supported(self) -> None:
        """测试 YAML 文件在支持列表中"""
        self.assertIn(".yml", SUPPORTED_EXTENSIONS)
        self.assertIn(".yaml", SUPPORTED_EXTENSIONS)

    def test_json_supported(self) -> None:
        """测试 JSON 文件在支持列表中"""
        self.assertIn(".json", SUPPORTED_EXTENSIONS)

    def test_shell_supported(self) -> None:
        """测试 Shell 文件在支持列表中"""
        self.assertIn(".sh", SUPPORTED_EXTENSIONS)
        self.assertIn(".bash", SUPPORTED_EXTENSIONS)
        self.assertIn(".zsh", SUPPORTED_EXTENSIONS)


class TestScanner(unittest.TestCase):
    """扫描引擎测试"""

    def setUp(self) -> None:
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = Scanner()

    def tearDown(self) -> None:
        """测试后清理"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_file(self, filename: str, content: str) -> str:
        """创建测试文件"""
        file_path = os.path.join(self.temp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path

    def test_scan_file_with_aws_key(self) -> None:
        """测试扫描包含 AWS Key 的文件"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'AWS_ACCESS_KEY = "{aws_key}"\n'
        file_path = self._create_test_file("test.py", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].rule_name, "AWS Access Key ID")

    def test_scan_file_with_github_token(self) -> None:
        """测试扫描包含 GitHub Token 的文件"""
        gh_tok = "ghp_" + "fakeToken1234567890abcdefghijklmnopq"
        content = f'token = "{gh_tok}"\n'
        file_path = self._create_test_file("config.py", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)

    def test_scan_file_with_rsa_key(self) -> None:
        """测试扫描包含 RSA 私钥的文件"""
        content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n-----END RSA PRIVATE KEY-----\n'
        file_path = self._create_test_file("key.pem", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)

    def test_scan_file_with_db_connection(self) -> None:
        """测试扫描包含数据库连接串的文件"""
        content = 'DATABASE_URL = "postgresql://user:password@localhost:5432/mydb"\n'
        file_path = self._create_test_file(".env", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)

    def test_scan_clean_file(self) -> None:
        """测试扫描干净文件"""
        content = '# This is a clean file\nprint("Hello, World!")\n'
        file_path = self._create_test_file("clean.py", content)
        matches = self.scanner.scan_file(file_path)
        # 注释中的示例值不应被匹配
        self.assertEqual(len(matches), 0)

    def test_scan_directory(self) -> None:
        """测试扫描目录"""
        self._create_test_file("safe.py", "print('hello')\n")
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        self._create_test_file("unsafe.py", f'key = "{aws_key}"\n')

        result = self.scanner.scan_directory(self.temp_dir)
        self.assertIsInstance(result, ScanResult)
        self.assertGreater(result.files_scanned, 0)
        self.assertGreater(result.total_findings, 0)

    def test_scan_nonexistent_path(self) -> None:
        """测试扫描不存在的路径"""
        result = self.scanner.scan("/nonexistent/path")
        self.assertGreater(len(result.errors), 0)

    def test_scan_binary_file_skipped(self) -> None:
        """测试二进制文件被跳过"""
        file_path = self._create_test_file("image.png", b"\x89PNG\r\n\x1a\n".decode("latin-1"))
        matches = self.scanner.scan_file(file_path)
        self.assertEqual(len(matches), 0)

    def test_severity_filter(self) -> None:
        """测试严重等级过滤"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'key = "{aws_key}"\n'
        file_path = self._create_test_file("test.py", content)

        scanner_high = Scanner(min_severity=Severity.HIGH)
        matches = scanner_high.scan_file(file_path)
        for match in matches:
            self.assertIn(match.severity, [Severity.HIGH, Severity.CRITICAL])

    def test_ignore_patterns(self) -> None:
        """测试忽略文件模式"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'key = "{aws_key}"\n'
        file_path = self._create_test_file("test.py", content)

        scanner = Scanner(ignore_patterns=["test.py"])
        matches = scanner.scan_file(file_path)
        self.assertEqual(len(matches), 0)

    def test_line_number_detection(self) -> None:
        """测试行号定位"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'line1\nline2\nkey = "{aws_key}"\nline4\n'
        file_path = self._create_test_file("test.py", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].line_number, 3)

    def test_scan_result_to_dict(self) -> None:
        """测试扫描结果序列化"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'key = "{aws_key}"\n'
        file_path = self._create_test_file("test.py", content)
        result = self.scanner.scan(file_path)
        data = result.to_dict()
        self.assertIn("summary", data)
        self.assertIn("findings", data)

    def test_scan_match_to_dict(self) -> None:
        """测试匹配结果序列化"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f'key = "{aws_key}"\n'
        file_path = self._create_test_file("test.py", content)
        matches = self.scanner.scan_file(file_path)
        if matches:
            data = matches[0].to_dict()
            self.assertIn("rule_name", data)
            self.assertIn("file_path", data)
            self.assertIn("line_number", data)


class TestScannerMultipleSecrets(unittest.TestCase):
    """多密钥扫描测试"""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = Scanner()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_file(self, filename: str, content: str) -> str:
        file_path = os.path.join(self.temp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path

    def test_multiple_secrets_in_one_file(self) -> None:
        """测试单文件多密钥检测"""
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        gh_tok = "ghp_" + "fakeToken1234567890abcdefghijklmnopq"
        content = (
            f'AWS_KEY = "{aws_key}"\n'
            f'GITHUB_TOKEN = "{gh_tok}"\n'
            'DB_URL = "postgresql://admin:secret@db.example.com/prod"\n'
        )
        file_path = self._create_test_file("config.py", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreaterEqual(len(matches), 3)

    def test_env_file_scanning(self) -> None:
        """测试 .env 文件扫描"""
        sk = "sk_live_" + "51XXXXXXXXXXXXXXXfake000000000000"
        content = (
            'DATABASE_URL=postgresql://user:pass@host/db\n'
            'SECRET_KEY=abcdefghijklmnopqrstuvwxyz123456\n'
            f'STRIPE_KEY={sk}\n'
        )
        file_path = self._create_test_file(".env", content)
        matches = self.scanner.scan_file(file_path)
        self.assertGreater(len(matches), 0)


if __name__ == "__main__":
    unittest.main()
