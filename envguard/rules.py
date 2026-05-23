"""
EnvGuard-CLI 密钥扫描规则定义模块

包含 80+ 条内置正则规则，覆盖主流 API 密钥、Token、凭证、
连接字符串和私钥等敏感信息检测。

每条规则包含:
    - name: 规则唯一名称
    - pattern: 编译后的正则表达式
    - category: 规则分类
    - severity: 默认严重等级
    - description: 规则描述
    - examples: 匹配示例
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern


class RuleCategory(Enum):
    """规则分类枚举"""
    API_KEY = "api_key"
    TOKEN = "token"
    SECRET = "secret"
    CONNECTION_STRING = "connection_string"
    PRIVATE_KEY = "private_key"
    HIGH_ENTROPY = "high_entropy"
    OTHER = "other"


class Severity(Enum):
    """严重等级枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """返回严重等级对应的权重值，用于评分计算"""
        weights = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        return weights[self]

    @property
    def color_code(self) -> str:
        """返回终端颜色 ANSI 转义码"""
        colors = {
            Severity.CRITICAL: "\033[91m",   # 红色
            Severity.HIGH: "\033[38;5;208m",  # 橙色
            Severity.MEDIUM: "\033[93m",      # 黄色
            Severity.LOW: "\033[92m",         # 绿色
            Severity.INFO: "\033[90m",        # 灰色
        }
        return colors[self]

    @property
    def reset_color(self) -> str:
        """返回颜色重置 ANSI 转义码"""
        return "\033[0m"


@dataclass
class Rule:
    """扫描规则数据类"""
    name: str
    pattern: Pattern
    category: RuleCategory
    severity: Severity
    description: str
    examples: List[str] = field(default_factory=list)

    def matches(self, text: str) -> List[re.Match]:
        """
        在给定文本中查找所有匹配项。

        Args:
            text: 待匹配的文本内容

        Returns:
            匹配结果列表
        """
        return list(self.pattern.finditer(text))


# ============================================================================
# 规则定义 - AWS
# ============================================================================

AWS_RULES: List[Rule] = [
    Rule(
        name="AWS Access Key ID",
        pattern=re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
        category=RuleCategory.API_KEY,
        severity=Severity.CRITICAL,
        description="AWS Access Key ID，用于 AWS API 身份验证",
        examples=["格式: AKIA/ABIA/ACCA/ASIA + 16位大写字母数字"],
    ),
    Rule(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9/+=]{40})["\']?'
        ),
        category=RuleCategory.SECRET,
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key，与 Access Key ID 配对使用",
        examples=["格式: aws_secret_access_key = 40位Base64字符"],
    ),
    Rule(
        name="AWS Session Token",
        pattern=re.compile(
            r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9/+=]{16,})["\']?'
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.CRITICAL,
        description="AWS 临时会话 Token，用于 STS 临时凭证",
        examples=["格式: aws_session_token = Base64长字符串"],
    ),
]

# ============================================================================
# 规则定义 - GitHub
# ============================================================================

GITHUB_RULES: List[Rule] = [
    Rule(
        name="GitHub Personal Access Token",
        pattern=re.compile(r'ghp_[A-Za-z0-9_]{36,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token，拥有仓库访问权限",
        examples=["格式: ghp_ + 36位以上字母数字下划线"],
    ),
    Rule(
        name="GitHub OAuth Access Token",
        pattern=re.compile(r'gho_[A-Za-z0-9_]{36,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub OAuth Access Token",
        examples=["格式: gho_ + 36位以上字母数字下划线"],
    ),
    Rule(
        name="GitHub App Token",
        pattern=re.compile(r'(?:ghs_|ghr_)[A-Za-z0-9_]{36,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub App Token (Server-to-Server 或 Refresh Token)",
        examples=["格式: ghs_/ghr_ + 36位以上字母数字下划线"],
    ),
    Rule(
        name="GitHub Fine-grained Token",
        pattern=re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub Fine-grained Personal Access Token",
        examples=["格式: github_pat_ + 22位以上字母数字下划线"],
    ),
]

# ============================================================================
# 规则定义 - Google
# ============================================================================

GOOGLE_RULES: List[Rule] = [
    Rule(
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Google API Key，用于访问 Google Cloud 服务",
        examples=["格式: AIza + 35位字母数字减号下划线"],
    ),
    Rule(
        name="Google OAuth Token",
        pattern=re.compile(r'ya29\.[0-9A-Za-z\-_]+'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Google OAuth 2.0 Access Token",
        examples=["格式: ya29. + Base64URL编码字符串"],
    ),
    Rule(
        name="Google Cloud API Key (Type)",
        pattern=re.compile(
            r'(?:GOOGLE_API_KEY|google_api_key|GOOGLE_CLOUD_API_KEY)\s*[=:]\s*["\']?'
            r'(AIza[0-9A-Za-z\-_]{35})["\']?'
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="通过环境变量配置的 Google API Key",
        examples=["格式: GOOGLE_API_KEY=AIza + 35位字符"],
    ),
    Rule(
        name="Google Service Account Private Key",
        pattern=re.compile(r'"type":\s*"service_account"'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="Google Cloud Service Account JSON 密钥文件",
        examples=["格式: {\"type\": \"service_account\", \"project_id\": \"...\"}"],
    ),
    Rule(
        name="Google Firebase URL",
        pattern=re.compile(
            r'firebaseio\.com',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.MEDIUM,
        description="Firebase 数据库 URL，可能暴露项目信息",
        examples=["格式: https://项目名.firebaseio.com"],
    ),
]

# ============================================================================
# 规则定义 - Stripe
# ============================================================================

STRIPE_RULES: List[Rule] = [
    Rule(
        name="Stripe Secret Key",
        pattern=re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        category=RuleCategory.SECRET,
        severity=Severity.CRITICAL,
        description="Stripe Secret Key，可执行完整 API 操作",
        examples=["格式: sk_live_ + 24位以上字母数字"],
    ),
    Rule(
        name="Stripe Publishable Key",
        pattern=re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.MEDIUM,
        description="Stripe Publishable Key，可公开但不应硬编码",
        examples=["格式: pk_live_ + 24位以上字母数字"],
    ),
    Rule(
        name="Stripe Restricted Key",
        pattern=re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Stripe Restricted Key，受限的 API 密钥",
        examples=["格式: rk_live_ + 24位以上字母数字"],
    ),
    Rule(
        name="Stripe Test Secret Key",
        pattern=re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
        category=RuleCategory.SECRET,
        severity=Severity.MEDIUM,
        description="Stripe 测试环境 Secret Key",
        examples=["格式: sk_test_ + 24位以上字母数字"],
    ),
]

# ============================================================================
# 规则定义 - OpenAI
# ============================================================================

OPENAI_RULES: List[Rule] = [
    Rule(
        name="OpenAI API Key",
        pattern=re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.CRITICAL,
        description="OpenAI API Key (旧格式)，可访问 GPT 等模型",
        examples=["格式: sk- + 20位以上字符 + T3BlbkFJ + 20位以上字符"],
    ),
    Rule(
        name="OpenAI Project API Key",
        pattern=re.compile(r'sk-proj-[A-Za-z0-9\-_]{20,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.CRITICAL,
        description="OpenAI Project API Key (新格式)",
        examples=["格式: sk-proj- + 20位以上字母数字减号下划线"],
    ),
    Rule(
        name="OpenAI Organization Key",
        pattern=re.compile(
            r'(?:OPENAI_API_KEY|openai_api_key)\s*[=:]\s*["\']?'
            r'(sk-[A-Za-z0-9\-_]{20,})["\']?'
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.CRITICAL,
        description="通过环境变量配置的 OpenAI API Key",
        examples=["格式: OPENAI_API_KEY=sk- + 20位以上字符"],
    ),
]

# ============================================================================
# 规则定义 - Azure
# ============================================================================

AZURE_RULES: List[Rule] = [
    Rule(
        name="Azure Subscription Key",
        pattern=re.compile(
            r'(?:AZURE_SUBSCRIPTION_KEY|azure_subscription_key)\s*[=:]\s*["\']?'
            r'([0-9a-f]{32})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Azure 订阅密钥",
        examples=["格式: AZURE_SUBSCRIPTION_KEY=32位十六进制字符"],
    ),
    Rule(
        name="Azure Connection String",
        pattern=re.compile(
            r'(?:DefaultEndpointsProtocol|AccountName|AccountKey)'
            r'=[^;\s]+;[^\s]+',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="Azure Storage 连接字符串，包含账户密钥",
        examples=["格式: DefaultEndpointsProtocol=https;AccountName=...;AccountKey=..."],
    ),
    Rule(
        name="Azure SQL Connection String",
        pattern=re.compile(
            r'(?:Server|Data Source)\s*=\s*[^;]+;[^\s]*(?:Password|Pwd)\s*=\s*[^;]+',
            re.IGNORECASE,
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.CRITICAL,
        description="Azure SQL 数据库连接字符串，包含密码",
        examples=["格式: Server=tcp:hostname;Password=..."],
    ),
    Rule(
        name="Azure DevOps PAT",
        pattern=re.compile(r'[a-z0-9]{52}\.([a-z0-9]{52})'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Azure DevOps Personal Access Token",
        examples=["格式: 52位小写字母数字 + . + 52位小写字母数字"],
    ),
]

# ============================================================================
# 规则定义 - JWT Token
# ============================================================================

JWT_RULES: List[Rule] = [
    Rule(
        name="JWT Token",
        pattern=re.compile(
            r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="JSON Web Token，可能包含身份认证信息",
        examples=["格式: eyJ + Base64URL + . + eyJ + Base64URL + . + Base64URL"],
    ),
]

# ============================================================================
# 规则定义 - Private Key
# ============================================================================

PRIVATE_KEY_RULES: List[Rule] = [
    Rule(
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="RSA 私钥，用于加密签名",
        examples=["格式: -----BEGIN RSA PRIVATE KEY----- + PEM内容"],
    ),
    Rule(
        name="DSA Private Key",
        pattern=re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="DSA 私钥",
        examples=["格式: -----BEGIN DSA PRIVATE KEY----- + PEM内容"],
    ),
    Rule(
        name="EC Private Key",
        pattern=re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="EC (Elliptic Curve) 私钥",
        examples=["格式: -----BEGIN EC PRIVATE KEY----- + PEM内容"],
    ),
    Rule(
        name="OpenSSH Private Key",
        pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="OpenSSH 格式私钥",
        examples=["格式: -----BEGIN OPENSSH PRIVATE KEY----- + PEM内容"],
    ),
    Rule(
        name="PKCS8 Private Key",
        pattern=re.compile(r'-----BEGIN PRIVATE KEY-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="PKCS#8 格式私钥",
        examples=["格式: -----BEGIN PRIVATE KEY----- + PEM内容"],
    ),
    Rule(
        name="PGP Private Key Block",
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="PGP 私钥块",
        examples=["格式: -----BEGIN PGP PRIVATE KEY BLOCK----- + PGP内容"],
    ),
]

# ============================================================================
# 规则定义 - 数据库连接串
# ============================================================================

DATABASE_RULES: List[Rule] = [
    Rule(
        name="MySQL Connection String",
        pattern=re.compile(
            r'mysql://[^\s:]+:[^\s@]+@[^\s/]+(?:/[^\s]*)?',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="MySQL 数据库连接字符串，包含用户名和密码",
        examples=["格式: mysql://用户名:密码@主机:端口/数据库名"],
    ),
    Rule(
        name="PostgreSQL Connection String",
        pattern=re.compile(
            r'(?:postgresql|postgres)://[^\s:]+:[^\s@]+@[^\s/]+(?:/[^\s]*)?',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="PostgreSQL 数据库连接字符串，包含用户名和密码",
        examples=["格式: postgresql://用户名:密码@主机:端口/数据库名"],
    ),
    Rule(
        name="MongoDB Connection String",
        pattern=re.compile(
            r'mongodb(?:\+srv)?://[^\s:]+:[^\s@]+@[^\s/]+(?:/[^\s]*)?',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="MongoDB 数据库连接字符串，包含凭证",
        examples=["格式: mongodb://用户名:密码@主机:端口/数据库名"],
    ),
    Rule(
        name="Redis Connection String",
        pattern=re.compile(
            r'redis://[^\s:]*:[^\s@]+@[^\s/]+(?:/[^\s]*)?',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="Redis 连接字符串，包含密码",
        examples=["格式: redis://:密码@主机:端口/数据库编号"],
    ),
    Rule(
        name="SQLite Database Path",
        pattern=re.compile(
            r'(?:sqlite://|sqlite3://)(?:/[^\s"\']+)',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.LOW,
        description="SQLite 数据库文件路径",
        examples=["格式: sqlite:///绝对路径/to/database.db"],
    ),
    Rule(
        name="MSSQL Connection String",
        pattern=re.compile(
            r'(?:mssql|sqlserver)://[^\s:]+:[^\s@]+@[^\s/]+(?:/[^\s]*)?',
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="Microsoft SQL Server 连接字符串",
        examples=["格式: mssql://用户名:密码@主机:端口/数据库名"],
    ),
]

# ============================================================================
# 规则定义 - Slack
# ============================================================================

SLACK_RULES: List[Rule] = [
    Rule(
        name="Slack Token (xoxb)",
        pattern=re.compile(r'xoxb-[0-9]{10,13}-[A-Za-z0-9]{24,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Slack Bot Token (xoxb-)",
        examples=["格式: xoxb- + 10-13位数字 + - + 24位以上字母数字"],
    ),
    Rule(
        name="Slack User Token (xoxp)",
        pattern=re.compile(r'xoxp-[0-9]{10,13}-[A-Za-z0-9]{24,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Slack User Token (xoxp-)",
        examples=["格式: xoxp- + 10-13位数字 + - + 24位以上字母数字"],
    ),
    Rule(
        name="Slack App Token (xapp)",
        pattern=re.compile(r'xapp-[0-9A-Za-z\-]{30,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Slack App-Level Token (xapp-)",
        examples=["格式: xapp- + 30位以上字母数字减号"],
    ),
    Rule(
        name="Slack Webhook URL",
        pattern=re.compile(
            r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24,}'
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Slack Incoming Webhook URL",
        examples=["格式: https://hooks.slack.com/services/T + ID/B + ID/ + Token"],
    ),
]

# ============================================================================
# 规则定义 - Discord
# ============================================================================

DISCORD_RULES: List[Rule] = [
    Rule(
        name="Discord Bot Token",
        pattern=re.compile(r'[MN][A-Za-z\d]{20,}\.[\w-]{4,}\.[\w-]{20,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Discord Bot Token",
        examples=["格式: M/N + 20位以上字母数字 + . + 4位以上字符 + . + 20位以上字符"],
    ),
    Rule(
        name="Discord Webhook URL",
        pattern=re.compile(
            r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+'
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Discord Webhook URL",
        examples=["格式: https://discord.com/api/webhooks/数字ID/Token"],
    ),
]

# ============================================================================
# 规则定义 - Telegram
# ============================================================================

TELEGRAM_RULES: List[Rule] = [
    Rule(
        name="Telegram Bot Token",
        pattern=re.compile(r'[0-9]{8,10}:[A-Za-z0-9_-]{20,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Telegram Bot API Token",
        examples=["格式: 8-10位数字 + : + 20位以上字母数字下划线减号"],
    ),
]

# ============================================================================
# 规则定义 - SendGrid / Twilio / Mailgun
# ============================================================================

EMAIL_SERVICE_RULES: List[Rule] = [
    Rule(
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="SendGrid API Key",
        examples=["格式: SG. + 22位以上字符 + . + 22位以上字符"],
    ),
    Rule(
        name="Twilio Account SID",
        pattern=re.compile(r'AC[a-f0-9]{32}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Twilio Account SID",
        examples=["格式: AC + 32位十六进制字符"],
    ),
    Rule(
        name="Twilio Auth Token",
        pattern=re.compile(
            r'(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[=:]\s*["\']?'
            r'([a-f0-9]{32})["\']?'
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="Twilio Auth Token",
        examples=["格式: TWILIO_AUTH_TOKEN=32位十六进制字符"],
    ),
    Rule(
        name="Mailgun API Key",
        pattern=re.compile(r'key-[a-f0-9]{32}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Mailgun API Key",
        examples=["格式: key- + 32位十六进制字符"],
    ),
]

# ============================================================================
# 规则定义 - Shopify / PayPal / Heroku
# ============================================================================

COMMERCE_PLATFORM_RULES: List[Rule] = [
    Rule(
        name="Shopify Secret Key",
        pattern=re.compile(r'sh(pss|pat|sec)_[a-fA-F0-9]{32}'),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="Shopify Secret/Password/App Token",
        examples=["格式: shpat_ + 32位十六进制字符"],
    ),
    Rule(
        name="Shopify Access Token",
        pattern=re.compile(r'shpat_[a-fA-F0-9]{32}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Shopify Private App Access Token",
        examples=["格式: shpat_ + 32位十六进制字符"],
    ),
    Rule(
        name="PayPal Token",
        pattern=re.compile(r'EE[A-Za-z0-9]{15,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="PayPal Bearer Token",
        examples=["格式: EE + 15位以上字母数字"],
    ),
    Rule(
        name="Heroku API Key",
        pattern=re.compile(
            r'(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*["\']?'
            r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Heroku API Key",
        examples=["格式: HEROKU_API_KEY=UUID格式(8-4-4-4-12十六进制)"],
    ),
]

# ============================================================================
# 规则定义 - 通用凭证模式
# ============================================================================

GENERIC_CREDENTIAL_RULES: List[Rule] = [
    Rule(
        name="Generic API Key Assignment",
        pattern=re.compile(
            r'(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.MEDIUM,
        description="通用 API Key 赋值语句",
        examples=["格式: api_key = '20位以上字母数字'"],
    ),
    Rule(
        name="Generic Secret Assignment",
        pattern=re.compile(
            r'(?:secret[_\-]?key|secretkey|app[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="通用 Secret Key 赋值语句",
        examples=["格式: secret_key = '20位以上字母数字'"],
    ),
    Rule(
        name="Generic Token Assignment",
        pattern=re.compile(
            r'(?:token|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="通用 Token 赋值语句",
        examples=["格式: access_token = '20位以上字母数字'"],
    ),
    Rule(
        name="Generic Password Assignment",
        pattern=re.compile(
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="通用密码赋值语句",
        examples=["格式: password = '8位以上密码'"],
    ),
    Rule(
        name="Authorization Bearer Header",
        pattern=re.compile(
            r'[Aa]uthorization\s*:\s*[Bb]earer\s+[A-Za-z0-9_\-\.]+',
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="HTTP Authorization Bearer Token",
        examples=["格式: Authorization: Bearer + Token字符串"],
    ),
    Rule(
        name="Generic Private Key Variable",
        pattern=re.compile(
            r'(?:PRIVATE_KEY|private_key|SSH_KEY|ssh_key)\s*[=:]\s*["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        description="私钥变量赋值语句",
        examples=["格式: PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----'"],
    ),
]

# ============================================================================
# 规则定义 - 其他服务
# ============================================================================

OTHER_SERVICE_RULES: List[Rule] = [
    Rule(
        name="npm Token",
        pattern=re.compile(r'npm_[A-Za-z0-9]{36}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="npm 访问令牌",
        examples=["格式: npm_ + 36位字母数字"],
    ),
    Rule(
        name="PyPI API Token",
        pattern=re.compile(r'pypi-[A-Za-z0-9\-_]{30,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="PyPI 发布 API Token",
        examples=["格式: pypi- + 30位以上字母数字减号下划线"],
    ),
    Rule(
        name="NuGet API Key",
        pattern=re.compile(r'oy2[a-z0-9]{43}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="NuGet API Key",
        examples=["格式: oy2 + 43位小写字母数字"],
    ),
    Rule(
        name="RubyGems API Key",
        pattern=re.compile(r'[a-f0-9]{40}@rubygems\.org'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="RubyGems API Key",
        examples=["格式: 40位十六进制@rubygems.org"],
    ),
    Rule(
        name="Clojars Token",
        pattern=re.compile(r'(?:CLOJARS_[A-Z_]+|clj-env)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{30,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Clojars 部署 Token",
        examples=["格式: CLOJARS_TOKEN=30位以上字母数字"],
    ),
    Rule(
        name="Codecov Token",
        pattern=re.compile(r'[a-f0-9]{32}@codecov\.io'),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Codecov Upload Token",
        examples=["格式: 32位十六进制@codecov.io"],
    ),
    Rule(
        name="Coveralls Token",
        pattern=re.compile(r'coveralls\.io/api/v1/jobs\?[a-zA-Z0-9\-_=&]+'),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Coveralls Webhook Token",
        examples=["格式: coveralls.io/api/v1/jobs?repo_token=..."],
    ),
    Rule(
        name="Graphcool API Key",
        pattern=re.compile(r'#[A-Za-z0-9\-_]{30,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.MEDIUM,
        description="Graphcool API Key",
        examples=["格式: # + 30位以上字母数字减号下划线"],
    ),
    Rule(
        name="Kubernetes Secret",
        pattern=re.compile(
            r'(?:kubernetes_secret|KUBERNETES_SECRET)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9+/=]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="Kubernetes Secret 数据",
        examples=["格式: KUBERNETES_SECRET=20位以上Base64字符"],
    ),
    Rule(
        name="Docker Hub Token",
        pattern=re.compile(
            r'(?:DOCKER_HUB_TOKEN|docker_hub_token|DOCKER_PASSWORD|docker_password)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-\.]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Docker Hub 认证 Token",
        examples=["格式: DOCKER_HUB_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Terraform Cloud Token",
        pattern=re.compile(r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{40,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Terraform Cloud / Atlas API Token",
        examples=["格式: 14位字母数字.atlasv1.40位以上字母数字"],
    ),
    Rule(
        name="Datadog API Key",
        pattern=re.compile(
            r'(?:DD_API_KEY|datadog_api_key)\s*[=:]\s*["\']?'
            r'([a-f0-9]{32})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Datadog API Key",
        examples=["格式: DD_API_KEY=32位十六进制字符"],
    ),
    Rule(
        name="Datadog App Key",
        pattern=re.compile(
            r'(?:DD_APP_KEY|datadog_app_key)\s*[=:]\s*["\']?'
            r'([a-f0-9]{32})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Datadog Application Key",
        examples=["格式: DD_APP_KEY=32位十六进制字符"],
    ),
    Rule(
        name="Sentry DSN",
        pattern=re.compile(
            r'https://[a-f0-9]+@[a-f0-9]+\.ingest\.sentry\.io/[0-9]+'
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.MEDIUM,
        description="Sentry DSN (Data Source Name)",
        examples=["格式: https://密钥@o项目ID.ingest.sentry.io/项目编号"],
    ),
    Rule(
        name="Segment API Key",
        pattern=re.compile(r'sg_[a-zA-Z0-9]{32}'),
        category=RuleCategory.API_KEY,
        severity=Severity.MEDIUM,
        description="Segment Write API Key",
        examples=["格式: sg_ + 32位字母数字"],
    ),
    Rule(
        name="Pulumi Token",
        pattern=re.compile(r'pul-[a-f0-9]{40}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Pulumi Access Token",
        examples=["格式: pul- + 40位十六进制字符"],
    ),
    Rule(
        name="Vercel Token",
        pattern=re.compile(
            r'(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Vercel API Token",
        examples=["格式: VERCEL_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Netlify Token",
        pattern=re.compile(
            r'(?:NETLIFY_AUTH_TOKEN|netlify_auth_token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Netlify Auth Token",
        examples=["格式: NETLIFY_AUTH_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Cloudflare API Token",
        pattern=re.compile(
            r'(?:CLOUDFLARE_API_TOKEN|cloudflare_api_token|CF_API_TOKEN)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{30,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Cloudflare API Token",
        examples=["格式: CLOUDFLARE_API_TOKEN=30位以上字母数字"],
    ),
    Rule(
        name="Cloudflare Global API Key",
        pattern=re.compile(
            r'(?:CLOUDFLARE_API_KEY|cloudflare_api_key)\s*[=:]\s*["\']?'
            r'([a-f0-9]{37})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Cloudflare Global API Key",
        examples=["格式: CLOUDFLARE_API_KEY=37位十六进制字符"],
    ),
    Rule(
        name="DigitalOcean Token",
        pattern=re.compile(
            r'(?:DIGITALOCEAN_TOKEN|digitalocean_token|DO_API_TOKEN)\s*[=:]\s*["\']?'
            r'(dop_v1_[a-f0-9]{64})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="DigitalOcean API Token (v2)",
        examples=["格式: DIGITALOCEAN_TOKEN=dop_v1_ + 64位十六进制字符"],
    ),
    Rule(
        name="Twitch Token",
        pattern=re.compile(
            r'(?:TWITCH_TOKEN|twitch_token)\s*[=:]\s*["\']?'
            r'([a-z0-9]{30})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Twitch API Token",
        examples=["格式: TWITCH_TOKEN=30位小写字母数字"],
    ),
    Rule(
        name="Zendesk Token",
        pattern=re.compile(
            r'(?:ZENDESK_TOKEN|zendesk_token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Zendesk API Token",
        examples=["格式: ZENDESK_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Jenkins Credential",
        pattern=re.compile(
            r'(?:JENKINS_TOKEN|jenkins_token|JENKINS_API_TOKEN)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Jenkins API Token",
        examples=["格式: JENKINS_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Grafana API Key",
        pattern=re.compile(
            r'(?:GRAFANA_API_KEY|grafana_api_key)\s*[=:]\s*["\']?'
            r'(eyJ[a-zA-Z0-9]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="Grafana API Key (JWT 格式)",
        examples=["格式: GRAFANA_API_KEY=eyJ + 20位以上字符"],
    ),
    Rule(
        name="SonarQube Token",
        pattern=re.compile(
            r'(?:SONAR_TOKEN|sonar_token|SONARQUBE_TOKEN)\s*[=:]\s*["\']?'
            r'([a-f0-9]{40})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="SonarQube User Token",
        examples=["格式: SONAR_TOKEN=40位十六进制字符"],
    ),
    Rule(
        name="New Relic License Key",
        pattern=re.compile(
            r'(?:NEW_RELIC_LICENSE_KEY|new_relic_license_key)\s*[=:]\s*["\']?'
            r'([a-f0-9]{40})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="New Relic License Key",
        examples=["格式: NEW_RELIC_LICENSE_KEY=40位十六进制字符"],
    ),
    Rule(
        name="New Relic API Key",
        pattern=re.compile(
            r'(?:NEW_RELIC_API_KEY|new_relic_api_key)\s*[=:]\s*["\']?'
            r'(NRAK-[A-Za-z0-9]{27})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="New Relic REST API Key",
        examples=["格式: NEW_RELIC_API_KEY=NRAK- + 27位字母数字"],
    ),
    Rule(
        name="CircleCI Token",
        pattern=re.compile(
            r'(?:CIRCLECI_TOKEN|CIRCLE_TOKEN|circleci_token)\s*[=:]\s*["\']?'
            r'([a-f0-9]{40})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="CircleCI API Token",
        examples=["格式: CIRCLECI_TOKEN=40位十六进制字符"],
    ),
    Rule(
        name="Travis CI Token",
        pattern=re.compile(
            r'(?:TRAVIS_CI_TOKEN|travis_ci_token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9]{22,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.MEDIUM,
        description="Travis CI API Token",
        examples=["格式: TRAVIS_CI_TOKEN=22位以上字母数字"],
    ),
    Rule(
        name="GitLab Token",
        pattern=re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="GitLab Personal Access Token",
        examples=["格式: glpat- + 20位以上字母数字减号下划线"],
    ),
    Rule(
        name="Bitbucket Token",
        pattern=re.compile(r'BBDC-[A-Za-z0-9\-_]{30,}'),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Bitbucket Data Center Access Token",
        examples=["格式: BBDC- + 30位以上字母数字减号下划线"],
    ),
    Rule(
        name="Bitbucket App Password",
        pattern=re.compile(
            r'(?:BITBUCKET_APP_PASSWORD|bitbucket_app_password)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="Bitbucket App Password",
        examples=["格式: BITBUCKET_APP_PASSWORD=20位以上字母数字"],
    ),
    Rule(
        name="Anthropic API Key",
        pattern=re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.CRITICAL,
        description="Anthropic API Key",
        examples=["格式: sk-ant- + 20位以上字母数字减号下划线"],
    ),
    Rule(
        name="Coinbase Access Token",
        pattern=re.compile(
            r'(?:COINBASE_ACCESS_TOKEN|coinbase_access_token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.TOKEN,
        severity=Severity.HIGH,
        description="Coinbase Access Token",
        examples=["格式: COINBASE_ACCESS_TOKEN=20位以上字母数字"],
    ),
    Rule(
        name="Alibaba Cloud Access Key",
        pattern=re.compile(r'LTAI[A-Za-z0-9]{12,}'),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="阿里云 AccessKey ID",
        examples=["格式: LTAI + 12位以上字母数字"],
    ),
    Rule(
        name="Tencent Cloud Secret Key",
        pattern=re.compile(
            r'(?:TENCENT_SECRET_KEY|TENCENT_SECRET_ID|tencent_secret_key)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9]{32,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="腾讯云 SecretKey / SecretId",
        examples=["格式: TENCENT_SECRET_KEY=32位以上字母数字"],
    ),
    Rule(
        name="Huawei Cloud Access Key",
        pattern=re.compile(
            r'(?:HUAWEI_ACCESS_KEY|HUAWEI_SECRET_KEY)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9]{16,})["\']?',
            re.IGNORECASE,
        ),
        category=RuleCategory.API_KEY,
        severity=Severity.HIGH,
        description="华为云 Access Key",
        examples=["格式: HUAWEI_ACCESS_KEY=16位以上字母数字"],
    ),
]

# ============================================================================
# 规则定义 - 高熵字符串检测
# ============================================================================

HIGH_ENTROPY_RULES: List[Rule] = [
    Rule(
        name="High Entropy String (64+ chars)",
        pattern=re.compile(r'["\']([A-Za-z0-9+/=]{64,})["\']'),
        category=RuleCategory.HIGH_ENTROPY,
        severity=Severity.MEDIUM,
        description="高熵字符串 (64字符以上)，可能是 Base64 编码的密钥",
        examples=["格式: 64字符以上Base64编码字符串"],
    ),
    Rule(
        name="High Entropy Hex String (32+ chars)",
        pattern=re.compile(r'["\']([a-f0-9]{32,})["\']', re.IGNORECASE),
        category=RuleCategory.HIGH_ENTROPY,
        severity=Severity.MEDIUM,
        description="高熵十六进制字符串 (32字符以上)，可能是密钥哈希",
        examples=["格式: 32字符以上十六进制字符串"],
    ),
    Rule(
        name="Potential Base64 Encoded Secret",
        pattern=re.compile(
            r'(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)\s*[=:]\s*["\']'
            r'([A-Za-z0-9+/=]{40,})["\']',
            re.IGNORECASE,
        ),
        category=RuleCategory.HIGH_ENTROPY,
        severity=Severity.HIGH,
        description="赋值给敏感变量名的 Base64 编码长字符串",
        examples=["格式: SECRET_KEY=\"40位以上Base64编码字符串\""],
    ),
]

# ============================================================================
# 规则定义 - 环境变量文件特有
# ============================================================================

ENV_FILE_RULES: List[Rule] = [
    Rule(
        name="Environment Variable with Credentials",
        pattern=re.compile(
            r'^(?:DB_|DATABASE_|REDIS_|MONGO_|MYSQL_|POSTGRES_)'
            r'(?:PASS|PASSWORD|SECRET|KEY|URL|URI|HOST|PORT)'
            r'\s*=\s*[^\s]+',
            re.MULTILINE,
        ),
        category=RuleCategory.CONNECTION_STRING,
        severity=Severity.HIGH,
        description="数据库相关环境变量，可能包含凭证",
        examples=["格式: DB_PASSWORD=密码值", "格式: DATABASE_URL=postgresql://user:pass@host/db"],
    ),
    Rule(
        name="Environment Variable with API Credentials",
        pattern=re.compile(
            r'^(?:AUTH|CLIENT|USER|ADMIN)'
            r'(?:_SECRET|_KEY|_TOKEN|_PASSWORD|_PASS)'
            r'\s*=\s*[^\s]+',
            re.MULTILINE,
        ),
        category=RuleCategory.SECRET,
        severity=Severity.HIGH,
        description="认证相关环境变量",
        examples=["格式: AUTH_SECRET=密钥值", "格式: CLIENT_TOKEN=令牌值"],
    ),
]


# ============================================================================
# 聚合所有规则
# ============================================================================

def get_all_rules() -> List[Rule]:
    """
    获取所有内置扫描规则。

    Returns:
        包含所有规则的列表
    """
    all_rules: List[Rule] = []
    rule_groups = [
        AWS_RULES,
        GITHUB_RULES,
        GOOGLE_RULES,
        STRIPE_RULES,
        OPENAI_RULES,
        AZURE_RULES,
        JWT_RULES,
        PRIVATE_KEY_RULES,
        DATABASE_RULES,
        SLACK_RULES,
        DISCORD_RULES,
        TELEGRAM_RULES,
        EMAIL_SERVICE_RULES,
        COMMERCE_PLATFORM_RULES,
        GENERIC_CREDENTIAL_RULES,
        OTHER_SERVICE_RULES,
        HIGH_ENTROPY_RULES,
        ENV_FILE_RULES,
    ]
    for group in rule_groups:
        all_rules.extend(group)
    return all_rules


def get_rules_by_category(category: RuleCategory) -> List[Rule]:
    """
    按分类获取规则。

    Args:
        category: 规则分类

    Returns:
        该分类下的所有规则
    """
    return [r for r in get_all_rules() if r.category == category]


def get_rules_by_severity(severity: Severity) -> List[Rule]:
    """
    按严重等级获取规则。

    Args:
        severity: 严重等级

    Returns:
        该严重等级下的所有规则
    """
    return [r for r in get_all_rules() if r.severity == severity]


def get_rule_by_name(name: str) -> Optional[Rule]:
    """
    按名称获取规则。

    Args:
        name: 规则名称

    Returns:
        匹配的规则，未找到则返回 None
    """
    for rule in get_all_rules():
        if rule.name == name:
            return rule
    return None


def get_rule_summary() -> Dict[str, int]:
    """
    获取规则统计摘要。

    Returns:
        包含各分类和严重等级规则数量的字典
    """
    rules = get_all_rules()
    summary: Dict[str, int] = {
        "total": len(rules),
    }
    for cat in RuleCategory:
        summary[f"category_{cat.value}"] = len(get_rules_by_category(cat))
    for sev in Severity:
        summary[f"severity_{sev.value}"] = len(get_rules_by_severity(sev))
    return summary
