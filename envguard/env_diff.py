"""
EnvGuard-CLI 环境变量差异对比模块

对比多个 .env 文件的差异，检测：
- 缺失/多余的变量
- 值类型变化
- 敏感变量差异
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class DiffType(Enum):
    """差异类型枚举"""
    ADDED = "added"          # 仅在目标文件中存在
    REMOVED = "removed"      # 仅在源文件中存在
    MODIFIED = "modified"    # 两文件都存在但值不同
    TYPE_CHANGED = "type_changed"  # 值类型发生变化
    UNCHANGED = "unchanged"  # 值相同


class ValueType(Enum):
    """值类型枚举"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    URL = "url"
    PATH = "path"
    JSON = "json"
    LIST = "list"
    EMPTY = "empty"
    UNKNOWN = "unknown"


@dataclass
class EnvVariable:
    """环境变量"""
    key: str
    value: str
    line_number: int
    value_type: ValueType
    is_sensitive: bool = False

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "key": self.key,
            "value": self._mask_value(),
            "line_number": self.line_number,
            "value_type": self.value_type.value,
            "is_sensitive": self.is_sensitive,
        }

    def _mask_value(self) -> str:
        """遮蔽敏感值"""
        if not self.is_sensitive or not self.value:
            return self.value
        if len(self.value) <= 4:
            return "***"
        return self.value[:2] + "***" + self.value[-2:]


@dataclass
class DiffEntry:
    """单条差异条目"""
    key: str
    diff_type: DiffType
    source_value: Optional[str]
    target_value: Optional[str]
    source_type: ValueType
    target_type: ValueType
    is_sensitive: bool
    description: str

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "key": self.key,
            "diff_type": self.diff_type.value,
            "source_value": self._mask(self.source_value),
            "target_value": self._mask(self.target_value),
            "source_type": self.source_type.value,
            "target_type": self.target_type.value,
            "is_sensitive": self.is_sensitive,
            "description": self.description,
        }

    @staticmethod
    def _mask(value: Optional[str]) -> str:
        """遮蔽敏感值"""
        if value is None:
            return "(not set)"
        if len(value) <= 4:
            return "***"
        return value[:2] + "***" + value[-2:]


@dataclass
class DiffResult:
    """差异对比结果"""
    source_file: str
    target_file: str
    entries: List[DiffEntry] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        return sum(1 for e in self.entries if e.diff_type == DiffType.ADDED)

    @property
    def removed_count(self) -> int:
        return sum(1 for e in self.entries if e.diff_type == DiffType.REMOVED)

    @property
    def modified_count(self) -> int:
        return sum(1 for e in self.entries if e.diff_type == DiffType.MODIFIED)

    @property
    def type_changed_count(self) -> int:
        return sum(1 for e in self.entries if e.diff_type == DiffType.TYPE_CHANGED)

    @property
    def unchanged_count(self) -> int:
        return sum(1 for e in self.entries if e.diff_type == DiffType.UNCHANGED)

    @property
    def has_differences(self) -> bool:
        return any(
            e.diff_type in (DiffType.ADDED, DiffType.REMOVED, DiffType.MODIFIED, DiffType.TYPE_CHANGED)
            for e in self.entries
        )

    @property
    def sensitive_diff_count(self) -> int:
        return sum(1 for e in self.entries if e.is_sensitive and e.diff_type != DiffType.UNCHANGED)

    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            "source_file": self.source_file,
            "target_file": self.target_file,
            "summary": {
                "total_entries": len(self.entries),
                "added": self.added_count,
                "removed": self.removed_count,
                "modified": self.modified_count,
                "type_changed": self.type_changed_count,
                "unchanged": self.unchanged_count,
                "sensitive_diffs": self.sensitive_diff_count,
            },
            "differences": [e.to_dict() for e in self.entries],
        }


# 敏感变量名关键词
SENSITIVE_KEYWORDS: Set[str] = {
    "password", "passwd", "pwd", "secret", "token", "key",
    "api_key", "apikey", "access_key", "secret_key",
    "private_key", "auth", "credential", "certificate",
    "db_pass", "database_url", "connection_string",
}

# URL 模式
URL_PATTERN = re.compile(r'^https?://[^\s]+', re.IGNORECASE)
PATH_PATTERN = re.compile(r'^(/|~/|[A-Za-z]:\\)[^\s]*')
JSON_PATTERN = re.compile(r'^\s*[\{\[].*[\}\]]\s*$', re.DOTALL)


class EnvDiff:
    """
    环境变量差异对比器。

    对比两个或多个 .env 文件，检测变量差异。
    """

    def __init__(self) -> None:
        """初始化差异对比器"""
        pass

    @staticmethod
    def _detect_value_type(value: str) -> ValueType:
        """
        检测值的类型。

        Args:
            value: 环境变量值

        Returns:
            值类型
        """
        if not value or value.strip() == "":
            return ValueType.EMPTY

        stripped = value.strip()

        # 布尔值
        if stripped.lower() in ("true", "false", "yes", "no", "on", "off", "1", "0"):
            return ValueType.BOOLEAN

        # 整数
        try:
            int(stripped)
            return ValueType.INTEGER
        except ValueError:
            pass

        # 浮点数
        try:
            float(stripped)
            return ValueType.FLOAT
        except ValueError:
            pass

        # URL
        if URL_PATTERN.match(stripped):
            return ValueType.URL

        # 路径
        if PATH_PATTERN.match(stripped):
            return ValueType.PATH

        # JSON
        if JSON_PATTERN.match(stripped):
            try:
                import json
                json.loads(stripped)
                return ValueType.JSON
            except (ValueError, json.JSONDecodeError):
                pass

        # 列表（逗号分隔）
        if "," in stripped and all(part.strip() for part in stripped.split(",")):
            return ValueType.LIST

        return ValueType.STRING

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """
        判断变量名是否属于敏感变量。

        Args:
            key: 变量名

        Returns:
            是否为敏感变量
        """
        key_lower = key.lower()
        return any(kw in key_lower for kw in SENSITIVE_KEYWORDS)

    @staticmethod
    def _parse_env_file(file_path: str) -> Dict[str, EnvVariable]:
        """
        解析 .env 文件。

        Args:
            file_path: .env 文件路径

        Returns:
            变量名到环境变量的映射
        """
        variables: Dict[str, EnvVariable] = {}

        if not os.path.isfile(file_path):
            return variables

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()

                    # 跳过空行和注释
                    if not line or line.startswith("#"):
                        continue

                    # 解析 KEY=VALUE 或 KEY: VALUE
                    match = re.match(
                        r'^([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*)',
                        line,
                    )
                    if match:
                        key = match.group(1)
                        value = match.group(2).strip()
                        # 去除引号
                        if (value.startswith('"') and value.endswith('"')) or \
                           (value.startswith("'") and value.endswith("'")):
                            value = value[1:-1]

                        variables[key] = EnvVariable(
                            key=key,
                            value=value,
                            line_number=line_num,
                            value_type=EnvDiff._detect_value_type(value),
                            is_sensitive=EnvDiff._is_sensitive_key(key),
                        )
        except (OSError, IOError, PermissionError) as e:
            pass

        return variables

    def compare(self, source_file: str, target_file: str) -> DiffResult:
        """
        对比两个 .env 文件。

        Args:
            source_file: 源文件路径
            target_file: 目标文件路径

        Returns:
            差异对比结果
        """
        source_vars = self._parse_env_file(source_file)
        target_vars = self._parse_env_file(target_file)

        result = DiffResult(
            source_file=os.path.abspath(source_file),
            target_file=os.path.abspath(target_file),
        )

        all_keys: Set[str] = set(source_vars.keys()) | set(target_vars.keys())

        for key in sorted(all_keys):
            in_source = key in source_vars
            in_target = key in target_vars

            source_var = source_vars.get(key)
            target_var = target_vars.get(key)

            if in_source and not in_target:
                # 仅在源文件中存在 -> 已移除
                result.entries.append(DiffEntry(
                    key=key,
                    diff_type=DiffType.REMOVED,
                    source_value=source_var.value if source_var else None,
                    target_value=None,
                    source_type=source_var.value_type if source_var else ValueType.UNKNOWN,
                    target_type=ValueType.EMPTY,
                    is_sensitive=source_var.is_sensitive if source_var else False,
                    description=f"变量 '{key}' 在源文件中存在但目标文件中缺失",
                ))
            elif not in_source and in_target:
                # 仅在目标文件中存在 -> 新增
                result.entries.append(DiffEntry(
                    key=key,
                    diff_type=DiffType.ADDED,
                    source_value=None,
                    target_value=target_var.value if target_var else None,
                    source_type=ValueType.EMPTY,
                    target_type=target_var.value_type if target_var else ValueType.UNKNOWN,
                    is_sensitive=target_var.is_sensitive if target_var else False,
                    description=f"变量 '{key}' 在目标文件中新增",
                ))
            else:
                # 两文件都存在
                src_val = source_var.value if source_var else ""
                tgt_val = target_var.value if target_var else ""
                src_type = source_var.value_type if source_var else ValueType.UNKNOWN
                tgt_type = target_var.value_type if target_var else ValueType.UNKNOWN
                is_sensitive = (source_var.is_sensitive if source_var else False) or \
                               (target_var.is_sensitive if target_var else False)

                if src_val == tgt_val:
                    result.entries.append(DiffEntry(
                        key=key,
                        diff_type=DiffType.UNCHANGED,
                        source_value=src_val,
                        target_value=tgt_val,
                        source_type=src_type,
                        target_type=tgt_type,
                        is_sensitive=is_sensitive,
                        description=f"变量 '{key}' 未变化",
                    ))
                elif src_type != tgt_type:
                    result.entries.append(DiffEntry(
                        key=key,
                        diff_type=DiffType.TYPE_CHANGED,
                        source_value=src_val,
                        target_value=tgt_val,
                        source_type=src_type,
                        target_type=tgt_type,
                        is_sensitive=is_sensitive,
                        description=(
                            f"变量 '{key}' 值和类型均发生变化: "
                            f"{src_type.value} -> {tgt_type.value}"
                        ),
                    ))
                else:
                    result.entries.append(DiffEntry(
                        key=key,
                        diff_type=DiffType.MODIFIED,
                        source_value=src_val,
                        target_value=tgt_val,
                        source_type=src_type,
                        target_type=tgt_type,
                        is_sensitive=is_sensitive,
                        description=f"变量 '{key}' 值发生变化",
                    ))

        return result

    def compare_multiple(self, file_paths: List[str]) -> List[DiffResult]:
        """
        对比多个 .env 文件（两两对比）。

        Args:
            file_paths: .env 文件路径列表

        Returns:
            差异对比结果列表
        """
        results: List[DiffResult] = []
        for i in range(len(file_paths)):
            for j in range(i + 1, len(file_paths)):
                result = self.compare(file_paths[i], file_paths[j])
                results.append(result)
        return results
