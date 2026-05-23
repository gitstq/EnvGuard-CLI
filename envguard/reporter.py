"""
EnvGuard-CLI 报告生成器模块

支持多种输出格式：
- JSON 格式报告
- CSV 格式报告
- Markdown 格式报告
- SARIF 格式报告（CI/CD 集成）
- 终端彩色表格输出
"""

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TextIO

from envguard.rules import RuleCategory, Severity
from envguard.scanner import ScanMatch, ScanResult
from envguard.evaluator import SecurityScore


class Reporter:
    """
    报告生成器。

    将扫描结果转换为多种格式的报告输出。
    """

    def __init__(
        self,
        use_color: bool = True,
        verbose: bool = False,
        quiet: bool = False,
    ) -> None:
        """
        初始化报告生成器。

        Args:
            use_color: 是否使用彩色输出
            verbose: 是否输出详细信息
            quiet: 是否静默模式
        """
        self.use_color = use_color
        self.verbose = verbose
        self.quiet = quiet

    # =========================================================================
    # 颜色工具方法
    # =========================================================================

    def _color(self, text: str, severity: Severity) -> str:
        """为文本添加严重等级对应的颜色"""
        if not self.use_color:
            return text
        return f"{severity.color_code}{text}{severity.reset_color}"

    def _bold(self, text: str) -> str:
        """加粗文本"""
        if not self.use_color:
            return text
        return f"\033[1m{text}\033[0m"

    def _dim(self, text: str) -> str:
        """灰色文本"""
        if not self.use_color:
            return text
        return f"\033[2m{text}\033[0m"

    # =========================================================================
    # 终端表格输出
    # =========================================================================

    def format_table(self, result: ScanResult, score: Optional[SecurityScore] = None) -> str:
        """
        生成终端彩色表格报告。

        Args:
            result: 扫描结果
            score: 可选的安全评分

        Returns:
            格式化的表格字符串
        """
        output = io.StringIO()

        # 标题
        output.write(self._bold("=" * 70) + "\n")
        output.write(self._bold("  EnvGuard-CLI 扫描报告") + "\n")
        output.write(self._bold("=" * 70) + "\n\n")

        # 摘要
        output.write(f"  扫描文件数: {result.files_scanned}\n")
        output.write(f"  跳过文件数: {result.files_skipped}\n")
        output.write(f"  扫描耗时:   {result.scan_duration:.3f}s\n")
        output.write(f"  发现总数:   {result.total_findings}\n\n")

        # 按严重等级统计
        severity_counts = [
            (Severity.CRITICAL, result.critical_count),
            (Severity.HIGH, result.high_count),
            (Severity.MEDIUM, result.medium_count),
            (Severity.LOW, result.low_count),
            (Severity.INFO, result.info_count),
        ]

        output.write("  风险等级分布:\n")
        for sev, count in severity_counts:
            bar = self._color("\u2588" * min(count * 2, 40), sev)
            output.write(f"    {sev.value:10s} {bar} {count}\n")

        # 安全评分
        if score:
            output.write(f"\n  安全评分: {self._bold(str(score.score))}/100")
            output.write(f"  等级: {self._bold(score.grade)}\n")
            output.write(f"  {score.summary}\n")

        output.write("\n")

        # 发现详情
        if result.total_findings == 0:
            output.write(self._bold("  未发现安全问题。\n"))
        else:
            output.write(self._bold("-" * 70) + "\n")
            output.write(self._bold("  发现详情\n"))
            output.write(self._bold("-" * 70) + "\n\n")

            # 按严重等级排序
            severity_order = [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]
            sorted_matches = sorted(
                result.matches,
                key=lambda m: (
                    severity_order.index(m.severity),
                    m.file_path,
                    m.line_number,
                ),
            )

            current_severity: Optional[Severity] = None
            for match in sorted_matches:
                if match.severity != current_severity:
                    current_severity = match.severity
                    output.write(
                        f"\n  [{self._color(match.severity.value, match.severity)}]\n"
                    )

                # 截断文件路径显示
                display_path = match.file_path
                if len(display_path) > 50:
                    display_path = "..." + display_path[-47:]

                output.write(f"    {self._dim(f'{display_path}:{match.line_number}')}\n")
                output.write(f"    {self._color(f'  [{match.rule_name}]', match.severity)}\n")

                if self.verbose:
                    output.write(f"    {self._dim(f'  {match.description}')}\n")
                    output.write(f"    {self._dim(f'  匹配: {match.matched_text[:80]}')}\n")

                output.write("\n")

        # 错误信息
        if result.errors:
            output.write(self._bold("-" * 70) + "\n")
            output.write(self._bold("  扫描错误\n"))
            output.write(self._bold("-" * 70) + "\n\n")
            for error in result.errors:
                output.write(f"    {self._color(error, Severity.HIGH)}\n")

        output.write("\n" + self._bold("=" * 70) + "\n")

        return output.getvalue()

    # =========================================================================
    # JSON 报告
    # =========================================================================

    def format_json(
        self,
        result: ScanResult,
        score: Optional[SecurityScore] = None,
        pretty: bool = True,
    ) -> str:
        """
        生成 JSON 格式报告。

        Args:
            result: 扫描结果
            score: 可选的安全评分
            pretty: 是否美化输出

        Returns:
            JSON 字符串
        """
        data = result.to_dict()
        if score:
            data["security_score"] = score.to_dict()
        data["scan_metadata"] = {
            "tool": "envguard-cli",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, ensure_ascii=False)

    # =========================================================================
    # CSV 报告
    # =========================================================================

    def format_csv(self, result: ScanResult) -> str:
        """
        生成 CSV 格式报告。

        Args:
            result: 扫描结果

        Returns:
            CSV 字符串
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # 表头
        headers = [
            "severity", "rule_name", "category", "file_path",
            "line_number", "matched_text", "description",
        ]
        writer.writerow(headers)

        # 数据行
        for match in result.matches:
            writer.writerow([
                match.severity.value,
                match.rule_name,
                match.rule_category.value,
                match.file_path,
                match.line_number,
                match.matched_text,
                match.description,
            ])

        return output.getvalue()

    # =========================================================================
    # Markdown 报告
    # =========================================================================

    def format_markdown(
        self,
        result: ScanResult,
        score: Optional[SecurityScore] = None,
    ) -> str:
        """
        生成 Markdown 格式报告。

        Args:
            result: 扫描结果
            score: 可选的安全评分

        Returns:
            Markdown 字符串
        """
        output = io.StringIO()

        # 标题
        output.write("# EnvGuard-CLI 扫描报告\n\n")
        output.write(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # 摘要表格
        output.write("## 扫描摘要\n\n")
        output.write("| 指标 | 数值 |\n")
        output.write("|------|------|\n")
        output.write(f"| 扫描文件数 | {result.files_scanned} |\n")
        output.write(f"| 跳过文件数 | {result.files_skipped} |\n")
        output.write(f"| 扫描耗时 | {result.scan_duration:.3f}s |\n")
        output.write(f"| 发现总数 | {result.total_findings} |\n")

        # 严重等级统计
        output.write("\n### 风险等级分布\n\n")
        output.write("| 等级 | 数量 |\n")
        output.write("|------|------|\n")
        output.write(f"| CRITICAL | {result.critical_count} |\n")
        output.write(f"| HIGH | {result.high_count} |\n")
        output.write(f"| MEDIUM | {result.medium_count} |\n")
        output.write(f"| LOW | {result.low_count} |\n")
        output.write(f"| INFO | {result.info_count} |\n")

        # 安全评分
        if score:
            output.write(f"\n### 安全评分\n\n")
            output.write(f"**评分**: {score.score}/100 ({score.grade})\n\n")
            output.write(f"{score.summary}\n\n")

        # 发现详情
        if result.total_findings > 0:
            output.write("## 发现详情\n\n")

            severity_order = [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]
            sorted_matches = sorted(
                result.matches,
                key=lambda m: severity_order.index(m.severity),
            )

            current_severity: Optional[Severity] = None
            for match in sorted_matches:
                if match.severity != current_severity:
                    current_severity = match.severity
                    output.write(f"### {match.severity.value}\n\n")

                output.write(f"- **{match.rule_name}**\n")
                output.write(f"  - 文件: `{match.file_path}:{match.line_number}`\n")
                output.write(f"  - 分类: {match.rule_category.value}\n")
                output.write(f"  - 描述: {match.description}\n")
                output.write(f"  - 匹配: `{match.matched_text[:80]}`\n\n")

        # 错误信息
        if result.errors:
            output.write("## 扫描错误\n\n")
            for error in result.errors:
                output.write(f"- {error}\n")

        return output.getvalue()

    # =========================================================================
    # SARIF 报告 (CI/CD 集成)
    # =========================================================================

    def format_sarif(self, result: ScanResult) -> str:
        """
        生成 SARIF (Static Analysis Results Interchange Format) 格式报告。

        SARIF 是 GitHub Code Scanning 等平台支持的标准格式。

        Args:
            result: 扫描结果

        Returns:
            SARIF JSON 字符串
        """
        severity_to_sarif_level = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        rules = []
        results = []

        seen_rules: Dict[str, Dict] = {}
        for match in result.matches:
            rule_id = match.rule_name.replace(" ", "-").lower()

            if rule_id not in seen_rules:
                rule_entry = {
                    "id": rule_id,
                    "name": match.rule_name,
                    "shortDescription": {
                        "text": match.description,
                    },
                    "properties": {
                        "category": match.rule_category.value,
                        "severity": match.severity.value,
                    },
                }
                seen_rules[rule_id] = rule_entry
                rules.append(rule_entry)

            # 构造匹配文本区域
            column = 1
            snippet = match.line_content.strip()
            # 尝试定位匹配文本在行中的位置
            idx = match.line_content.find(match.matched_text)
            if idx >= 0:
                column = idx + 1

            result_entry = {
                "ruleId": rule_id,
                "level": severity_to_sarif_level.get(match.severity, "warning"),
                "message": {
                    "text": f"{match.rule_name}: {match.description}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": match.file_path,
                            },
                            "region": {
                                "startLine": match.line_number,
                                "startColumn": column,
                            },
                        },
                    }
                ],
            }
            results.append(result_entry)

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "EnvGuard-CLI",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/envguard-cli",
                            "rules": rules,
                        },
                    },
                    "results": results,
                },
            ],
        }

        return json.dumps(sarif_report, indent=2, ensure_ascii=False)

    # =========================================================================
    # 通用输出方法
    # =========================================================================

    def generate_report(
        self,
        result: ScanResult,
        format_type: str = "table",
        score: Optional[SecurityScore] = None,
        output_file: Optional[str] = None,
    ) -> str:
        """
        生成指定格式的报告。

        Args:
            result: 扫描结果
            format_type: 输出格式 (table/json/csv/md/sarif)
            score: 可选的安全评分
            output_file: 可选的输出文件路径

        Returns:
            报告字符串
        """
        format_map = {
            "table": lambda: self.format_table(result, score),
            "json": lambda: self.format_json(result, score),
            "csv": lambda: self.format_csv(result),
            "md": lambda: self.format_markdown(result, score),
            "markdown": lambda: self.format_markdown(result, score),
            "sarif": lambda: self.format_sarif(result),
        }

        generator = format_map.get(format_type.lower())
        if generator is None:
            raise ValueError(f"不支持的输出格式: {format_type}。支持: {', '.join(format_map.keys())}")

        report_content = generator()

        # 写入文件
        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_content)

        return report_content

    def write_to_file(self, content: str, file_path: str) -> None:
        """
        将报告内容写入文件。

        Args:
            content: 报告内容
            file_path: 输出文件路径
        """
        dir_path = os.path.dirname(os.path.abspath(file_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
