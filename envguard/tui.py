"""
EnvGuard-CLI TUI 仪表盘模块

使用 ANSI 转义码实现终端用户界面，包括：
- 扫描进度条
- 结果分类展示
- 颜色高亮
- 交互式结果浏览
"""

import os
import sys
import time
from typing import Callable, Dict, List, Optional

from envguard.rules import RuleCategory, Severity
from envguard.scanner import ScanMatch, ScanResult
from envguard.evaluator import KeyEvaluation, SecurityScore


class TUI:
    """
    终端用户界面（TUI）组件。

    使用 ANSI 转义码实现彩色输出、进度条和交互式浏览。
    不依赖 curses，兼容所有终端。
    """

    # ANSI 转义码
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    REVERSE = "\033[7m"

    # 前景色
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;208m"
    GRAY = "\033[90m"

    # 背景色
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    # 光标控制
    CLEAR_LINE = "\033[2K"
    MOVE_UP = "\033[1A"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"

    def __init__(self, use_color: bool = True) -> None:
        """
        初始化 TUI。

        Args:
            use_color: 是否使用颜色
        """
        self.use_color = use_color
        self._progress_lines = 0

    def _c(self, text: str, color: str) -> str:
        """为文本添加颜色"""
        if not self.use_color:
            return text
        return f"{color}{text}{self.RESET}"

    def _bold(self, text: str) -> str:
        """加粗文本"""
        if not self.use_color:
            return text
        return f"{self.BOLD}{text}{self.RESET}"

    def _dim(self, text: str) -> str:
        """灰色文本"""
        if not self.use_color:
            return text
        return f"{self.DIM}{text}{self.RESET}"

    def severity_color(self, severity: Severity) -> str:
        """获取严重等级对应的颜色"""
        color_map = {
            Severity.CRITICAL: self.RED,
            Severity.HIGH: self.ORANGE,
            Severity.MEDIUM: self.YELLOW,
            Severity.LOW: self.GREEN,
            Severity.INFO: self.GRAY,
        }
        return color_map.get(severity, self.WHITE)

    # =========================================================================
    # 进度条
    # =========================================================================

    def progress_bar(
        self,
        current: int,
        total: int,
        prefix: str = "",
        width: int = 40,
        file_path: Optional[str] = None,
    ) -> str:
        """
        生成进度条字符串。

        Args:
            current: 当前进度
            total: 总数
            prefix: 前缀文本
            width: 进度条宽度（字符数）
            file_path: 当前处理的文件路径

        Returns:
            进度条字符串
        """
        if total == 0:
            percent = 100.0
        else:
            percent = (current / total) * 100

        filled = int(width * current / total) if total > 0 else width
        empty = width - filled

        # 进度条颜色
        if percent >= 100:
            bar_color = self.GREEN
        elif percent >= 75:
            bar_color = self.CYAN
        elif percent >= 50:
            bar_color = self.YELLOW
        else:
            bar_color = self.ORANGE

        filled_char = "\u2588" * filled
        empty_char = "\u2591" * empty
        bar = (
            f"{self._c('[' + filled_char, bar_color)}"
            f"{self._dim(empty_char)}"
            f"{self._c(']', bar_color)}"
        )

        status = f"{current}/{total} ({percent:.0f}%)"
        line = f"  {prefix}{bar} {status}"

        if file_path:
            # 截断文件路径
            display_path = file_path
            max_path_len = 50
            if len(display_path) > max_path_len:
                display_path = "..." + display_path[-(max_path_len - 3):]
            line += f"\n  {self._dim(f'Scanning: {display_path}')}"

        return line

    def show_progress(
        self,
        current: int,
        total: int,
        file_path: Optional[str] = None,
    ) -> None:
        """
        显示进度条（原地更新）。

        Args:
            current: 当前进度
            total: 总数
            file_path: 当前文件路径
        """
        bar_text = self.progress_bar(current, total, file_path=file_path)
        # 清除之前的进度行
        sys.stderr.write(f"\r{self.CLEAR_LINE}{bar_text}")
        if file_path:
            sys.stderr.write(f"\r{self.CLEAR_LINE}")
        sys.stderr.flush()

        if current == total:
            sys.stderr.write("\n")
            sys.stderr.flush()

    # =========================================================================
    # 标题和分隔线
    # =========================================================================

    def title(self, text: str, width: int = 70) -> str:
        """
        生成标题。

        Args:
            text: 标题文本
            width: 标题宽度

        Returns:
            格式化的标题字符串
        """
        padding = (width - len(text) - 4) // 2
        line = self._bold("=" * width)
        title_line = f"  {text.center(width - 4)}"
        return f"{line}\n{title_line}\n{line}"

    def separator(self, char: str = "-", width: int = 70) -> str:
        """生成分隔线"""
        return self._bold(char * width)

    def section_header(self, text: str) -> str:
        """生成章节标题"""
        return f"\n{self._bold(text)}"

    # =========================================================================
    # 结果展示
    # =========================================================================

    def display_scan_result(
        self,
        result: ScanResult,
        score: Optional[SecurityScore] = None,
        verbose: bool = False,
    ) -> None:
        """
        在终端显示扫描结果。

        Args:
            result: 扫描结果
            score: 安全评分
            verbose: 是否显示详细信息
        """
        # 标题
        print(self.title("EnvGuard-CLI 扫描报告"))

        # 摘要
        print(f"\n  扫描文件数: {result.files_scanned}")
        print(f"  跳过文件数: {result.files_skipped}")
        print(f"  扫描耗时:   {result.scan_duration:.3f}s")
        print(f"  发现总数:   {self._bold(str(result.total_findings))}")

        # 风险等级分布
        print(self.section_header("  风险等级分布:"))
        severity_items = [
            (Severity.CRITICAL, result.critical_count),
            (Severity.HIGH, result.high_count),
            (Severity.MEDIUM, result.medium_count),
            (Severity.LOW, result.low_count),
            (Severity.INFO, result.info_count),
        ]
        for sev, count in severity_items:
            color = self.severity_color(sev)
            label = f"{sev.value:10s}"
            bar = self._c("\u2588" * min(count * 2, 40), color)
            count_str = self._c(str(count), color)
            print(f"    {label} {bar} {count_str}")

        # 安全评分
        if score:
            print(self.section_header("  安全评分:"))
            score_color = (
                self.GREEN if score.score >= 75
                else self.YELLOW if score.score >= 50
                else self.RED
            )
            print(f"    {self._c(f'{score.score}/100', score_color)}  "
                  f"等级: {self._bold(score.grade)}")
            print(f"    {score.summary}")

        # 发现详情
        if result.total_findings == 0:
            print(f"\n  {self._c('未发现安全问题。', self.GREEN)}")
        else:
            print(self.separator())
            print(self.section_header("  发现详情:"))
            print(self.separator())

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
                    color = self.severity_color(current_severity)
                    print(f"\n  {self._c(f'[{current_severity.value}]', color)}")

                display_path = match.file_path
                if len(display_path) > 55:
                    display_path = "..." + display_path[-52:]

                print(f"    {self._dim(f'{display_path}:{match.line_number}')}")
                print(f"    {self._c(f'  [{match.rule_name}]', self.severity_color(match.severity))}")

                if verbose:
                    print(f"    {self._dim(f'  {match.description}')}")
                    matched_display = match.matched_text[:80]
                    print(f"    {self._dim(f'  Match: {matched_display}')}")

                print()

        # 错误信息
        if result.errors:
            print(self.separator())
            print(self.section_header("  扫描错误:"))
            print(self.separator())
            for error in result.errors:
                print(f"    {self._c(error, self.RED)}")

        print(f"\n{self._bold('=' * 70)}")

    def display_evaluation(
        self,
        evaluations: List[KeyEvaluation],
    ) -> None:
        """
        显示密钥强度评估结果。

        Args:
            evaluations: 评估结果列表
        """
        print(self.title("密钥强度评估"))

        for idx, ev in enumerate(evaluations, 1):
            color = self.severity_color(ev.risk_level)
            print(f"\n  {self._c(f'#{idx}', color)} "
                  f"{self._c(f'[{ev.risk_level.value}]', color)} "
                  f"{ev.rule_name}")
            print(f"    类型: {ev.key_type}")
            print(f"    长度: {ev.length} 字符")
            print(f"    熵值: {ev.entropy:.4f} bits")

            if ev.risk_reasons:
                print(f"    风险:")
                for reason in ev.risk_reasons:
                    print(f"      - {self._c(reason, color)}")

            if ev.suggestions:
                print(f"    建议:")
                for suggestion in ev.suggestions:
                    print(f"      - {self._dim(suggestion)}")

        print(f"\n{self._bold('=' * 70)}")

    def display_diff_summary(self, diff_result) -> None:
        """
        显示环境变量差异对比摘要。

        Args:
            diff_result: DiffResult 实例
        """
        print(self.title("环境变量差异对比"))

        print(f"\n  源文件: {diff_result.source_file}")
        print(f"  目标文件: {diff_result.target_file}")

        print(self.section_header("  差异统计:"))
        print(f"    新增变量:   {self._c(str(diff_result.added_count), self.GREEN)}")
        print(f"    移除变量:   {self._c(str(diff_result.removed_count), self.RED)}")
        print(f"    修改变量:   {self._c(str(diff_result.modified_count), self.YELLOW)}")
        print(f"    类型变化:   {self._c(str(diff_result.type_changed_count), self.ORANGE)}")
        print(f"    未变化:     {self._dim(str(diff_result.unchanged_count))}")
        print(f"    敏感差异:   {self._c(str(diff_result.sensitive_diff_count), self.RED)}")

        if diff_result.has_differences:
            print(self.separator())
            print(self.section_header("  差异详情:"))
            print(self.separator())

            for entry in diff_result.entries:
                if entry.diff_type.value == "unchanged":
                    continue

                type_colors = {
                    "added": self.GREEN,
                    "removed": self.RED,
                    "modified": self.YELLOW,
                    "type_changed": self.ORANGE,
                }
                color = type_colors.get(entry.diff_type.value, self.WHITE)

                sensitive_marker = " [SENSITIVE]" if entry.is_sensitive else ""
                print(f"\n  {self._c(f'[{entry.diff_type.value.upper()}]{sensitive_marker}', color)}")
                print(f"    Key: {entry.key}")
                print(f"    源: {entry.source_value or '(not set)'}")
                print(f"    目标: {entry.target_value or '(not set)'}")
                if entry.diff_type.value == "type_changed":
                    print(f"    类型: {entry.source_type.value} -> {entry.target_type.value}")
                print(f"    {self._dim(entry.description)}")
        else:
            print(f"\n  {self._c('两个文件完全一致。', self.GREEN)}")

        print(f"\n{self._bold('=' * 70)}")

    def display_audit_result(self, audit_result) -> None:
        """
        显示 .gitignore 审计结果。

        Args:
            audit_result: AuditResult 实例
        """
        print(self.title(".gitignore 安全审计"))

        if not audit_result.gitignore_exists:
            print(f"\n  {self._c('ERROR: .gitignore 文件不存在！', self.RED)}")
            print(f"  {self._dim('建议立即创建 .gitignore 文件。')}")
        else:
            print(f"\n  .gitignore 路径: {audit_result.gitignore_path}")
            print(f"  规则数量: {audit_result.rules_count}")

            status = (
                self._c("PASS", self.GREEN) if audit_result.is_secure
                else self._c("FAIL", self.RED)
            )
            print(f"  审计结果: {status}")

        if audit_result.findings:
            print(self.separator())
            print(self.section_header("  审计发现:"))
            print(self.separator())

            severity_colors = {
                "ERROR": self.RED,
                "WARNING": self.YELLOW,
                "INFO": self.CYAN,
                "OK": self.GREEN,
            }

            for finding in audit_result.findings:
                color = severity_colors.get(finding.severity.value, self.WHITE)
                print(f"\n  {self._c(f'[{finding.severity.value}]', color)} "
                      f"{finding.message}")
                if finding.suggestion:
                    print(f"    {self._dim(finding.suggestion)}")
                if finding.recommended_rule:
                    print(f"    {self._dim(f'推荐规则: {finding.recommended_rule}')}")
        else:
            print(f"\n  {self._c('未发现审计问题。', self.GREEN)}")

        print(f"\n{self._bold('=' * 70)}")

    # =========================================================================
    # 交互式浏览
    # =========================================================================

    def interactive_browse(self, result: ScanResult) -> None:
        """
        交互式浏览扫描结果。

        支持键盘导航：
        - 上/下箭头: 选择条目
        - Enter: 查看详情
        - q: 退出

        Args:
            result: 扫描结果
        """
        if not result.matches:
            print("  无结果可浏览。")
            return

        matches = sorted(
            result.matches,
            key=lambda m: (
                [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(m.severity),
                m.file_path,
                m.line_number,
            ),
        )

        current_idx = 0
        page_size = 10

        print(self.title("交互式结果浏览"))
        print(f"  共 {len(matches)} 条结果，使用 j/k 或 上/下箭头导航，q 退出\n")

        try:
            while True:
                # 显示当前页
                start = max(0, current_idx - page_size // 2)
                end = min(len(matches), start + page_size)

                for i in range(start, end):
                    match = matches[i]
                    color = self.severity_color(match.severity)
                    marker = " > " if i == current_idx else "   "
                    sev_label = f"[{match.severity.value[0]}]"
                    display_path = match.file_path
                    if len(display_path) > 40:
                        display_path = "..." + display_path[-37:]

                    line = f"  {marker}{self._c(sev_label, color)} {display_path}:{match.line_number} {match.rule_name}"
                    if i == current_idx:
                        line = self._c(line, color)
                    print(line)

                # 状态栏
                print(f"\n  [{current_idx + 1}/{len(matches)}] j/k:导航  Enter:详情  q:退出")

                # 读取输入
                key = input().strip().lower()

                if key == "q":
                    break
                elif key in ("j", "down"):
                    current_idx = min(current_idx + 1, len(matches) - 1)
                elif key in ("k", "up"):
                    current_idx = max(current_idx - 1, 0)
                elif key == "enter" or key == "":
                    # 显示详情
                    match = matches[current_idx]
                    print(self._bold(f"\n  详情: {match.rule_name}"))
                    print(f"  文件: {match.file_path}")
                    print(f"  行号: {match.line_number}")
                    print(f"  严重等级: {match.severity.value}")
                    print(f"  分类: {match.rule_category.value}")
                    print(f"  描述: {match.description}")
                    print(f"  匹配: {match.matched_text}")
                    print(f"  行内容: {match.line_content.strip()}")
                    print(f"\n  按任意键继续...")
                    input()

                # 清屏重绘
                print(f"\033[{page_size + 4}A", end="")

        except (KeyboardInterrupt, EOFError):
            pass

        print(f"\n{self._bold('=' * 70)}")

    # =========================================================================
    # 规则列表展示
    # =========================================================================

    def display_rules(self, rules: List) -> None:
        """
        显示规则列表。

        Args:
            rules: 规则列表
        """
        print(self.title(f"扫描规则列表 ({len(rules)} 条)"))

        # 按分类分组
        categories: Dict[str, List] = {}
        for rule in rules:
            cat = rule.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(rule)

        for cat_name, cat_rules in sorted(categories.items()):
            print(self.section_header(f"  {cat_name.replace('_', ' ').title()} ({len(cat_rules)} 条):"))
            for rule in cat_rules:
                color = self.severity_color(rule.severity)
                print(f"    {self._c(f'[{rule.severity.value[0]}]', color)} "
                      f"{rule.name}")
                print(f"      {self._dim(rule.description)}")
                if rule.examples:
                    print(f"      {self._dim(f'Example: {rule.examples[0][:60]}')}")
            print()

        print(self._bold("=" * 70))
