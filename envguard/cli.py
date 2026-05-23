"""
EnvGuard-CLI 命令行入口模块

提供子命令架构的 CLI 接口：
- scan: 扫描目录/文件
- audit: .gitignore 审计
- diff: 环境变量差异对比
- report: 生成报告
- check: 检查单个文件
"""

import argparse
import os
import sys
from typing import List, Optional

from envguard import __version__
from envguard.rules import Severity, get_all_rules, get_rule_summary
from envguard.scanner import Scanner, ScanResult
from envguard.evaluator import Evaluator
from envguard.gitignore_auditor import GitignoreAuditor
from envguard.env_diff import EnvDiff
from envguard.reporter import Reporter
from envguard.tui import TUI


def _parse_severity(value: str) -> Severity:
    """
    解析严重等级字符串。

    Args:
        value: 严重等级字符串

    Returns:
        Severity 枚举值

    Raises:
        argparse.ArgumentTypeError: 无效的严重等级
    """
    try:
        return Severity[value.upper()]
    except KeyError:
        valid = [s.value for s in Severity]
        raise argparse.ArgumentTypeError(
            f"无效的严重等级 '{value}'，可选值: {', '.join(valid)}"
        )


def build_parser() -> argparse.ArgumentParser:
    """
    构建 CLI 参数解析器。

    Returns:
        配置好的 ArgumentParser 实例
    """
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="EnvGuard-CLI - 轻量级环境变量与密钥安全智能扫描引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  envguard scan ./src              扫描 src 目录
  envguard scan . --format json    扫描当前目录并输出 JSON
  envguard audit                   审计 .gitignore
  envguard diff .env .env.prod     对比两个 .env 文件
  envguard check config.py         检查单个文件
  envguard report . --output report.md  生成 Markdown 报告
  envguard --rules                 列出所有扫描规则
        """,
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"EnvGuard-CLI v{__version__}",
    )

    parser.add_argument(
        "--rules",
        action="store_true",
        default=False,
        help="列出所有内置扫描规则",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="禁用彩色输出",
    )

    subparsers = parser.add_subparsers(dest="command", help="可用子命令")

    # ---- scan 子命令 ----
    scan_parser = subparsers.add_parser(
        "scan",
        help="扫描目录/文件中的硬编码密钥",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="要扫描的文件或目录路径（默认: 当前目录）",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv", "md", "sarif"],
        default="table",
        help="输出格式（默认: table）",
    )
    scan_parser.add_argument(
        "--severity", "-s",
        type=_parse_severity,
        default=None,
        help="最低报告严重等级 (CRITICAL/HIGH/MEDIUM/LOW/INFO)",
    )
    scan_parser.add_argument(
        "--ignore", "-i",
        action="append",
        default=[],
        help="忽略的文件 glob 模式（可多次使用）",
    )
    scan_parser.add_argument(
        "--exclude", "-e",
        action="append",
        default=[],
        help="排除的目录名（可多次使用）",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default=None,
        help="输出文件路径",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="显示详细信息",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="静默模式，仅输出摘要",
    )
    scan_parser.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="交互式结果浏览",
    )

    # ---- audit 子命令 ----
    audit_parser = subparsers.add_parser(
        "audit",
        help=".gitignore 安全审计",
    )
    audit_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="项目根目录路径（默认: 当前目录）",
    )
    audit_parser.add_argument(
        "--format", "-f",
        choices=["table", "json"],
        default="table",
        help="输出格式（默认: table）",
    )

    # ---- diff 子命令 ----
    diff_parser = subparsers.add_parser(
        "diff",
        help="环境变量差异对比",
    )
    diff_parser.add_argument(
        "files",
        nargs=2,
        metavar=("FILE1", "FILE2"),
        help="要对比的两个 .env 文件路径",
    )
    diff_parser.add_argument(
        "--format", "-f",
        choices=["table", "json"],
        default="table",
        help="输出格式（默认: table）",
    )

    # ---- report 子命令 ----
    report_parser = subparsers.add_parser(
        "report",
        help="生成扫描报告",
    )
    report_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="要扫描的文件或目录路径（默认: 当前目录）",
    )
    report_parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "md", "sarif"],
        default="json",
        help="报告格式（默认: json）",
    )
    report_parser.add_argument(
        "--output", "-o",
        default=None,
        help="输出文件路径",
    )
    report_parser.add_argument(
        "--severity", "-s",
        type=_parse_severity,
        default=None,
        help="最低报告严重等级",
    )
    report_parser.add_argument(
        "--ignore", "-i",
        action="append",
        default=[],
        help="忽略的文件 glob 模式",
    )
    report_parser.add_argument(
        "--exclude", "-e",
        action="append",
        default=[],
        help="排除的目录名",
    )

    # ---- check 子命令 ----
    check_parser = subparsers.add_parser(
        "check",
        help="检查单个文件",
    )
    check_parser.add_argument(
        "file",
        help="要检查的文件路径",
    )
    check_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="输出格式（默认: table）",
    )
    check_parser.add_argument(
        "--severity", "-s",
        type=_parse_severity,
        default=None,
        help="最低报告严重等级",
    )
    check_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="显示详细信息",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """
    执行 scan 子命令。

    Args:
        args: 命令行参数

    Returns:
        退出码（0=安全, 1=发现问题）
    """
    use_color = not args.no_color
    tui = TUI(use_color=use_color)
    reporter = Reporter(use_color=use_color, verbose=args.verbose, quiet=args.quiet)

    # 构建排除目录集合
    exclude_dirs = None
    if args.exclude:
        from envguard.scanner import DEFAULT_EXCLUDE_DIRS
        exclude_dirs = DEFAULT_EXCLUDE_DIRS | set(args.exclude)

    # 创建扫描器
    scanner = Scanner(
        ignore_patterns=args.ignore,
        exclude_dirs=exclude_dirs,
        min_severity=args.severity,
    )

    # 执行扫描
    if not args.quiet and args.format == "table":
        print(tui._bold(f"\n  EnvGuard-CLI v{__version__}"))
        print(f"  扫描路径: {os.path.abspath(args.path)}\n")

    result = scanner.scan(args.path)

    # 评估
    evaluator = Evaluator()
    score = evaluator.calculate_security_score(result.matches)

    # 输出
    if args.format == "table":
        tui.display_scan_result(result, score=score, verbose=args.verbose)
        if args.interactive and result.matches:
            tui.interactive_browse(result)
    else:
        report = reporter.generate_report(
            result,
            format_type=args.format,
            score=score,
            output_file=args.output,
        )
        if not args.output:
            print(report)

    # 返回退出码
    if result.critical_count > 0 or result.high_count > 0:
        return 1
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """
    执行 audit 子命令。

    Args:
        args: 命令行参数

    Returns:
        退出码
    """
    use_color = not args.no_color
    tui = TUI(use_color=use_color)

    auditor = GitignoreAuditor(project_path=args.path)
    result = auditor.audit()

    if args.format == "table":
        tui.display_audit_result(result)
    else:
        import json
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

    return 0 if result.is_secure else 1


def cmd_diff(args: argparse.Namespace) -> int:
    """
    执行 diff 子命令。

    Args:
        args: 命令行参数

    Returns:
        退出码
    """
    use_color = not args.no_color
    tui = TUI(use_color=use_color)

    differ = EnvDiff()
    result = differ.compare(args.files[0], args.files[1])

    if args.format == "table":
        tui.display_diff_summary(result)
    else:
        import json
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """
    执行 report 子命令。

    Args:
        args: 命令行参数

    Returns:
        退出码
    """
    use_color = not args.no_color
    reporter = Reporter(use_color=use_color)

    # 构建排除目录集合
    exclude_dirs = None
    if args.exclude:
        from envguard.scanner import DEFAULT_EXCLUDE_DIRS
        exclude_dirs = DEFAULT_EXCLUDE_DIRS | set(args.exclude)

    scanner = Scanner(
        ignore_patterns=args.ignore,
        exclude_dirs=exclude_dirs,
        min_severity=args.severity,
    )

    result = scanner.scan(args.path)
    evaluator = Evaluator()
    score = evaluator.calculate_security_score(result.matches)

    report = reporter.generate_report(
        result,
        format_type=args.format,
        score=score,
        output_file=args.output,
    )

    if not args.output:
        print(report)

    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """
    执行 check 子命令。

    Args:
        args: 命令行参数

    Returns:
        退出码
    """
    use_color = not args.no_color
    tui = TUI(use_color=use_color)
    reporter = Reporter(use_color=use_color, verbose=args.verbose)

    scanner = Scanner(min_severity=args.severity)
    result = scanner.scan(args.file)

    evaluator = Evaluator()
    score = evaluator.calculate_security_score(result.matches)

    if args.format == "table":
        tui.display_scan_result(result, score=score, verbose=args.verbose)
    else:
        report = reporter.generate_report(result, format_type=args.format)
        print(report)

    if result.critical_count > 0 or result.high_count > 0:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI 主入口。

    Args:
        argv: 命令行参数列表，为 None 时使用 sys.argv

    Returns:
        退出码
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # 列出规则
    if args.rules:
        tui = TUI(use_color=not args.no_color)
        rules = get_all_rules()
        tui.display_rules(rules)
        return 0

    # 无子命令时显示帮助
    if args.command is None:
        parser.print_help()
        return 0

    # 分发子命令
    command_map = {
        "scan": cmd_scan,
        "audit": cmd_audit,
        "diff": cmd_diff,
        "report": cmd_report,
        "check": cmd_check,
    }

    handler = command_map.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n\n  操作已取消。")
        return 130
    except Exception as e:
        print(f"\n  错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
