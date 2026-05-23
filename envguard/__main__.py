"""
EnvGuard-CLI 包入口点

支持通过 python -m envguard 运行。
"""

import sys
from envguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
