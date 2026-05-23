"""
EnvGuard-CLI setup.py

提供 setuptools 安装支持。
"""

from setuptools import setup, find_packages

setup(
    name="envguard-cli",
    version="1.0.0",
    description="轻量级环境变量与密钥安全智能扫描引擎 CLI 工具",
    author="EnvGuard Team",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "envguard=envguard.cli:main",
        ],
    },
    zip_safe=False,
)
