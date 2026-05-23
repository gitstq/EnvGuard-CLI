<p align="center">
  <a href="#简体中文">简体中文</a> &nbsp;|&nbsp;
  <a href="#繁體中文">繁體中文</a> &nbsp;|&nbsp;
  <a href="#english">English</a>
</p>

---

<h1 align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-blue.svg" alt="Version" />
  &nbsp;
  <img src="https://img.shields.io/badge/python-3.8%2B-green.svg" alt="Python 3.8+" />
  &nbsp;
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="MIT License" />
  &nbsp;
  <img src="https://img.shields.io/badge/dependencies-zero-red.svg" alt="Zero Dependencies" />
</h1>

<h2 align="center">EnvGuard-CLI</h2>

<p align="center">
  <strong>轻量级环境变量与密钥安全智能扫描引擎</strong><br/>
  <em>Lightweight Environment Variable & Secret Security Intelligent Scanning Engine</em>
</p>

<p align="center">
  <a href="https://github.com/gitstq/EnvGuard-CLI">GitHub</a> &nbsp;|&nbsp;
  Report Bug &nbsp;|&nbsp;
  Feature Request
</p>

---

<a id="简体中文"></a>

# EnvGuard-CLI 简体中文文档

## 🎉 项目介绍

### 项目定位

EnvGuard-CLI 是一款**轻量级、零依赖**的环境变量与密钥安全智能扫描引擎，专为开发团队在日常开发流程中快速发现和评估代码仓库中的敏感信息泄露风险而设计。

### 核心价值

在软件开发过程中，API 密钥、数据库密码、私钥等敏感信息意外泄露到代码仓库是**最常见也最危险**的安全隐患之一。EnvGuard-CLI 通过内置 100 条精心调优的正则规则、Shannon 熵值分析引擎和智能风险评估算法，帮助团队在代码提交之前**秒级发现**潜在的安全漏洞。

### 解决的用户痛点

- **密钥泄露难发现** — 代码仓库中散落着各种格式的密钥，人工排查效率极低
- **现有工具依赖重** — truffleHog、gitleaks 等工具需要安装 Go 运行时或大量第三方依赖
- **只检测不评估** — 大多数工具只能告诉你"发现了密钥"，但无法评估密钥的实际风险等级
- **多环境配置混乱** — 开发/测试/生产环境变量差异大，缺乏有效的对比审计手段
- **.gitignore 配置不当** — 敏感文件未被正确忽略，导致密钥被提交到版本控制

### 差异化亮点

与 truffleHog、gitleaks 等主流工具相比，EnvGuard-CLI 具有以下独特优势：

| 特性 | EnvGuard-CLI | truffleHog | gitleaks |
|------|:-----------:|:----------:|:--------:|
| **零外部依赖** | ✅ 纯标准库 | ❌ 需 Go 运行时 | ❌ 需 Go 运行时 |
| **内置 TUI 仪表盘** | ✅ ANSI 彩色 | ❌ | ❌ |
| **密钥强度评分** | ✅ Shannon 熵值 | ❌ | ❌ |
| **环境变量差异对比** | ✅ | ❌ | ❌ |
| **.gitignore 审计** | ✅ | ❌ | ❌ |
| **单文件可执行** | ✅ | ❌ | ❌ |
| **总代码量** | <6000 行 | ~15000 行 | ~8000 行 |

---

## ✨ 核心特性

- 🔍 **100 条内置正则规则** — 覆盖 **AWS / GitHub / Google / Stripe / OpenAI / Azure / JWT / 私钥 / 数据库连接串 / Slack / Discord / Telegram** 等主流 API 密钥与服务凭证
- 📂 **22+ 种文件类型扫描** — 支持 `.py / .js / .ts / .java / .go / .rs / .rb / .php / .env / .yaml / .yml / .json / .xml / .ini / .conf / .cfg / .toml / .properties / .sh / .bash / .zsh / .ps1` 等多种文件格式
- 📊 **Shannon 熵值计算** — 基于信息论原理的密钥强度评估引擎，输出 **0-100 分安全评分**，精准量化密钥泄露风险
- 🛡️ **.gitignore 安全审计** — 一键检测 `.gitignore` 配置缺陷，识别可能被意外提交的敏感文件
- 🔄 **环境变量差异对比** — 智能对比多份 `.env` 文件，快速发现开发/测试/生产环境间的配置偏差与安全隐患
- 📝 **5 种报告格式输出** — 支持 **JSON / CSV / Markdown / SARIF / Table** 格式，无缝对接 GitHub Actions、GitLab CI 等主流 CI/CD 平台
- 🎨 **ANSI 彩色 TUI 仪表盘** — 美观的终端交互界面，风险等级一目了然，支持颜色开关
- ⌨️ **CLI 子命令架构** — `scan / audit / diff / report / check` 五大子命令，各司其职，灵活组合
- 🪶 **零外部依赖** — 纯 Python 标准库实现，`pip install` 后即可使用，无需安装任何第三方包
- ⚡ **极速扫描** — 秒级扫描万行代码，不拖慢开发流程

---

## 🚀 快速开始

### 环境要求

- **Python 3.8+**（已测试兼容 3.8 / 3.9 / 3.10 / 3.11 / 3.12）
- 无需任何第三方依赖

### 安装方式

#### 方式一：直接运行（推荐快速体验）

```bash
# 克隆仓库
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI

# 直接以模块方式运行
python -m envguard scan .
```

#### 方式二：pip 安装（推荐日常使用）

```bash
# 从 GitHub 安装
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# 安装后即可全局使用
envguard scan .
```

#### 方式三：作为 Python 模块导入

```python
from envguard.scanner import SecretScanner

scanner = SecretScanner()
results = scanner.scan_file("config.py")

for finding in results:
    print(f"[{finding.severity}] {finding.rule_name}: {finding.matched_value[:20]}...")
```

### 验证安装

```bash
# 查看版本信息
envguard --version

# 列出所有内置规则
envguard --rules

# 快速扫描当前目录
envguard scan .
```

---

## 📖 详细使用指南

### 全局参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--format` | 输出格式 (`json` / `csv` / `md` / `sarif` / `table`) | `table` |
| `--severity` | 最低风险等级 (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) | `LOW` |
| `--ignore` | 忽略指定规则 ID 或文件匹配模式 | - |
| `--exclude` | 排除指定目录（如 `node_modules,venv,.git`） | `.git` |
| `--no-color` | 禁用 ANSI 彩色输出 | `false` |
| `--quiet` | 静默模式，仅输出发现结果 | `false` |
| `--verbose` | 详细模式，输出扫描过程信息 | `false` |
| `--output` | 将结果输出到指定文件路径 | - |

### 子命令详解

#### 1. `scan` — 扫描目录或文件

扫描指定目录或文件中的敏感信息，输出风险评估报告。

```bash
# 扫描当前目录
envguard scan .

# 扫描指定目录
envguard scan /path/to/project

# 扫描单个文件
envguard scan config.py

# 仅报告 CRITICAL 和 HIGH 级别风险
envguard scan . --severity HIGH

# 输出 JSON 格式报告
envguard scan . --format json --output report.json

# 排除测试目录和依赖目录
envguard scan . --exclude "tests,node_modules,venv,dist"

# 忽略特定规则
envguard scan . --ignore "AWS_ACCESS_KEY,GITHUB_TOKEN"

# 详细模式（显示扫描过程）
envguard scan . --verbose
```

#### 2. `audit` — .gitignore 安全审计

检测 `.gitignore` 文件的配置安全性，识别可能被意外提交的敏感文件。

```bash
# 审计当前项目的 .gitignore
envguard audit

# 审计指定路径的 .gitignore
envguard audit /path/to/project

# 输出 Markdown 格式审计报告
envguard audit --format md --output audit_report.md
```

**审计内容包括：**
- 检查是否忽略了 `.env` 系列文件（`.env.local`、`.env.production` 等）
- 检查是否忽略了密钥文件（`*.pem`、`*.key`、`id_rsa` 等）
- 检查是否忽略了数据库配置文件
- 检查是否忽略了云服务凭证文件
- 评估 `.gitignore` 规则的覆盖完整度

#### 3. `diff` — 环境变量差异对比

对比两份环境变量文件，识别配置差异与潜在安全隐患。

```bash
# 对比两个 .env 文件
envguard diff .env.development .env.production

# 输出详细对比报告
envguard diff .env.staging .env.production --format json --output diff_report.json

# 对比并标注敏感变量差异
envguard diff .env.example .env.local --verbose
```

**对比维度：**
- 新增变量（目标文件独有的变量）
- 缺失变量（源文件有但目标文件没有的变量）
- 值变更（同名变量的值发生变化）
- 敏感变量识别（自动标注包含密钥/密码/Token 的变量）

#### 4. `report` — 生成综合报告

对指定路径生成完整的安全扫描报告。

```bash
# 生成 Markdown 格式报告
envguard report . --format md --output security_report.md

# 生成 SARIF 格式报告（用于 GitHub Code Scanning）
envguard report . --format sarif --output results.sarif

# 生成 CSV 格式报告（用于 Excel 分析）
envguard report . --format csv --output findings.csv

# 仅包含 CRITICAL 级别发现
envguard report . --severity CRITICAL --format json --output critical.json
```

#### 5. `check` — 检查单个文件

快速检查单个文件中是否包含敏感信息。

```bash
# 检查指定文件
envguard check config.py

# 检查并输出详细信息
envguard check .env --verbose

# 检查并以 JSON 格式输出
envguard check deployment.yaml --format json
```

### 典型使用场景

#### 场景一：日常开发安全检查

```bash
# 在提交代码前快速扫描
envguard scan . --severity MEDIUM

# 检查即将提交的文件
envguard check src/config/settings.py
```

#### 场景二：CI/CD 流水线集成

```bash
# 在 CI 中运行，输出 SARIF 格式供 GitHub Code Scanning 使用
envguard report . --format sarif --output results.sarif --no-color --quiet

# 在 CI 中运行，检查失败时返回非零退出码
envguard scan . --severity HIGH --quiet || exit 1
```

#### 场景三：多环境配置审计

```bash
# 审计 .gitignore 配置
envguard audit --format md --output audit.md

# 对比各环境配置差异
envguard diff .env.development .env.staging --format json --output dev_vs_staging.json
envguard diff .env.staging .env.production --format json --output staging_vs_prod.json
```

#### 场景四：项目安全评估

```bash
# 全面扫描并生成完整报告
envguard report /path/to/project --format md --output full_report.md --verbose

# 仅关注关键风险
envguard scan /path/to/project --severity CRITICAL --format json --output critical.json
```

---

## 💡 设计思路与迭代规划

### 设计理念

1. **零依赖哲学** — 依赖越少，安全风险越低。EnvGuard-CLI 完全基于 Python 标准库构建，消除了供应链攻击的风险面。
2. **安全工具本身要安全** — 不引入任何第三方网络请求、遥测数据收集，所有计算均在本地完成。
3. **人机友好的输出** — 通过 ANSI 彩色 TUI 和多格式报告，让安全审计结果既对开发者友好，也对自动化系统友好。
4. **检测与评估并重** — 不止步于"发现密钥"，更通过 Shannon 熵值分析评估密钥的实际风险等级，减少误报。

### 技术选型原因

| 决策 | 原因 |
|------|------|
| Python 标准库 | 生态最成熟、开发者最熟悉、跨平台兼容性最好 |
| 正则表达式引擎 | 密钥检测的业界标准方案，兼顾性能与准确率 |
| Shannon 熵值 | 信息论经典算法，科学量化密钥随机性与强度 |
| SARIF 格式 | 微软主导的静态分析结果交换标准，GitHub/GitLab 原生支持 |
| CLI 子命令架构 | 符合 Unix 哲学，单一职责，易于组合与自动化 |

### 后续迭代规划

- [ ] **增量扫描** — 支持 Git diff 增量检测，仅扫描变更文件
- [ ] **自定义规则** — 支持用户通过 YAML/JSON 文件定义自定义检测规则
- [ ] **基线模式** — 建立项目安全基线，仅报告新增风险
- [ ] **密钥轮换提醒** — 检测长期未变更的密钥并发出告警
- [ ] **IDE 插件** — 提供 VS Code / JetBrains 插件，实时高亮敏感信息
- [ ] **Pre-commit Hook** — 提供开箱即用的 Git pre-commit 集成
- [ ] **多语言规则引擎** — 支持语义级检测，减少正则误报
- [ ] **Web Dashboard** — 可选的 Web 界面，支持团队级安全看板

---

## 📦 打包与部署指南

### 安装方式汇总

```bash
# 1. 从 GitHub 克隆（开发模式）
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI
python -m envguard --version

# 2. pip 安装（推荐）
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# 3. 升级到最新版本
pip install --upgrade git+https://github.com/gitstq/EnvGuard-CLI.git

# 4. 卸载
pip uninstall envguard-cli
```

### CI/CD 集成

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  envguard:
    name: EnvGuard Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install EnvGuard-CLI
        run: pip install git+https://github.com/gitstq/EnvGuard-CLI.git

      - name: Run Security Scan
        run: envguard scan . --severity HIGH --format sarif --output results.sarif --no-color

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
stages:
  - security

envguard_scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install git+https://github.com/gitstq/EnvGuard-CLI.git
  script:
    - envguard scan . --severity HIGH --format json --output results.json --no-color --quiet
  artifacts:
    paths:
      - results.json
    when: always
  allow_failure: false
```

#### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/EnvGuard-CLI
    rev: v1.0.0
    hooks:
      - id: envguard-scan
        args: ['--severity', 'MEDIUM', '--quiet']
```

---

## 🤝 贡献指南

我们欢迎并感谢所有形式的贡献！无论是提交 Bug 报告、改进文档还是提交代码，都是对项目的宝贵支持。

### 提交 Issue

- **Bug 报告** — 请包含复现步骤、预期行为、实际行为、环境信息（Python 版本、操作系统）
- **功能建议** — 请详细描述使用场景和期望的行为
- **规则请求** — 如需新增检测规则，请提供密钥格式示例和来源服务文档链接

### 提交 Pull Request

1. **Fork** 本仓库并创建特性分支：`git checkout -b feature/your-feature-name`
2. 确保代码通过所有测试：`python -m pytest tests/`
3. 遵循 **Conventional Commits** 规范提交：
   - `feat: 新增 XXX 规则`
   - `fix: 修复 XXX 检测误报`
   - `docs: 更新 XXX 文档`
   - `refactor: 重构 XXX 模块`
   - `test: 新增 XXX 测试用例`
4. 提交 PR 并详细描述变更内容

### 代码规范

- 遵循 PEP 8 编码规范
- 所有新增规则必须附带测试用例
- 保持零外部依赖的约束
- 注释和文档字符串使用英文

---

## 📄 开源协议

本项目基于 [MIT License](./LICENSE) 开源。

```
MIT License

Copyright (c) 2026 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <a href="#简体中文">回到顶部</a> &nbsp;|&nbsp;
  <a href="#繁體中文">繁體中文</a> &nbsp;|&nbsp;
  <a href="#english">English</a>
</p>

---

<a id="繁體中文"></a>

# EnvGuard-CLI 繁體中文文檔

## 🎉 專案介紹

### 專案定位

EnvGuard-CLI 是一款**輕量級、零依賴**的環境變數與密鑰安全智慧掃描引擎，專為開發團隊在日常開發流程中快速發現和評估程式碼倉庫中的敏感資訊洩露風險而設計。

### 核心價值

在軟體開發過程中，API 密鑰、資料庫密碼、私鑰等敏感資訊意外洩露到程式碼倉庫是**最常見也最危險**的安全隱患之一。EnvGuard-CLI 透過內建 100 條精心調優的正則規則、Shannon 熵值分析引擎和智慧風險評估演算法，幫助團隊在程式碼提交之前**秒級發現**潛在的安全漏洞。

### 解決的使用者痛點

- **密鑰洩露難發現** — 程式碼倉庫中散落著各種格式的密鑰，人工排查效率極低
- **現有工具依賴重** — truffleHog、gitleaks 等工具需要安裝 Go 執行期或大量第三方依賴
- **只檢測不評估** — 大多數工具只能告訴你「發現了密鑰」，但無法評估密鑰的實際風險等級
- **多環境配置混亂** — 開發/測試/生產環境變數差異大，缺乏有效的對比審計手段
- **.gitignore 配置不當** — 敏感檔案未被正確忽略，導致密鑰被提交到版本控制

### 差異化亮點

與 truffleHog、gitleaks 等主流工具相比，EnvGuard-CLI 具有以下獨特優勢：

| 特性 | EnvGuard-CLI | truffleHog | gitleaks |
|------|:-----------:|:----------:|:--------:|
| **零外部依賴** | ✅ 純標準庫 | ❌ 需 Go 執行期 | ❌ 需 Go 執行期 |
| **內建 TUI 儀表板** | ✅ ANSI 彩色 | ❌ | ❌ |
| **密鑰強度評分** | ✅ Shannon 熵值 | ❌ | ❌ |
| **環境變數差異對比** | ✅ | ❌ | ❌ |
| **.gitignore 審計** | ✅ | ❌ | ❌ |
| **單檔案可執行** | ✅ | ❌ | ❌ |
| **總程式碼量** | <6000 行 | ~15000 行 | ~8000 行 |

---

## ✨ 核心特性

- 🔍 **100 條內建正則規則** — 覆蓋 **AWS / GitHub / Google / Stripe / OpenAI / Azure / JWT / 私鑰 / 資料庫連接串 / Slack / Discord / Telegram** 等主流 API 密鑰與服務憑證
- 📂 **22+ 種檔案類型掃描** — 支援 `.py / .js / .ts / .java / .go / .rs / .rb / .php / .env / .yaml / .yml / .json / .xml / .ini / .conf / .cfg / .toml / .properties / .sh / .bash / .zsh / .ps1` 等多種檔案格式
- 📊 **Shannon 熵值計算** — 基於資訊論原理的密鑰強度評估引擎，輸出 **0-100 分安全評分**，精準量化密鑰洩露風險
- 🛡️ **.gitignore 安全審計** — 一鍵檢測 `.gitignore` 配置缺陷，識別可能被意外提交的敏感檔案
- 🔄 **環境變數差異對比** — 智慧對比多份 `.env` 檔案，快速發現開發/測試/生產環境間的配置偏差與安全隱患
- 📝 **5 種報告格式輸出** — 支援 **JSON / CSV / Markdown / SARIF / Table** 格式，無縫對接 GitHub Actions、GitLab CI 等主流 CI/CD 平台
- 🎨 **ANSI 彩色 TUI 儀表板** — 美觀的終端互動介面，風險等級一目了然，支援顏色開關
- ⌨️ **CLI 子命令架構** — `scan / audit / diff / report / check` 五大子命令，各司其職，靈活組合
- 🪶 **零外部依賴** — 純 Python 標準庫實現，`pip install` 後即可使用，無需安裝任何第三方套件
- ⚡ **極速掃描** — 秒級掃描萬行程式碼，不拖慢開發流程

---

## 🚀 快速開始

### 環境要求

- **Python 3.8+**（已測試相容 3.8 / 3.9 / 3.10 / 3.11 / 3.12）
- 無需任何第三方依賴

### 安裝方式

#### 方式一：直接執行（推薦快速體驗）

```bash
# 克隆倉庫
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI

# 直接以模組方式執行
python -m envguard scan .
```

#### 方式二：pip 安裝（推薦日常使用）

```bash
# 從 GitHub 安裝
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# 安裝後即可全域使用
envguard scan .
```

#### 方式三：作為 Python 模組匯入

```python
from envguard.scanner import SecretScanner

scanner = SecretScanner()
results = scanner.scan_file("config.py")

for finding in results:
    print(f"[{finding.severity}] {finding.rule_name}: {finding.matched_value[:20]}...")
```

### 驗證安裝

```bash
# 查看版本資訊
envguard --version

# 列出所有內建規則
envguard --rules

# 快速掃描當前目錄
envguard scan .
```

---

## 📖 詳細使用指南

### 全域參數

| 參數 | 說明 | 預設值 |
|------|------|--------|
| `--format` | 輸出格式 (`json` / `csv` / `md` / `sarif` / `table`) | `table` |
| `--severity` | 最低風險等級 (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) | `LOW` |
| `--ignore` | 忽略指定規則 ID 或檔案匹配模式 | - |
| `--exclude` | 排除指定目錄（如 `node_modules,venv,.git`） | `.git` |
| `--no-color` | 停用 ANSI 彩色輸出 | `false` |
| `--quiet` | 靜默模式，僅輸出發現結果 | `false` |
| `--verbose` | 詳細模式，輸出掃描過程資訊 | `false` |
| `--output` | 將結果輸出到指定檔案路徑 | - |

### 子命令詳解

#### 1. `scan` — 掃描目錄或檔案

掃描指定目錄或檔案中的敏感資訊，輸出風險評估報告。

```bash
# 掃描當前目錄
envguard scan .

# 掃描指定目錄
envguard scan /path/to/project

# 掃描單個檔案
envguard scan config.py

# 僅報告 CRITICAL 和 HIGH 級別風險
envguard scan . --severity HIGH

# 輸出 JSON 格式報告
envguard scan . --format json --output report.json

# 排除測試目錄和依賴目錄
envguard scan . --exclude "tests,node_modules,venv,dist"

# 忽略特定規則
envguard scan . --ignore "AWS_ACCESS_KEY,GITHUB_TOKEN"

# 詳細模式（顯示掃描過程）
envguard scan . --verbose
```

#### 2. `audit` — .gitignore 安全審計

檢測 `.gitignore` 檔案的配置安全性，識別可能被意外提交的敏感檔案。

```bash
# 審計當前專案的 .gitignore
envguard audit

# 審計指定路徑的 .gitignore
envguard audit /path/to/project

# 輸出 Markdown 格式審計報告
envguard audit --format md --output audit_report.md
```

**審計內容包括：**
- 檢查是否忽略了 `.env` 系列檔案（`.env.local`、`.env.production` 等）
- 檢查是否忽略了密鑰檔案（`*.pem`、`*.key`、`id_rsa` 等）
- 檢查是否忽略了資料庫配置檔案
- 檢查是否忽略了雲端服務憑證檔案
- 評估 `.gitignore` 規則的覆蓋完整度

#### 3. `diff` — 環境變數差異對比

對比兩份環境變數檔案，識別配置差異與潛在安全隱患。

```bash
# 對比兩個 .env 檔案
envguard diff .env.development .env.production

# 輸出詳細對比報告
envguard diff .env.staging .env.production --format json --output diff_report.json

# 對比並標註敏感變數差異
envguard diff .env.example .env.local --verbose
```

**對比維度：**
- 新增變數（目標檔案獨有的變數）
- 缺失變數（來源檔案有但目標檔案沒有的變數）
- 值變更（同名變數的值發生變化）
- 敏感變數識別（自動標註包含密鑰/密碼/Token 的變數）

#### 4. `report` — 生成綜合報告

對指定路徑生成完整的安全掃描報告。

```bash
# 生成 Markdown 格式報告
envguard report . --format md --output security_report.md

# 生成 SARIF 格式報告（用於 GitHub Code Scanning）
envguard report . --format sarif --output results.sarif

# 生成 CSV 格式報告（用於 Excel 分析）
envguard report . --format csv --output findings.csv

# 僅包含 CRITICAL 級別發現
envguard report . --severity CRITICAL --format json --output critical.json
```

#### 5. `check` — 檢查單個檔案

快速檢查單個檔案中是否包含敏感資訊。

```bash
# 檢查指定檔案
envguard check config.py

# 檢查並輸出詳細資訊
envguard check .env --verbose

# 檢查並以 JSON 格式輸出
envguard check deployment.yaml --format json
```

### 典型使用場景

#### 場景一：日常開發安全檢查

```bash
# 在提交程式碼前快速掃描
envguard scan . --severity MEDIUM

# 檢查即將提交的檔案
envguard check src/config/settings.py
```

#### 場景二：CI/CD 流水線整合

```bash
# 在 CI 中執行，輸出 SARIF 格式供 GitHub Code Scanning 使用
envguard report . --format sarif --output results.sarif --no-color --quiet

# 在 CI 中執行，檢查失敗時返回非零退出碼
envguard scan . --severity HIGH --quiet || exit 1
```

#### 場景三：多環境配置審計

```bash
# 審計 .gitignore 配置
envguard audit --format md --output audit.md

# 對比各環境配置差異
envguard diff .env.development .env.staging --format json --output dev_vs_staging.json
envguard diff .env.staging .env.production --format json --output staging_vs_prod.json
```

#### 場景四：專案安全評估

```bash
# 全面掃描並生成完整報告
envguard report /path/to/project --format md --output full_report.md --verbose

# 僅關注關鍵風險
envguard scan /path/to/project --severity CRITICAL --format json --output critical.json
```

---

## 💡 設計思路與迭代規劃

### 設計理念

1. **零依賴哲學** — 依賴越少，安全風險越低。EnvGuard-CLI 完全基於 Python 標準庫建構，消除了供應鏈攻擊的風險面。
2. **安全工具本身要安全** — 不引入任何第三方網路請求、遙測資料收集，所有計算均在本地完成。
3. **人機友好的輸出** — 透過 ANSI 彩色 TUI 和多格式報告，讓安全審計結果既對開發者友好，也對自動化系統友好。
4. **檢測與評估並重** — 不止步於「發現密鑰」，更透過 Shannon 熵值分析評估密鑰的實際風險等級，減少誤報。

### 技術選型原因

| 決策 | 原因 |
|------|------|
| Python 標準庫 | 生態最成熟、開發者最熟悉、跨平台相容性最好 |
| 正則表示式引擎 | 密鑰檢測的業界標準方案，兼顧效能與準確率 |
| Shannon 熵值 | 資訊論經典演算法，科學量化密鑰隨機性與強度 |
| SARIF 格式 | 微軟主導的靜態分析結果交換標準，GitHub/GitLab 原生支援 |
| CLI 子命令架構 | 符合 Unix 哲學，單一職責，易於組合與自動化 |

### 後續迭代規劃

- [ ] **增量掃描** — 支援 Git diff 增量檢測，僅掃描變更檔案
- [ ] **自訂規則** — 支援使用者透過 YAML/JSON 檔案定義自訂檢測規則
- [ ] **基線模式** — 建立專案安全基線，僅報告新增風險
- [ ] **密鑰輪換提醒** — 檢測長期未變更的密鑰並發出告警
- [ ] **IDE 外掛** — 提供 VS Code / JetBrains 外掛，即時高亮敏感資訊
- [ ] **Pre-commit Hook** — 提供開箱即用的 Git pre-commit 整合
- [ ] **多語言規則引擎** — 支援語義級檢測，減少正則誤報
- [ ] **Web Dashboard** — 可選的 Web 介面，支援團隊級安全看板

---

## 📦 打包與部署指南

### 安裝方式彙總

```bash
# 1. 從 GitHub 克隆（開發模式）
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI
python -m envguard --version

# 2. pip 安裝（推薦）
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# 3. 升級到最新版本
pip install --upgrade git+https://github.com/gitstq/EnvGuard-CLI.git

# 4. 解除安裝
pip uninstall envguard-cli
```

### CI/CD 整合

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  envguard:
    name: EnvGuard Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install EnvGuard-CLI
        run: pip install git+https://github.com/gitstq/EnvGuard-CLI.git

      - name: Run Security Scan
        run: envguard scan . --severity HIGH --format sarif --output results.sarif --no-color

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
stages:
  - security

envguard_scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install git+https://github.com/gitstq/EnvGuard-CLI.git
  script:
    - envguard scan . --severity HIGH --format json --output results.json --no-color --quiet
  artifacts:
    paths:
      - results.json
    when: always
  allow_failure: false
```

#### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/EnvGuard-CLI
    rev: v1.0.0
    hooks:
      - id: envguard-scan
        args: ['--severity', 'MEDIUM', '--quiet']
```

---

## 🤝 貢獻指南

我們歡迎並感謝所有形式的貢獻！無論是提交 Bug 回報、改進文件還是提交程式碼，都是對專案的寶貴支持。

### 提交 Issue

- **Bug 回報** — 請包含重現步驟、預期行為、實際行為、環境資訊（Python 版本、作業系統）
- **功能建議** — 請詳細描述使用場景和期望的行為
- **規則請求** — 如需新增檢測規則，請提供密鑰格式範例和來源服務文件連結

### 提交 Pull Request

1. **Fork** 本倉庫並建立特性分支：`git checkout -b feature/your-feature-name`
2. 確保程式碼通過所有測試：`python -m pytest tests/`
3. 遵循 **Conventional Commits** 規範提交：
   - `feat: 新增 XXX 規則`
   - `fix: 修復 XXX 檢測誤報`
   - `docs: 更新 XXX 文件`
   - `refactor: 重構 XXX 模組`
   - `test: 新增 XXX 測試用例`
4. 提交 PR 並詳細描述變更內容

### 程式碼規範

- 遵循 PEP 8 編碼規範
- 所有新增規則必須附帶測試用例
- 保持零外部依賴的約束
- 註解和文件字串使用英文

---

## 📄 開源協議

本專案基於 [MIT License](./LICENSE) 開源。

```
MIT License

Copyright (c) 2026 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <a href="#简体中文">简体中文</a> &nbsp;|&nbsp;
  <a href="#繁體中文">回到頂部</a> &nbsp;|&nbsp;
  <a href="#english">English</a>
</p>

---

<a id="english"></a>

# EnvGuard-CLI English Documentation

## 🎉 Introduction

### Project Overview

EnvGuard-CLI is a **lightweight, zero-dependency** environment variable and secret security intelligent scanning engine, designed to help development teams quickly discover and assess sensitive information leakage risks in code repositories during their daily development workflow.

### Core Value

During software development, the accidental exposure of sensitive information such as API keys, database passwords, and private keys to code repositories is one of the **most common and dangerous** security vulnerabilities. EnvGuard-CLI leverages 100 carefully tuned built-in regex rules, a Shannon entropy analysis engine, and intelligent risk assessment algorithms to help teams **detect potential security vulnerabilities in seconds** before code is committed.

### Pain Points Addressed

- **Hard-to-discover secret leaks** — Keys in various formats are scattered across code repositories, making manual inspection extremely inefficient
- **Heavy dependencies of existing tools** — Tools like truffleHog and gitleaks require installing the Go runtime or numerous third-party dependencies
- **Detection without assessment** — Most tools can only tell you that a key was found, but cannot assess the actual risk level of the key
- **Chaotic multi-environment configurations** — Large differences between development/testing/production environment variables, with no effective comparison audit mechanism
- **Improper .gitignore configuration** — Sensitive files not properly ignored, leading to secrets being committed to version control

### Differentiation Highlights

Compared to mainstream tools like truffleHog and gitleaks, EnvGuard-CLI offers the following unique advantages:

| Feature | EnvGuard-CLI | truffleHog | gitleaks |
|---------|:-----------:|:----------:|:--------:|
| **Zero external dependencies** | ✅ Pure stdlib | ❌ Requires Go runtime | ❌ Requires Go runtime |
| **Built-in TUI dashboard** | ✅ ANSI colored | ❌ | ❌ |
| **Key strength scoring** | ✅ Shannon entropy | ❌ | ❌ |
| **Environment variable diff** | ✅ | ❌ | ❌ |
| **.gitignore audit** | ✅ | ❌ | ❌ |
| **Single-file executable** | ✅ | ❌ | ❌ |
| **Total code size** | <6000 lines | ~15000 lines | ~8000 lines |

---

## ✨ Core Features

- 🔍 **100 built-in regex rules** — Covers **AWS / GitHub / Google / Stripe / OpenAI / Azure / JWT / Private Keys / Database Connection Strings / Slack / Discord / Telegram** and other mainstream API keys and service credentials
- 📂 **22+ file type scanning** — Supports `.py / .js / .ts / .java / .go / .rs / .rb / .php / .env / .yaml / .yml / .json / .xml / .ini / .conf / .cfg / .toml / .properties / .sh / .bash / .zsh / .ps1` and more file formats
- 📊 **Shannon entropy calculation** — Key strength assessment engine based on information theory principles, outputting a **0-100 security score** to precisely quantify key leakage risk
- 🛡️ **.gitignore security audit** — One-click detection of `.gitignore` configuration defects, identifying sensitive files that may be accidentally committed
- 🔄 **Environment variable diff** — Intelligent comparison of multiple `.env` files to quickly discover configuration deviations and security risks between development/testing/production environments
- 📝 **5 report format outputs** — Supports **JSON / CSV / Markdown / SARIF / Table** formats, seamlessly integrating with GitHub Actions, GitLab CI, and other mainstream CI/CD platforms
- 🎨 **ANSI colored TUI dashboard** — Beautiful terminal interactive interface with risk levels visible at a glance, supporting color toggle
- ⌨️ **CLI subcommand architecture** — Five major subcommands: `scan / audit / diff / report / check`, each with its own responsibility, flexibly composable
- 🪶 **Zero external dependencies** — Implemented entirely with the Python standard library, ready to use after `pip install` with no third-party packages required
- ⚡ **Ultra-fast scanning** — Scans tens of thousands of lines of code in seconds without slowing down the development workflow

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (tested with 3.8 / 3.9 / 3.10 / 3.11 / 3.12)
- No third-party dependencies required

### Installation

#### Option 1: Run directly (recommended for quick trial)

```bash
# Clone the repository
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI

# Run as a module directly
python -m envguard scan .
```

#### Option 2: pip install (recommended for daily use)

```bash
# Install from GitHub
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# Use globally after installation
envguard scan .
```

#### Option 3: Import as a Python module

```python
from envguard.scanner import SecretScanner

scanner = SecretScanner()
results = scanner.scan_file("config.py")

for finding in results:
    print(f"[{finding.severity}] {finding.rule_name}: {finding.matched_value[:20]}...")
```

### Verify Installation

```bash
# Check version information
envguard --version

# List all built-in rules
envguard --rules

# Quick scan of the current directory
envguard scan .
```

---

## 📖 Detailed Usage Guide

### Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format (`json` / `csv` / `md` / `sarif` / `table`) | `table` |
| `--severity` | Minimum severity level (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) | `LOW` |
| `--ignore` | Ignore specific rule IDs or file match patterns | - |
| `--exclude` | Exclude directories (e.g., `node_modules,venv,.git`) | `.git` |
| `--no-color` | Disable ANSI colored output | `false` |
| `--quiet` | Quiet mode, only output findings | `false` |
| `--verbose` | Verbose mode, output scan process information | `false` |
| `--output` | Write results to the specified file path | - |

### Subcommand Reference

#### 1. `scan` — Scan directories or files

Scan specified directories or files for sensitive information and output a risk assessment report.

```bash
# Scan the current directory
envguard scan .

# Scan a specific directory
envguard scan /path/to/project

# Scan a single file
envguard scan config.py

# Report only CRITICAL and HIGH severity findings
envguard scan . --severity HIGH

# Output JSON format report
envguard scan . --format json --output report.json

# Exclude test and dependency directories
envguard scan . --exclude "tests,node_modules,venv,dist"

# Ignore specific rules
envguard scan . --ignore "AWS_ACCESS_KEY,GITHUB_TOKEN"

# Verbose mode (show scan process)
envguard scan . --verbose
```

#### 2. `audit` — .gitignore security audit

Detect `.gitignore` file configuration security issues and identify sensitive files that may be accidentally committed.

```bash
# Audit the current project's .gitignore
envguard audit

# Audit a .gitignore at a specific path
envguard audit /path/to/project

# Output Markdown format audit report
envguard audit --format md --output audit_report.md
```

**Audit contents include:**
- Check if `.env` family files are ignored (`.env.local`, `.env.production`, etc.)
- Check if key files are ignored (`*.pem`, `*.key`, `id_rsa`, etc.)
- Check if database configuration files are ignored
- Check if cloud service credential files are ignored
- Assess the coverage completeness of `.gitignore` rules

#### 3. `diff` — Environment variable diff

Compare two environment variable files to identify configuration differences and potential security risks.

```bash
# Compare two .env files
envguard diff .env.development .env.production

# Output detailed comparison report
envguard diff .env.staging .env.production --format json --output diff_report.json

# Compare and annotate sensitive variable differences
envguard diff .env.example .env.local --verbose
```

**Comparison dimensions:**
- Added variables (variables unique to the target file)
- Missing variables (variables present in the source but not in the target file)
- Value changes (values of same-named variables that have changed)
- Sensitive variable identification (automatically annotate variables containing keys/passwords/tokens)

#### 4. `report` — Generate comprehensive report

Generate a complete security scan report for a specified path.

```bash
# Generate Markdown format report
envguard report . --format md --output security_report.md

# Generate SARIF format report (for GitHub Code Scanning)
envguard report . --format sarif --output results.sarif

# Generate CSV format report (for Excel analysis)
envguard report . --format csv --output findings.csv

# Include only CRITICAL severity findings
envguard report . --severity CRITICAL --format json --output critical.json
```

#### 5. `check` — Check a single file

Quickly check whether a single file contains sensitive information.

```bash
# Check a specific file
envguard check config.py

# Check and output detailed information
envguard check .env --verbose

# Check and output in JSON format
envguard check deployment.yaml --format json
```

### Common Use Cases

#### Use Case 1: Daily development security check

```bash
# Quick scan before committing code
envguard scan . --severity MEDIUM

# Check files about to be committed
envguard check src/config/settings.py
```

#### Use Case 2: CI/CD pipeline integration

```bash
# Run in CI, output SARIF format for GitHub Code Scanning
envguard report . --format sarif --output results.sarif --no-color --quiet

# Run in CI, return non-zero exit code on failure
envguard scan . --severity HIGH --quiet || exit 1
```

#### Use Case 3: Multi-environment configuration audit

```bash
# Audit .gitignore configuration
envguard audit --format md --output audit.md

# Compare configuration differences across environments
envguard diff .env.development .env.staging --format json --output dev_vs_staging.json
envguard diff .env.staging .env.production --format json --output staging_vs_prod.json
```

#### Use Case 4: Project security assessment

```bash
# Full scan with comprehensive report
envguard report /path/to/project --format md --output full_report.md --verbose

# Focus on critical risks only
envguard scan /path/to/project --severity CRITICAL --format json --output critical.json
```

---

## 💡 Design Philosophy & Roadmap

### Design Principles

1. **Zero-dependency philosophy** — Fewer dependencies mean lower security risk. EnvGuard-CLI is built entirely on the Python standard library, eliminating the attack surface for supply chain attacks.
2. **Security tools must be secure themselves** — No third-party network requests or telemetry data collection; all computation is performed locally.
3. **Human and machine-friendly output** — Through ANSI colored TUI and multi-format reports, security audit results are friendly to both developers and automated systems.
4. **Detection and assessment in equal measure** — Going beyond simply "finding keys" to assessing actual risk levels through Shannon entropy analysis, reducing false positives.

### Technology Choices

| Decision | Rationale |
|----------|-----------|
| Python standard library | Most mature ecosystem, most familiar to developers, best cross-platform compatibility |
| Regex engine | Industry-standard approach for key detection, balancing performance and accuracy |
| Shannon entropy | Classic information theory algorithm for scientifically quantifying key randomness and strength |
| SARIF format | Microsoft-led static analysis result interchange standard, natively supported by GitHub/GitLab |
| CLI subcommand architecture | Follows Unix philosophy: single responsibility, easy to compose and automate |

### Roadmap

- [ ] **Incremental scanning** — Git diff-based incremental detection, scanning only changed files
- [ ] **Custom rules** — User-defined detection rules via YAML/JSON configuration files
- [ ] **Baseline mode** — Establish project security baselines, reporting only new risks
- [ ] **Key rotation reminders** — Detect long-unchanged keys and issue alerts
- [ ] **IDE plugins** — VS Code / JetBrains plugins for real-time sensitive information highlighting
- [ ] **Pre-commit hook** — Out-of-the-box Git pre-commit integration
- [ ] **Multi-language rule engine** — Semantic-level detection to reduce regex false positives
- [ ] **Web dashboard** — Optional web interface for team-level security dashboards

---

## 📦 Packaging & Deployment Guide

### Installation Summary

```bash
# 1. Clone from GitHub (development mode)
git clone https://github.com/gitstq/EnvGuard-CLI.git
cd EnvGuard-CLI
python -m envguard --version

# 2. pip install (recommended)
pip install git+https://github.com/gitstq/EnvGuard-CLI.git

# 3. Upgrade to the latest version
pip install --upgrade git+https://github.com/gitstq/EnvGuard-CLI.git

# 4. Uninstall
pip uninstall envguard-cli
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  envguard:
    name: EnvGuard Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install EnvGuard-CLI
        run: pip install git+https://github.com/gitstq/EnvGuard-CLI.git

      - name: Run Security Scan
        run: envguard scan . --severity HIGH --format sarif --output results.sarif --no-color

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
stages:
  - security

envguard_scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install git+https://github.com/gitstq/EnvGuard-CLI.git
  script:
    - envguard scan . --severity HIGH --format json --output results.json --no-color --quiet
  artifacts:
    paths:
      - results.json
    when: always
  allow_failure: false
```

#### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitstq/EnvGuard-CLI
    rev: v1.0.0
    hooks:
      - id: envguard-scan
        args: ['--severity', 'MEDIUM', '--quiet']
```

---

## 🤝 Contributing Guide

We welcome and appreciate all forms of contribution! Whether it's submitting bug reports, improving documentation, or submitting code, every contribution is valuable to the project.

### Submitting Issues

- **Bug reports** — Please include reproduction steps, expected behavior, actual behavior, and environment information (Python version, operating system)
- **Feature requests** — Please describe use cases and expected behavior in detail
- **Rule requests** — If you need new detection rules, please provide key format examples and links to the source service documentation

### Submitting Pull Requests

1. **Fork** this repository and create a feature branch: `git checkout -b feature/your-feature-name`
2. Ensure all tests pass: `python -m pytest tests/`
3. Follow the **Conventional Commits** specification:
   - `feat: add XXX rule`
   - `fix: fix XXX false positive`
   - `docs: update XXX documentation`
   - `refactor: refactor XXX module`
   - `test: add XXX test case`
4. Submit your PR with a detailed description of the changes

### Code Standards

- Follow PEP 8 coding conventions
- All new rules must include test cases
- Maintain the zero external dependency constraint
- Use English for comments and docstrings

---

## 📄 License

This project is licensed under the [MIT License](./LICENSE).

```
MIT License

Copyright (c) 2026 gitstq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  <a href="#简体中文">简体中文</a> &nbsp;|&nbsp;
  <a href="#繁體中文">繁體中文</a> &nbsp;|&nbsp;
  <a href="#english">Back to Top</a>
</p>
