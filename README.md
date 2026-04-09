# SkillGuard

一个面向 AI Skills 的安全检测系统，自动化爬取和分析 ClawHub 上未被杀毒软件扫描的技能。

![Gemini_Generated_Image_usw9l3usw9l3usw9](.\img\picture.png)

## 核心流程

1. **周期爬取** — 从 ClawHub 获取最新发布的 Skills，筛选出 VirusTotal 未扫描的
2. **批量下载** — 下载目标 Skills 的完整包体
3. **集成分析** — 静态扫描、危险特征提取、LLM 验证、生成安全报告

## 技术方案

### 静态扫描与特征提取
使用 **skill-scanner** 工具对每个 Skill 的源代码进行静态扫描，自动识别以下关键风险：

- **高危命令执行 (RCE)** — 检测 `os.system`、`subprocess`、`eval`、`exec` 等动态执行代码，以及隐蔽混淆的调用链
- **供应链投毒** — 识别无文件攻击（`curl | bash`、`wget | sh`）和未固定版本的依赖注入
- **Prompt 注入与越狱** — 检测绕过大模型安全限制的恶意指令和角色劫持
- **数据窃取** — 识别非法的数据外发、凭证访问、敏感信息泄露等行为

扫描基于规则库和模式匹配，输出 JSON 格式报告，包含：
- 发现的漏洞列表（名称、类别、严重等级）
- 代码片段引用
- 风险评分

### LLM 验证与误报过滤
将扫描结果连同完整源代码输入 LLM（支持多种模型如GLM-4.5、GPT 等），进行二次验证：

- **真实性判断** — 区分"真实漏洞"与"误报"，判断漏洞是否有实际可利用性和代码证实
- **去除假阳性** — 识别示例代码、注释代码、或技能声明范围内的正常功能
- **生成验证证据** — 对确认的漏洞，LLM 提供代码证据链和复现步骤

### 双重报告输出
扫描完成后生成两类报告：

- **all** — 包含所有扫描发现，供深度分析和回顾
- **verified** — 仅包含LLM验证后的高置信漏洞，Markdown格式包含完整证据

### 并发处理
使用多线程加速分析流程，支持自定义并发数（默认10），适合大规模 Skill 集合的快速处理

## 快速开始

启动周期爬虫（每 10 分钟检查一次新 Skills）：
```bash
nohup python3 clawhub_unscanned_downloader.py > clawhub_crawl.log 2>&1 &
```

启动完整扫描分析流程：
```bash
bash run.sh
```

## 文件说明

- **clawhub_unscanned_downloader.py** — 爬虫模块，定期获取并过滤未扫描的 Skills
- **scan_and_analyze.py** — 分析模块，执行扫描、特征提取和 LLM 验证
- **run.sh** — 启动脚本，协调爬虫和分析流程
- **clawhub/** — 本地存储目录

## 环境要求

- Python 3.7+
- 依赖包：
  - `requests`、`beautifulsoup4`、`lxml` — 爬虫模块
  - `cisco-ai-skill-scanner` — 技能扫描工具（核心依赖）
  - `litellm` — LLM 调用（可选，用于漏洞验证）

安装依赖：
```bash
pip install -r requirements.txt
```

