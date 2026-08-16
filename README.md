# cat_checkin

轻量签到自动化：通过 GitHub Actions 按计划执行 `scripts/*.py` 签到脚本，统一推送 Telegram 汇总。无服务器，无数据库。

## 架构

```text
GitHub Actions (cron)
  └─ python3 scripts/daily_report.py
       ├─ discover_tasks() → 遍历 scripts/*.py（排除 _ 前缀 / common / daily_report）
       ├─ 顺序执行每个脚本（子进程，互不影响）
       ├─ 解析 # new Env("站点名称") 构建 Telegram 报告
       └─ 推送到 Telegram
```

Latvi 独立 workflow，基于 `actions/cache` 的 `.latvi_state.json` 实现 24h 冷却。

## 目录

```text
.
├── .github/workflows/        # GitHub Actions 工作流
│   ├── checkin.yml           # 主签到工作流
│   └── latvi.yml             # Latvi 独立签到（24h 冷却）
├── scripts/
│   ├── common.py             # 共享 stdlib HTTP 客户端 + 辅助函数
│   ├── daily_report.py       # 签到调度器 + Telegram 汇总
│   └── <site>.py             # 每站签到模块
├── .env.example              # 环境变量模板
```

**零第三方依赖** — 全部使用 Python 标准库，CI 无需 `pip install`。

**无持久化存储** — Telegram 通知是唯一日志。Latvi 通过 `actions/cache` 保存 `.latvi_state.json` 记录上次签到时间戳。

## 常用命令

```bash
# 语法检查
python3 -m py_compile scripts/*.py

# 本地运行单个脚本 (需配置 .env)
python3 scripts/sophnet.py

# 本地运行完整报告 (跳过 Telegram 推送)
DAILY_PUSH=false python3 scripts/daily_report.py
```

## 环境变量

复制 `.env.example` 为 `.env`，仅填需要的站点凭据。

### Telegram

```text
TG_BOT_TOKEN=xxx
TG_CHAT_ID=xxx
# 或 TG_USER_ID=xxx
```

### 签到调度

```text
DAILY_PUSH=true              # 是否推送 Telegram
DAILY_EXCLUDE=latvi.py,workbuddy.py   # 排除的脚本
DAILY_TIMEOUT=180            # 单个脚本超时（秒）
DAILY_MAX_TASK_OUTPUT=1500   # 单个任务日志最大字符数
```

站点凭据遵循 `<SITE>_cookie` / `<SITE>_username` / `<SITE>_password` / `<SITE>_token`。多账号用 `&&` 或换行分隔。

> ⚠️ `.env` 使用手动 parser，不会 strip 行内 `#` 注释。Secret 行末不要放 `#` 尾注。

## 添加新签到脚本

查看 `CLAUDE.md` 中的 "Adding a New Sign-in Script" 章节 —— 每个脚本需遵守：
- `from common import Http, env, main_guard`
- `# new Env("站点名称 签到")`
- `main_guard(main)`
- 首行打印 `【站点名称 签到】`

## CI 部署

在 GitHub Repo Settings → Secrets 填写站点凭据，签到任务在 UTC 16:50（北京 00:50，Actions 低谷期）自动触发，Latvi 独立工作流（北京 18:00，24h 冷却约束），每日北京 10:00 统一邮件汇总。
