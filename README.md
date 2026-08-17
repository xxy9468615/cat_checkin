# cat_checkin

轻量签到自动化：GitHub Actions 低谷期（北京 00:50）矩阵执行 `scripts/*.py` 签到脚本，结果经 artifact/cache 双通道汇聚，每日北京 10:00 统一推送邮件（Resend 主通道 + SMTP 备选）。无服务器，无数据库。

## 架构

```text
00:50  checkin.yml ── 11 站点矩阵（run_task.py 子进程执行，产出结构化结果 JSON）
00:50  workbuddy.yml ─ 2 账号并行；放风领奖经 QStash 延时 dispatch 接力（~05:00）
09:10  modelscope.yml ─ 魔粒奖励 09:10 后才发放，单独调度
18:00  latvi.yml ─ 24h 冷却；签到成功后 +24h+3~5min 经 QStash dispatch 接力，
                    18:00 cron 仅作兜底锚点（链活着时幂等快速退出）
10:00  report.yml ─ fetch_latest 跨 run 收集当日 artifact → unified_report.py
                    期望清单比对（缺席即红卡）→ Resend 邮件走 QStash 持久投递
                    （retries=2, content_dedup=true；直发回退吃 @retry）
                    10:30 兜底升级为投递状态核查（check_qstash_delivery.py）
```

单个任务的链路：workflow → `run_task.py`（进程组超时控制）→ `scripts/<site>.py`（`main_guard` 统一异常出口）→ `.task_results/<site>.json`（ok/output/elapsed/date）→ artifact + actions/cache 双写 → 次日 report 汇聚。

## 目录

```text
.
├── .github/workflows/        # GitHub Actions 工作流
│   ├── checkin.yml           # 主签到矩阵（11 站点，北京 00:50）
│   ├── workbuddy.yml         # WorkBuddy 双账号 + QStash 放风接力
│   ├── modelscope.yml        # ModelScope 独立调度（北京 09:10）
│   ├── latvi.yml             # Latvi 24h 冷却 + QStash 接力（北京 18:00 兜底）
│   └── report.yml            # 每日统一邮件（北京 10:00 / 10:30 兜底）
├── scripts/
│   ├── common.py             # 共享 stdlib HTTP 客户端 / 重试 / QStash dispatch 助手
│   │                           # qstash_publish 通用发布 + schedule_repo_dispatch 薄封装
│   ├── run_task.py           # 单任务运行器（超时进程组击杀 + 结果 JSON 落盘）
│   ├── unified_report.py     # 结果汇聚 + 期望清单 + 发送语义（report.yml 入口）
│   ├── daily_report.py       # 报告构建 + HTML 邮件卡片 + SMTP/Resend 发送（函数库）
│   │                           # send_resend: QStash 持久投递主路径 + common.Http 直发回退
│   └── <site>.py             # 每站签到模块
├── templates/                # 邮件 HTML 模板
└── .env.example              # 环境变量模板（CI 走 GitHub Secrets 同名注入）
```

依赖：签到脚本全部使用 Python 标准库（requirements.txt 仅保留本地调试可选项）。

持久化：Latvi 的上次签到时间戳经 `actions/cache` 保存 `.latvi_state.json`；各任务结果当日经 artifact/cache 传递，跨日过期由日期白名单挡住。

## 常用命令

```bash
# 语法检查
python3 -m py_compile scripts/*.py

# 本地跑单个任务（需先 export 对应站点环境变量，仓库不做 .env 自动加载）
python3 scripts/run_task.py scripts/sophnet.py

# 本地预览统一报告（不发送；TASK_OUTPUT_DIR 指向已有结果目录）
DAILY_PUSH=false TASK_OUTPUT_DIR=.task_results python3 scripts/unified_report.py
```

## 环境变量

CI 在 Repo Settings → Secrets 填写站点凭据（命名对照 `.env.example`），本地调试需自行 `export`。通用项：

```text
TASK_TIMEOUT=300            # 单任务超时秒数（workbuddy/latvi/modelscope 在 workflow 内单独放宽）
DAILY_PUSH=true             # 是否发送报告邮件
QSTASH_URL / QSTASH_TOKEN / GH_PAT   # QStash 延时接力（workbuddy 放风 / latvi 24h 冷却）
                                       # + Resend 邮件持久投递（自动重试/DLQ/状态核查）
RESEND_API_KEY / RESEND_FROM / RESEND_TO   # 邮件主通道
MAIL_HOST / MAIL_USER / MAIL_PASS / MAIL_TO 等   # 邮件 SMTP 备选通道
```

站点凭据遵循 `<SITE>_cookie` / `<SITE>_username` / `<SITE>_password` / `<SITE>_token`。多账号用 `&&` 或换行分隔。以数字开头的变量在 GitHub Secrets 中需改名（如 `2LIBRA_COOKIES` → `TWO_LIBRA_COOKIES`）。

## 添加新签到脚本

查看 `CLAUDE.md` 中的 "Adding a New Sign-in Script" 章节 —— 每个脚本需遵守：
- `from common import Http, env, main_guard`
- `# new Env("站点名称 签到")`
- `main_guard(main)`
- 首行打印 `【站点名称 签到】`
- 失败路径必须 raise（exit 1），禁止打印错误后正常退出（假成功）

同时把 `checkin.yml` matrix 与 `unified_report.py` 的 `EXPECTED_RESULTS` 清单各加一行（后者缺席会以红卡形式在邮件里报警）。

## CI 部署

在 GitHub Repo Settings → Secrets 填写站点凭据。调度总览（北京时间）：

| 时间 | Workflow | 说明 |
|------|----------|------|
| 00:50 | checkin.yml | 11 站点矩阵，Actions 低谷期 |
| 00:50 | workbuddy.yml | 双账号；放风奖励 QStash 延时接力（~05:00 完成） |
| 09:10 | modelscope.yml | 魔粒奖励凌晨未开放，单独调度 |
| 18:00 | latvi.yml | 24h 冷却兜底锚点（主链路为 QStash 接力） |
| 10:00 / 10:30 | report.yml | 统一邮件（QStash 持久投递）/ 投递状态核查与兜底重发 |
