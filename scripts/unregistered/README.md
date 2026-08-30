# 未注册任务（搁置区）

已编写完成但**未注册进 task_registry** 的任务脚本——不参与每日调度，仅存档。

## 当前搁置列表

| 脚本 | 站点 | 搁置原因 | 重新启用条件 |
|---|---|---|---|
| `quark.py` | 夸克网盘 | 签到本体（growth 接口）需要 App 三参数 kps/sign/vcode（客户端会话签名），抓包一次才能激活；资产+保活部分已可跑但每日黄线提示无意义 | Reqable 抓 PC 客户端「签到领容量」页的 drive-m 请求 → set QUARK_MPARAM_1 |

## 重新启用方法

1. 把脚本移回 `scripts/`（或注册表 script 字段写 `unregistered/quark.py`）
2. 在 `scripts/task_registry.py` 加回注册条目
3. secret 已在库：QUARK_COOKIE_1（Cookie 可能需更新，__puus 24h 滑动已停，主会话 __pus 14 天窗口大概率已过 → 重新扫码换票一次）
4. `gh workflow run checkin.yml -f tasks=quark` 验证

注：脚本中的报告解析器（report_fields.py 的 ex_quark）与 fixture 保留在原位，重启用无需改动。
