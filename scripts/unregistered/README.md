# 未注册任务（搁置区）

已编写完成但**未注册进 task_registry** 的任务脚本——不参与每日调度，仅存档。

## 当前搁置列表

（空——quark 已于 2026-09-07 启用；ctyun 因基础实例需付费订阅被用户裁决回滚删除，教训记录在《新增任务计划.md》排除表）

## 重新启用方法（通用）

1. 把脚本移回 `scripts/`（或注册表 script 字段写 `unregistered/<id>.py`）
2. 在 `scripts/task_registry.py` 加回注册条目
3. 补齐对应 secrets 与 workflow env 映射
4. `gh workflow run checkin.yml -f tasks=<id>` 验证
