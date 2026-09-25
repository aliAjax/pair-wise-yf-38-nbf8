# 基因组数据访问治理

这是一个只使用Python标准库和SQLite的模块化项目，默认端口为`8304`。所有业务规则集中在`src/rules.py`，`app.py`只负责组装依赖和启动服务。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、数据结构、领域异常和基础校验。
- `src/rules.py`：状态机、权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务和乐观锁。
- `src/service.py`：用例编排、幂等处理、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、请求解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8304
```

服务启动时会自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。

## 核心对象

- `dataset`：受控数据集；`application`：访问申请；`grant`：限时数据使用凭证。
- `emergency_access`：事故排查时的紧急访问单（别名 `emergencies` / `emergency_accesses`）。

## 紧急访问单流程

事故排查可临时放行受控数据，状态机为 `pending → active → expired → reviewed`（另有 `rejected`、`revoked` 终态）。

- **发起**（`applicant`/`admin`）：必填 `incident_id`（事故编号）、`dataset_id`（数据集）、`purpose`（用途）、`expires_at`（截止时间，ISO 8601）；申请人取请求身份，不能冒填。
- **批准**（`committee`/`admin` 任一人即可）：申请人不能自批；截止时间过后单据自动失效，无法再批准。
- **不受理**：同一事故在同一数据集已有未结束单据（`pending`/`active`/`expired`）；数据集上存在未到期的普通有效 `grant`；前一张紧急单尚未完成事后复核；截止时间已过。
- **到期失效**：读取或查询时惰性判定，过了截止时间自动置为 `expired`，响应数据中带 `remaining_seconds`、`expired`、`finished` 字段。
- **事后复核**（`auditor`/`admin`）：`finding=compliant` 结案为 `reviewed`；`finding=unauthorized` 并填写 `reason` 时撤销凭证（状态 `revoked`）。
- 数据集曾有越权撤销记录后，再次申请同一数据集必须提交 `remediation_note` 补充说明（普通 `application` 同理）。

复核完成后同一事故/数据集才能再开新单。

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

请求身份通过`X-User-Id`和`X-Role`请求头传入。创建和动作的可执行角色由规则引擎控制。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

数据目录和授权凭证是治理流程演示，不包含真实数据下载、加密或机构身份联邦。
