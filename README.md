# CFDP Class 2 事务闭环审计服务

深空探测器回传文件时，链路重传或丢段可能让“表面完成”的 CFDP Class 2
事务实际缺少字节。本服务在入库前对归档员按捕获顺序提交的双向
Base64 CFDP PDU 做一次确定性重放，复核事务是否**真正闭环**，并冻结裁决。

纯 Python 3.11 标准库实现，无第三方运行时依赖。

## 支持范围（受限子集）

- 8 字节短固定头；16 位实体 ID、16 位事务序号；
- 仅 acknowledged mode（Class 2）；文件 ≤ 64 KiB；
- PDU：Metadata、File Data、EOF、ACK、NAK、Finished；
- CRC32C（Castagnoli）完整性校验。

PDU 线格式见 `app/cfdp.py` 顶部文档字符串。构造器在
`app/cfdp.py`（`metadata / file_data / eof / ack / nak / finished`），
捕获装配辅助在 `tests/captures.py`。

## 审计规则

按**捕获顺序**逐条重放双向 PDU：

- 重传允许，但**重叠字节必须一致**，首个不一致字节即判冲突；
- 仅接受属于同一事务（方向、两端实体、序号全部匹配）的 PDU；
- EOF 之后，NAK 必须由**当前未覆盖区间**精确生成（scope 为
  `[0, file_size)`，请求段列表与实际缺口逐段相等）；
- 补齐缺口、覆盖完整且 CRC32C 与 EOF 相符后，才允许 Finished；
- ACK 类型必须正确：接收方 `ACK(EOF, subtype=0x00)` 走 to_sender，
  发送方 `ACK(Finished, subtype=0x01)` 走 to_receiver；
- 终态（Finished 握手完成）后的任何写入/PDU 均判冲突；
- 任一违规输出 `first_violation`：违规 PDU 的捕获下标、类型、方向、
  违规定类、**当时阶段（stage / 双方 phase）**与原因，并撤销任何
  旧成功结论（该捕获永远不会得到 closed）。

裁决三态：

| verdict | 含义 |
| --- | --- |
| `closed` | 完整覆盖 + CRC32C 相符 + Finished/ACK 双向握手闭环，含双方阶段证据 |
| `incomplete` | 无违规但未闭环；`expected_nak` 给出精确缺口段，供生成 NAK |
| `conflict` | 协议违规；`first_violation` 定位首个违规 PDU 与当时阶段 |

报告含冻结的文件长度、CRC32C、覆盖/未覆盖区间、阶段证据链
（每条证据记录 PDU 下标、类型、方向与当时 sender/receiver 阶段）
及首个违约位置。

## HTTP 接口

- `GET /health` — 健康响应；
- `POST /audit` — 提交捕获：

```json
{
  "audit_id": "job-2026-0001",
  "pdus": [
    {"direction": "to_receiver", "pdu_base64": "..."},
    {"direction": "to_sender",   "pdu_base64": "..."}
  ]
}
```

`direction` 为捕获方向标签：`to_receiver`（发送方→接收方）或
`to_sender`（接收方→发送方）。

- `GET /audit/<audit_id>` — 读取冻结裁决。

冻结语义：同一 `audit_id` 的**完全相同**捕获（方向序列与原始 PDU 字节
逐字节一致，SHA-256 指纹）返回原冻结裁决（`replayed:false`）；任一方向
或任一原始 PDU 改变返回 HTTP 409 `frozen_conflict`，原裁决不变且仍可读。

宿主与端口可用 `CFDP_AUDIT_HOST`（默认 `0.0.0.0`）和
`CFDP_AUDIT_PORT`（默认 `8080`）配置。

## 运行

### 直接运行

```bash
python3 -m app.server
curl -s http://127.0.0.1:8080/health
```

### Compose（宿主端口可配置）

```bash
HOST_PORT=9090 docker compose up --build web
# 一次性验收服务（构建检查 → 等服务健康 → HTTP 闭环冒烟 →
# 缺段修复/冲突重传代码测试），以退出码报告结果：
docker compose run --build verify
```

`verify` 与 `web` 在同一编排中，`depends_on: service_healthy`
确保先完成构建检查、服务启动并通过健康检查后才开始验收。

## 一次性验收（无 Docker 时）

`app/verify.py` 是执行后即退出的验收服务，退出码 0 表示通过：

1. 构建检查：字节编译全部模块、导入服务入口、校验 CRC32C 向量；
2. 启动/等待服务并轮询 `/health`；
3. HTTP 冒烟：提交完整闭环捕获，断言 closed、完整覆盖、CRC 相符、
   双方阶段证据，并验证冻结复现与改变即冲突；
4. 代码测试：缺中段 → 精确 NAK `[1500,1560)` → 重传闭环；
   冲突重传 → 定位首个 FileData 违规 PDU、阶段与字节偏移。

```bash
python3 -m app.verify            # 自动拉起进程内服务
CFDP_AUDIT_BASE_URL=http://web:8080 python3 -m app.verify   # Compose 模式
```

## 测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
pytest            # 43 项：编解码、审计状态机、HTTP 冻结语义
```

## 目录

```
app/cfdp.py    短头 PDU 编解码 + CRC32C
app/audit.py   闭环审计状态机与裁决
app/server.py  HTTP 入口与冻结存储
app/verify.py  一次性验收服务（退出码报告）
tests/         pytest 套件与捕获装配辅助
Dockerfile, docker-compose.yml  web（可配置宿主端口）+ verify
```
