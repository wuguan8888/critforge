# CritForge 端到端真实实测报告（续）

- **更新时间**：2026-10-29（America/Los_Angeles）
- **范围**：本地授权靶场 +（计划中）GitHub **仅本人仓库** 信息收集 → DeepSeek 实调用 → CritForge 流水线
- **红线**：不扫描第三方公开仓库；不回显任何密钥/token 值；无利用载荷；只读

---

## 0. 诚实限制（先读）

| 项 | 状态 |
|---|---|
| `GITHUB_TOKEN`（`.env`） | **变量存在**，但此前探测为 **401 Bad credentials**（已失效） |
| Cursor GitHub 连接器 | **待用户连接**（已弹出连接卡；本阶段未再调用 GitHub API） |
| 本人仓库扫描 | **推迟** — 等连接器/有效 token 就绪后自动续跑；**不会**扫第三方仓库 |
| DeepSeek | **实调用成功**（`mode=deepseek_live`，返回 model=`deepseek-flash`） |
| 本地靶场 | **实跑成功**（`127.0.0.1:8765` stdlib lab；Docker 仍不可用） |

---

## 1. 流水线执行情况

```
信息收集(GitHub own-repos) → AI 分析(DeepSeek) → 检测/验证/置信度 → 报告
        [推迟/失败]              [实调用 OK]           [本地 lab 实跑 OK]
```

### 1.1 GitHub 本人仓库信息收集

- 配置要求：只用 token 账户 **affiliation=owner** 的仓库。
- 实现模块：`python/critforge/github_recon.py`（密钥值一律 redact；只报 location + type）。
- 本次结果：因 token 401 + 连接器待授权，**未枚举、未下载、未扫描任何仓库内容**。
- 产物：`range_artifacts/github_recon.json`（仅状态，无秘密值）。

### 1.2 DeepSeek AI 分析（真实 API）

- Key 变量：`DEEPSEEK_API_KEY` = **已配置**（不回显值）
- base_url：`https://api.deepseek.com/v1`
- 角色：planner（请求模型名 deepseek-reasoner；响应记录为 `deepseek-flash`）
- 模式：**`deepseek_live`**
- 输入：本地 lab 脱敏发现 8 条（GitHub hits=0，因扫描推迟）
- 优先排序条数：8
- 摘要（模型输出，无密钥）：

> Eight local-lab findings were reviewed. The highest-risk items are direct exposure of a sensitive API endpoint and reflected XSS, with the reported exploit chain corroborating related weaknesses. Directory listing, default-credential hinting, verbose errors, banner disclosure, and missing security headers are real but ranked lower unless evidence shows sensitive data exposure or direct exploitability.

- 置信度备注：["No secret values were requested, inferred, or included; analysis uses only the redacted findings.", "Severity was normalized independently of the provided severity hints, based on demonstrated impact and exploitability evidence.", "Confirmed findings were accepted as observed in the authorized local lab, but severity still depends on data sensitivity and exploit context.", "The chain finding is treated as corroborating evidence and an aggregate risk signal, not as proof that every possible chain step is fully exploitable.", "Recon/defense-in-depth findings such as banners and missing headers are real but ranked below direct access-control and input-handling flaws."]
- 产物：`range_artifacts/ai_analysis.json`

### 1.3 本地靶场完整流水线（保留）

与上一轮一致并已复跑：

| 指标 | 值 |
|---|---|
| 漏报率 FN | **0.0** |
| 误报率 FP | **0.0** |
| 检出 GT | ['GT-1', 'GT-2', 'GT-3', 'GT-4', 'GT-5', 'GT-6', 'GT-7'] |
| 漏检 GT | 无 |
| 置信度分布 | {'confirmed': 7, 'high': 1} |
| 三段式 Detection | 1.0 |
| 三段式 Confirmation | 1.0 |
| 三段式 Evidence | 1.0 |
| 报告发现数 | 7（含 1 条攻击链） |
| 范围外拒绝 | `evil.example.com` 已拒绝 |

产物：`range_artifacts/e2e_lab_stage.json`、`e2e_metrics.json`。

---

## 2. 阈值校准建议

当前：`severity_gate=High`，`confidence_gate=medium`。

- 本地靶场 FN=0 / FP=0：保持 High × medium。
- GitHub own-repo 扫描因 token 401 + 连接器待授权而推迟；重连后复跑再校准密钥类发现阈值。
- DeepSeek 模式=deepseek_live model=deepseek-flash

**建议保持** High × medium（本地靶场最优）。  
GitHub 密钥类发现复跑后：若 FP>10%，将 `confidence_gate` 提到 `high`，并要求 `confirmation_marker`。

---

## 3. 新增代码（本次）

| 路径 | 作用 |
|---|---|
| `critforge/github_recon.py` | 仅扫描 token 所有者自己的仓库；密钥 redact |
| `critforge/ai_analyze.py` | DeepSeek 实调用 + 离线回退 |
| `lab/run_e2e_real.py` | 端到端编排脚本 |
| `tests/test_github_recon.py` / `test_ai_analyze.py` | 单测（不联网也可过） |

---

## 4. 测试

```
pytest: 113 passed
critforge health: OK（scope.lab.yaml）
```

---

## 5. 下一步（自动续跑条件）

1. 用户完成聊天里的 **Connect GitHub** 卡片，或向 `.env` 写入有效的 `GITHUB_TOKEN`（classic，至少能读本人仓库内容）。
2. 续跑将：`GET /user/repos?affiliation=owner` → 只扫这些仓库的配置/密钥/内网域名/API 端点（值脱敏）→ 再喂 DeepSeek → 更新本报告与 `range_artifacts/`。

---

## 6. 复现

```bash
# 本地 lab
./.venv/bin/python lab/vuln_lab.py --host 127.0.0.1 --port 8765
# 端到端（GitHub 需有效 token）
./.venv/bin/python lab/run_e2e_real.py
```

原始数据目录：`/workspace/critforge/range_artifacts/`  
本报告：`/workspace/critforge/RANGE_TEST_REPORT.md`


---

# 复杂靶场端到端实测（OWASP Juice Shop）

- **时间**：2026-10-30 Asia/Singapore（box UTC+8）
- **选型**：OWASP Juice Shop（`juice-shop/juice-shop`，~14k★，前后端分离 + REST/JSON API + 多模块挑战）
- **备选未部署**：OWASP crAPI（需 Docker Compose）、WebGoat（需 Java/Docker）— 本机仍无 Docker、无 Java
- **部署**：`git clone --depth 1` + `npm install` + `npm start` → `http://127.0.0.1:3000/`（NODE_ENV=production）
- **授权**：`scope.lab.yaml` allowlist=`127.0.0.1`,`localhost`；`kuaishou.com` 仍在 `pending_authorization`（fail-closed）

## 流水线结果

| 阶段 | 结果 |
|---|---|
| 目标解析 | `http://127.0.0.1:3000/` 解析成功 |
| 范围闸 | **ALLOW** localhost；**DENY** `kuaishou.com`（pending_authorization）；**DENY** `evil.example.com`（out of scope） |
| 探活/爬取 | HttpObserveProbe 抓取 Juice Shop 公开面（/api/Products、/ftp、/encryptionkeys、/metrics 等） |
| 检测 | 5 条 High 发现 + 1 条攻击链 |
| 验证 | 全部进入 evidence；报告 6 条（suppressed=0） |

### 报告发现（通过 High × medium 双轴闸）

- Unauthenticated sensitive API endpoint
- Directory listing enabled
- Encryption key material directory exposed
- Unauthenticated metrics / Prometheus endpoint
- Missing HTTP security headers
- Chain on http://127.0.0.1:3000/: misconfig → auth_flaw

实际 titles：
- Unauthenticated sensitive API endpoint
- Directory listing enabled
- Encryption key material directory exposed
- Unauthenticated metrics / Prometheus endpoint
- Missing HTTP security headers
- Chain on http://127.0.0.1:3000/: misconfig → auth_flaw

### 拒绝目标

[
  {
    "target": "https://www.kuaishou.com",
    "reason": "pending authorization by rule 'kuaishou.com': recorded as target, not active until signed authorization is provided (fail-closed)"
  },
  {
    "target": "https://evil.example.com",
    "reason": "not in allowlist (out of scope)"
  }
]

## 端到端结论

**完整链路可用**：目标解析 → 范围/待授权闸 → HTTP 观察探针 → 插件检测 → 三段式验证 → 攻击链合成 → 双轴报告。  
相对早期 stdlib 单页 lab，Juice Shop 暴露了更大的真实攻击面（目录列表 /ftp、密钥目录、metrics、未鉴权 API）。

## 产物

- `range_artifacts/juice_shop_stage.json`
- `range_artifacts/juice_shop_report.json` / `.txt`
- `range_artifacts/juice-shop-audit.jsonl`


---

## pt41u — Nuclei 同源修复复测 + WebGoat / crAPI 非侵入式全流水线（2026-10-30 09:00–09:40 UTC+8）

红线保持：仅非侵入（被动检测 + Nuclei 安全模板，排除 intrusive/fuzz/dos/rce/sqli/xss/cve/default-login 等），无利用载荷，未自动审批授权，未删除任何红线配置；`kuaishou.com` 每次运行均被 M1 拒绝（pending_authorization）。产物中未写入任何密钥值。

### Nuclei 同源过滤复测
- Juice Shop（127.0.0.1:3000）在本轮开始后进程已退出（端口关闭；内核日志有内存压力 balloon 告警），按约束**未重启**。复测结果 0 条（`juice_shop_nuclei_rerun.json`），不能作为同源修复的证据。
- 同源修复在 WebGoat、crAPI 实跑中得到实证：所有 Nuclei 结果端点均在目标端口（8080 / 8888），无 6080 noVNC 等范围外结果。

### WebGoat（http://127.0.0.1:8080/WebGoat）
- 阶段：M1 授权 1、拒绝 1（kuaishou）→ http_observe 13 页 ✓ → nuclei ✓（12 条，同源）→ 检测 13 → 验证 13（evidence 阶段）→ 攻击链 0 → 双轴闸门后报告 1（High 缺失安全头），抑制 12。
- 发现：缺失安全响应头（High）；Tomcat 堆栈跟踪开启（Low，`/?f=[`）；WAF 指纹（Info）；HTTP 缺失安全头 ×10（Info，nuclei）。
- 首轮出现 10 条备份文件误报（Spring 对未知路径统一返回登录页）→ 已修复为"同目录不存在兄弟文件"对照 + 回归测试，复跑 0 误报。
- 局限：`/WebGoat/actuator*` 返回 200 但被动检测未判定为暴露（未区分登录页/真实内容），WebGoat 课程类漏洞（SQLi/XSS/IDOR/JWT 等）均需主动交互，未覆盖。

### crAPI（http://127.0.0.1:8888/，identity / community / workshop 经网关）
- 阶段：M1 授权 1、拒绝 1 → http_observe 16 页 ✓（多数 API 401/404，需登录）→ nuclei ✓（14 条，同源）→ 检测 16 → 验证 16 → 攻击链 0 → 报告 4，抑制 12。
- 发现：**`/.env` 文件可公开下载（High，真实阳性，3 个 Nuclei 模板重复命中同一端点，内容未落盘）**；缺失安全响应头（High）；Server banner 泄露（Medium）；OpenResty 指纹（Info）。
- 局限：crAPI 的核心漏洞（BOLA/BFLA、批量赋值、SSRF、NoSQLi、JWT 等）都需要已认证的主动 API 测试，未覆盖。MailHog（8025）因可能含 OTP 未纳入。

### 结论
端到端链路（M0 → M1 闸门 → 探测 → Nuclei → 检测 → 验证 → 双轴闸门 → 报告）在 WebGoat 与 crAPI 上均跑通；攻击链合成两边均为 0（缺少 misconfig+auth_flaw 组合信号）。pytest 139 passed，health OK。
产物：`range_artifacts/{webgoat,crapi}_{stage,report}.json`、`*_report.txt`、`*_summary.json`、`*-audit.jsonl`、`juice_shop_nuclei_rerun.json`；驱动脚本 `lab/run_lab_range.py`。

---

## pt42u — 全功能实现与优化（授权/利用荷载除外）（2026-10-30，Asia/Shanghai）

**红线保持**：kuaishou.com 仍为 pending_authorization，每次运行均被拒绝；未自动批准授权；`craft_offensive_payload` 仍为 NotImplementedError；仅 GET/HEAD 非侵入式探测；heapdump/threaddump/shutdown/jolokia 等及一切变更型路由（delete/reset/login/add/buy…）均在抓取前过滤；凭据/密钥值从不入证据（只记数量/形态）。

### 新增/优化组件
- **discovery.py**：常见路径字典（.env/.git/actuator/*/metrics/swagger/robots/sitemap…）、robots/sitemap/asset-manifest 解析、深度 2 链接爬取、JS 路由提取（含 crAPI 式 `SERVICE + "api/..."` 拼接与网关服务实时校验）、回退感知分类（per-dir 对照请求：soft404 / login_redirect / auth_required / client_error…）、内容校验器、技术指纹。
- **detectors**：ExposureDetector、TechFingerprintDetector、ApiSurfaceDetector；安全头/metrics/verbose error 严重度重新标定。
- **nuclei.py**：按 (template, matched-at) 归并 matcher，`issue_key` 映射；**dedup.py**：跨引擎合并（passive+nuclei → `cross_engine`）。
- **verify.py**：仅 finding 级可复现才升 High；内容校验+复现 → High；跨引擎+校验 → Confirmed；heuristic_only 封顶 Medium。
- **attackchain.py**：丢弃 Info、按 issue_key 去重、终点必须为实质性发现、≤6 节点、主题化标题。

### 测试
- 新增 `tests/test_pt42u_discovery.py`（12 例，含本地 Spring/SPA 模拟靶场）；**pytest 152 passed**。
- `/health` → 200 `{"status":"ok","version":"0.3.0",...}`。

### 靶场全量运行（含 Nuclei v3.11.1）
| 靶场 | detect raw→dedup | 上报 (High) | 链 |
|---|---|---|---|
| WebGoat | 9→8 | Actuator /env、/configprops（High/confirmed） | 1 |
| crAPI (+MailHog 8025) | 16→11 | `.env` 公开可读（High/confirmed）；MailHog API 未授权（Medium，门限下） | 1 |
| Juice Shop | 20→17 | 未授权敏感 API、/ftp 与 /encryptionkeys 目录列举、密钥材料暴露 | 1 |

产物：`range_artifacts/{webgoat,crapi,juice}_{report.json,report.txt,stage.json}`、`*-audit.jsonl`、`pt42u_*_summary.json`。
**覆盖声明**：仅为非侵入式黑盒观测，不代表无漏洞；未执行任何注入/XSS/RCE/IDOR/认证绕过验证。

---

## 十、AI 驱动架构改造（DeepSeek 成为主流程"大脑"）

### 1. 改造动机
此前所有漏洞都由确定性规则判定，`ai_analyze.py` 只做事后排序，`pipeline.py` 从未调用 AI。现在 AI 已接入主扫描流程，负责**侦察推理 → 漏洞判定 → 攻击链综合 → 报告解读**；确定性探针只负责"手和眼"——采集证据。

### 2. 新主流程（`stages.py` STAGE_ORDER）
```
discovery → probe → ai_recon → crawl → detect → verify → ai_judge → chain(+AI 叙事) → severity_gate → report
```
- **ai_recon（AI 侦察推理）**：把已观测的路径/状态/技术栈交给 AI，AI 给出值得重点审视的端点及理由，并建议额外的非侵入 GET 路径。建议经过过滤（仅相对同源路径、`discovery.is_safe_to_fetch`、拒绝 `..`/引号/尖括号/外链、最多 15 条），再由确定性的 `HttpObserveProbe`（仅回环、仅 GET）通过受 scope 门控的引擎执行。
- **ai_judge（AI 判定）**：每条带证据的发现 + 原始观测（脱敏后）交给 AI，AI 给出 confirm/reject、类别、严重性、置信度、理由，并**必须引用证据**。AI 也可以把原始观测"提升"为新发现。
- **chain（AI 攻击链）**：规则链照常生成，AI 在此基础上把多条发现组合成攻击链与影响叙事，每条 AI 链必须引用 ≥2 个真实发现 id。
- **report**：报告新增 `analysis_engine`（标明 AI 模型）、每条发现的 AI 结论/理由/引用证据/是否 grounded、AI 攻击链叙事；**保留**覆盖范围限制声明，并新增说明：红线下无法测试的类别须走 HITL 审批的授权主动测试路径。

### 3. 仍保持确定性的部分（红线护栏，AI 不能放松）
- 证据采集全部是原有非侵入 GET 探针 / Nuclei 安全模板；AI 不生成任何载荷，提示词明确禁止。
- 无证据不报告：AI 不能引用未知发现 id；"提升"的新发现必须对应一条真实观测（状态码 <400 且分类为 real），否则丢弃（`ungrounded_dropped`）；AI 提升的发现置信度上限为 high。
- 引用核对：AI 的 evidence_cited 必须在证据原文中能找到，否则置信度降级。
- AI 判 reject → 置信度降为 low，被双轴门控压制（不删除，留在 suppressed 中可审计）。
- 授权门控不变：kuaishou.com 仍为 pending_authorization，被拒绝。
- 外发前统一脱敏（`ai_detect.scrub`），密钥只经 config loader 读取，任何日志/报告不出现密钥值。
- 开关：`critforge run --ai auto|on|off`（或环境变量 `CRITFORGE_AI`），默认 auto = 有密钥即开；无密钥或调用失败自动回落到确定性流程，不会中断扫描。

### 4. 实测结果（OWASP WebGoat，127.0.0.1:8080，AI 实时开启，本次未启用 Nuclei）
- 响应模型：API 返回的模型名为 `deepseek-flash`；3 次调用（plan_recon / judge / narrate_chains）全部成功。
- AI 侦察：建议并实际执行了 11 条额外 GET 路径（如 `/WebGoat/actuator/scheduledtasks`、`/caches`、`/conditions`、`/sessions`、`/httptrace`、`/swagger-resources`）。
- AI 判定：共判定 6 条，确认 4 条，驳回 2 条，提升 0 条，无依据丢弃 0 条。
  - 确认示例：`/WebGoat/actuator/env` 未授权暴露 → High / confirmed，grounded。理由："返回 8 个属性源、131 个属性，内容已校验且可复现"。
  - 驳回示例："API surface discovered (3 routes)" → low。理由："3 个路由返回同一个 1929 字节登录页（login_redirect），不存在的路径也返回相同长度，是兜底跳转而非真实 API"。这是 AI 主动识别软 404、压制误报的实例。
  - 驳回示例：技术指纹（Spring/Actuator）→ 仅为信息项，不构成漏洞。
- AI 攻击链："未授权 Actuator 索引发现 → /env、/configprops 配置泄露" (High)；"缺失安全头削弱整体防护" (Medium)。
- 最终报告：3 条通过门控（/env、/configprops、规则链），4 条被压制。产物：`range_artifacts/webgoat_ai_live_summary.json`、`webgoat_ai_live_report.txt`。
- 测试：161 个 pytest 全部通过（新增 `tests/test_ai_detect.py`，LLM 全部 mock、不联网）；`critforge health` OK。
