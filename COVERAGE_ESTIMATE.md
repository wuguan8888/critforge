# CritForge 对 OWASP Juice Shop 的覆盖率提升预估（只读分析）

- **时间**：2026-10-30 Asia/Singapore（UTC+8）
- **性质**：只读估算，未改任何代码、未运行任何扫描器/靶场
- **基线来源**：`RANGE_TEST_REPORT.md` 复杂靶场段 + `range_artifacts/juice_shop_report.json`
- **基线**：16 个官方漏洞类别、116 个挑战；当前类别覆盖 **2/16 = 12.5%**；严格挑战命中 **~1–3%**；检测器为**纯被动**（只观察、不发利用载荷）

## 待评估的三项改进
- **(A) 被动检测器**（现在可运行）：报错/冗长错误触发、备份文件名识别（.bak/.old/.swp/~/.orig）、目录列表拆分为独立检查
- **(B) Nuclei 集成**（现在可运行）：仅官方**非侵入**模板（info / misconfig / exposure）
- **(C) HITL 主动测试**（**仅设计文档，不运行**）：授权后交接给 ZAP 等主动扫描器——**不计入运行期覆盖**

---

## (1) 16 类别 × 改进 映射表

| # | 类别 (挑战数) | 覆盖改进 | 现在可运行? | 覆盖程度 |
|---|---|---|---|---|
| 1 | Sensitive Data Exposure (17) | 被动(备份文件)+Nuclei(exposure) | ✅ 可运行 | 部分（文件/目录暴露，非逻辑泄露） |
| 2 | Injection (14) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 3 | Improper Input Validation (12) | 被动(冗长报错)一小片；其余 主动 | ⚠️ 极少可运行 | 边缘 |
| 4 | Broken Access Control (12) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 5 | XSS (9) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 6 | Vulnerable Components (9) | Nuclei(技术指纹/CVE 非侵入) | ✅ 可运行 | 部分（版本暴露类） |
| 7 | Broken Authentication (9) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 8 | Miscellaneous (6) | 混合；多数 主动 | ❌ 多数设计态 | 基本未覆盖 |
| 9 | Security Misconfiguration (5) | 被动(报错/目录/头)+Nuclei | ✅ 可运行 | 较好 |
| 10 | Cryptographic Issues (5) | Nuclei(弱TLS)+被动(密钥目录暴露) | ✅ 可运行 | 部分（暴露类，非破解） |
| 11 | Observability Failures (4) | 被动(metrics)【基线已命中】 | ✅ 可运行 | 较好 |
| 12 | Broken Anti Automation (4) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 13 | Security through Obscurity (3) | 被动(备份/隐藏路径) | ✅ 可运行 | 部分 |
| 14 | Insecure Deserialization (3) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 15 | Unvalidated Redirects (2) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |
| 16 | XXE (2) | 仅 主动-HITL | ❌ 设计态 | 未覆盖 |

> 关键点：**(C) 主动-HITL 覆盖的是上表所有 ❌ 类别，但因「仅设计、不运行」，不产生任何运行期覆盖。** 真正能跑的只有 (A)+(B)。

---

## (2) 覆盖率估算（分改进拆解 + 置信区间）

### 类别覆盖率
基线可运行覆盖 = **2/16（Observability Failures、Sensitive Data Exposure）**

| 改进 | 新增可运行类别 | 增量 |
|---|---|---|
| (A) 被动 | Security Misconfiguration、Security through Obscurity（+Improper Input Validation 边缘片） | +2 |
| (B) Nuclei 非侵入 | Vulnerable Components、Cryptographic Issues（强化 SecMisconfig） | +1 ~ +2 |
| (C) 主动-HITL | 0（设计态，不运行） | +0 |

| 置信档 | 可运行类别 | 类别覆盖率 |
|---|---|---|
| Low | 4/16 | **25%** |
| Mid | 5/16 | **≈31%** |
| High | 6–7/16 | **38–44%** |

### 严格挑战命中率
被动+Nuclei 只能严格完成少量「暴露/配置」型挑战（Exposed Metrics、Error Handling、若干文件暴露、过时组件提示）。Juice Shop ~90% 挑战需主动交互，故提升有限：

| 置信档 | 严格命中挑战 | 命中率 |
|---|---|---|
| Low | ~3/116 | **~2–3%** |
| Mid | ~5/116 | **~4%** |
| High | ~7–8/116 | **~6–7%** |

**结论**：类别覆盖从 12.5% → **约 31%（25–44%）**；严格挑战命中从 1–3% → **约 4%（2–7%）**。提升主要来自暴露/配置维度，不触及注入/认证/越权逻辑。

---

## (3) 仍然未覆盖的类别及原因

均需**主动交互或构造利用载荷**，被「不写利用载荷」红线挡住；(C) 设计文档涵盖但未运行：

- **Injection (14)**、**XSS (9)**：需注入 payload 并观察执行/回显。
- **Broken Access Control (12)**、**Broken Authentication (9)**：需伪造会话、越权请求、篡改 JWT、暴力/逻辑绕过。
- **Insecure Deserialization (3)**、**XXE (2)**：需构造恶意序列化/XML 实体载荷。
- **Unvalidated Redirects (2)**：需构造跳转参数验证。
- **Broken Anti Automation (4)**：需自动化冲刷 / CAPTCHA 绕过。
- **Miscellaneous (6)**、**Improper Input Validation (12,大部分)**：多为业务逻辑型，需主动输入变异。

这些仅在 HITL 审批接入授权主动扫描器（ZAP 等）后才能转为运行期覆盖。

---

## 诚实边界
- (C) 主动路径为**设计文档**，本估算**不把它计入运行期数值**。
- Nuclei 非侵入模板偏 exposure/misconfig/version，不覆盖注入与认证逻辑；高档估值已对「技术指纹→过时组件」做了乐观假设。
- 估值为分析性预期，实际数需待 (A)(B) 落地后复跑 Juice Shop 对比验证。
