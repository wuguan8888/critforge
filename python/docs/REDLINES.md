# CritForge 红线清单（不做事项）

本文档为独立参考，列出 CritForge 明确**不做**的事项。这些边界不可通过配置关闭。

## 一、利用与攻击
- 不编写、不启用利用载荷（exploit payloads）。
- 不执行主动利用：远程代码执行（RCE）、SQL 注入利用、反序列化利用等。
- 仅做被动观察与非侵入式检测（如 Nuclei 非侵入模板），不对目标造成破坏或状态改变。

## 二、安全配置
- 不移除、不绕过任何安全/红线配置。
- 不把授权审批改为自动通过；高危主动动作必须经人工确认（HITL）。

## 三、授权与范围
- 不攻击授权范围之外的目标。
- 待授权（pending_authorization）与拒绝名单中的目标一律拦下，不发任何请求。
- 授权须可核验（带完整邮件头的原件或签署文件），截图不构成授权。

## 四、测试类型
- 仅黑盒测试。
- 不涉及白盒/源码审计，不涉及 CI/CD 接入。

## 五、密钥
- 不在对话或报告中回显任何密钥、token 的值，仅报变量名与状态。

## 六、因红线而无法测试的漏洞类型
以下类型需要主动交互或构造利用载荷才能验证，受上述红线约束，CritForge 不做运行期测试（只能靠 HITL 审批后的授权主动测试路径覆盖）：

- 注入类：SQL 注入、NoSQL 注入、命令注入、LDAP/模板注入等。
- 跨站脚本 XSS：反射型、存储型、DOM 型、CSP 绕过。
- 认证破解（Broken Authentication）：弱口令爆破、密码重置绕过、会话固定。
- 越权（Broken Access Control）：IDOR、BOLA、BFLA、垂直/水平越权、功能级越权。
- 输入校验不当（Improper Input Validation）：Poison Null Byte 等。
- 加密问题（Cryptographic Issues）：JWT 伪造/篡改（未签名、弱密钥）、弱加密绕过。
- 不安全反序列化（Insecure Deserialization）及由此导致的 RCE/DoS。
- XXE（XML 外部实体注入）。
- SSRF（服务端请求伪造）。
- 未验证跳转（Unvalidated Redirects）。
- 反自动化缺陷（Broken Anti-Automation）：验证码绕过、限速绕过。
- 隐蔽式安全（Security through Obscurity）中需交互触发的部分。
- 业务逻辑漏洞：优惠券伪造、批量赋值、支付/订单逻辑绕过等。

**能覆盖的（非侵入观测）**：敏感文件/目录暴露（.env、.git、备份文件、目录列举）、未授权可读的管理/监控端点（actuator、metrics、swagger、MailHog 等）、缺失或过时的安全响应头、Server banner 与技术指纹、报错/堆栈信息泄露，以及 Nuclei 非侵入模板命中的暴露/配置类问题。
