# kuaishou.com 测试授权核验清单

本清单列出解锁 CritForge 中 kuaishou.com（当前为 `pending_authorization` 状态）所需的授权文件要素。
**仅凭截图不予接受**——截图无法核验真伪，发件人与内容均可伪造。

## 必备要素

1. **被授权人**：全名 + 邮箱（吴官清 wuguanqing@kuaishou.com）。
2. **授权人**：全名、职务、邮箱（姜晨炜 jiangchenwei@kuaishou.com），并附签名。
3. **授权范围**：明确列出在范围的具体域名与资产（如 kuaishou.com 及其子域名），逐项写明。
4. **排除项**：明确列出不在范围的资产/域名。
5. **有效期**：起始与结束日期。
6. **测试类型**：仅黑盒；不含 CI/CD；不含白盒。
7. **交付物**：评估完成后需向授权人提交的结果内容。
8. **可核验性**：须为带**完整邮件头**的原始邮件，或一份签署的正式文件，以便核验真实性。

## 说明
- 单独一张邮件或资料截图不构成有效授权。
- 解锁流程：收到并核验通过上述授权后，将 kuaishou.com 从 `pending_authorization` 移入 `allowlist`，并更新 `authorization_reference`。
