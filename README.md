# qiqi-scan-triage：QiQi的安全研判

DeepSeek Harness（DSH）插件。帮你研判网络安全工具的扫描结果、告警和日志，给出风险分级、误报甄别、处置步骤和复测方法。**只做防御研判，不执行扫描或攻击。**

## 包含什么

| 组成 | 说明 |
|---|---|
| 「QiQi的安全研判」Agent 预设 | 在会话的模式列表里选择。设定了蓝队分析师的角色、边界和输出格式，只挂载研判需要的工具（读写文件、搜索、终端、联网查 CVE、技能、待办、提问），不挂载子智能体、工作流、定时任务、插件管理等工具。 |
| `scan-triage` 技能 | 研判流程、误报甄别清单、常见端口风险表、输出模板（标准研判、整改清单、告警研判单、教学讲解）。任何模式下都能用 `/scan-triage` 调用。 |
| Nmap XML 解析脚本 | `skills/scan-triage/scripts/nmap-summary.mjs`，零依赖，只读文件、不联网。 |
| 练习样例 | `skills/scan-triage/examples/sample-nmap.xml`，虚构的实训网段，不对应真实主机。 |

## 环境要求

- DeepSeek Harness 0.2.x，且不低于 0.2.2（`dsh --version` 查看）；Node.js 24.9 或更高

## 安装

任选一种：

```bash
# 1. 从 npm 安装（推荐）
dsh plugin --profile web add qiqi-scan-triage

# 2. 离线安装老师分发的安装包
dsh plugin --profile web add ./qiqi-scan-triage-0.1.2.tgz
```

3. 装了 DSH Market 插件的，在 **插件 → 插件市场** 搜索 `qiqi-scan-triage`，点安装。

装好后重启 `dsh web`，在 **插件** 页面确认 qiqi-scan-triage 已启用。

## 使用

1. 新建会话，在模式列表里选 **QiQi的安全研判**。
2. 把扫描结果文件放进工作目录（或直接粘贴内容），然后说：
   - “研判一下 scan.xml，按优先级给出整改清单”
   - “这条 WAF 告警是不是攻击成功？”（附上告警内容）
   - “讲解模式：用样例带我分析一遍”
3. 在其他模式里，也可以输入 `/scan-triage` 加上你的问题来调用技能。

单独使用解析脚本：

```bash
node skills/scan-triage/scripts/nmap-summary.mjs scan.xml              # 终端摘要
node skills/scan-triage/scripts/nmap-summary.mjs scan.xml --out 报告.md # 完整报告写入文件
node skills/scan-triage/scripts/nmap-summary.mjs scan.xml --json       # JSON
```

## 使用边界与数据安全

- 只用于自有或已授权的资产（包括实训靶场）。扫描、复测命令由你自己在授权范围内执行，助手不会替你扫描或攻击。
- 扫描结果包含 IP 规划、开放端口、未修漏洞，属于敏感信息，并且会发送给你配置的模型服务商。上传前先脱敏：IP、主机名、域名、单位名称换成代号（如 10.A.B.15、HOST-01）。涉密网络的数据不要使用。
- 联网搜索只用 CVE 编号、产品名、版本号等公开信息作关键词。
- 结论仅供参考，整改前请由管理员核实。

## 卸载

```bash
dsh plugin --profile web remove qiqi-scan-triage
```

## 许可证

MIT
