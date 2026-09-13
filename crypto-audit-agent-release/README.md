# CryptoAudit Agent

一个面向 Python 密码代码的**可验证智能审校 Agent 演示**。它把「大模型动态选择工具」「必要时向人提问」「本地密码审计工具」组合进同一个受约束的 Agent 循环里，专门演示：**在一个有明确安全边界的闭环内，模型负责推理与编排、本地工具负责产出可复核证据**，而不会被模型自己的"想当然"带偏。

核心约束很简单、却很关键：**模型永远只能输出 `likely / unknown` 的结论，不能把猜测当成"已确认"。** 任何一条"确认"Findings 都必须由本地确定性工具给出证据链；任何一次"审查结束"都必须通过本地 `EvidenceGate` 的完整性校验，模型无权自己宣布成功。

## 它解决了什么问题

传统"用 GPT 审计代码"的 Agent 容易犯两类错：

1. **幻觉**——模型看到可疑代码就推理出结论，但代码未必真有问题，或行号/位置猜测错误；
2. **越权**——Agent 无边界地执行命令、改文件，或拿知识库引用当作"漏洞已证实"。

CryptoAudit Agent 用三道硬边界堵住它们：

| 边界 | 作用 |
|---|---|
| **工具白名单 + 参数约束** | Agent 只能调用 7 个固定工具，且工具不接受任意文件路径/代码执行；源码只做文本与 AST 分析，**不导入、不执行** |
| **证据分离** | `LocalFinding`（本地确认）与 `ModelHypothesis`（模型假设）分开保存；知识库引用只解释整改依据，**不能单独确认漏洞** |
| **EvidenceGate 完成门槛** | `finish` 请求只有通过本地完整性校验（算法盘点、本地扫描、行号链接、补丁指纹、独立复扫）才会被接受 |

## 项目结构

```
├── cli.py                  # 命令行入口（baseline / agent / compare / eval）
├── app.py                  # Streamlit 工作台（图形界面）
├── start.cmd / start.ps1   # Windows 一键启动器（自动探测含 Streamlit 的 Python）
├── config.py               # 环境变量驱动的运行配置（model、步数上限、超时等）
├── cryptoaudit/            # 核心包
│   ├── provider.py         # 决策来源：OpenAI / Offline / Scripted 三分实现
│   ├── agent.py            # AgentOrchestrator：限步决策循环 + 降级到基线
│   ├── baseline.py         # BaselineRunner：确定性离线对照（固定序列）
│   ├── tools.py            # 7 个只读分析工具 + AST 语义扫描器
│   ├── policies.py         # 17 条可执行密码策略规则（含 CWE 映射）
│   ├── knowledge.py        # 版本化知识卡片检索（33 张，含国密条目）
│   ├── verifier.py         # 独立验证 + EvidenceGate 完成门槛
│   ├── contracts.py        # 稳定数据契约（pydantic 模型）
│   └── services.py         # 安全checkpoint、报告渲染、基线/Agent对比
├── knowledge/cards.jsonl   # 知识库（33 张版本化指导卡片）
├── cases/                  # 演示样例（含故意构造的漏洞样例）
├── evals/                  # 手工标注的离线回归评测集（30 + 18 个 case）
└── tests/                  # 52 个合约/边界测试
```

## 安装

**核心（离线基线，无需 API Key / 网络 / 可选依赖）**

```powershell
python -m pip install -r requirements.txt
```

**工作台 / GPT 模式（可选依赖）**

```powershell
python -m pip install -r requirements-ai.txt
```

> `requirements.txt`：`pydantic`、`pytest`。
> `requirements-ai.txt`：追加 `openai`、`langgraph`（可选运行时）、`streamlit`、`python-docx`。

## 快速开始

### 离线基线（确定性对照，不需要 GPT）

```powershell
python cli.py baseline cases/vulnerable_messenger.py --output-dir runtime/messenger
```

### 启动图形工作台

```powershell
python -m streamlit run app.py
```

或双击 `start.cmd`（自动探测安装了 Streamlit 的 Python）。

建议首次用「**对比实验**」加载 `cases/vulnerable_messenger.py`：左边是固定顺序的本地基线，右边是动态 Agent 的工具轨迹，一眼看清两者的 Finding 来源、知识库引用与验证结果差异。

### 使用 GPT Agent（可选）

1. 在界面输入 OpenAI API Key（**只在当前进程内存中使用**，不落盘）；
2. 勾选「将脱敏后的源码发送给 OpenAI」授权；
3. 点「开始审查」。

不输入 Key 时，界面仍可运行，显示为「离线 Agent（OfflineProvider）」；若 GPT 请求失败，结果会**明确标记为「已降级为本地基线」**，绝不伪装成 GPT 结论。

> **敏感信息处理**：提交给模型前，源码先经 `redact_sensitive_text` 脱敏（`password`、`api_key`、`token` 等赋值会被替换为 `<REDACTED>`）；原始文件不会被覆盖。「验证 API Key」只检查 Key 和模型是否可访问，不发送源码。

## 命令行

```powershell
# 离线基线审查一个文件
python cli.py baseline cases/secure_aes_gcm.py --output-dir runtime/secure

# 动态 Agent（无 Key 时用 OfflineProvider，有 Key 且 --allow-source 则用 GPT）
python cli.py agent cases/vulnerable_messenger.py --allow-source --output-dir runtime/agent

# 基线 vs Agent 对照
python cli.py compare cases/vulnerable_messenger.py --allow-source --output-dir runtime/compare

# 评测：基础回归集 与 定向扩展集
python cli.py eval --dataset evals/dataset.json
python cli.py eval --dataset evals/targeted_v2.json

# 用 Agent 模式跑同一批输入（无 Key 时仍是离线 Provider）
python cli.py eval --mode agent --dataset evals/dataset.json
```

## 支持检测的密码问题（17 条策略规则）

- **过时/弱密码算法**：RC4、MD4、MD5、SHA-1、DES、3DES、HMAC 弱摘要
- **不安全模式与参数**：ECB、固定/复用 nonce（CWE-323）、固定/可预测 IV（CWE-329）、RSA 短密钥（<2048，CWE-326）、PBKDF2 低迭代（CWE-916）
- **凭证与数据流**：硬编码凭证（CWE-798）、密钥进入 token（CWE-200）、敏感数据写入日志（CWE-532）、CRC32 冒充完整性校验（CWE-328）
- **实现细节**：敏感值用非常量时间 `==` 比较（CWE-208）、可预测随机数用于安全材料（CWE-338）

每个规则都映射到 CWE，并附带确定性的行号与证据片段（来自 AST 语义分析，而非简单字符串匹配）。算法盘点额外覆盖 **国密 SM2/SM3/SM4** 与现代算法（AES、ChaCha20、SHA-256 等），并标注 `recommended / review / deprecated` 状态。

## 评测结果怎么读

评测集是**仓库内手工构造的离线回归样例**，不是生产代码语料，也不用于宣称生产环境检出率。每个 case 标有 `expected_rules`、`expected_algorithms`、`expected_lines`、`secret_literals` 作为参考答案；`evals/runner.py` 重新运行本地工具逐条对比，不读取预先保存的结果。

当前两份数据集（基线模式）实测结果：

| 数据集 | 用途 | case 数 | Precision | Recall | F1 | 反例通过率 | 密钥泄漏 |
|---|---|---|---|---|---|---|---|
| `dataset.json` | 确认已有规则无退化 | 30 | 1.0 | 1.0 | 1.0 | 1.0 | 0 |
| `targeted_v2.json` | 验证新增定向规则 | 18 | 1.0 | 1.0 | 1.0 | 1.0 | 0 |

> 含义是「**实现与当前标签一致**」，不是「对真实工程检出率 100%」。真正有说服力的后续工作，是取得授权后加入**真实项目片段**，保留来源与人工复核标签作为独立外部验证集，而不是继续扩大规则作者自己写的样例。

## 设计边界（诚实说明）

- `BaselineRunner` 是确定性离线对照，**不冒充**动态 Agent；
- Agent 的 `finish` 必须通过本地 `EvidenceGate`，模型不能凭文字自行宣布成功；
- 补丁只在**内存中生成和验证**；涉及 DES/3DES/ECB 的迁移需要**人工审批**（`requires_review`），系统不会自动改写算法；
- 源码按**文本和 AST**分析，不导入、不执行用户代码；
- 评测集的 P/R/F1 只代表在当前手工标注下正确，不代表生产级检出率；
- 未输入 API Key 时跑的是离线 Provider，**不能当作真实 GPT 评测**。

## 性能与定制

- 运行配置可通过环境变量调整：`OPENAI_MODEL`、`CRYPTOAUDIT_MAX_STEPS`（默认 8，上限 32）、`CRYPTOAUDIT_TIMEOUT_SECONDS`（默认 30，上限 120）、`CRYPTOAUDIT_KNOWLEDGE_PATH`。
- 在 `policies.py` 增删策略规则即可扩展检测能力；在 `knowledge/cards.jsonl` 追加卡片即可扩充知识库。

## 测试

```powershell
python -m pytest -q          # 52 个合约/边界测试，需先装 requirements.txt
```

测试主要验证契约而非生产质量：工具白名单、证据门槛、补丁指纹、敏感信息脱敏、checkpoint 恢复、扩展规则的安全反例与 UI 入口。

## 许可证

本项目以 [MIT License](LICENSE) 开源，可用于学习、研究与二次开发。详见 `LICENSE` 文件。
