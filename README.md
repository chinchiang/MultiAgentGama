# 🛡️ VibeHarness-MAS: Multi-Agent Testing Harness for Vibe Coding

> **先白箱（異構模型交叉評議與突變驗證）後黑箱（STRIDE/OWASP 威脅建模驅動動態穿透）的 AI 軟體品質保證工具包。**

針對當前 **Vibe Coding（自然語言提示驅動編程）** 容易產生「表面看似可行（Happy Path 通過），內部缺乏防禦邊界、存在 BOLA/IDOR 與未捕獲異常」的特點設計。

---

## 🏛️ 系統架構圖 (Architecture Overview)

```
                       ┌──────────────────────────────────────────────┐
                       │      總指揮官 Harness (Commander Agent)       │
                       └──────────────────────┬───────────────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
      ┌─────────────────────────────┐                   ┌─────────────────────────────┐
      │  階段一：白箱異構多模型審查  │                   │  階段二：黑箱威脅建模與穿透  │
      ├─────────────────────────────┤                   ├─────────────────────────────┤
      │ • Claude: 深度邏輯與狀態     │                   │ • 資產邊界與數據流解析     │
      │ • Nemotron: 防禦護欄與記憶體 │                   │ • STRIDE 矩陣與 OWASP Top 10│
      │ • ChatGPT: API規格與合約    │                   │ • 威脅轉化為自動化攻擊腳本  │
      │ • 仲裁 Agent: 消除模型幻覺  │                   │ • 動態 DAST / 邊界 Fuzzing  │
      └──────────────┬──────────────┘                   └──────────────┬──────────────┘
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │     安全隔離沙盒 (Sandbox)   │
                               │  (Pytest / Process Isolation│
                               └──────────────┬──────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │   品管門禁與最終審計報告     │
                               │  (vibe_harness_report.md)   │
                               └─────────────────────────────┘
```

---

## 🚀 核心特性

1. **AI Harness 總指揮官**：掌控全域狀態機，自動依序調度白箱與黑箱各子 Agent，並執行最後的品質閘門（Quality Gate）仲裁。
2. **多模型異構消除偏差（De-biasing）**：白箱審查階段可平行指派至不同權重體系的 LLM：
   - **Claude 3.7**：專精複雜邊界條件、非空指針假設與狀態機漏洞。
   - **NVIDIA Nemotron**：專精輸入清洗、資源消耗上限（DoS 防禦）與記憶體安全護欄。
   - **ChatGPT (GPT-4o)**：專精 API 協定契約遵守、規範一致性與通用測試案例合成。
   - **Arbiter Debater**：多 Agent 對抗評議，計算共識率（Consensus Ratio），剔除個別模型的誤報與幻覺。
3. **黑箱強制威脅建模先行（Threat-Modeling First）**：拒絕盲目暴力測試，先依據 STRIDE（S 仿冒、T 竄改、R 否認、I 資訊洩漏、D 拒絕服務、E 越權）與 OWASP API Security Top 10 建立攻擊矩陣，再針對性生成攻擊測試。
4. **安全隔離沙盒執行**：所有自動生成之測試與 Payload 皆在受保護的隔離目錄與子程序中執行，防止未受信任之程式碼逃逸。

---

## 📦 目錄結構

```text
MultiAgentGama/
├── config/
│   ├── agents_config.yaml       # 多模型路由 (Claude, Nemotron, ChatGPT)
│   └── threat_rules.yaml        # STRIDE 與 OWASP 基準規則
├── core/
│   ├── harness.py               # 指揮官狀態機 (Commander Orchestrator)
│   ├── llm_gateway.py           # 統一 LiteLLM 閘道與模擬回退引擎
│   ├── models.py                # Pydantic 數據模型
│   └── sandbox.py               # 隔離執行沙盒
├── agents/
│   ├── whitebox/
│   │   ├── ast_extractor.py     # AST 符號解析與路由提取
│   │   ├── multi_reviewer.py    # 異構模型評議 (Ensemble)
│   │   ├── debater.py           # 多模型共識與爭議仲裁
│   │   └── test_generator.py    # 單元/邊界測試自動生成
│   └── blackbox/
│       ├── threat_modeler.py    # STRIDE 威脅建模引擎
│       └── scenario_builder.py  # 威脅轉化可執行攻擊腳本
├── runners/
│   └── test_executor.py         # 沙盒 Pytest 執行器與 PoC 抓取
├── reports/
│   └── report_generator.py      # Markdown 審計報告生成器
├── examples/
│   └── vibe_sample_app.py       # 具代表性的 Vibe-Coding 典型缺陷範例
├── tests/
│   └── test_harness_components.py # 工具包本身之單元測試
└── main.py                      # CLI 執行入口
```

---

## 🛠️ 快速開始

### 1. 安裝依賴

```bash
pip install -r requirements.txt
```

### 2. 設定 API 金鑰（可選）

工具包支援真實 API 調用與本機模擬模式（Hybrid Mode）：

```bash
# 若要使用即時模型：
export ANTHROPIC_API_KEY="sk-ant-..."
export NVIDIA_API_KEY="nvapi-..."
export OPENAI_API_KEY="sk-..."
```
*註：若未配置 API 金鑰，工具包會自動啟用高保真模擬引擎（Simulation Engine），確保任何開發者皆可無痛體驗完整工作流。*

### 3. 對目標專案執行全流程檢驗

```bash
python main.py --target examples --output vibe_harness_report.md
```

### 4. 運行工具包本身單元測試

```bash
python -m pytest tests/test_harness_components.py -v
```
