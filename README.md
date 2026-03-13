# SentinelAI — Prompt Injection Firewall


---

## Run Instructions

### 1. Install backend dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the backend server
```bash
uvicorn main:app --reload --port 8000
```
Backend runs at: http://localhost:8000

### 3. Open the frontend
Open `frontend/index.html` in your browser.
(Or use Live Server in VS Code)

---

## Architecture

```
External Prompt
      ↓
[Module 1] Content Inspection   ← firewall.py: inspect()
      ↓
[Module 2] Threat Detection     ← firewall.py: rule_detect() + llm_detect()
      ↓
[Module 3] Policy Enforcement   ← firewall.py: enforce_policy()
      ↓
[Module 4] Sanitization         ← firewall.py: sanitize()
      ↓
[Module 5] Audit Logging        ← logs.py: LogStore
      ↓
AI Agent (agent.py)             ← only receives safe prompts
      ↓
Secure Response
```

## API Endpoints

| Method | Endpoint  | Description                        |
|--------|-----------|------------------------------------|
| POST   | /analyze  | Run firewall on a prompt           |
| POST   | /agent    | Firewall + forward to AI agent     |
| GET    | /logs     | Get all audit logs                 |
| DELETE | /logs     | Clear audit logs                   |
| GET    | /stats    | Get threat statistics              |

## Detection Types

1. **Instruction Override** — ignoring/overriding system instructions
2. **Data Exfiltration** — extracting secrets, API keys, credentials
3. **Tool Misuse** — executing commands, shell access
4. **Jailbreak Attempt** — bypassing AI safety guidelines

## Hybrid Detection

- **Rule Engine** — fast keyword matching (always active)
- **LLM Semantic** — SambaNova API semantic analysis (requires API key)
- **Hybrid Mode** — both run in parallel, highest confidence wins
