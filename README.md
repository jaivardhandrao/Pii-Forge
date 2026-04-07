---
title: PII Scanner Environment
emoji: "🔒"
colorFrom: red
colorTo: purple
sdk: docker
app_port: 7860
pinned: true
license: mit
---

# PII Scanner Environment

An **OpenEnv-compatible** environment where AI agents learn to detect, classify, and redact Personally Identifiable Information (PII) from real-world documents.

## Overview

Every organization handles sensitive data — employee records, medical files, legal documents, financial reports. This environment challenges AI agents to act as **Data Privacy Officers**, scanning documents for PII and ensuring compliance with regulations like **GDPR**, **HIPAA**, and India's **DPDP Act 2023**.

### What Makes This Unique

- **Adversarial & Obfuscated PII**: Documents contain spelled-out phone numbers ("four-zero-eight..."), encoded emails ("name at domain dot com"), partially masked identifiers, and contextual health information — not just simple regex-matchable patterns
- **Multi-Regulation Compliance Auditing**: Hard mode requires agents to produce compliance reports citing specific sections of DPDP Act, GDPR, HIPAA, POSH Act, and Aadhaar Act
- **Visual Risk Analysis Dashboard**: Interactive Gradio UI with color-coded PII highlighting, risk heatmaps, side-by-side redaction diffs, and score dashboards
- **Position-Aware + Fuzzy Grading**: Two-pass grading engine that matches by both value similarity and character-span overlap, handling obfuscated and contextual PII
- **Multi-Pass LLM Agent**: Baseline inference uses a second-pass detection specifically targeting contextual and obfuscated PII that simple detectors miss

## Task Difficulty Levels

| Level | Tasks | What the Agent Does | Grading |
|-------|-------|---------------------|---------|
| **Easy** | 10 | Identify structured PII (emails, phones, SSNs, names) | F1 Score |
| **Medium** | 15 | Detect PII embedded in natural language — obfuscated numbers, contextual health data, indirect age references, partially masked values | F1 Score |
| **Hard** | 5 | Full audit: detect PII, generate redacted document, produce compliance report with risk assessment | Weighted: 40% Detection + 30% Redaction + 30% Compliance |

## Environment API

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (returns 200) |
| `/reset` | POST | Start new episode |
| `/step` | POST | Submit PII detection |
| `/state/{session_id}` | GET | Get current progress |
| `/ws` | WebSocket | Real-time agent connection |
| `/web` | GET | Interactive Gradio UI |
| `/docs` | GET | Swagger API docs |

### Action Space

```json
{
  "detected_pii": [
    {
      "pii_type": "EMAIL",
      "value": "user@example.com",
      "start": 15,
      "end": 31
    }
  ],
  "redacted_text": "Contact [NAME] at [EMAIL]...",
  "compliance_report": {
    "findings": [
      {
        "value": "user@example.com",
        "pii_type": "EMAIL",
        "risk_level": "medium",
        "regulation": "GDPR Art.6",
        "recommended_action": "Obtain consent for processing"
      }
    ],
    "summary": "1 PII instance found..."
  }
}
```

### Observation Space

```json
{
  "done": false,
  "reward": 0.85,
  "document": "The text to scan...",
  "task_type": "easy",
  "task_id": "easy_01",
  "instructions": "Detect all PII...",
  "feedback": "Detection F1: 85%...",
  "total_tasks": 10,
  "current_task_number": 3
}
```

### Supported PII Types (20)

`EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `DATE_OF_BIRTH`, `NAME`, `AGE`, `ADDRESS`, `LOCATION`, `IP_ADDRESS`, `EMPLOYEE_ID`, `MEDICAL_CONDITION`, `MEDICATION`, `ORGANIZATION`, `SALARY`, `BANK_ACCOUNT`, `PASSPORT`, `LICENSE_NUMBER`, `USERNAME`, `PASSWORD`

## Reward Function

- **Easy & Medium**: F1 Score (harmonic mean of precision and recall)
  - `reward = 2 * P * R / (P + R)` where P = precision, R = recall
  - Range: 0.0 (no correct detections) to 1.0 (perfect detection)

- **Hard**: Weighted composite
  - `reward = 0.4 * detection_f1 + 0.3 * redaction_score + 0.3 * compliance_score`
  - Each component ranges 0.0 to 1.0

### Matching Logic
A detected PII entity matches ground truth when:
1. **Pass 1**: PII type matches AND value overlaps >= 60% (sequence-based fuzzy matching)
2. **Pass 2**: PII type matches AND character span overlap >= 50% (catches position-accurate detections)

## Quick Start

### Install Dependencies

```bash
pip install -r server/requirements.txt
```

### Run Locally

```bash
# Start the server
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload

# Or run the Gradio UI directly
python server/gradio_ui.py
```

### Run Inference

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export OPENAI_API_KEY="your-key-here"

python inference.py
```

### Docker

```bash
docker build -t pii-scanner-env .
docker run -p 7860:7860 pii-scanner-env
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_BASE_URL` | LLM API endpoint | `https://api.openai.com/v1` |
| `MODEL_NAME` | Model identifier | `gpt-4o-mini` |
| `HF_TOKEN` | HuggingFace API token | — |

## Project Structure

```
pii-scanner-env/
├── inference.py            # Multi-pass LLM baseline agent
├── models.py               # Pydantic data models
├── client.py               # WebSocket client
├── openenv.yaml            # Environment manifest
├── Dockerfile              # HF Spaces deployment
├── server/
│   ├── app.py              # FastAPI server
│   ├── environment.py      # Core environment logic
│   ├── grader.py           # Position-aware F1 scoring engine
│   ├── gradio_ui.py        # Enhanced interactive web UI
│   ├── tasks/              # Task instructions per difficulty
│   └── data/               # Synthetic document datasets
└── README.md
```

## Dataset

All documents are **synthetic** — no real PII is used. Documents span:
- Employee records, HR files
- Medical/clinical notes
- Legal memos, insurance claims
- Chat logs, meeting notes, WhatsApp groups
- School records, support tickets
- **Adversarial**: Obfuscated emails, spelled-out numbers, partially masked IDs, contextual health references, gossip-style indirect PII

Each document includes pre-annotated ground truth with exact PII positions.

## Compliance Frameworks Covered

- **DPDP Act 2023** (India) — Digital Personal Data Protection
- **GDPR** (EU) — General Data Protection Regulation
- **HIPAA** (US) — Health Insurance Portability and Accountability Act
- **POSH Act 2013** (India) — Prevention of Sexual Harassment
- **Aadhaar Act** (India) — Biometric ID regulations
- **IRDAI / Insurance Act 1938** (India) — Insurance data regulations
- **POCSO Act** (India) — Protection of Children from Sexual Offences

## Technical Constraints

- Inference runtime: < 20 minutes
- Infrastructure: 2 vCPU, 8GB RAM
- All LLM calls via OpenAI-compatible client

## License

MIT
# Pii-Forge
