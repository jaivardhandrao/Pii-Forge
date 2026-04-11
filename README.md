---
title: PII-Forge
emoji: "🔒"
colorFrom: red
colorTo: purple
sdk: docker
app_port: 7860
pinned: true
license: mit
---

# PII-Forge

**Detect & Redact Personally Identifiable Information** — powered by **Microsoft Presidio** + **Aho-Corasick** algorithm.

PII-Forge scans documents for sensitive data (names, emails, SSNs, medical records, and more) and produces redacted versions instantly. It combines NLP-based entity recognition with fast multi-pattern keyword matching for comprehensive PII coverage.

## Quick Start

### Docker Compose (Recommended)

```bash
git clone <repo-url>
cd Pii-Forge
docker compose up --build
```

Open **http://localhost:80** in your browser. That's it.

### Local Development

```bash
pip install -r server/requirements.txt
python -m spacy download en_core_web_lg
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload
```

## How It Works

PII-Forge uses two detection engines that run in parallel:

### 1. Microsoft Presidio (NLP/NER)

[Presidio](https://github.com/microsoft/presidio) is Microsoft's open-source SDK for PII detection. It uses spaCy NER models to recognize entities like names, organizations, and locations, plus built-in pattern recognizers for structured data (emails, phone numbers, SSNs, credit cards, etc.).

We extend Presidio with custom recognizers for:
- Employee IDs (`EMP-XXXX`, `PAT-XXXX`)
- Indian salary formats (`₹18,50,000`, `45 LPA`)
- Generic passport numbers
- Age patterns

### 2. Aho-Corasick Algorithm (Fast Pattern Matching)

The [Aho-Corasick algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) builds a finite-state automaton from keyword dictionaries and scans text in **O(n + m)** time (n = text length, m = matches). This makes it extremely fast for matching against large keyword lists.

We use Aho-Corasick for:
- **50+ medical conditions** (diabetes, PTSD, depression, cancer, etc.)
- **50+ medications** (Metformin, Sertraline, Insulin, etc.)
- Additional regex patterns for Indian phone numbers, addresses, and medication dosages

### Detection Pipeline

```
Input Text
    │
    ├──► Presidio Analyzer (NER + patterns) ──► entities
    │
    ├──► Aho-Corasick Automaton (keywords)  ──► entities
    │
    └──► Merge + Deduplicate (span overlap) ──► final entities
                                                    │
                                                    ▼
                                              Redacted Text
                                            (PII → [TYPE] tags)
```

## Features

- **Paste & Scan**: Simple UI — paste any document, click "Scan & Redact"
- **20 PII Types**: NAME, EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, AGE, ADDRESS, LOCATION, IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY, BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD
- **Color-coded highlighting**: Each PII type has a distinct color in the results
- **Risk analysis**: Automatic risk level assessment (low/medium/high/critical)
- **Copy-ready redacted text**: One-click copy of the redacted document
- **REST API**: Programmatic access via `POST /scan`
- **OpenEnv compatible**: Full environment API for training AI agents

## API

### POST /scan — Quick PII Detection

```bash
curl -X POST http://localhost:80/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact Sarah Miller at sarah@test.com, SSN: 482-93-1057"}'
```

Response:

```json
{
  "entities": [
    {"pii_type": "NAME", "value": "Sarah Miller", "start": 8, "end": 20, "score": 0.85, "source": "presidio"},
    {"pii_type": "EMAIL", "value": "sarah@test.com", "start": 24, "end": 38, "score": 1.0, "source": "presidio"},
    {"pii_type": "SSN", "value": "482-93-1057", "start": 45, "end": 56, "score": 0.85, "source": "presidio"}
  ],
  "redacted_text": "Contact [NAME] at [EMAIL], SSN: [SSN]",
  "entity_count": 3,
  "type_counts": {"NAME": 1, "EMAIL": 1, "SSN": 1}
}
```

### OpenEnv Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/scan` | POST | Quick PII scan (Presidio + Aho-Corasick) |
| `/reset` | POST | Start new OpenEnv episode |
| `/step` | POST | Submit PII detection for grading |
| `/state/{session_id}` | GET | Get episode progress |
| `/ws` | WebSocket | Real-time agent connection |
| `/docs` | GET | Swagger API docs |

## OpenEnv Training Environment

PII-Forge also includes a full **OpenEnv-compatible** training environment for AI agents:

### Task Difficulty Levels

| Level | Tasks | What the Agent Does | Grading |
|-------|-------|---------------------|---------|
| **Easy** | 10 | Identify structured PII (emails, phones, SSNs, names) | F1 Score |
| **Medium** | 45 | Contextual, obfuscated, and cross-reference PII detection | F1 Score |
| **Hard** | 10 | Full audit: detect + redact + compliance report | 40% Detection + 30% Redaction + 30% Compliance |

### Run Inference (LLM-based agent)

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export OPENAI_API_KEY="your-key-here"

python inference.py
```

### Reward Function

- **Easy & Medium**: `F1 = 2 * P * R / (P + R)`
- **Hard**: `0.4 * detection_f1 + 0.3 * redaction_score + 0.3 * compliance_score`

## Project Structure

```
Pii-Forge/
├── docker-compose.yml          # Docker Compose — run with: docker compose up
├── Dockerfile                  # Container build config
├── inference.py                # LLM-based baseline agent
├── models.py                   # Pydantic data models
├── client.py                   # WebSocket client
├── openenv.yaml                # Environment manifest
├── server/
│   ├── app.py                  # FastAPI server (REST + WebSocket + Gradio)
│   ├── pii_detector.py         # Presidio + Aho-Corasick detection engine
│   ├── environment.py          # OpenEnv environment logic
│   ├── grader.py               # F1 scoring engine
│   ├── gradio_ui.py            # Simplified web UI
│   ├── tasks/                  # Task instructions per difficulty
│   └── data/                   # Synthetic document datasets
└── README.md
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| PII Detection (NER) | [Microsoft Presidio](https://github.com/microsoft/presidio) + spaCy |
| PII Detection (Keywords) | [Aho-Corasick](https://pypi.org/project/pyahocorasick/) algorithm |
| Backend | FastAPI + Uvicorn |
| Frontend | Gradio |
| NLP Model | spaCy `en_core_web_lg` |
| Container | Docker + Docker Compose |

## Compliance Frameworks Covered

- **DPDP Act 2023** (India) — Digital Personal Data Protection
- **GDPR** (EU) — General Data Protection Regulation
- **HIPAA** (US) — Health Insurance Portability and Accountability Act
- **POSH Act 2013** (India) — Prevention of Sexual Harassment
- **Aadhaar Act** (India) — Biometric ID regulations

## Dataset

All documents are **synthetic** — no real PII is used. Documents span employee records, medical notes, legal memos, insurance claims, chat logs, and adversarial examples with obfuscated PII.

## License

MIT
