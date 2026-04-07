"""Hard task: Full PII Detection + Redaction + Compliance Report."""

HARD_INSTRUCTIONS = """## Task: PII Detection, Redaction & Compliance Report (Hard)

You are a Chief Privacy Officer conducting a full data protection audit. Analyze the document and:

1. **Detect** all PII (same types as Medium task, plus MEDICATION, BANK_ACCOUNT, LICENSE_NUMBER)
2. **Redact** the document by replacing each PII with [TYPE] tags
3. **Generate a compliance report** with risk assessment

### Step 1 — PII Detection:
Same as Medium task. Return all detected PII entities.

### Step 2 — Redaction:
Create a redacted version of the document where every PII value is replaced:
- "Amit Sharma" → "[NAME]"
- "482-93-1057" → "[SSN]"
- "asthma" → "[MEDICAL_CONDITION]"
- "42 Brigade Road, Bangalore" → "[ADDRESS]"

### Step 3 — Compliance Report:
For the most critical PII findings, generate a compliance report with:
- `findings`: List of findings, each containing:
  - `value`: The PII text
  - `pii_type`: Category
  - `risk_level`: "low", "medium", "high", or "critical"
  - `regulation`: Applicable law/regulation (e.g., "DPDP Section 9", "HIPAA §164.502", "GDPR Art.9")
  - `recommended_action`: What should be done
- `summary`: Executive summary (2-3 sentences)

### Risk Level Guide:
- **critical**: Health data, children's data, biometric IDs (Aadhaar/SSN)
- **high**: Names linked to sensitive context, financial data, personal contact info
- **medium**: Addresses, organizational affiliations
- **low**: Publicly available information

### Output format:
Return:
1. `detected_pii`: JSON list of entities (same as Easy/Medium)
2. `redacted_text`: The full redacted document text
3. `compliance_report`: {"findings": [...], "summary": "..."}
"""
