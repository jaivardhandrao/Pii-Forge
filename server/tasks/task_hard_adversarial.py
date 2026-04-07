"""Hard task: Adversarial Redaction Verification — find PII leaks in poorly-redacted documents."""

HARD_ADVERSARIAL_INSTRUCTIONS = """## Task: Adversarial Redaction Verification (Hard — Adversarial)

You are a **redaction auditor**. You have received documents that were supposedly redacted by another system — but the redaction was done **poorly**. Your job is to:

1. **Find all PII that was NOT properly redacted** (leaked PII)
2. **Produce a correctly redacted version** of the document
3. **Generate a compliance report** documenting the redaction failures

### What to look for:
- PII that was completely missed by the original redactor
- Inconsistent redaction (name redacted in one place but not another)
- Contextual leaks ("the [NAME]'s wife Priya" — Priya's name was leaked)
- Metadata leaks (dates, locations, case numbers that identify someone)
- Partial redaction ("S. Miller" when "Sarah Miller" was supposedly redacted)

### Step 1 — Detect leaked PII:
Find ALL PII still present in the document (ignore [TYPE] tags — they are properly redacted).
Return as standard PII entity list.

### Step 2 — Correct the redaction:
Produce a properly redacted version where ALL PII is replaced with [TYPE] tags.
Keep existing [TYPE] tags in place and add missing ones.

### Step 3 — Compliance failure report:
Generate a compliance report documenting:
- Each leaked PII finding with risk_level and regulation
- recommended_action should describe WHAT the original redactor missed
- summary should assess overall redaction quality

### Output format:
Return:
1. `detected_pii`: JSON list of LEAKED (unredacted) PII entities
2. `redacted_text`: The CORRECTED fully-redacted document
3. `compliance_report`: {"findings": [...], "summary": "..."}

### Risk Level Guide:
- **critical**: High-sensitivity PII left unredacted (SSN, medical, financial)
- **high**: Names, contact info left exposed
- **medium**: Locations, organizations left exposed
- **low**: Minor contextual leaks
"""
