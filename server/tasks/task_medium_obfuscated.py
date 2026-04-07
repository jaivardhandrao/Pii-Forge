"""Medium task: Obfuscated & Encoded PII Detection."""

MEDIUM_OBFUSCATED_INSTRUCTIONS = """## Task: Obfuscated PII Detection (Medium — Obfuscated)

You are a privacy scanner specialized in detecting **hidden, encoded, and obfuscated PII** — the kind that basic regex scanners miss entirely.

### What makes this different:
Documents contain PII that has been intentionally or accidentally disguised:
- **Spelled-out numbers**: "four-zero-eight, five-five-five, zero-one-two-three" (a phone number)
- **Encoded emails**: "priya dot sharma at gmail dot com"
- **Partially masked values**: "XXXX-XXXX-7834" (still PII — the partial Aadhaar is identifiable)
- **Abbreviated/informal references**: "born in '94", "north of 20 lakhs"
- **Split PII**: Information spread across multiple sentences

### PII Types to detect:
EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, NAME, AGE, ADDRESS, LOCATION,
IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY,
BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD

### Output format:
Return a JSON list of detected PII entities, each with:
- `pii_type`: One of the types listed above
- `value`: The exact text of the PII **as it appears** in the document (even if obfuscated)
- `start`: Character position where the PII starts (0-indexed)
- `end`: Character position where the PII ends

### Example:
For input: "Call me at four-one-five, five-five-five, one-two-three-four"
Output: [{"pii_type": "PHONE", "value": "four-one-five, five-five-five, one-two-three-four", "start": 11, "end": 60}]

Think beyond regex — detect the **intent** of the information, not just its format.
"""
