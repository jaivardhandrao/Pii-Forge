"""Medium task: Cross-Reference & Re-identification PII Detection."""

MEDIUM_CROSSREF_INSTRUCTIONS = """## Task: Cross-Reference PII Detection (Medium — Cross-Reference)

You are a re-identification risk analyst. Your job is to detect **quasi-identifiers** — data points that seem harmless alone but can uniquely identify a person when combined.

### The re-identification problem:
Research shows that **87% of the US population** can be uniquely identified by just three fields: ZIP code + date of birth + gender. This task tests whether you can spot these quasi-identifiers.

### What to detect:
All standard PII types, PLUS pay special attention to:
- **Quasi-identifiers**: ZIP/pin codes, age/DOB, gender, job title + company combos
- **Linkage keys**: Employee IDs, case numbers, timestamps that link to other records
- **Contextual identifiers**: "the only female engineer on the 3rd floor" (unique within context)
- **Aggregate leaks**: Statistics about small groups that reveal individuals

### PII Types:
EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, NAME, AGE, ADDRESS, LOCATION,
IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY,
BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD

### Output format:
Return a JSON list of detected PII entities, each with:
- `pii_type`: One of the types listed above
- `value`: The exact text of the PII found
- `start`: Character position where the PII starts (0-indexed)
- `end`: Character position where the PII ends

### Key principle:
If combining 2-3 fields from this document could identify a specific person, each of those fields is PII — even if it looks innocuous on its own.
"""
