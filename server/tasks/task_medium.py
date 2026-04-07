"""Medium task: Contextual PII Detection — requires understanding context."""

MEDIUM_INSTRUCTIONS = """## Task: Contextual PII Detection (Medium)

You are an advanced data privacy scanner. Analyze the given document and detect ALL Personally Identifiable Information (PII), including contextual and indirect identifiers.

### What to detect (in addition to Easy-level types):
- **NAME**: All person names (including Dr., Mr., Mrs. prefixes)
- **AGE**: Age references (e.g., "34", "mid-fifties", "born in '94")
- **LOCATION**: Cities, neighborhoods, areas (e.g., "Koramangala", "Palo Alto")
- **ORGANIZATION**: Companies, hospitals, universities
- **MEDICAL_CONDITION**: Any health conditions, diagnoses, symptoms
- **MEDICATION**: Drug names and dosages
- **USERNAME**: Usernames, handles, screen names
- **IP_ADDRESS**: IP addresses
- **SALARY**: Compensation amounts (e.g., "45 LPA", "$95,000")

### Key challenge:
This task includes **contextual PII** that is embedded in natural language:
- Names linked to health conditions ("Ramesh has diabetes")
- Indirect age references ("born in '94", "mid-fifties")
- Locations mentioned casually ("lives near Koramangala")
- Organizational affiliations that reveal identity

### Output format:
Return a JSON list of detected PII entities, each with:
- `pii_type`: One of the types listed above
- `value`: The exact text of the PII found
- `start`: Character position where the PII starts (0-indexed)
- `end`: Character position where the PII ends

Be thorough — contextual PII is easy to miss but critical for privacy compliance.
"""
