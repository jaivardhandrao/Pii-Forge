"""Easy task: Basic PII Detection — structured, regex-catchable patterns."""

EASY_INSTRUCTIONS = """## Task: Basic PII Detection (Easy)

You are a data privacy scanner. Analyze the given document and detect all Personally Identifiable Information (PII).

### What to detect:
- **EMAIL**: Email addresses (e.g., user@example.com)
- **PHONE**: Phone numbers in any format
- **SSN**: Social Security Numbers (e.g., 123-45-6789)
- **CREDIT_CARD**: Credit card numbers
- **DATE_OF_BIRTH**: Dates of birth
- **NAME**: Person names
- **EMPLOYEE_ID**: Employee/ID numbers (e.g., EMP-1234)
- **ADDRESS**: Physical addresses
- **PASSPORT**: Passport numbers
- **BANK_ACCOUNT**: Bank account or routing numbers
- **IP_ADDRESS**: IP addresses
- **SALARY**: Salary or wage amounts

### Output format:
Return a JSON list of detected PII entities, each with:
- `pii_type`: One of the types listed above
- `value`: The exact text of the PII found
- `start`: Character position where the PII starts (0-indexed)
- `end`: Character position where the PII ends

### Example:
For input: "Email john@test.com for info"
Output: [{"pii_type": "EMAIL", "value": "john@test.com", "start": 6, "end": 19}]

Be thorough — detect ALL PII instances. Missing PII reduces your score.
"""
