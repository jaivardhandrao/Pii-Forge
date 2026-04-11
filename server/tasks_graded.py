"""
PII-Forge — Graded Tasks.

5 paragraph-based tasks with known PII ground truth.
Each task has a UUID, a document paragraph, and a list of PII values
that must be removed for a perfect score.

The grader checks each PII value (case-insensitive) — if it's absent
from the submitted result, that PII scores 1.0; if still present, 0.0.
Final score = average across all PII items.
"""

from __future__ import annotations

TASKS = [
    {
        "task_id": "a1b2c3d4-1111-4000-a000-000000000001",
        "title": "Employee Termination Notice",
        "difficulty": "medium",
        "document": (
            "CONFIDENTIAL — TERMINATION NOTICE\n\n"
            "To: Amit Verma\n"
            "Employee ID: EMP-29471\n"
            "Department: Engineering\n"
            "Date: March 15, 2026\n\n"
            "Dear Amit,\n\n"
            "This letter confirms the termination of your employment effective "
            "March 31, 2026. Your final salary of ₹18,50,000 will be credited to "
            "your HDFC Bank account ending in 4829. Your performance review scores "
            "of 2.1/5 for the last two quarters were below the minimum threshold.\n\n"
            "Your manager, Rajesh Kumar, and HR representative Sneha Patel "
            "(sneha.patel@company.com) have documented the performance improvement "
            "plan discussions. Please return your laptop and ID badge to the "
            "Whitefield office, Bangalore.\n\n"
            "Your health insurance (Policy #MED-88421) covering your pre-existing "
            "asthma condition will remain active until April 30, 2026. Continuation "
            "details will be sent to your registered address at 42 Brigade Road, "
            "Bangalore 560025.\n\n"
            "For questions, contact Sneha directly at 080-4555-0192.\n\n"
            "Sincerely,\nVP Human Resources"
        ),
        "pii": [
            {"type": "NAME", "value": "Amit Verma"},
            {"type": "EMPLOYEE_ID", "value": "EMP-29471"},
            {"type": "SALARY", "value": "₹18,50,000"},
            {"type": "NAME", "value": "Rajesh Kumar"},
            {"type": "NAME", "value": "Sneha Patel"},
            {"type": "EMAIL", "value": "sneha.patel@company.com"},
            {"type": "MEDICAL_CONDITION", "value": "asthma"},
            {"type": "ADDRESS", "value": "42 Brigade Road, Bangalore 560025"},
            {"type": "PHONE", "value": "080-4555-0192"},
        ],
    },
    {
        "task_id": "a1b2c3d4-2222-4000-a000-000000000002",
        "title": "Patient Discharge Summary",
        "difficulty": "hard",
        "document": (
            "PATIENT DISCHARGE SUMMARY\n"
            "Fortis Hospital, Bangalore\n"
            "Date: February 20, 2026\n\n"
            "Patient: Kavitha Reddy, Age: 45, Female\n"
            "Patient ID: PAT-772901\n"
            "Admission Date: February 14, 2026\n\n"
            "Diagnosis: Type 2 Diabetes Mellitus with diabetic retinopathy. The "
            "patient also has a history of clinical depression managed with "
            "Sertraline 50mg.\n\n"
            "Treatment: Insulin glargine 20 units daily, laser photocoagulation "
            "for retinopathy performed on Feb 16. Psychiatric consult by "
            "Dr. Meena Rao recommended continuing current medication.\n\n"
            "Follow-up: Ophthalmology appointment on March 5, 2026 with "
            "Dr. Suresh at the Indiranagar clinic. Psychiatry follow-up in "
            "4 weeks.\n\n"
            "Emergency Contact: Husband — Venkat Reddy, Phone: 080-2555-0834. "
            "Residence: 18, 3rd Cross, HSR Layout, Bangalore 560102.\n\n"
            "Insurance: Star Health Policy #SH-4429017, covering self and spouse.\n\n"
            "Attending Physician: Dr. Arun Mathew, MD Internal Medicine"
        ),
        "pii": [
            {"type": "NAME", "value": "Kavitha Reddy"},
            {"type": "AGE", "value": "45"},
            {"type": "EMPLOYEE_ID", "value": "PAT-772901"},
            {"type": "MEDICAL_CONDITION", "value": "Type 2 Diabetes Mellitus"},
            {"type": "MEDICAL_CONDITION", "value": "diabetic retinopathy"},
            {"type": "MEDICAL_CONDITION", "value": "clinical depression"},
            {"type": "MEDICATION", "value": "Sertraline 50mg"},
            {"type": "MEDICATION", "value": "Insulin glargine 20 units"},
            {"type": "NAME", "value": "Dr. Meena Rao"},
            {"type": "NAME", "value": "Dr. Suresh"},
            {"type": "NAME", "value": "Venkat Reddy"},
            {"type": "PHONE", "value": "080-2555-0834"},
            {"type": "ADDRESS", "value": "18, 3rd Cross, HSR Layout, Bangalore 560102"},
            {"type": "NAME", "value": "Dr. Arun Mathew"},
        ],
    },
    {
        "task_id": "a1b2c3d4-3333-4000-a000-000000000003",
        "title": "Workplace Harassment Complaint",
        "difficulty": "hard",
        "document": (
            "LEGAL MEMO — PRIVILEGED AND CONFIDENTIAL\n"
            "Re: Workplace Harassment Complaint — Case #HR-2026-0089\n\n"
            "Complainant: Nisha Verma, Senior Analyst, Finance Team\n"
            "Employee ID: EMP-18823\n"
            "Date Filed: January 28, 2026\n\n"
            "Ms. Verma reported that her direct supervisor, Karthik Menon "
            "(EMP-09412), made repeated unwanted advances between November 2025 "
            "and January 2026. Witnesses include team members Aditi Shah and "
            "Rohan Desai.\n\n"
            "During the investigation interview on Feb 3, Ms. Verma disclosed "
            "that the incidents worsened her existing PTSD condition, for which "
            "she sees Dr. Lakshmi Iyer at Mindspace Clinic, MG Road, Bangalore. "
            "She is currently on Paroxetine 20mg.\n\n"
            "Mr. Menon resides at 55 Cunningham Road, Bangalore 560052. His "
            "personal email is k.menon.personal@gmail.com and phone is "
            "99800-12345.\n\n"
            "Ms. Verma's contact: nisha.v@company.com, personal: "
            "nisha.verma92@outlook.com. She lives at Flat 204, Prestige "
            "Lakeside, Whitefield, Bangalore 560066.\n\n"
            "Recommendation: Immediate suspension of Mr. Menon pending full "
            "investigation. Offer Ms. Verma paid medical leave and EAP counseling."
        ),
        "pii": [
            {"type": "NAME", "value": "Nisha Verma"},
            {"type": "EMPLOYEE_ID", "value": "EMP-18823"},
            {"type": "NAME", "value": "Karthik Menon"},
            {"type": "EMPLOYEE_ID", "value": "EMP-09412"},
            {"type": "NAME", "value": "Aditi Shah"},
            {"type": "NAME", "value": "Rohan Desai"},
            {"type": "MEDICAL_CONDITION", "value": "PTSD"},
            {"type": "NAME", "value": "Dr. Lakshmi Iyer"},
            {"type": "MEDICATION", "value": "Paroxetine 20mg"},
            {"type": "ADDRESS", "value": "55 Cunningham Road, Bangalore 560052"},
            {"type": "EMAIL", "value": "k.menon.personal@gmail.com"},
            {"type": "PHONE", "value": "99800-12345"},
            {"type": "EMAIL", "value": "nisha.v@company.com"},
            {"type": "EMAIL", "value": "nisha.verma92@outlook.com"},
            {"type": "ADDRESS", "value": "Flat 204, Prestige Lakeside, Whitefield, Bangalore 560066"},
        ],
    },
    {
        "task_id": "a1b2c3d4-4444-4000-a000-000000000004",
        "title": "Insurance Claim Processing",
        "difficulty": "medium",
        "document": (
            "INSURANCE CLAIM — REFERENCE #IC-2026-44821\n"
            "Date: March 3, 2026\n\n"
            "Policyholder: Deepak Nair\n"
            "Policy Number: LIC-9923-4410\n"
            "Date of Birth: 08/12/1978\n"
            "SSN: 412-68-9073\n\n"
            "Mr. Nair filed a claim for hospitalization at Apollo Hospital, "
            "Chennai, from February 18 to February 24, 2026. He was admitted "
            "for acute pancreatitis and was treated with IV fluids, pain "
            "management using Tramadol 50mg, and nutritional support.\n\n"
            "The attending physician, Dr. Priya Menon, confirmed that the "
            "condition was not pre-existing. Mr. Nair has a known history of "
            "hypertension managed with Amlodipine 5mg.\n\n"
            "Total claim amount: ₹4,75,000. Payment to be credited to "
            "ICICI Bank account 0012-3398-7654.\n\n"
            "Contact details: deepak.nair@email.com, Phone: +91-98410-55678. "
            "Registered address: 12, Thiruvalluvar Street, T. Nagar, "
            "Chennai 600017.\n\n"
            "Claim approved by: Sunita Rao, Claims Manager"
        ),
        "pii": [
            {"type": "NAME", "value": "Deepak Nair"},
            {"type": "DATE_OF_BIRTH", "value": "08/12/1978"},
            {"type": "SSN", "value": "412-68-9073"},
            {"type": "MEDICAL_CONDITION", "value": "pancreatitis"},
            {"type": "MEDICATION", "value": "Tramadol 50mg"},
            {"type": "NAME", "value": "Dr. Priya Menon"},
            {"type": "MEDICAL_CONDITION", "value": "hypertension"},
            {"type": "MEDICATION", "value": "Amlodipine 5mg"},
            {"type": "SALARY", "value": "₹4,75,000"},
            {"type": "BANK_ACCOUNT", "value": "0012-3398-7654"},
            {"type": "EMAIL", "value": "deepak.nair@email.com"},
            {"type": "PHONE", "value": "+91-98410-55678"},
            {"type": "ADDRESS", "value": "12, Thiruvalluvar Street, T. Nagar, Chennai 600017"},
            {"type": "NAME", "value": "Sunita Rao"},
        ],
    },
    {
        "task_id": "a1b2c3d4-5555-4000-a000-000000000005",
        "title": "School Incident Report",
        "difficulty": "easy",
        "document": (
            "INCIDENT REPORT — Delhi Public School, Vasant Kunj\n"
            "Date: February 10, 2026\n"
            "Report Filed By: Mrs. Anjali Kapoor, Class Teacher\n\n"
            "Student: Arjun Mehta, Class 8-B, Age: 13\n"
            "Student ID: STU-20260034\n"
            "Parent/Guardian: Vikram Mehta (Father)\n"
            "Contact: vikram.mehta@gmail.com, Phone: 011-2614-5589\n\n"
            "At approximately 11:30 AM during the sports period, Arjun fell "
            "from the climbing frame and sustained a fracture to his left wrist. "
            "The school nurse, Ms. Rekha Sharma, administered first aid and "
            "noted that Arjun has a known allergy to Penicillin as per his "
            "medical records.\n\n"
            "The student was taken to Max Hospital, Saket by his father. "
            "Dr. Sunil Verma at the hospital confirmed a hairline fracture and "
            "prescribed Ibuprofen 200mg for pain relief.\n\n"
            "Vikram Mehta's Aadhaar number on file: 4832-9917-6254. Home "
            "address: B-204, Vasant Enclave, New Delhi 110057.\n\n"
            "Action taken: Safety inspection of climbing equipment scheduled "
            "for February 12. Incident reported to the District Education "
            "Office as per protocol."
        ),
        "pii": [
            {"type": "NAME", "value": "Anjali Kapoor"},
            {"type": "NAME", "value": "Arjun Mehta"},
            {"type": "AGE", "value": "13"},
            {"type": "EMPLOYEE_ID", "value": "STU-20260034"},
            {"type": "NAME", "value": "Vikram Mehta"},
            {"type": "EMAIL", "value": "vikram.mehta@gmail.com"},
            {"type": "PHONE", "value": "011-2614-5589"},
            {"type": "NAME", "value": "Rekha Sharma"},
            {"type": "MEDICATION", "value": "Penicillin"},
            {"type": "NAME", "value": "Dr. Sunil Verma"},
            {"type": "MEDICATION", "value": "Ibuprofen 200mg"},
            {"type": "SSN", "value": "4832-9917-6254"},
            {"type": "ADDRESS", "value": "B-204, Vasant Enclave, New Delhi 110057"},
        ],
    },
]

# Build lookup by task_id
TASKS_BY_ID = {t["task_id"]: t for t in TASKS}


def _extract_non_pii_words(document: str, pii_list: list) -> set:
    """Extract words from the document that are NOT part of any PII value."""
    import re
    all_words = set(re.findall(r"[a-zA-Z]{4,}", document.lower()))
    pii_words = set()
    for pii_item in pii_list:
        pii_words.update(re.findall(r"[a-zA-Z]{4,}", pii_item["value"].lower()))
    return all_words - pii_words


def grade_result(task_id: str, result_text: str | None = None) -> dict:
    """
    Grade a submitted redacted paragraph against the task's PII ground truth.

    Anti-gaming protections:
      1. If result is None/empty, returns the original document with score 0.0
      2. Non-PII content must be preserved — submitting blank/gibberish scores 0.0
      3. Score = pii_removal_score * content_preservation_score

    For each PII value:
      - Absent from result (case-insensitive) → 1.0 (removed)
      - Still present → 0.0 (leaked)

    Content preservation: percentage of non-PII words from the original that
    still appear in the submitted result.

    Final score = (pii_removal_avg) * (content_preservation)
    """
    task = TASKS_BY_ID.get(task_id)
    if task is None:
        return {"error": f"Task '{task_id}' not found."}

    # If no result submitted, return original document with score 0
    if not result_text or not result_text.strip():
        return {
            "task_id": task_id,
            "score": 0.0,
            "total_pii": len(task["pii"]),
            "removed": 0,
            "leaked": len(task["pii"]),
            "content_preservation": 0.0,
            "original_document": task["document"],
            "details": [
                {
                    "pii_type": p["type"],
                    "value": p["value"],
                    "removed": False,
                    "score": 0.0,
                }
                for p in task["pii"]
            ],
            "message": "No result submitted. Returning original document with score 0.0.",
        }

    result_lower = result_text.lower()

    # ── PII removal scoring ──────────────────────────────────────────────
    details = []
    removed_count = 0

    for pii_item in task["pii"]:
        pii_value = pii_item["value"]
        pii_type = pii_item["type"]
        present = pii_value.lower() in result_lower
        item_score = 0.0 if present else 1.0

        if not present:
            removed_count += 1

        details.append({
            "pii_type": pii_type,
            "value": pii_value,
            "removed": not present,
            "score": item_score,
        })

    total = len(task["pii"])
    pii_score = removed_count / total if total > 0 else 0.0

    # ── Content preservation scoring (anti-gaming) ───────────────────────
    non_pii_words = _extract_non_pii_words(task["document"], task["pii"])
    if non_pii_words:
        import re
        result_words = set(re.findall(r"[a-zA-Z]{4,}", result_lower))
        preserved = len(non_pii_words & result_words)
        preservation_score = preserved / len(non_pii_words)
    else:
        preservation_score = 1.0

    # Final score: both PII removal AND content preservation must be high
    final_score = pii_score * preservation_score

    return {
        "task_id": task_id,
        "score": round(final_score, 4),
        "pii_removal_score": round(pii_score, 4),
        "content_preservation": round(preservation_score, 4),
        "total_pii": total,
        "removed": removed_count,
        "leaked": total - removed_count,
        "details": details,
    }
