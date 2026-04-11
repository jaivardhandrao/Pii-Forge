"""
PII Detector — Microsoft Presidio + Aho-Corasick based detection engine.

Combines:
  - Microsoft Presidio Analyzer for NER-based PII detection
  - Aho-Corasick algorithm for fast multi-pattern keyword matching
  - Regex patterns for custom PII formats (Employee IDs, Indian phones, etc.)

The two engines run in parallel and results are merged + deduplicated.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import ahocorasick

from presidio_analyzer import AnalyzerEngine, RecognizerResult, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ── Presidio entity type -> our PII type mapping ─────────────────────────────

PRESIDIO_TO_PII = {
    "PERSON": "NAME",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "US_SSN": "SSN",
    "CREDIT_CARD": "CREDIT_CARD",
    "DATE_TIME": "DATE_OF_BIRTH",
    "LOCATION": "LOCATION",
    "IP_ADDRESS": "IP_ADDRESS",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "LICENSE_NUMBER",
    "IBAN_CODE": "BANK_ACCOUNT",
    "US_BANK_NUMBER": "BANK_ACCOUNT",
    "NRP": "ORGANIZATION",
    "ORGANIZATION": "ORGANIZATION",
    # Custom recognizers we register:
    "EMPLOYEE_ID": "EMPLOYEE_ID",
    "SALARY": "SALARY",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "PASSPORT_GENERIC": "PASSPORT",
    "AGE": "AGE",
    "MEDICAL_CONDITION": "MEDICAL_CONDITION",
    "MEDICATION": "MEDICATION",
    "USERNAME": "USERNAME",
    "PASSWORD": "PASSWORD",
    "ADDRESS": "ADDRESS",
}

PII_TO_PRESIDIO = {v: k for k, v in PRESIDIO_TO_PII.items()}

# ── Aho-Corasick keyword dictionaries ────────────────────────────────────────

MEDICAL_CONDITIONS = [
    "diabetes", "diabetic", "hypertension", "asthma", "cancer", "tumor",
    "hiv", "aids", "depression", "anxiety", "ptsd", "bipolar",
    "schizophrenia", "epilepsy", "arthritis", "alzheimer", "dementia",
    "tuberculosis", "hepatitis", "covid", "pneumonia", "bronchitis",
    "retinopathy", "neuropathy", "clinical depression", "type 2 diabetes",
    "type 1 diabetes", "type 2 diabetes mellitus", "diabetic retinopathy",
    "chronic kidney disease", "heart disease", "coronary artery disease",
    "congestive heart failure", "stroke", "migraine", "fibromyalgia",
    "lupus", "celiac", "crohn", "ulcerative colitis", "parkinson",
    "multiple sclerosis", "anemia", "leukemia", "lymphoma", "melanoma",
    "obesity", "insomnia", "sleep apnea", "thyroid", "hypothyroidism",
    "hyperthyroidism", "osteoporosis", "gout", "psoriasis", "eczema",
]

MEDICATIONS = [
    "metformin", "insulin", "insulin glargine", "lisinopril", "amlodipine",
    "atorvastatin", "omeprazole", "sertraline", "paroxetine", "fluoxetine",
    "citalopram", "escitalopram", "venlafaxine", "duloxetine", "bupropion",
    "alprazolam", "diazepam", "lorazepam", "clonazepam", "zolpidem",
    "gabapentin", "pregabalin", "tramadol", "oxycodone", "hydrocodone",
    "ibuprofen", "naproxen", "acetaminophen", "aspirin", "warfarin",
    "clopidogrel", "prednisone", "prednisolone", "albuterol", "montelukast",
    "levothyroxine", "metoprolol", "propranolol", "losartan", "valsartan",
    "simvastatin", "rosuvastatin", "pantoprazole", "esomeprazole",
    "amoxicillin", "azithromycin", "ciprofloxacin", "doxycycline",
    "metronidazole", "clindamycin", "cetirizine", "loratadine",
    "hydroxychloroquine", "tacrolimus", "cyclosporine", "adalimumab",
]


# ── Custom Presidio Recognizers ──────────────────────────────────────────────

def _build_custom_recognizers() -> list:
    """Build custom Presidio recognizers for PII types not covered by defaults."""
    recognizers = []

    # Employee ID (EMP-XXXX or PAT-XXXX patterns)
    recognizers.append(PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[
            Pattern("emp_id", r"\b(?:EMP|PAT|HR|FIN|IT|MKT)-\d{3,6}\b", 0.9),
        ],
    ))

    # Salary patterns (Indian and Western)
    recognizers.append(PatternRecognizer(
        supported_entity="SALARY",
        patterns=[
            Pattern("salary_inr", r"₹[\d,]+(?:\.\d{1,2})?", 0.85),
            Pattern("salary_lpa", r"\b\d+(?:\.\d+)?\s*(?:LPA|lpa|lakhs?|crores?)\b", 0.80),
            Pattern("salary_usd", r"\$[\d,]+(?:\.\d{1,2})?\s*(?:per\s+(?:year|month|annum))?", 0.75),
        ],
    ))

    # Credit card (explicit high-priority pattern)
    recognizers.append(PatternRecognizer(
        supported_entity="CREDIT_CARD",
        patterns=[
            Pattern("cc_dashed", r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b", 0.95),
            Pattern("cc_nodash", r"\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b", 0.90),
        ],
    ))

    # Bank account numbers (must NOT match 16-digit credit cards)
    recognizers.append(PatternRecognizer(
        supported_entity="BANK_ACCOUNT",
        patterns=[
            Pattern("bank_acct_12", r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.55),
        ],
    ))

    # Generic passport (non-US)
    recognizers.append(PatternRecognizer(
        supported_entity="PASSPORT_GENERIC",
        patterns=[
            Pattern("passport_generic", r"\b[A-Z]\d{7,8}\b", 0.7),
        ],
    ))

    # Age patterns
    recognizers.append(PatternRecognizer(
        supported_entity="AGE",
        patterns=[
            Pattern("age_years", r"\bAge:\s*\d{1,3}\b", 0.9),
            Pattern("age_yo", r"\b\d{1,3}\s*(?:years?\s*old|y/?o)\b", 0.85),
            Pattern("age_aged", r"\baged\s+\d{1,3}\b", 0.85),
        ],
    ))

    # Address patterns
    recognizers.append(PatternRecognizer(
        supported_entity="ADDRESS",
        patterns=[
            Pattern("addr_us", r"\b\d{1,5}\s+\w+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b[^.]*?\b[A-Z]{2}\s+\d{5}\b", 0.80),
            Pattern("addr_in", r"\b(?:Flat|No\.?|#)\s*\d+[^.]*?(?:Road|Layout|Nagar|Colony|Cross|Main|Street)[^.]*?\d{6}\b", 0.80),
        ],
    ))

    return recognizers


# ── Aho-Corasick engine ──────────────────────────────────────────────────────

class AhoCorasickPIIDetector:
    """
    Fast multi-pattern PII keyword matcher using the Aho-Corasick algorithm.

    Builds an automaton from known PII keyword dictionaries (medical conditions,
    medications) and scans text in O(n + m) time where n = text length,
    m = total matches.
    """

    def __init__(self):
        self._med_automaton = ahocorasick.Automaton()
        self._drug_automaton = ahocorasick.Automaton()

        for idx, term in enumerate(MEDICAL_CONDITIONS):
            self._med_automaton.add_word(term.lower(), (idx, term, "MEDICAL_CONDITION"))
        self._med_automaton.make_automaton()

        for idx, term in enumerate(MEDICATIONS):
            self._drug_automaton.add_word(term.lower(), (idx, term, "MEDICATION"))
        self._drug_automaton.make_automaton()

        # Additional regex patterns for things Aho-Corasick can't catch
        self._extra_patterns = [
            # Medication with dosage
            (re.compile(
                r"\b(" + "|".join(re.escape(m) for m in MEDICATIONS) + r")\s+\d+\s*(?:mg|mcg|ml|units?)\b",
                re.IGNORECASE,
            ), "MEDICATION"),
            # Indian phone numbers (require +91 or 0XX prefix to avoid matching card fragments)
            (re.compile(r"(?:\+91[-\s]?|0\d{2,4}[-\s])\d{4,5}[-\s]?\d{4,5}\b"), "PHONE"),
            # Address-like patterns (number + street + zip)
            (re.compile(
                r"\b\d+[,\s]+(?:\d+(?:st|nd|rd|th)\s+)?(?:Cross|Main|Street|Road|Ave|Avenue|Lane|Drive|Blvd|Layout|Nagar|Colony|Block)\b[^.]*?\b\d{5,6}\b",
                re.IGNORECASE,
            ), "ADDRESS"),
        ]

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text using Aho-Corasick automatons and regex patterns.
        Returns list of detected PII entities.
        """
        results = []
        text_lower = text.lower()

        # Scan medical conditions
        for end_idx, (_, term, pii_type) in self._med_automaton.iter(text_lower):
            start = end_idx - len(term) + 1
            end = end_idx + 1
            # Verify word boundary
            if start > 0 and text_lower[start - 1].isalpha():
                continue
            if end < len(text_lower) and text_lower[end].isalpha():
                continue
            results.append({
                "pii_type": pii_type,
                "value": text[start:end],
                "start": start,
                "end": end,
                "score": 0.85,
                "source": "aho-corasick",
            })

        # Scan medications
        for end_idx, (_, term, pii_type) in self._drug_automaton.iter(text_lower):
            start = end_idx - len(term) + 1
            end = end_idx + 1
            if start > 0 and text_lower[start - 1].isalpha():
                continue
            if end < len(text_lower) and text_lower[end].isalpha():
                continue
            results.append({
                "pii_type": pii_type,
                "value": text[start:end],
                "start": start,
                "end": end,
                "score": 0.85,
                "source": "aho-corasick",
            })

        # Scan extra regex patterns
        for pattern, pii_type in self._extra_patterns:
            for match in pattern.finditer(text):
                results.append({
                    "pii_type": pii_type,
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "score": 0.70,
                    "source": "regex",
                })

        return results


# ── Combined PII Detector ────────────────────────────────────────────────────

class PIIDetector:
    """
    Combined PII detector using Microsoft Presidio + Aho-Corasick.

    - Presidio handles NER-based detection (names, emails, phones, SSNs, etc.)
    - Aho-Corasick handles fast keyword matching (medical terms, medications)
    - Results are merged and deduplicated by span overlap
    """

    def __init__(self):
        # Initialize Presidio
        self._analyzer = AnalyzerEngine()
        for recognizer in _build_custom_recognizers():
            self._analyzer.registry.add_recognizer(recognizer)

        self._anonymizer = AnonymizerEngine()

        # Initialize Aho-Corasick detector
        self._ac_detector = AhoCorasickPIIDetector()

    def detect(self, text: str, language: str = "en") -> List[Dict[str, Any]]:
        """
        Detect all PII in the given text.

        Returns a list of PII entities with:
          - pii_type: Our unified PII type string
          - value: The matched text
          - start: Character offset start
          - end: Character offset end
          - score: Confidence score (0-1)
          - source: "presidio" or "aho-corasick" or "regex"
        """
        results = []

        # 1. Run Presidio analyzer
        presidio_results = self._analyzer.analyze(
            text=text,
            language=language,
            entities=None,  # detect all supported types
        )
        for r in presidio_results:
            pii_type = PRESIDIO_TO_PII.get(r.entity_type, r.entity_type)
            results.append({
                "pii_type": pii_type,
                "value": text[r.start:r.end],
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 2),
                "source": "presidio",
            })

        # 2. Run Aho-Corasick detector
        ac_results = self._ac_detector.scan(text)
        results.extend(ac_results)

        # 3. Deduplicate by span overlap
        results = self._deduplicate(results)

        # 4. Sort by start position
        results.sort(key=lambda x: x["start"])

        return results

    def redact(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """
        Redact PII from text by replacing detected values with [TYPE] tags.
        Uses span-based replacement (most accurate).
        """
        if not entities:
            return text

        # Sort by start position descending to replace from end
        sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
        result = text
        for entity in sorted_entities:
            start = entity["start"]
            end = entity["end"]
            pii_type = entity["pii_type"]
            if 0 <= start < end <= len(result):
                result = result[:start] + f"[{pii_type}]" + result[end:]
        return result

    def detect_and_redact(self, text: str, language: str = "en") -> Dict[str, Any]:
        """
        Detect PII and produce redacted text in one call.

        Returns:
          - entities: List of detected PII entities
          - redacted_text: Text with PII replaced by [TYPE] tags
          - summary: Quick stats summary
        """
        entities = self.detect(text, language)
        redacted = self.redact(text, entities)

        # Build summary
        type_counts: Dict[str, int] = {}
        for e in entities:
            t = e["pii_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "entities": entities,
            "redacted_text": redacted,
            "entity_count": len(entities),
            "type_counts": type_counts,
        }

    def _deduplicate(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove overlapping detections, keeping the longer/higher-confidence one."""
        if not results:
            return results

        # Sort by span length descending (prefer longer matches), then score descending
        results.sort(key=lambda x: (-(x["end"] - x["start"]), -x["score"]))

        deduped = []
        for entity in results:
            overlaps = False
            for i, kept in enumerate(deduped):
                overlap_start = max(entity["start"], kept["start"])
                overlap_end = min(entity["end"], kept["end"])
                if overlap_start < overlap_end:
                    overlap_len = overlap_end - overlap_start
                    entity_len = entity["end"] - entity["start"]
                    kept_len = kept["end"] - kept["start"]

                    if overlap_len / max(min(entity_len, kept_len), 1) > 0.5:
                        # Prefer longer span, or more specific type at same length
                        specific_types = {"MEDICAL_CONDITION", "MEDICATION", "CREDIT_CARD", "ADDRESS", "SALARY"}
                        if entity_len > kept_len:
                            deduped[i] = entity
                        elif entity["pii_type"] in specific_types and kept["pii_type"] not in specific_types:
                            deduped[i] = entity
                        overlaps = True
                        break

            if not overlaps:
                deduped.append(entity)

        return deduped


# ── Module-level singleton for convenience ───────────────────────────────────

_detector: Optional[PIIDetector] = None


def get_detector() -> PIIDetector:
    """Get or create the global PII detector instance."""
    global _detector
    if _detector is None:
        _detector = PIIDetector()
    return _detector
