from __future__ import annotations

import re

def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())

def contains_any(text: str, terms: list[str]) -> bool:
    lower = (text or "").lower()
    return any(term.lower() in lower for term in terms)

def keyword_score(text: str, terms: list[str]) -> int:
    lower = (text or "").lower()
    return sum(1 for term in terms if term.lower() in lower)

def extract_excerpt(text: str, terms: list[str], window: int = 120) -> str:
    lower = (text or "")
    low = lower.lower()
    for term in terms:
        idx = low.find(term.lower())
        if idx >= 0:
            start = max(0, idx - window // 2)
            end = min(len(lower), idx + len(term) + window // 2)
            return normalize_whitespace(lower[start:end])
    return normalize_whitespace(lower[:window])

def first_heading(markdown_text: str, fallback: str) -> str:
    for line in (markdown_text or "").splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return fallback
