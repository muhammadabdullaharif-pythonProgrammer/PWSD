"""Offline NLP cosine-similarity engine for the cybersecurity chatbot.

Uses sentence-transformers when available; transparently falls back to a
pure-NumPy bag-of-words TF vector if the model cannot be loaded (keeps
the app responsive on machines without the heavy ML download).
"""
from __future__ import annotations
import json
import math
import re
from pathlib import Path
from threading import Lock

import numpy as np

KNOWLEDGE_BASE: list[dict] = [
    {"q": "What is phishing?",
     "a": "Phishing is a social-engineering attack where attackers impersonate "
          "trusted entities to steal credentials, financial data, or install malware."},
    {"q": "How does PWDS detect phishing URLs?",
     "a": "PWDS extracts lexical features (length, entropy, subdomains, IP usage, "
          "keywords) and runs them through a Random-Forest-style classifier, "
          "complemented by live WHOIS and DNS intelligence."},
    {"q": "What is a suspicious URL?",
     "a": "A suspicious URL typically uses an IP address, contains @ symbols, "
          "has high character entropy, mimics known brands, or hosts on a "
          "newly-registered domain."},
    {"q": "How do I scan a website?",
     "a": "Open the Dashboard, paste the target URL in the scan box and press "
          "‘Analyse’. Results stream back asynchronously without a page reload."},
    {"q": "What does the threat score mean?",
     "a": "The threat score is a 0–100 % probability produced by the classifier. "
          "Below 40 % = Safe, 40–70 % = Suspicious, above 70 % = Phishing."},
    {"q": "Can I download a report?",
     "a": "Yes. Open any scan from your History and click ‘Download PDF report’ "
          "to obtain a formal forensic PDF."},
    {"q": "What roles exist in the system?",
     "a": "PWDS supports three roles: Administrator, Security Analyst, and "
          "Standard User. Each role unlocks different dashboard capabilities."},
    {"q": "How is my password stored?",
     "a": "Passwords are hashed with Argon2 (falling back to PBKDF2-SHA256). "
          "Plain-text passwords are never stored or logged."},
    {"q": "Does PWDS check the domain age?",
     "a": "Yes — the network analyser performs a live WHOIS lookup and reports "
          "the registrar, country and domain age in days."},
    {"q": "What is DNS used for in the scan?",
     "a": "PWDS resolves A, MX and NS records to confirm the domain is active "
          "and to surface its hosting and mail infrastructure."},
    {"q": "How do I report a confirmed phishing site?",
     "a": "Notify your organisation's SOC team and submit the URL to "
          "anti-phishing services like PhishTank, Google Safe Browsing, and the "
          "APWG."},
    {"q": "Who built PWDS?",
     "a": "PWDS was developed by Muhammad Abdullah Arif as a Final Year Project "
          "for the BS Computer Science programme (2022-2026) at GCUF."},
]

_TOKEN_RE = re.compile(r"[a-zA-Z]{2,}")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


class _CosineEngine:
    """Offline TF-cosine engine — deterministic, zero network."""

    def __init__(self, kb: list[dict]):
        self.kb = kb
        self.vocab: dict[str, int] = {}
        for entry in kb:
            for tok in _tokenize(entry["q"] + " " + entry["a"]):
                self.vocab.setdefault(tok, len(self.vocab))
        self.vectors = np.vstack([self._vec(e["q"] + " " + e["a"]) for e in kb])

    def _vec(self, text: str) -> np.ndarray:
        v = np.zeros(len(self.vocab), dtype=np.float32)
        for tok in _tokenize(text):
            idx = self.vocab.get(tok)
            if idx is not None:
                v[idx] += 1.0
        n = np.linalg.norm(v)
        return v / n if n else v

    def query(self, message: str) -> tuple[str, float, str]:
        q = self._vec(message)
        if not q.any():
            return ("I’m not sure I understood that. Try asking about phishing, "
                    "scans, threat scores, WHOIS, DNS or reports.", 0.0, "")
        sims = self.vectors @ q
        best = int(np.argmax(sims))
        score = float(sims[best])
        if score < 0.15:
            return ("I don’t have a confident answer for that. Please rephrase "
                    "your question about phishing detection or PWDS usage.",
                    score, self.kb[best]["q"])
        return self.kb[best]["a"], score, self.kb[best]["q"]


class _SentenceTransformerEngine:
    """Optional richer engine using sentence-transformers."""

    def __init__(self, kb: list[dict]):
        from sentence_transformers import SentenceTransformer  # heavy import
        self.kb = kb
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.embeddings = self.model.encode(
            [e["q"] + " " + e["a"] for e in kb],
            convert_to_numpy=True, normalize_embeddings=True,
        )

    def query(self, message: str) -> tuple[str, float, str]:
        emb = self.model.encode([message], convert_to_numpy=True,
                                normalize_embeddings=True)[0]
        sims = self.embeddings @ emb
        best = int(np.argmax(sims))
        score = float(sims[best])
        if score < 0.30:
            return ("I don’t have a confident answer for that. Please rephrase "
                    "your question about phishing detection or PWDS usage.",
                    score, self.kb[best]["q"])
        return self.kb[best]["a"], score, self.kb[best]["q"]


_engine = None
_lock = Lock()


def _get_engine():
    global _engine
    if _engine is not None:
        return _engine
    with _lock:
        if _engine is None:
            try:
                _engine = _SentenceTransformerEngine(KNOWLEDGE_BASE)
            except Exception:
                _engine = _CosineEngine(KNOWLEDGE_BASE)
    return _engine


def ask(message: str) -> dict:
    """Public API used by the view layer."""
    message = (message or "").strip()
    if not message:
        return {"answer": "Please type a question.", "score": 0.0, "match": ""}
    answer, score, match = _get_engine().query(message)
    return {"answer": answer, "score": round(score, 4), "match": match}
