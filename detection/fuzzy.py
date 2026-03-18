"""
detection/fuzzy.py

FuzzyDetector — Multi-signal similarity detection engine.

Problems with exact-match detection (XSStrike has this partially, XScanner v1 too):
  - Server encodes & then re-decodes → payload appears transformed
  - WAF strips individual chars → payload partially reflected
  - Template engines render payload differently

Solution: Multi-signal fuzzy analysis:
  1. Levenshtein similarity ratio     — how similar is reflection to payload?
  2. Token overlap score              — how many payload tokens appear in response?
  3. Entropy delta                    — does injection change response randomness?
  4. Response length delta            — significant change = something happened
  5. Structure mutation score         — did HTML structure change post-injection?
  6. Semantic tag injection check     — did new executable tags appear?
"""

import re
import math
from typing import Optional, Tuple, List
from collections import Counter

try:
    from rapidfuzz import fuzz as rfuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False

from utils.logger import debug


# ─── Entropy calculator ──────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total  = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ─── Token extractor ─────────────────────────────────────────────────────────

def _tokenize(text: str) -> set:
    """Extract meaningful tokens from payload/response."""
    return set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', text.lower()))


# ─── HTML tag extractor ──────────────────────────────────────────────────────

_EXECUTABLE_TAGS = {
    "script", "svg", "img", "iframe", "object", "embed",
    "video", "audio", "body", "details", "input", "form",
    "marquee", "math", "link", "meta", "base", "style",
}

def _extract_executable_tags(html: str) -> set:
    """Extract all executable HTML tags from a response."""
    tags = set(re.findall(r'<(\w+)', html.lower()))
    return tags & _EXECUTABLE_TAGS


# ─── Main FuzzyDetector ──────────────────────────────────────────────────────

class FuzzyDetector:
    """
    Multi-signal fuzzy XSS detection.

    Thresholds tuned to minimize false positives while catching
    partial/encoded reflections that exact-match would miss.
    """

    # Minimum similarity ratio (0-100) to consider "reflected"
    SIMILARITY_THRESHOLD   = 65
    # Minimum token overlap to consider "reflected"
    TOKEN_OVERLAP_THRESHOLD = 0.4
    # Entropy delta that indicates injection had structural effect
    ENTROPY_DELTA_THRESHOLD = 0.3

    def analyze(
        self,
        payload:      str,
        baseline:     str,
        response:     str,
        fast_mode:    bool = False,
    ) -> dict:
        """
        Full fuzzy analysis.

        Args:
            payload:   The injected payload string
            baseline:  Response WITHOUT payload injection (for diff)
            response:  Response WITH payload injection
            fast_mode: Skip expensive checks if True

        Returns dict with:
            reflected:        bool
            confidence:       float (0.0–1.0)
            similarity:       float (0–100, Levenshtein ratio)
            token_overlap:    float (0.0–1.0)
            entropy_delta:    float
            new_tags:         List[str]  — new executable tags that appeared
            structural_change: bool
            method:           str — which signal triggered detection
        """
        result = {
            "reflected":         False,
            "confidence":        0.0,
            "similarity":        0.0,
            "token_overlap":     0.0,
            "entropy_delta":     0.0,
            "new_tags":          [],
            "structural_change": False,
            "method":            "none",
        }

        # ── Signal 1: Exact match (fastest) ──────────────────────────────────
        if payload in response:
            result.update({
                "reflected":  True,
                "confidence": 1.0,
                "similarity": 100.0,
                "method":     "exact",
            })
            return result

        # ── Signal 2: Levenshtein similarity ─────────────────────────────────
        # Compare payload against all substrings of response of similar length
        similarity = self._best_similarity(payload, response)
        result["similarity"] = similarity

        if similarity >= self.SIMILARITY_THRESHOLD:
            conf = (similarity - self.SIMILARITY_THRESHOLD) / (100 - self.SIMILARITY_THRESHOLD)
            result.update({
                "reflected":  True,
                "confidence": round(conf * 0.85, 3),  # max 0.85 for fuzzy
                "method":     f"levenshtein({similarity:.0f}%)",
            })

        # ── Signal 3: Token overlap ───────────────────────────────────────────
        payload_tokens  = _tokenize(payload)
        response_tokens = _tokenize(response)
        if payload_tokens:
            overlap = len(payload_tokens & response_tokens) / len(payload_tokens)
            result["token_overlap"] = round(overlap, 3)
            if overlap >= self.TOKEN_OVERLAP_THRESHOLD and not result["reflected"]:
                result.update({
                    "reflected":  True,
                    "confidence": round(overlap * 0.6, 3),
                    "method":     f"token_overlap({overlap:.0%})",
                })

        if fast_mode:
            return result

        # ── Signal 4: New executable tags ─────────────────────────────────────
        baseline_tags = _extract_executable_tags(baseline)
        response_tags = _extract_executable_tags(response)
        new_tags      = list(response_tags - baseline_tags)
        result["new_tags"] = new_tags

        if new_tags:
            # New executable tag appeared → high confidence
            boost = min(0.3, len(new_tags) * 0.1)
            result["confidence"] = min(1.0, result["confidence"] + boost)
            if not result["reflected"]:
                result.update({
                    "reflected":  True,
                    "confidence": 0.7,
                    "method":     f"new_exec_tags({new_tags})",
                })

        # ── Signal 5: Entropy delta ───────────────────────────────────────────
        ent_baseline = _entropy(baseline[:5000])
        ent_response = _entropy(response[:5000])
        ent_delta    = abs(ent_response - ent_baseline)
        result["entropy_delta"] = round(ent_delta, 4)

        if ent_delta > self.ENTROPY_DELTA_THRESHOLD and not result["reflected"]:
            result.update({
                "reflected":  True,
                "confidence": 0.4,
                "method":     f"entropy_delta({ent_delta:.3f})",
            })

        # ── Signal 6: Response length structural change ───────────────────────
        len_base = len(baseline)
        len_resp = len(response)
        if len_base > 0:
            delta_ratio = abs(len_resp - len_base) / len_base
            if delta_ratio > 0.15:
                result["structural_change"] = True
                if result["reflected"]:
                    result["confidence"] = min(1.0, result["confidence"] + 0.1)

        return result

    def _best_similarity(self, payload: str, response: str) -> float:
        """
        Find the best Levenshtein similarity between payload and
        any substring of response. Uses full payload — no truncation.
        """
        if not _HAS_RAPIDFUZZ:
            return self._fallback_similarity(payload, response)

        plen = len(payload)
        if plen == 0:
            return 0.0

        # Use full payload for partial_ratio — critical for long polyglots/mXSS
        best = rfuzz.partial_ratio(payload, response)

        # Also check most distinctive segment (middle 60%) for very long payloads
        if plen > 150:
            start = plen // 5
            end   = plen - plen // 5
            mid_score = rfuzz.partial_ratio(payload[start:end], response)
            best = max(best, mid_score)

        return float(best)

    def _fallback_similarity(self, s1: str, s2: str) -> float:
        """
        Pure-Python Levenshtein ratio fallback (no external deps).
        Only checks if s1 appears roughly in s2.
        """
        s1 = s1[:80].lower()
        s2 = s2.lower()
        plen = len(s1)
        if plen == 0:
            return 0.0

        best = 0.0
        step = max(1, plen // 4)
        for i in range(0, len(s2) - plen + 1, step):
            window  = s2[i:i + plen]
            matches = sum(a == b for a, b in zip(s1, window))
            ratio   = (matches / plen) * 100
            if ratio > best:
                best = ratio
            if best >= 95:
                break
        return best


# ─── Response Differ ─────────────────────────────────────────────────────────

class ResponseDiffer:
    """
    Structural diff between baseline and injected response.
    Detects DOM mutations introduced by payload injection.
    Goes beyond simple string comparison — looks at tag structure.
    """

    def diff(self, baseline: str, response: str) -> dict:
        """
        Returns:
            added_tags:    new HTML tags in response
            removed_tags:  tags that disappeared
            new_scripts:   new <script> blocks
            new_handlers:  new event handlers (onXxx attributes)
            delta_ratio:   length change ratio
        """
        base_tags    = self._extract_tags(baseline)
        resp_tags    = self._extract_tags(response)
        base_scripts = self._extract_scripts(baseline)
        resp_scripts = self._extract_scripts(response)
        base_handlers = self._extract_handlers(baseline)
        resp_handlers = self._extract_handlers(response)

        added_tags   = [t for t in resp_tags   if t not in base_tags]
        new_scripts  = [s for s in resp_scripts if s not in base_scripts]
        new_handlers = [h for h in resp_handlers if h not in base_handlers]

        delta_ratio = (
            abs(len(response) - len(baseline)) / max(1, len(baseline))
        )

        return {
            "added_tags":   added_tags[:10],
            "new_scripts":  new_scripts[:5],
            "new_handlers": new_handlers[:10],
            "delta_ratio":  round(delta_ratio, 3),
            "suspicious":   bool(new_scripts or new_handlers or added_tags),
        }

    @staticmethod
    def _extract_tags(html: str) -> List[str]:
        return re.findall(r'<(\w+)[^>]*>', html.lower())

    @staticmethod
    def _extract_scripts(html: str) -> List[str]:
        return re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

    @staticmethod
    def _extract_handlers(html: str) -> List[str]:
        return re.findall(r'\bon\w+\s*=\s*["\'][^"\']*["\']', html, re.IGNORECASE)
