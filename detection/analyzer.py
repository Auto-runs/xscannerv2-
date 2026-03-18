"""
detection/analyzer.py
Multi-layer XSS detection engine.

Layers:
1. Reflection check        — is payload present in response?
2. HTML parser analysis    — is payload in executable position?
3. DOM sink heuristics     — does body contain dangerous sinks?
4. Signature matching      — known XSS patterns
5. Confidence scoring      — weight all signals
"""

import re
from typing import Optional, Tuple
from bs4 import BeautifulSoup, Comment
from urllib.parse import unquote

from utils.config import Context, DOM_SINKS, DOM_SOURCES
from utils.logger import debug


# ─── Reflection Analyzer ─────────────────────────────────────────────────────

class ReflectionAnalyzer:
    """Determine whether a payload appears unencoded in the response."""

    # Characters that MUST survive unencoded to be exploitable
    _INDICATOR_CHARS = ["<", ">", "\"", "'", "(", ")", "/"]

    def check(self, payload: str, body: str) -> Tuple[bool, str]:
        """
        Returns (reflected: bool, evidence: str).
        evidence is the surrounding text context.
        """
        if payload not in body:
            # Try URL-decoded version
            decoded = unquote(payload)
            if decoded not in body:
                return False, ""
            body = body  # use decoded check below
            search = decoded
        else:
            search = payload

        idx = body.find(search)
        snippet = body[max(0, idx - 80): idx + len(search) + 80]
        return True, snippet

    def chars_survive(self, payload: str, body: str) -> bool:
        """Check if critical characters appear unencoded."""
        for char in self._INDICATOR_CHARS:
            if char in payload and char not in body:
                return False
        return True


# ─── DOM Sink Analyzer ────────────────────────────────────────────────────────

class DOMAnalyzer:
    """
    Scan response body for DOM-based XSS sink/source patterns.
    Does NOT require payload execution — detects structural risk.
    """

    def analyze(self, body: str) -> Tuple[bool, list[str]]:
        """
        Returns (vulnerable: bool, matched_sinks: List[str]).
        Searches a bidirectional 600-char window around each sink occurrence.
        """
        found = []
        body_lower = body.lower()

        for sink in DOM_SINKS:
            sink_lower = sink.lower()
            idx = 0
            while True:
                idx = body_lower.find(sink_lower, idx)
                if idx == -1:
                    break
                window_start = max(0, idx - 600)
                window_end   = min(len(body_lower), idx + len(sink_lower) + 600)
                window       = body_lower[window_start:window_end]
                for src in DOM_SOURCES:
                    if src.lower() in window:
                        found.append(f"{sink} <- {src}")
                idx += len(sink_lower)

        return (len(found) > 0, list(set(found)))


# ─── HTML Position Analyzer ──────────────────────────────────────────────────

class HTMLPositionAnalyzer:
    """
    Use BeautifulSoup to determine if the reflected payload ended up
    in an executable position (script tag, event handler, etc.).
    """

    def is_executable(self, payload: str, body: str) -> Tuple[bool, str]:
        """
        Returns (is_executable: bool, reason: str).
        """
        if payload not in body:
            return False, "not reflected"

        soup = BeautifulSoup(body, "html.parser")

        # 1. Check if payload landed inside a <script> block
        for script in soup.find_all("script"):
            if script.string and payload in script.string:
                return True, "inside <script> block"

        # 2. Check if payload appears as a tag or attribute value
        if re.search(r"<[a-z]+[^>]*" + re.escape(payload[:20]), body, re.IGNORECASE):
            return True, "in HTML tag context"

        # 3. Check if payload appears in event handler
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if isinstance(val, str) and payload[:20] in val:
                    if attr.lower().startswith("on"):
                        return True, f"in event handler: {attr}"

        # 4. Check for script tag injection
        if soup.find("script") and payload in str(soup):
            return True, "payload created script tag"

        # 5. Check inline event handlers in raw HTML
        event_pattern = r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload[:15])
        if re.search(event_pattern, body, re.IGNORECASE):
            return True, "reflected in event handler (raw)"

        return False, "reflected but not executable"


# ─── Confidence Scorer ───────────────────────────────────────────────────────

class ConfidenceScorer:
    """
    Combine signals from all analyzers into a confidence score.
    """

    def score(
        self,
        reflected:     bool,
        chars_survive: bool,
        executable:    bool,
        waf_bypass:    bool,
        context:       str = "unknown",
        exec_reason:   str = "",
    ) -> Tuple[str, str]:
        """
        Context-aware confidence scoring.
        Reflection inside <script> block = much higher risk than in HTML comment.
        """
        points = 0
        if reflected:      points += 30
        if chars_survive:  points += 20
        if executable:     points += 35
        if waf_bypass:     points += 10

        # Context multiplier — same reflection is more dangerous in certain contexts
        context_bonus = {
            "javascript":    15,  # inside script block = very high
            "js_string":     12,
            "js_template":   12,
            "attribute":     10,  # inside attribute = high
            "html":           5,  # HTML body = standard
            "url":            8,
            "css":            3,
            "comment":        0,  # inside comment = low risk
            "unknown":        5,
        }.get(context, 5)
        points += context_bonus

        # Execution reason bonus
        if "script" in exec_reason.lower():    points += 5
        if "event handler" in exec_reason.lower(): points += 8
        if "event_handler" in exec_reason.lower(): points += 8

        if points >= 80:
            return "High", "High"
        elif points >= 55:
            return "Medium", "Medium"
        elif points >= 35:
            return "Low", "Low"
        else:
            return "Informational", "Info"


# ─── Master Detection Engine ─────────────────────────────────────────────────

class DetectionEngine:
    """
    Orchestrates all analyzers. Call `.analyze()` per (payload, response).
    """

    def __init__(self):
        self.reflection  = ReflectionAnalyzer()
        self.dom         = DOMAnalyzer()
        self.html_pos    = HTMLPositionAnalyzer()
        self.scorer      = ConfidenceScorer()

    def analyze(
        self,
        payload: str,
        response_body: str,
        context: str = Context.UNKNOWN,
        waf_bypassed: bool = False,
    ) -> Optional[dict]:
        """
        Full analysis of a single payload/response pair.
        Returns detection dict or None if not vulnerable.
        """
        # Layer 1: Reflection
        reflected, evidence = self.reflection.check(payload, response_body)
        if not reflected:
            debug(f"No reflection: {payload[:40]}")
            return None

        # Layer 2: Critical char survival
        chars_ok = self.reflection.chars_survive(payload, response_body)

        # Layer 3: HTML position
        executable, exec_reason = self.html_pos.is_executable(payload, response_body)

        # Layer 4: DOM analysis
        dom_vuln, dom_sinks = self.dom.analyze(response_body)

        # Layer 5: Confidence
        confidence, severity = self.scorer.score(
            reflected, chars_ok, executable or dom_vuln, waf_bypassed,
            context=context, exec_reason=exec_reason,
        )

        # Only report Medium+ confidence
        if confidence == "Informational" and not executable:
            return None

        return {
            "reflected":   reflected,
            "executable":  executable,
            "exec_reason": exec_reason,
            "dom_vuln":    dom_vuln,
            "dom_sinks":   dom_sinks,
            "chars_ok":    chars_ok,
            "confidence":  confidence,
            "severity":    severity,
            "evidence":    evidence[:300],
        }

    def quick_reflect(self, payload: str, body: str) -> bool:
        """Fast check: is payload in body? (for bulk filtering)"""
        return payload in body or unquote(payload) in body
