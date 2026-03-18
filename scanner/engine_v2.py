"""
scanner/engine_v2.py — XScanner v5 Complete Unified Scan Engine

All modules fully integrated:
- CombinatorialEngine      (151M+ HTML/JS/Attr combinations)
- MXSSEngine               (11,424 mXSS combinations)
- JSONAPIEngine            (5,760 JSON API combinations)
- FilterProbe              (concurrent CharacterMatrix, URL-level cache)
- FuzzyDetector            (6-signal detection)
- ResponseDiffer           (structural DOM diff)
- SmartGenerator           (matrix-aware payload builder)
- AdaptiveSequencer        (real-time feedback learning)
- HeaderInjector           (14 HTTP header tests)
- CSRFHandler              (auto-extract + refresh CSRF tokens)
- HPPTester                (HTTP parameter pollution)
- SecondOrderTracker       (stored/second-order XSS)
- ContentTypeAnalyzer      (skip irrelevant payloads)
- RateLimitHandler         (exponential backoff)
- WAFDetector + Evasion    (9 vendors, 10 techniques)
"""

import asyncio
import copy
from typing import List, Optional, Dict, Set
from urllib.parse import urlparse

from utils.config import ScanConfig, ScanTarget, Finding, Context, SCAN_PROFILES
from utils.http_client import HttpClient
from utils.logger import debug, info, warn, success, finding as log_finding

from crawler.spider import Spider, ContextDetector
from payloads.generator import PayloadGenerator
from payloads.smart_generator import SmartGenerator, AdaptiveSequencer
from payloads.combinatorial_engine import CombinatorialEngine
from payloads.mxss_and_api import MXSSEngine, JSONAPIEngine, JSONAPITester
from detection.analyzer import DetectionEngine
from detection.fuzzy import FuzzyDetector, ResponseDiffer
from waf_bypass.detector import WAFDetector, EvasionEngine
from scanner.filter_probe import FilterProbe, SmartPayloadFilter
from scanner.header_injector import (
    HeaderInjector, CSRFHandler,
    ContentTypeAnalyzer, RateLimitHandler,
)
from scanner.real_world import HPPTester, SecondOrderTracker

# Payloads per profile from combinatorial engine
COMBO_TOP_N  = {"fast": 200, "normal": 500, "deep": 2000, "stealth": 300}
MXSS_TOP_N   = {"fast":  50, "normal": 150, "deep":  500, "stealth":  80}
JSON_TOP_N   = {"fast":  50, "normal": 150, "deep":  500, "stealth":  80}


class ScanEngineV2:
    """
    Unified scan engine with all modules integrated.
    Every feature flag from CLI is wired to actual execution.
    """

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.http     = HttpClient(config)
        self._profile = SCAN_PROFILES.get(config.profile, SCAN_PROFILES["normal"])
        self.findings: List[Finding] = []
        self._lock    = asyncio.Lock()

        # Stats
        self._stats = {
            "requests_sent": 0, "requests_saved": 0,
            "payloads_tested": 0, "urls_scanned": 0,
        }

        # Payload engines
        max_p = self._profile["payloads_per_ctx"]
        self.payload_gen  = PayloadGenerator(max_per_ctx=max_p, waf_bypass=config.waf_bypass)
        self.smart_gen    = SmartGenerator(max_payloads=max_p)
        self.combo_engine = CombinatorialEngine()
        self.mxss_engine  = MXSSEngine()
        self.json_engine  = JSONAPIEngine()

        # Detection engines
        self.detector  = DetectionEngine()
        self.fuzzy     = FuzzyDetector()
        self.differ    = ResponseDiffer()

        # WAF + evasion
        self.waf_detector = WAFDetector()
        self.evasion      = EvasionEngine()

        # Context + crawl
        self.ctx_detector = ContextDetector()
        self.filter_probe = FilterProbe(self.http)
        self.smart_filter = SmartPayloadFilter()
        self.sequencer    = AdaptiveSequencer()

        # Real-world modules
        self.header_injector  = HeaderInjector(self.http)
        self.csrf_handler     = CSRFHandler(self.http)
        self.content_analyzer = ContentTypeAnalyzer()
        self.rate_limiter     = RateLimitHandler()
        self.hpp_tester       = HPPTester(self.http)
        self.second_order     = SecondOrderTracker(self.http)
        self.json_tester      = JSONAPITester(self.http)

        # Caches
        self._waf_cache: Dict[str, Optional[str]] = {}
        self._filter_cache: Dict[str, object]      = {}  # url → CharacterMatrix
        self._tested_payloads: Set[str]             = set()  # global dedup

        total = self.combo_engine.total + self.mxss_engine.total + self.json_engine.total
        info(f"XScanner v5 ready — {total:,} total payload combinations")

    # ─── Public API ──────────────────────────────────────────────────────────

    async def run(self) -> List[Finding]:
        tasks = [self._scan_url(url) for url in self.config.targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Second-order XSS verification pass
        if self.second_order._records:
            so_findings = await self.second_order.verify_all()
            async with self._lock:
                self.findings.extend(so_findings)

        self._print_stats()
        return self.findings

    # ─── Per-URL ─────────────────────────────────────────────────────────────

    async def _scan_url(self, url: str):
        info(f"Scanning: {url}")
        self._stats["urls_scanned"] += 1

        # Crawl
        if self.config.crawl:
            targets = await Spider(self.config, self.http).crawl(url)
        else:
            targets = self._url_to_targets(url)

        if not targets:
            warn(f"No injection points found: {url}")
            return

        info(f"Found {len(targets)} injection points")

        # WAF probe (once per host, cached)
        host = urlparse(url).netloc
        if host not in self._waf_cache:
            base_resp = await self.http.get(url)
            self._waf_cache[host] = self.waf_detector.detect(base_resp)
            if self._waf_cache[host]:
                warn(f"WAF detected: {self._waf_cache[host]} on {host}")

        waf = self._waf_cache.get(host)

        # Header injection test (once per URL, not per param)
        if getattr(self.config, 'test_headers', False):
            base_resp = await self.http.get(url)
            baseline  = base_resp.text if base_resp else ""
            hdr_findings = await self.header_injector.test_url(url, baseline)
            async with self._lock:
                self.findings.extend(hdr_findings)
            if hdr_findings:
                info(f"Header injection: {len(hdr_findings)} findings at {url}")

        # Scan each param
        sem   = asyncio.Semaphore(self.config.threads)
        tasks = [self._scan_one_sem(t, sem, waf) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_one_sem(self, target, sem, waf):
        async with sem:
            await self._scan_one(target, waf)

    async def _scan_one(self, target: ScanTarget, waf: Optional[str] = None):
        """Full scan of one injection point with all modules active."""

        # ── Context detection ─────────────────────────────────────────────
        context = await self.ctx_detector.detect(target, self.http)
        target.context = context

        # ── Baseline response ─────────────────────────────────────────────
        baseline_resp = await self._send(target)
        if baseline_resp is None:
            return
        baseline_body = baseline_resp.text

        # ── Content-Type check — skip if irrelevant ───────────────────────
        ct_info = self.content_analyzer.analyze(baseline_resp)
        if not self.content_analyzer.should_test_html_payloads(baseline_resp):
            # JSON endpoint — use JSON engine only
            if getattr(self.config, 'test_json', False):
                json_findings = await self.json_tester.test_json_endpoint(
                    target.url, target.params,
                    method=target.method,
                    top_n=JSON_TOP_N.get(self.config.profile, 150),
                )
                async with self._lock:
                    self.findings.extend(json_findings)
            return

        # Override context from content-type if more specific
        if ct_info["is_json"] and context == Context.UNKNOWN:
            context = ct_info["context"]
            target.context = context

        # ── FilterProbe — URL-level cache ─────────────────────────────────
        url_cache_key = f"{target.url}|{target.method}"
        if url_cache_key in self._filter_cache:
            matrix = self._filter_cache[url_cache_key]
            debug(f"FilterProbe: cache hit for {target.url}")
        else:
            matrix = await self.filter_probe.analyze(target)
            self._filter_cache[url_cache_key] = matrix
            self._stats["requests_saved"] += max(0,
                len(self._filter_cache) - 1)

        # ── CSRF token refresh for POST ───────────────────────────────────
        if target.method == "POST":
            target = await self.csrf_handler.prepare_post(target)

        # ── HPP testing ───────────────────────────────────────────────────
        if getattr(self.config, 'test_hpp', False) and target.method == "GET":
            hpp_findings = await self.hpp_tester.test(target, baseline_body)
            async with self._lock:
                self.findings.extend(hpp_findings)

        # ── Build full payload list ───────────────────────────────────────
        top_n    = COMBO_TOP_N.get(self.config.profile, 500)
        mxss_n   = MXSS_TOP_N.get(self.config.profile, 150)
        json_n   = JSON_TOP_N.get(self.config.profile, 150)

        # 1. Combinatorial HTML/JS/Attr payloads
        combo_raw  = self.combo_engine.generate(
            context=context,
            matrix=matrix if matrix.exploitable else None,
            top_n=top_n,
        )
        combo_list = [(p, lbl) for p, _, lbl in combo_raw]

        # 2. mXSS payloads (always include — context-independent)
        mxss_raw  = self.mxss_engine.generate(top_n=mxss_n)
        mxss_list = [(p, lbl) for p, _, lbl in mxss_raw]

        # 3. Smart matrix-aware payloads
        smart_list = [(p, lbl) for p, lbl, _ in
                      self.smart_gen.generate(matrix, context)] \
                     if matrix.exploitable else []

        # 4. Standard static payloads (supplement)
        std_raw  = self.payload_gen.for_context(context)
        if matrix.exploitable:
            scored   = self.smart_filter.filter_payloads(std_raw, matrix)
            std_list = [(p, e) for p, e, _ in scored]
            self._stats["requests_saved"] += max(0, len(std_raw) - len(std_list))
        else:
            std_list = std_raw

        # 5. WAF evasion variants on top combos
        evasion_list = []
        if waf and self.config.waf_bypass:
            for p, enc in combo_list[:15]:
                evasion_list += [(ep, f"evasion:{t}")
                                 for ep, t in self.evasion.apply(p, waf)]

        # 6. Blind XSS
        blind_list = self.payload_gen.for_blind_xss(self.config.blind_callback) \
                     if self.config.blind_callback else []

        # 7. JSON API payloads (if enabled)
        json_list = []
        if getattr(self.config, 'test_json', False):
            json_raw  = self.json_engine.generate(top_n=json_n)
            json_list = [(p, lbl) for p, _, ct, lbl in json_raw]

        # ── Merge + global dedup + adaptive rerank ────────────────────────
        all_payloads = (combo_list + mxss_list + smart_list +
                        std_list + evasion_list + blind_list + json_list)

        # Global dedup: skip payload+param combos already tested across URL
        dedup_key = lambda p: f"{target.param_key}:{p}"
        all_payloads = [(p, e) for p, e in all_payloads
                        if dedup_key(p) not in self._tested_payloads]

        # Adaptive rerank
        ranked = self.sequencer.rerank([(p, e, 1.0) for p, e in all_payloads])
        all_payloads = [(p, e) for p, e, _ in ranked]

        info(f"Testing {len(all_payloads):,} payloads on '{target.param_key}' [{context}]")

        # ── Inject and analyze ────────────────────────────────────────────
        found = False
        for payload, encoding in all_payloads:
            # Mark as tested globally
            async with self._lock:
                self._tested_payloads.add(dedup_key(payload))

            # After first find, only continue with blind/evasion/mxss
            if found:
                if not any(x in encoding for x in ("blind", "evasion", "mxss")):
                    continue

            result = await self._test_payload(
                target, payload, encoding, context, waf, baseline_body
            )
            self._stats["payloads_tested"] += 1
            self._stats["requests_sent"]   += 1

            # Rate limit check
            resp_check = await self._send(target)
            await self.rate_limiter.handle(resp_check)

            self.sequencer.feedback(payload, encoding, result)

            if result and result.get("reflected"):
                found = True
                # Record for second-order verification if POST
                if target.method == "POST" and getattr(self.config, 'second_order', False):
                    canary = self.second_order.make_canary(target.param_key)
                    self.second_order.record(
                        target.url, target.param_key, payload, canary,
                        verify_urls=[target.url],
                    )

    # ─── Core injection test ─────────────────────────────────────────────────

    async def _test_payload(
        self, target, payload, encoding, context, waf, baseline_body
    ) -> Optional[dict]:
        injected = self._inject(target, payload)
        resp = await self._send(injected)
        if resp is None:
            return None

        # WAF block check
        if self.waf_detector.is_blocked(len(baseline_body), len(resp.text), resp.status):
            debug(f"Blocked [{resp.status}]: {payload[:40]}")
            return None

        # Multi-layer detection
        standard     = self.detector.analyze(payload, resp.text, context, waf is not None)
        fuzzy_result = self.fuzzy.analyze(payload, baseline_body, resp.text)
        diff         = self.differ.diff(baseline_body, resp.text)

        reflected = (standard is not None or
                     fuzzy_result["reflected"] or
                     diff["suspicious"])
        if not reflected:
            return None

        # Unified confidence
        scores = []
        if standard:
            scores.append({"High": 0.9, "Medium": 0.6, "Low": 0.3}.get(
                standard.get("confidence", "Low"), 0.3))
        if fuzzy_result["reflected"]:
            scores.append(fuzzy_result["confidence"])
        if diff["suspicious"]:
            scores.append(0.5)
        if diff.get("new_handlers"):
            scores.append(0.7)
        if diff.get("new_scripts"):
            scores.append(0.8)

        final_conf = max(scores) if scores else 0.0
        if final_conf < 0.3:
            return None

        severity = ("High"   if final_conf >= 0.8 else
                    "Medium" if final_conf >= 0.5 else "Low")

        # Evidence
        evidence = ""
        if standard:
            evidence = standard.get("evidence", "")[:300]
        elif fuzzy_result.get("new_tags"):
            evidence = f"new_tags={fuzzy_result['new_tags']}"
        elif diff.get("new_handlers"):
            evidence = f"new_handlers={diff['new_handlers'][:3]}"
        evidence = evidence or resp.text[100:300]

        xss_type = ("dom"      if (standard and standard.get("dom_vuln")
                                    and not standard.get("executable")) else
                    "stored"   if target.method == "POST" else
                    "reflected")

        f = Finding(
            url=target.url, param=target.param_key, payload=payload,
            context=context, xss_type=xss_type, evidence=evidence,
            waf_bypassed=waf is not None, severity=severity,
            confidence=severity, encoding_used=encoding,
        )

        async with self._lock:
            if not any(e.url == f.url and e.param == f.param
                       and e.context == f.context for e in self.findings):
                self.findings.append(f)
                log_finding(f.url, f.param, f.payload, f.xss_type, f.context)

        return {"reflected": True, "confidence": final_conf}

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _inject(self, target, payload):
        t = copy.deepcopy(target)
        if t.method == "GET":
            t.params[t.param_key] = payload
        else:
            t.data[t.param_key] = payload
        return t

    async def _send(self, target):
        if target.method == "GET":
            return await self.http.get(target.url, params=target.params)
        return await self.http.post(target.url, data=target.data)

    def _url_to_targets(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []
        base = {k: v[0] for k, v in params.items()}
        return [ScanTarget(url=url, method="GET", params=base.copy(),
                           param_key=k) for k in params]

    def _print_stats(self):
        sent  = self._stats["requests_sent"]
        saved = self._stats["requests_saved"]
        total = sent + saved
        pct   = (saved / total * 100) if total > 0 else 0
        info(f"Scan complete: {sent:,} requests | "
             f"{saved:,} eliminated ({pct:.0f}%) | "
             f"{self._stats['payloads_tested']:,} payloads tested | "
             f"{len(self.findings)} findings")

    async def close(self):
        await self.http.close()
