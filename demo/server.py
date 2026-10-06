"""
demo/server.py — local web demo for the Adaptive Agent Harness.

A thin presentation layer over the existing pipeline. It does not change any
harness, strategy, selector, or evaluation logic:

  GET  /                  → demo/index.html
  GET  /api/alerts        → alert list from data/sample_alerts.json
  POST /api/run           → {"alert_id": "ALT-001"}: runs the real StrategySelector
                            and BOTH real strategies on the alert, recording every
                            agent call, and scores them like run_benchmark.py
  GET  /api/benchmark     → policy / category comparison computed by evaluate.py's
                            helpers from experiments/results/benchmark_combined.jsonl

Uses config.LLM_BACKEND (default "mock": deterministic, no AWS credentials).
Standard library only — run from the repository root:

    python demo/server.py            # then open http://localhost:8000
    python demo/server.py --port 8080
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import config                                              # noqa: E402
import evaluate                                            # noqa: E402
from experiments.run_benchmark import _mitigation_correct  # noqa: E402
from harness.alert_loader import AlertLoader               # noqa: E402
from harness.llm_client import BaseLLMClient, LLMResponse, get_llm_client  # noqa: E402
from harness.metrics import MetricsCollector               # noqa: E402
from harness.selector import StrategySelector              # noqa: E402
from strategies.base import extract_json                   # noqa: E402
from strategies.hierarchical import HierarchicalStrategy   # noqa: E402
from strategies.panel import PanelStrategy                 # noqa: E402

ALERTS_FILE = os.path.join("data", "sample_alerts.json")
RESULTS_FILE = os.path.join("experiments", "results", "benchmark_combined.jsonl")
INDEX_FILE = os.path.join(ROOT, "demo", "index.html")
FEATURED = ["ALT-001", "ALT-005", "ALT-004", "ALT-014"]

PANEL, HIER = "panel_strategy", "hierarchical_strategy"
STRATEGIES = {PANEL: PanelStrategy, HIER: HierarchicalStrategy}
# Agents in the order each strategy invokes the LLM (see strategies/*.py).
AGENT_ORDER = {
    PANEL: ["threat", "forensics", "critic", "lead"],
    HIER: ["validator", "lead_plan", "network", "intel", "lead_final"],
}


class RecordingClient(BaseLLMClient):
    """Wraps the configured LLM client and records each call for display."""

    def __init__(self, inner: BaseLLMClient) -> None:
        self._inner = inner
        self.calls = []

    def invoke(self, system: str, user: str) -> LLMResponse:
        resp = self._inner.invoke(system, user)
        try:
            data: Optional[dict] = extract_json(resp.text)
        except ValueError:
            data = None
        self.calls.append({
            "text": resp.text,
            "data": data,
            "tokens": resp.input_tokens + resp.output_tokens,
        })
        return resp


def _alerts() -> dict:
    return {a.alert_id: a for a in AlertLoader.load_batch(ALERTS_FILE)}


def _alert_list() -> dict:
    items = [{
        "alert_id": a.alert_id,
        "title": a.title or a.description[:60],
        "category": a.category or a.type,
        "severity": a.severity,
        "description": a.description,
        "raw_evidence": a.raw_evidence,
    } for a in _alerts().values()]  # ground truth is only returned after a run
    return {"alerts": items, "featured": FEATURED, "backend": config.LLM_BACKEND}


def _investigate(alert, strategy_key: str) -> dict:
    client = RecordingClient(get_llm_client(alert_id=alert.alert_id, strategy=strategy_key))
    result = STRATEGIES[strategy_key](client).investigate(alert)
    gt = alert.ground_truth
    verdict_ok = mitigation_ok = score = None
    if gt:
        verdict_ok = result["verdict"] == gt["verdict"]
        mitigation_ok = _mitigation_correct(result["mitigation_action"], gt["expected_mitigation"])
        score = evaluate._score({"verdict_correct": verdict_ok, "mitigation_correct": mitigation_ok})
    tokens_in, tokens_out = result["total_input_tokens"], result["total_output_tokens"]
    return {
        "steps": [dict(call, agent=name) for name, call in zip(AGENT_ORDER[strategy_key], client.calls)],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "rationale": result["rationale"],
        "mitigation": result["mitigation_action"],
        "evidence_quality": result["evidence_quality"],
        "verdict_ok": verdict_ok,
        "mitigation_ok": mitigation_ok,
        "score": score,
        "tokens": tokens_in + tokens_out,
        "cost": MetricsCollector.compute_cost(tokens_in, tokens_out),
    }


def _selector_trace(alert) -> dict:
    """The selector's real decision, plus its rules annotated with this alert's values."""
    selector = StrategySelector()
    s = selector.compute_signals(alert)
    strategy, rule = selector.select(alert)
    rules = [
        ("rich_evidence", HIER,
         f"complexity ≥ {config.COMPLEXITY_THRESHOLD} and availability ≥ 0.75",
         f"{s.complexity} · {s.evidence_availability:.2f}"),
        ("ambiguous", PANEL, f"ambiguity ≥ {config.AMBIGUITY_THRESHOLD}", f"{s.ambiguity}"),
        ("critical_severity", HIER, "severity = critical", alert.severity),
        ("sparse_evidence", PANEL,
         f"availability < {config.EVIDENCE_AVAILABILITY_THRESHOLD}", f"{s.evidence_availability:.2f}"),
        ("default", PANEL, "otherwise", "—"),
    ]
    names = [r[0] for r in rules]
    matched = names.index(rule)
    return {
        "strategy": strategy,
        "rule": rule,
        "signals": {
            "complexity": {"value": s.complexity, "max": 5, "threshold": config.COMPLEXITY_THRESHOLD},
            "ambiguity": {"value": s.ambiguity, "max": 3, "threshold": config.AMBIGUITY_THRESHOLD},
            "evidence_availability": {"value": s.evidence_availability, "max": 1,
                                      "threshold": config.EVIDENCE_AVAILABILITY_THRESHOLD},
        },
        "rules": [{
            "name": n, "strategy": st, "condition": cond, "value": val,
            "status": "match" if i == matched else ("miss" if i < matched else "skipped"),
        } for i, (n, st, cond, val) in enumerate(rules)],
    }


def _run(alert_id: str) -> dict:
    alert = _alerts().get(alert_id)
    if alert is None:
        raise KeyError(alert_id)
    return {
        "alert": alert.to_dict(),
        "selector": _selector_trace(alert),  # never sees ground truth
        PANEL: _investigate(alert, PANEL),
        HIER: _investigate(alert, HIER),
        "backend": config.LLM_BACKEND,
    }


def _benchmark() -> dict:
    """Real benchmark numbers, computed with evaluate.py's own helpers."""
    records = evaluate._load_results(RESULTS_FILE)
    evaluate._enrich_from_alerts(records, ALERTS_FILE)
    pairs = evaluate._paired_alerts(records)

    def oracle(pair):
        if pair["best"] in (PANEL, HIER):
            return pair["best"]
        return min(pair["runs"], key=lambda s: pair["runs"][s].get("estimated_cost_usd", 0.0))

    def summarise(chosen):
        _, n_gt, correct, mit_ok = evaluate._accuracy_row(chosen)
        scores = [x for x in map(evaluate._score, chosen) if x is not None]
        return {
            "alerts": len(chosen),
            "accuracy": correct / n_gt if n_gt else None,
            "mitigation": mit_ok / n_gt if n_gt else None,
            "score": sum(scores) / len(scores) if scores else None,
        }

    policies = []
    for key, pick in (("always_panel", lambda p: PANEL), ("always_hierarchical", lambda p: HIER),
                      ("adaptive", lambda p: p["selector"]), ("oracle", oracle)):
        chosen = [p["runs"][pick(p)] for p in pairs if pick(p) in p["runs"]]
        policies.append(dict(summarise(chosen), policy=key))

    decisive = [p for p in pairs if p["best"] in (PANEL, HIER)]
    categories = []
    for cat in sorted({p["category"] for p in pairs}):
        grp = [p for p in pairs if p["category"] == cat]
        categories.append({
            "category": cat,
            "alerts": len(grp),
            "panel": summarise([p["runs"][PANEL] for p in grp])["score"],
            "hierarchical": summarise([p["runs"][HIER] for p in grp])["score"],
            "panel_wins": sum(p["best"] == PANEL for p in grp),
            "hier_wins": sum(p["best"] == HIER for p in grp),
            "ties": sum(p["best"] == "tie" for p in grp),
        })
    return {
        "source": RESULTS_FILE,
        "runs": len(records),
        "pairs": len(pairs),
        "policies": policies,
        "categories": categories,
        "agreement": {"agreed": sum(p["selector"] == p["best"] for p in decisive),
                      "decisive": len(decisive)},
        "per_alert": {p["alert_id"]: {"best": p["best"], "selector": p["selector"]} for p in pairs},
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json")

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(INDEX_FILE, "rb") as fh:
                self._send(200, fh.read(), "text/html; charset=utf-8")
        elif path == "/api/alerts":
            self._json(_alert_list())
        elif path == "/api/benchmark":
            if not os.path.exists(RESULTS_FILE):
                self._json({"error": f"{RESULTS_FILE} not found. Run: python experiments/run_benchmark.py "
                                     "--alert data/sample_alerts.json --compare-all"}, 404)
            else:
                self._json(_benchmark())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path != "/api/run":
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            alert_id = json.loads(self.rfile.read(length) or b"{}").get("alert_id", "")
            self._json(_run(alert_id))
        except KeyError:
            self._json({"error": "unknown alert_id"}, 404)
        except Exception as exc:  # surface backend errors (e.g. Bedrock credentials) in the UI
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def log_message(self, fmt, *args) -> None:
        pass


def main() -> None:
    p = argparse.ArgumentParser(description="Adaptive Agent Harness web demo")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Adaptive Agent Harness demo → http://localhost:{args.port}  (LLM backend: {config.LLM_BACKEND})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
