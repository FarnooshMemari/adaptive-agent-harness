"""
demo/build_static.py — build the demo as static files for public hosting (GitHub Pages).

With the deterministic mock backend, every /api response is fixed, so this runs
the same server functions (real selector, both real strategies, evaluate.py
benchmark helpers) once per alert and writes the JSON responses next to the page:

    <out>/index.html               (demo-mode = static)
    <out>/api/alerts.json
    <out>/api/benchmark.json
    <out>/api/run/<alert_id>.json

Usage (from the repository root):
    LLM_BACKEND=mock python demo/build_static.py --out _site
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402  (sets cwd to the repository root)


def _write(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--out", default="_site", help="Output directory (default: _site).")
    args = p.parse_args()
    out = os.path.abspath(args.out)

    if server.config.LLM_BACKEND != "mock":
        print("Refusing to build: static output must come from LLM_BACKEND=mock.", file=sys.stderr)
        return 1

    alerts = server._alert_list()
    _write(os.path.join(out, "api", "alerts.json"), alerts)
    _write(os.path.join(out, "api", "benchmark.json"), server._benchmark())
    for a in alerts["alerts"]:
        _write(os.path.join(out, "api", "run", f"{a['alert_id']}.json"), server._run(a["alert_id"]))

    with open(server.INDEX_FILE, encoding="utf-8") as fh:
        page = fh.read()
    live = '<meta name="demo-mode" content="live">'
    assert live in page, "demo-mode meta tag missing from index.html"
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page.replace(live, '<meta name="demo-mode" content="static">'))

    print(f"Built static demo for {len(alerts['alerts'])} alerts → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
