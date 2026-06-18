from __future__ import annotations

import json
from pathlib import Path


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return len(
        [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
    )


def build_dashboard(data_dir: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    metrics = {
        "malicious_domains": _count_lines(data_dir / "lists" / "malicious-domains.txt"),
        "phishing_domains": _count_lines(data_dir / "lists" / "phishing-domains.txt"),
        "malware_domains": _count_lines(data_dir / "lists" / "malware-domains.txt"),
        "c2_domains": _count_lines(data_dir / "lists" / "c2-domains.txt"),
        "fast_flux_domains": _count_lines(data_dir / "lists" / "fast-flux-domains.txt"),
        "open_resolvers": _count_lines(data_dir / "lists" / "open-resolvers.txt"),
    }
    dashboard_dir = data_dir / "dashboard"
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    (dashboard_dir / "summary.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8"
    )
    cards = "\n".join(
        (
            '<div class="card">'
            f'<div class="label">{key.replace("_", " ").title()}</div>'
            f'<div class="value">{value}</div>'
            "</div>"
        )
        for key, value in metrics.items()
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DNS Threat Intelligence Dataset</title>
  <style>
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      background: #f6f7f9;
      color: #18202a;
    }}
    header {{ padding: 24px 32px; background: #101820; color: #fff; }}
    main {{ padding: 24px 32px; max-width: 1180px; margin: 0 auto; }}
    h1 {{ margin: 0; font-size: 28px; }}
    .sub {{ margin-top: 6px; color: #c8d2dc; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .card {{
      background: #fff;
      border: 1px solid #d8dee6;
      border-radius: 8px;
      padding: 16px;
    }}
    .label {{ color: #5a6675; font-size: 13px; }}
    .value {{ font-size: 30px; font-weight: 700; margin-top: 6px; }}
    section {{ margin-top: 24px; }}
    code {{ background: #eef1f5; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <header>
    <h1>DNS Threat Intelligence Dataset</h1>
    <div class="sub">
      Legal OSINT indicators, enrichment context, scoring, and publication artifacts.
    </div>
  </header>
  <main>
    <div class="grid">
      {cards}
    </div>
    <section class="card">
      <h2>Safety Posture</h2>
      <p>
        Sample dashboard data is generated locally. Live feeds are optional and must
        respect source terms, rate limits, and legal OSINT boundaries.
      </p>
      <p>
        Weak signals such as CT, NRD, DGA suspicion, and public-code mentions require
        review unless corroborated.
      </p>
    </section>
  </main>
</body>
</html>
"""
    (output / "index.html").write_text(html, encoding="utf-8")
