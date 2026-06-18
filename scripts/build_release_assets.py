from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _copy_if_exists(source: Path, target_dir: Path) -> None:
    if source.exists():
        shutil.copy2(source, target_dir / source.name)


def _zip_dir(source_dir: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source_dir.parent))


def main(data_dir: Path = Path("data"), output: Path = Path("dist/release")) -> None:
    from dnsintel.stats import collect_dataset_stats, render_stats_markdown, write_stats

    stats = write_stats(data_dir)
    output.mkdir(parents=True, exist_ok=True)
    for path in [
        data_dir / "lists" / "adguard-dns-filter.txt",
        data_dir / "lists" / "malicious-domains.txt",
        data_dir / "lists" / "phishing-domains.txt",
        data_dir / "lists" / "malware-domains.txt",
        data_dir / "lists" / "c2-domains.txt",
        data_dir / "lists" / "malicious-urls.txt",
        data_dir / "normalized" / "domains.jsonl",
        data_dir / "normalized" / "urls.jsonl",
        data_dir / "reports" / "update-summary.md",
        data_dir / "reports" / "dataset-stats.md",
        data_dir / "dashboard" / "dataset-stats.json",
    ]:
        _copy_if_exists(path, output)
    _zip_dir(data_dir / "lists", output / "dnsintel-lists.zip")
    _zip_dir(data_dir / "enriched", output / "dnsintel-enriched.zip")
    notes = [
        "# DNS Threat Intelligence Dataset Release",
        "",
        "This release contains generated DNS threat intelligence artifacts.",
        "",
        "## Statistics",
        "",
        render_stats_markdown(collect_dataset_stats(data_dir)),
        "## Included Assets",
        "",
        "- `adguard-dns-filter.txt` - AdGuard DNS filter rules.",
        "- `malicious-domains.txt` - plain malicious domain list.",
        "- `phishing-domains.txt` - plain phishing domain list.",
        "- `malware-domains.txt` - plain malware domain list.",
        "- `c2-domains.txt` - plain C2 domain list.",
        "- `malicious-urls.txt` - malicious URL list.",
        "- `domains.jsonl`, `urls.jsonl` - normalized records.",
        "- `dnsintel-lists.zip` - all list artifacts.",
        "- `dnsintel-enriched.zip` - enrichment artifacts.",
    ]
    (output / "RELEASE_NOTES.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
    (output / "dataset-stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"release assets written to {output}")


if __name__ == "__main__":
    typer.run(main)
