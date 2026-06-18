from __future__ import annotations

import sys
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(data_dir: Path = Path("data"), readme: Path = Path("README.md")) -> None:
    from dnsintel.stats import update_readme_stats, write_stats

    stats = write_stats(data_dir)
    update_readme_stats(readme, stats)
    print(f"updated stats: {data_dir / 'dashboard' / 'dataset-stats.json'}")


if __name__ == "__main__":
    typer.run(main)
