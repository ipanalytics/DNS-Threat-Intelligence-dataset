from __future__ import annotations

import sys
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(
    sample: bool = False,
    live: bool = True,
    output: Path = Path("data"),
    limit_per_source: int | None = None,
) -> None:
    from dnsintel.pipeline import generate_dataset

    if sample:
        live = False
    print(generate_dataset(output, live=live, limit_per_source=limit_per_source))


if __name__ == "__main__":
    typer.run(main)
