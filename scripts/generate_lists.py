from __future__ import annotations

import sys
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(input: Path = Path("data"), output: Path = Path("data")) -> None:
    from dnsintel.pipeline import generate_sample_dataset

    _ = input
    print(generate_sample_dataset(output))


if __name__ == "__main__":
    typer.run(main)
