from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from dnsintel import __version__
from dnsintel.config import validate_config_dir
from dnsintel.pipeline import generate_dataset, generate_sample_dataset

app = typer.Typer(help="DNS threat intelligence dataset CLI.")
config_app = typer.Typer(help="Configuration commands.")
dashboard_app = typer.Typer(help="Static dashboard commands.")
app.add_typer(config_app, name="config")
app.add_typer(dashboard_app, name="dashboard")
console = Console()


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", help="Show version.")] = False) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit


@config_app.command("validate")
def validate(config_dir: Path = Path("configs")) -> None:
    paths = validate_config_dir(config_dir)
    console.print(f"validated {len(paths)} config files")


@app.command("sample-data")
def sample_data(output: Path = Path("data")) -> None:
    counts = generate_sample_dataset(output)
    console.print(counts)


@app.command("update")
def update(
    output: Path = Path("data"),
    live: bool = typer.Option(False, "--live", help="Collect from live public feeds."),
    limit_per_source: int | None = typer.Option(None, help="Maximum records per source."),
) -> None:
    counts = generate_dataset(output, live=live, limit_per_source=limit_per_source)
    console.print(counts)


@dashboard_app.command("build")
def dashboard_build(data_dir: Path = Path("data"), output: Path = Path("docs/dashboard")) -> None:
    from dnsintel.dashboard.static import build_dashboard

    build_dashboard(data_dir, output)
    console.print(f"dashboard written to {output}")


if __name__ == "__main__":
    app()
