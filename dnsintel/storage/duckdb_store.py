from __future__ import annotations

from pathlib import Path

import duckdb


def write_table(path: Path, table: str, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with duckdb.connect(str(path)) as conn:
        conn.sql(f"CREATE OR REPLACE TABLE {table} AS SELECT * FROM records")
