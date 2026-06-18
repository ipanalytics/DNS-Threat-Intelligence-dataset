# Contributing

Contributions are welcome when they preserve the project's legal OSINT boundary.

Source adapters must:

- document source terms and licensing assumptions;
- be disabled by default when credentials or authorization are required;
- include fixture tests;
- enforce timeouts and rate limits for live access;
- avoid storing full copyrighted reports;
- avoid credential dumps, stolen logs, private repositories, and personal data.

Run before submitting:

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run python -m compileall dnsintel scripts
```

