from __future__ import annotations


def fetch_disabled_notice() -> str:
    return (
        "Live report fetching is disabled in sample mode; configure sources.yml "
        "to enable public RSS/sitemap fetching."
    )
