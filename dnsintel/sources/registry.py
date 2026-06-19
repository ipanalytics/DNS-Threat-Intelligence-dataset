from __future__ import annotations

from dnsintel.sources.abusech_feodotracker import FeodoTrackerAdapter
from dnsintel.sources.abusech_threatfox import ThreatFoxAdapter
from dnsintel.sources.abusech_urlhaus import URLhausAdapter
from dnsintel.sources.openphish import OpenPhishAdapter


def build_adapters() -> list[object]:
    return [
        URLhausAdapter(),
        ThreatFoxAdapter(),
        FeodoTrackerAdapter(),
        OpenPhishAdapter(),
    ]
