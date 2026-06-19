from __future__ import annotations

from dnsintel.sources.abusech_feodotracker import FeodoTrackerAdapter
from dnsintel.sources.abusech_threatfox import ThreatFoxAdapter
from dnsintel.sources.abusech_urlhaus import URLhausAdapter
from dnsintel.sources.openphish import OpenPhishAdapter
from dnsintel.sources.public_dns_info import PublicDNSInfoAdapter
from dnsintel.sources.trickest_resolvers import TrickestResolversAdapter


def build_adapters() -> list[object]:
    return [
        URLhausAdapter(),
        ThreatFoxAdapter(),
        FeodoTrackerAdapter(),
        OpenPhishAdapter(),
        PublicDNSInfoAdapter(),
        TrickestResolversAdapter(),
    ]
