from __future__ import annotations

from dnsintel.sources.abusech_feodotracker import FeodoTrackerAdapter
from dnsintel.sources.abusech_malwarebazaar import MalwareBazaarAdapter
from dnsintel.sources.abusech_threatfox import ThreatFoxAdapter
from dnsintel.sources.abusech_urlhaus import URLhausAdapter
from dnsintel.sources.cert_pl import CertPLAdapter
from dnsintel.sources.misp import MISPAdapter
from dnsintel.sources.openphish import OpenPhishAdapter
from dnsintel.sources.otx import OTXAdapter
from dnsintel.sources.phishtank import PhishTankAdapter


def build_adapters() -> list[object]:
    return [
        URLhausAdapter(),
        ThreatFoxAdapter(),
        MalwareBazaarAdapter(),
        FeodoTrackerAdapter(),
        PhishTankAdapter(),
        OpenPhishAdapter(),
        OTXAdapter(),
        MISPAdapter(),
        CertPLAdapter(),
    ]
