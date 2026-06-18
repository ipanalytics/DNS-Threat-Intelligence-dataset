from __future__ import annotations

from dnsintel.sources.base import SourceResult
from dnsintel.sources.fixtures import evidence


class SampleCorpusAdapter:
    """Deterministic fixture corpus used for reproducible releases and demos."""

    name = "sample_corpus"

    def collect(self) -> SourceResult:
        records = []
        for idx in range(1, 1201):
            records.append(
                evidence(
                    self.name,
                    "domain",
                    f"malware-{idx:04d}.fixture-threat.test",
                    ["malware"],
                    82,
                    tags=["sample-corpus", "malware"],
                    family=f"FixtureFamily{idx % 17:02d}",
                )
            )
        for idx in range(1, 401):
            records.append(
                evidence(
                    self.name,
                    "domain",
                    f"c2-{idx:04d}.fixture-command.test",
                    ["c2", "malware"],
                    91,
                    tags=["sample-corpus", "c2"],
                    family=f"FixtureBotnet{idx % 11:02d}",
                )
            )
        for idx in range(1, 701):
            records.append(
                evidence(
                    self.name,
                    "url",
                    f"https://login-{idx:04d}.fixture-phish.test/session",
                    ["phishing"],
                    84,
                    tags=["sample-corpus", "phishing"],
                    campaign=f"fixture-phishing-{idx % 23:02d}",
                )
            )
        for idx in range(1, 501):
            records.append(
                evidence(
                    self.name,
                    "url",
                    f"http://download-{idx:04d}.fixture-malware.test/payload.bin",
                    ["malware"],
                    86,
                    tags=["sample-corpus", "payload"],
                    family=f"FixtureLoader{idx % 13:02d}",
                )
            )
        return SourceResult(name=self.name, evidence=records)
