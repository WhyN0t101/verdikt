"""Built-in source registry. One line per source; keys come from Settings."""

from __future__ import annotations

from verdikt.config import Settings
from verdikt.sources.abuseipdb import AbuseIPDB
from verdikt.sources.base import BaseSource, Source
from verdikt.sources.crtsh import CrtSh
from verdikt.sources.feeds import LocalFeeds
from verdikt.sources.greynoise import GreyNoise
from verdikt.sources.hashlookup import Hashlookup
from verdikt.sources.hybrid import HybridAnalysis
from verdikt.sources.internetdb import InternetDB
from verdikt.sources.malwarebazaar import MalwareBazaar
from verdikt.sources.otx import OTX
from verdikt.sources.passivedns import PassiveDNS
from verdikt.sources.rdap import RDAP
from verdikt.sources.threatfox import ThreatFox
from verdikt.sources.urlhaus import URLhaus
from verdikt.sources.urlscan import Urlscan
from verdikt.sources.virustotal import VirusTotal

__all__ = ["BaseSource", "Source", "build_sources"]


def build_sources(settings: Settings) -> list[Source]:
    """All built-in sources, enabled or not (`Source.enabled` says whether a key is set)."""
    k = settings.key
    abusech = k("abusech_auth_key")
    sources: list[Source] = [
        VirusTotal(k("vt_api_key")),
        AbuseIPDB(k("abuseipdb_api_key")),
        Urlscan(k("urlscan_api_key")),
        ThreatFox(abusech),
        URLhaus(abusech),
        MalwareBazaar(abusech),
        OTX(k("otx_api_key")),
        GreyNoise(k("greynoise_api_key")),
        InternetDB(),
        HybridAnalysis(k("hybrid_api_key")),
        Hashlookup(),
        RDAP(),
        CrtSh(settings.crtsh),
        PassiveDNS(k("vt_api_key"), settings.vt_resolutions),
        LocalFeeds(settings.resolved_feeds_dir),
    ]
    return sources
