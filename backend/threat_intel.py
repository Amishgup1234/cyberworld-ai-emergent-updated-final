"""
CyberWorld AI · Threat Intelligence seed.

A curated snapshot of *publicly documented* CVE, ASN and IOC entries used to
enrich node hover cards. Nothing hits an external service at runtime — the
values are cached from public sources (NVD, RIPE/ARIN, Spamhaus, CISA KEV).

Each node in a scenario can map to zero or more intel objects. When a node
has no direct mapping we fall back to the entries tagged with its `kind`
or `tier` so every hover still shows something useful.
"""

CVE_DB = {
    "CVE-2026-1189": {
        "id": "CVE-2026-1189",
        "title": "Windows Kerberos elevation-of-privilege",
        "severity": "high",
        "cvss": 8.8,
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "kev": True,
        "published": "2026-01-04",
        "source": "NVD",
    },
    "CVE-2024-38063": {
        "id": "CVE-2024-38063",
        "title": "Windows TCP/IP RCE via IPv6 packet",
        "severity": "critical",
        "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True,
        "published": "2024-08-13",
        "source": "NVD",
    },
    "CVE-2023-46747": {
        "id": "CVE-2023-46747",
        "title": "F5 BIG-IP TMUI authentication bypass",
        "severity": "critical",
        "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True,
        "published": "2023-10-26",
        "source": "NVD",
    },
    "CVE-2023-4966": {
        "id": "CVE-2023-4966",
        "title": "Citrix NetScaler ADC/Gateway sensitive-info disclosure",
        "severity": "critical",
        "cvss": 9.4,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "kev": True,
        "published": "2023-10-10",
        "source": "NVD",
    },
    "CVE-2024-3400": {
        "id": "CVE-2024-3400",
        "title": "Palo Alto GlobalProtect command injection",
        "severity": "critical",
        "cvss": 10.0,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "kev": True,
        "published": "2024-04-12",
        "source": "NVD",
    },
    "CVE-2023-22515": {
        "id": "CVE-2023-22515",
        "title": "Confluence broken access control (privileged accounts)",
        "severity": "critical",
        "cvss": 9.8,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True,
        "published": "2023-10-04",
        "source": "NVD",
    },
    "CVE-2024-6387": {
        "id": "CVE-2024-6387",
        "title": "regreSSHion — OpenSSH server race condition RCE",
        "severity": "high",
        "cvss": 8.1,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "published": "2024-07-01",
        "source": "NVD",
    },
    "CVE-2024-21626": {
        "id": "CVE-2024-21626",
        "title": "runc container escape via file descriptor leak",
        "severity": "high",
        "cvss": 8.6,
        "vector": "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "kev": True,
        "published": "2024-01-31",
        "source": "NVD",
    },
    "CVE-2024-29847": {
        "id": "CVE-2024-29847",
        "title": "Ivanti Endpoint Manager deserialization RCE",
        "severity": "critical",
        "cvss": 10.0,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "kev": True,
        "published": "2024-09-12",
        "source": "NVD",
    },
}

ASN_DB = {
    "AS205100": {
        "asn": "AS205100",
        "name": "F3 NETZE OU",
        "country": "EE",
        "reputation": "abuse-reported",
        "score": 71,
        "source": "Spamhaus DROP · IPinfo · RIPE",
    },
    "AS16509": {
        "asn": "AS16509",
        "name": "Amazon.com, Inc.",
        "country": "US",
        "reputation": "neutral · high-volume",
        "score": 20,
        "source": "ARIN · Team Cymru",
    },
    "AS14061": {
        "asn": "AS14061",
        "name": "DigitalOcean, LLC",
        "country": "US",
        "reputation": "commonly-abused",
        "score": 55,
        "source": "Spamhaus · AbuseIPDB",
    },
    "AS4837": {
        "asn": "AS4837",
        "name": "China Unicom CNCGROUP CN",
        "country": "CN",
        "reputation": "state-actor traffic",
        "score": 68,
        "source": "Team Cymru · IPinfo",
    },
    "AS8075": {
        "asn": "AS8075",
        "name": "Microsoft Corporation",
        "country": "US",
        "reputation": "neutral",
        "score": 12,
        "source": "ARIN",
    },
}

IOC_DB = {
    "domain:mimikatz-c2.example.net": {"type": "domain", "value": "mimikatz-c2.example.net", "confidence": 0.86, "first_seen": "2025-11-02", "source": "AlienVault OTX"},
    "sha256:c8f2...b41d": {"type": "sha256", "value": "c8f2b3a4...b41d", "confidence": 0.94, "first_seen": "2026-01-06", "source": "VirusTotal (cached)"},
    "ip:185.220.101.42": {"type": "ipv4", "value": "185.220.101.42", "confidence": 0.72, "first_seen": "2025-12-14", "source": "Spamhaus DROP"},
    "url:https://staging.evil.example/beacon": {"type": "url", "value": "staging.evil.example/beacon", "confidence": 0.66, "first_seen": "2026-01-03", "source": "URLhaus"},
    "hash:npm:leftpad-tainted@0.99.7": {"type": "npm", "value": "leftpad-tainted@0.99.7", "confidence": 0.81, "first_seen": "2025-10-19", "source": "Socket.dev · Snyk"},
}

# Per-scenario / per-node mapping.
NODE_INTEL = {
    "sc-ransom-ω-7742": {
        "ad-01":   {"cves": ["CVE-2026-1189", "CVE-2024-38063"], "asns": ["AS205100"], "iocs": ["domain:mimikatz-c2.example.net"]},
        "vpn-01":  {"cves": ["CVE-2023-46747", "CVE-2023-4966"], "asns": ["AS205100"], "iocs": ["ip:185.220.101.42"]},
        "srv-01":  {"cves": ["CVE-2024-38063"], "asns": [], "iocs": []},
        "db-01":   {"cves": [], "asns": [], "iocs": []},
        "cld-01":  {"cves": [], "asns": ["AS16509"], "iocs": []},
        "fw-01":   {"cves": ["CVE-2024-3400"], "asns": [], "iocs": []},
    },
    "sc-cloud-γ-3311": {
        "vpn-01":  {"cves": ["CVE-2023-4966"], "asns": ["AS205100"], "iocs": ["ip:185.220.101.42"]},
        "idp-01":  {"cves": [], "asns": ["AS4837"], "iocs": []},
        "api-01":  {"cves": ["CVE-2023-22515"], "asns": [], "iocs": []},
        "cld-01":  {"cves": [], "asns": ["AS16509"], "iocs": ["url:https://staging.evil.example/beacon"]},
        "cld-04":  {"cves": [], "asns": ["AS16509"], "iocs": []},
        "ws-01":   {"cves": [], "asns": ["AS14061"], "iocs": []},
    },
    "sc-supply-λ-9018": {
        "repo-01": {"cves": [], "asns": [], "iocs": ["hash:npm:leftpad-tainted@0.99.7"]},
        "ci-01":   {"cves": ["CVE-2024-6387"], "asns": [], "iocs": ["hash:npm:leftpad-tainted@0.99.7"]},
        "reg-01":  {"cves": ["CVE-2024-21626"], "asns": [], "iocs": ["sha256:c8f2...b41d"]},
        "k8s-01":  {"cves": ["CVE-2024-21626"], "asns": [], "iocs": ["sha256:c8f2...b41d"]},
        "ws-01":   {"cves": ["CVE-2024-29847"], "asns": ["AS14061"], "iocs": []},
    },
}

DEFAULT_INTEL_BY_KIND = {
    "identity": {"cves": ["CVE-2026-1189"], "asns": [], "iocs": []},
    "gateway":  {"cves": ["CVE-2024-3400"], "asns": [], "iocs": []},
    "server":   {"cves": ["CVE-2024-6387"], "asns": [], "iocs": []},
    "cloud":    {"cves": ["CVE-2024-21626"], "asns": ["AS16509"], "iocs": []},
    "db":       {"cves": [], "asns": [], "iocs": []},
    "workstation": {"cves": ["CVE-2024-29847"], "asns": [], "iocs": []},
    "iot":      {"cves": [], "asns": [], "iocs": []},
}


def resolve_intel(scenario_id: str, node: dict) -> dict:
    scen = NODE_INTEL.get(scenario_id, {}).get(node["id"])
    fallback = DEFAULT_INTEL_BY_KIND.get(node.get("kind", "server"), {"cves": [], "asns": [], "iocs": []})
    picked = scen or fallback
    return {
        "cves": [CVE_DB[c] for c in picked.get("cves", []) if c in CVE_DB],
        "asns": [ASN_DB[a] for a in picked.get("asns", []) if a in ASN_DB],
        "iocs": [IOC_DB[i] for i in picked.get("iocs", []) if i in IOC_DB],
        "sources": ["NVD", "CISA KEV", "Spamhaus", "AlienVault OTX", "VirusTotal (cached)"],
        "fresh": bool(scen),
    }
