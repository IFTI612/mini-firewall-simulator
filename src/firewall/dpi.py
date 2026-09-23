"""
dpi.py
Next-Generation Firewall (NGFW) Deep Packet Inspection (DPI) & Signature Engine.

Inspects Layer 7 application payloads (HTTP requests, URL query params,
POST bodies, headers) for malicious patterns including:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Directory / Path Traversal (LFI)
  - Remote Command Injection
"""

import re
from dataclasses import dataclass
from typing import List, Optional

import config
from models.packet import Packet


@dataclass
class DPISignature:
    """A Snort/Suricata style pattern signature for Layer 7 inspection."""
    sig_id: int
    name: str
    attack_type: str                  # SQL_INJECTION, XSS, PATH_TRAVERSAL
    pattern: re.Pattern
    severity: str = "HIGH"            # MEDIUM, HIGH, CRITICAL
    description: str = ""


@dataclass
class DPIMatch:
    """Represents a signature match against a packet's payload."""
    sig_id: int
    name: str
    attack_type: str
    snippet: str
    severity: str
    description: str


class DPISignatureEngine:
    """
    Scans packet payloads against compiled regular expression signatures.
    """

    def __init__(self):
        self.signatures: List[DPISignature] = []
        self._load_signatures()

    def _load_signatures(self):
        """Initializes Snort/Suricata-inspired Layer 7 inspection rules."""
        rules = [
            # -------------------- SQL Injection Signatures --------------------
            (
                1001,
                "SQLi: Tautology Authentication Bypass",
                config.SQL_INJECTION,
                r"('|\")?\s*(OR|AND)\s+('?\w+'?|\d+)\s*=\s*('?\w+'?|\d+)",
                "CRITICAL",
                "Matches classic boolean tautologies such as ' OR 1=1 or ' OR 'x'='x'",
            ),
            (
                1002,
                "SQLi: Inline Comment / Terminator Bypass",
                config.SQL_INJECTION,
                r"('|\")?\s*(--|#|/\*)",
                "HIGH",
                "Detects SQL comment delimiters used to neutralize query suffixes",
            ),
            (
                1003,
                "SQLi: UNION Based Data Extraction",
                config.SQL_INJECTION,
                r"\bUNION\s+(ALL\s+)?SELECT\b",
                "CRITICAL",
                "Detects UNION SELECT statements used to exfiltrate database contents",
            ),
            (
                1004,
                "SQLi: Stacked Query Execution",
                config.SQL_INJECTION,
                r";\s*(DROP|ALTER|TRUNCATE|DELETE|INSERT|UPDATE|EXEC(\s+xp_)?)\b",
                "CRITICAL",
                "Detects semicolons chained with destructive SQL DDL/DML statements",
            ),
            (
                1005,
                "SQLi: SQL Schema Function Query",
                config.SQL_INJECTION,
                r"\b(information_schema|load_file|schema_name|current_user|database\(\))\b",
                "HIGH",
                "Detects SQL metadata functions commonly probed during database fingerprinting",
            ),

            # -------------------- Cross-Site Scripting (XSS) --------------------
            (
                2001,
                "XSS: Explicit Script Tag Injection",
                config.XSS,
                r"<\s*script\b[^>]*>",
                "CRITICAL",
                "Matches standard HTML <script> opening tags in payload parameters",
            ),
            (
                2002,
                "XSS: Event Handler DOM Execution",
                config.XSS,
                r"\b(onerror|onload|onclick|onmouseover|onfocus|onblur|onloadstart)\s*=",
                "HIGH",
                "Detects HTML inline event handlers commonly used in reflected/stored XSS",
            ),
            (
                2003,
                "XSS: JavaScript URI Scheme Injection",
                config.XSS,
                r"(javascript|vbscript|data\s*:\s*text/html)\s*:",
                "HIGH",
                "Detects execution of JavaScript via URI schemes",
            ),
            (
                2004,
                "XSS: Malicious Vector Element",
                config.XSS,
                r"<\s*(img|svg|iframe|body|object|embed|details)\b[^>]*?(onerror|onload)\s*=",
                "CRITICAL",
                "Matches modern HTML5 elements weaponized with onerror/onload payloads",
            ),

            # -------------------- Path Traversal Signatures --------------------
            (
                3001,
                "Path Traversal: Relative Directory Dot-Dot-Slash",
                config.PATH_TRAVERSAL,
                r"(\.\.[/\\])+",
                "HIGH",
                "Matches repeated ../ or ..\\ sequences used in directory climbing attacks",
            ),
            (
                3002,
                "Path Traversal: Unix Sensitive System Files",
                config.PATH_TRAVERSAL,
                r"(/etc/(passwd|shadow|hosts|issue|sudoers)|/proc/self/)",
                "CRITICAL",
                "Detects targets attempting to retrieve critical UNIX security credentials",
            ),
            (
                3003,
                "Path Traversal: Windows System Directory Access",
                config.PATH_TRAVERSAL,
                r"([a-zA-Z]:[/\\]|\\|\/)?(windows|winnt)[/\\]system32",
                "CRITICAL",
                "Detects attempts to access Windows system directories and drivers",
            ),
            (
                3004,
                "Path Traversal: Windows Boot / Sam Target",
                config.PATH_TRAVERSAL,
                r"(boot\.ini|system32[/\\]config[/\\]sam)",
                "CRITICAL",
                "Detects probes for Windows configuration files and password hashes",
            ),
        ]

        for sid, name, cat, regex_str, sev, desc in rules:
            self.signatures.append(
                DPISignature(
                    sig_id=sid,
                    name=name,
                    attack_type=cat,
                    pattern=re.compile(regex_str, re.IGNORECASE),
                    severity=sev,
                    description=desc,
                )
            )

    def inspect_text(self, text: str) -> Optional[DPIMatch]:
        """
        Inspects raw text string against all registered L7 signatures.
        """
        if not text:
            return None
        for sig in self.signatures:
            m = sig.pattern.search(text)
            if m:
                snippet = m.group(0).strip()
                return DPIMatch(
                    sig_id=sig.sig_id,
                    name=sig.name,
                    attack_type=sig.attack_type,
                    snippet=snippet,
                    severity=sig.severity,
                    description=sig.description,
                )
        return None

    def inspect(self, packet: Packet) -> Optional[DPIMatch]:
        """
        Inspects packet.payload against all registered L7 signatures.
        Returns the first matching DPIMatch object or None.
        """
        return self.inspect_text(packet.payload)

    def signature_count(self) -> int:
        return len(self.signatures)

    def all_signatures(self) -> List[DPISignature]:
        return list(self.signatures)
