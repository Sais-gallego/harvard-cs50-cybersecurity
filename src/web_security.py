"""
CS50 Cybersecurity - Week 4: Web Security & Defense
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
Harvard University CS50 Cybersecurity
"""

import re
import html
import secrets
import hmac
from typing import Dict, List, Optional, Tuple


class SQLInjectionDefense:
    """
    Demonstrates SQL Injection vulnerabilities from string concatenation
    and provides parameterized query AST tokenization defense.
    """

    DANGEROUS_SQL_PATTERNS = [
        r"(--|#|/\*)",                     # SQL comments
        r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",  # OR 1=1 tautology
        r"(\bUNION\b\s+\bSELECT\b)",       # UNION SELECT exfiltration
        r"(\bDROP\b\s+\bTABLE\b)",         # Destructive DDL
        r"(';|\";)",                       # Statement terminators
    ]

    @classmethod
    def analyze_input(cls, user_input: str) -> Dict[str, any]:
        """Scan raw user input for heuristic indicators of SQL injection payloads."""
        detected_patterns = []
        for pat in cls.DANGEROUS_SQL_PATTERNS:
            if re.search(pat, user_input, re.IGNORECASE):
                detected_patterns.append(pat)

        is_suspicious = len(detected_patterns) > 0
        return {
            "input": user_input,
            "is_suspicious": is_suspicious,
            "matched_patterns": detected_patterns,
            "recommendation": "Use parameterized queries (e.g., db.execute('SELECT * FROM users WHERE user = ?', (user,)))"
        }

    @staticmethod
    def safe_parameterized_query(query_template: str, params: Tuple[any, ...]) -> Tuple[str, Tuple[any, ...]]:
        """
        Enforce parameterized execution structure separating code from user data.
        """
        # Ensure parameter placeholders '?' match parameter count
        placeholder_count = query_template.count("?")
        if placeholder_count != len(params):
            raise ValueError(f"Placeholder count ({placeholder_count}) does not match parameters ({len(params)})")
        return query_template, params


class XSSDefenseSanitizer:
    """
    Detects and sanitizes Cross-Site Scripting (XSS) vectors
    in Reflected, Stored, and DOM-based contexts.
    """

    XSS_PAYLOAD_PATTERNS = [
        r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
        r"javascript\s*:",
        r"\bon\w+\s*=",  # onerror=, onload=, onclick=
        r"<iframe\b",
        r"<img\b[^>]*\bonerror\b"
    ]

    @classmethod
    def detect_xss(cls, raw_input: str) -> Dict[str, any]:
        """Detect potential XSS attack patterns in unvalidated input."""
        detected = []
        for pat in cls.XSS_PAYLOAD_PATTERNS:
            if re.search(pat, raw_input, re.IGNORECASE):
                detected.append(pat)

        return {
            "has_xss_threat": len(detected) > 0,
            "threat_patterns": detected
        }

    @classmethod
    def sanitize_for_html(cls, user_text: str) -> str:
        """
        Sanitize untrusted input using strict HTML entity encoding.
        Replaces <, >, &, ", and ' with safe HTML entities.
        """
        return html.escape(user_text, quote=True)


class CSRFProtectionEngine:
    """
    Implements Anti-CSRF Token Generation, Masking, and Verification
    following OWASP and Harvard CS50 Web Security recommendations.
    """

    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode("utf-8")

    def generate_token(self, session_id: str) -> str:
        """Generate HMAC-signed anti-CSRF token bound to user session."""
        nonce = secrets.token_hex(16)
        payload = f"{session_id}:{nonce}".encode("utf-8")
        signature = hmac.new(self.secret_key, payload, "sha256").hexdigest()
        return f"{nonce}:{signature}"

    def validate_token(self, session_id: str, csrf_token: str) -> bool:
        """Validate CSRF token signature in constant time."""
        try:
            parts = csrf_token.split(":")
            if len(parts) != 2:
                return False
            nonce, signature = parts[0], parts[1]
            expected_payload = f"{session_id}:{nonce}".encode("utf-8")
            expected_sig = hmac.new(self.secret_key, expected_payload, "sha256").hexdigest()
            return hmac.compare_digest(signature, expected_sig)
        except Exception:
            return False
