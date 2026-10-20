"""
CS50 Cybersecurity - Week 5: Digital Forensics & Incident Response
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
Harvard University CS50 Cybersecurity
"""

import hashlib
import json
import time
from typing import Dict, List, Optional, Set, Tuple


class FileIntegrityAuditor:
    """
    Forensics baseline auditor: creates cryptographic hash manifests
    and detects file modifications, deletions, or unauthorized additions.
    """

    @staticmethod
    def compute_file_hash(data: bytes, algorithm: str = "sha256") -> str:
        """Compute cryptographic hash of arbitrary byte contents."""
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()

    @classmethod
    def audit_manifest(cls, baseline: Dict[str, str], current_files: Dict[str, bytes]) -> Dict[str, any]:
        """
        Compare current files against known good baseline.
        Returns modified, added, deleted, and intact files.
        """
        modified = []
        added = []
        deleted = []
        intact = []

        # Check existing baseline against current files
        for filename, expected_hash in baseline.items():
            if filename not in current_files:
                deleted.append(filename)
            else:
                current_hash = cls.compute_file_hash(current_files[filename])
                if current_hash == expected_hash:
                    intact.append(filename)
                else:
                    modified.append({
                        "file": filename,
                        "expected_hash": expected_hash,
                        "current_hash": current_hash
                    })

        # Check for unexpected additions
        for filename in current_files:
            if filename not in baseline:
                added.append(filename)

        is_compromised = len(modified) > 0 or len(added) > 0 or len(deleted) > 0
        return {
            "is_compromised": is_compromised,
            "intact_count": len(intact),
            "modified": modified,
            "added": added,
            "deleted": deleted
        }


class IncidentLogAnalyzer:
    """
    Parses authentication and audit log events to reconstruct attack timelines
    and detect brute-force, lateral movement, and privilege abuse.
    """

    def __init__(self, brute_force_threshold: int = 5, window_seconds: int = 60):
        self.brute_force_threshold = brute_force_threshold
        self.window_seconds = window_seconds

    def analyze_auth_logs(self, log_records: List[Dict[str, any]]) -> Dict[str, any]:
        """
        Analyze structured log events:
        [{"timestamp": float, "user": str, "ip": str, "status": "FAIL"|"SUCCESS"}]
        """
        # Sort logs chronologically
        sorted_logs = sorted(log_records, key=lambda x: x["timestamp"])

        failed_attempts_by_ip: Dict[str, List[float]] = {}
        compromised_accounts: Set[str] = set()
        detected_incidents = []

        for record in sorted_logs:
            ip = record.get("ip", "unknown")
            user = record.get("user", "unknown")
            status = record.get("status", "")
            ts = record.get("timestamp", 0)

            if status == "FAIL":
                failed_attempts_by_ip.setdefault(ip, []).append(ts)
                # Purge older timestamps outside window
                failed_attempts_by_ip[ip] = [t for t in failed_attempts_by_ip[ip] if ts - t <= self.window_seconds]

                if len(failed_attempts_by_ip[ip]) >= self.brute_force_threshold:
                    incident = {
                        "type": "BRUTE_FORCE_AUTHENTICATION_ATTACK",
                        "source_ip": ip,
                        "targeted_user": user,
                        "timestamp": ts,
                        "failed_count": len(failed_attempts_by_ip[ip])
                    }
                    if incident not in detected_incidents:
                        detected_incidents.append(incident)

            elif status == "SUCCESS":
                # Check if preceded by brute force from same IP
                recent_fails = failed_attempts_by_ip.get(ip, [])
                if len(recent_fails) >= self.brute_force_threshold:
                    compromised_accounts.add(user)
                    detected_incidents.append({
                        "type": "ACCOUNT_TAKEOVER_AFTER_BRUTE_FORCE",
                        "source_ip": ip,
                        "compromised_user": user,
                        "timestamp": ts
                    })

        return {
            "total_logs_analyzed": len(log_records),
            "incidents_detected": detected_incidents,
            "compromised_accounts": list(compromised_accounts),
            "incident_count": len(detected_incidents)
        }
