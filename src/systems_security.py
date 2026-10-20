"""
CS50 Cybersecurity - Week 2: Systems Security & Memory Protection
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
Harvard University CS50 Cybersecurity
"""

import os
from typing import Dict, List, Optional, Tuple


class VirtualStackFrame:
    """
    Simulates x86/x86-64 stack frame layout to demonstrate:
    1. Buffer overflows and return address hijacking.
    2. Stack Canaries (defense against overflow).
    3. NX / DEP (Data Execution Prevention).
    """

    def __init__(self, buffer_size: int = 16, enable_canary: bool = True, enable_nx: bool = True):
        self.buffer_size = buffer_size
        self.enable_canary = enable_canary
        self.enable_nx = enable_nx

        # Stack canary value (random magic canary)
        self.canary_value = 0xDEADBEEF if enable_canary else None

        # Return address (default normal execution pointer)
        self.saved_rip = 0x00401122  # normal return
        self.buffer = bytearray(buffer_size)
        self.corrupted_canary = False
        self.hijacked_rip = None
        self.stack_smashed = False
        self.nx_violation = False

    def write_buffer(self, payload: bytes) -> Dict[str, any]:
        """
        Simulate vulnerable function write (e.g. strcpy/gets) into stack buffer.
        """
        bytes_to_write = len(payload)
        self.buffer = bytearray(payload[:self.buffer_size])

        # Check if payload overflows buffer
        if bytes_to_write > self.buffer_size:
            overflow = payload[self.buffer_size:]

            # If canary is enabled, it sits immediately after buffer
            if self.enable_canary:
                if len(overflow) >= 4:
                    canary_in_payload = int.from_bytes(overflow[:4], byteorder="little")
                    if canary_in_payload != self.canary_value:
                        self.corrupted_canary = True
                        self.stack_smashed = True
                    overflow = overflow[4:]
                else:
                    self.corrupted_canary = True
                    self.stack_smashed = True
                    overflow = b""

            # Next 8 bytes represent saved RIP / return address
            if len(overflow) >= 8:
                overwritten_rip = int.from_bytes(overflow[:8], byteorder="little")
                self.hijacked_rip = overwritten_rip
            elif len(overflow) > 0:
                overwritten_rip = int.from_bytes(overflow.ljust(8, b"\x00"), byteorder="little")
                self.hijacked_rip = overwritten_rip

        # Return simulation summary
        if self.stack_smashed:
            status = "TERMINATED_STACK_SMASHING_DETECTED"
        elif self.hijacked_rip is not None:
            if self.enable_nx and self.hijacked_rip < 0x00400000:
                self.nx_violation = True
                status = "TERMINATED_NX_DEP_VIOLATION"
            else:
                status = "CONTROL_FLOW_HIJACKED"
        else:
            status = "EXECUTION_SUCCESSFUL_NORMAL_RETURN"

        return {
            "status": status,
            "buffer_size": self.buffer_size,
            "payload_length": bytes_to_write,
            "canary_corrupted": self.corrupted_canary,
            "stack_smashed": self.stack_smashed,
            "hijacked_rip": hex(self.hijacked_rip) if self.hijacked_rip else None,
            "nx_violation": self.nx_violation
        }


class PermissionAuditor:
    """
    Audits Unix / POSIX file permission bitmasks to identify
    privilege escalation, insecure SUID/SGID, and world-writable vulnerabilities.
    """

    SUID_BIT = 0o4000
    SGID_BIT = 0o2000
    STICKY_BIT = 0o1000

    @classmethod
    def audit_mode(cls, mode_octal: int) -> Dict[str, any]:
        """Audit file mode bitmask (e.g. 0o4755, 0o777)."""
        is_suid = bool(mode_octal & cls.SUID_BIT)
        is_sgid = bool(mode_octal & cls.SGID_BIT)
        is_sticky = bool(mode_octal & cls.STICKY_BIT)

        user_perms = (mode_octal >> 6) & 0o7
        group_perms = (mode_octal >> 3) & 0o7
        other_perms = mode_octal & 0o7

        world_writable = bool(other_perms & 0o2)
        world_readable = bool(other_perms & 0o4)
        world_executable = bool(other_perms & 0o1)

        vulnerabilities = []
        if world_writable:
            vulnerabilities.append("CRITICAL: World-writable permission allows arbitrary modification.")
        if is_suid and world_writable:
            vulnerabilities.append("CRITICAL: SUID bit enabled on writable file (immediate privilege escalation risk).")
        elif is_suid:
            vulnerabilities.append("WARNING: SUID bit set. Must strictly validate execution environment.")

        # Risk score calculation (0 to 100)
        risk_score = 0
        if world_writable:
            risk_score += 60
        if is_suid:
            risk_score += 30
        if is_sgid:
            risk_score += 10

        return {
            "mode_octal": oct(mode_octal),
            "is_suid": is_suid,
            "is_sgid": is_sgid,
            "is_sticky": is_sticky,
            "user_perms": oct(user_perms),
            "group_perms": oct(group_perms),
            "other_perms": oct(other_perms),
            "world_writable": world_writable,
            "vulnerabilities": vulnerabilities,
            "risk_score": min(risk_score, 100),
            "is_secure": len(vulnerabilities) == 0
        }
