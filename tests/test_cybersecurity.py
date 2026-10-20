"""
Unit Tests for Harvard CS50 Cybersecurity Suite
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
"""

import os
import sys
import unittest
import base64

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.account_security import (
    PasswordSecurityEvaluator,
    CryptographicHasher,
    TOTPAuthenticator
)
from src.systems_security import (
    VirtualStackFrame,
    PermissionAuditor
)
from src.network_security import (
    IPv4Packet,
    TCPHandshakeSimulator,
    ARPCacheAndPoisonDetector
)
from src.web_security import (
    SQLInjectionDefense,
    XSSDefenseSanitizer,
    CSRFProtectionEngine
)
from src.forensics_ir import (
    FileIntegrityAuditor,
    IncidentLogAnalyzer
)


class TestCS50CybersecuritySuite(unittest.TestCase):

    def test_password_entropy_and_tier(self):
        weak_eval = PasswordSecurityEvaluator.evaluate_strength("123456")
        self.assertIn(weak_eval["tier"], ["VERY_WEAK", "WEAK"])
        self.assertFalse(weak_eval["passes_cs50_standard"])

        strong_pass = "Harvard#CS50!Secure2026$Key"
        strong_eval = PasswordSecurityEvaluator.evaluate_strength(strong_pass)
        self.assertIn(strong_eval["tier"], ["STRONG", "VERY_STRONG"])
        self.assertTrue(strong_eval["passes_cs50_standard"])
        self.assertGreater(strong_eval["pool_entropy_bits"], 60)

    def test_cryptographic_pbkdf2_hasher(self):
        password = "DavidMalanCorrectHorseBatteryStaple"
        salt_hex, key_hex = CryptographicHasher.hash_password(password, iterations=10_000)

        # Correct password verification
        self.assertTrue(CryptographicHasher.verify_password(password, salt_hex, key_hex, iterations=10_000))

        # Incorrect password verification
        self.assertFalse(CryptographicHasher.verify_password("WrongPassword123", salt_hex, key_hex, iterations=10_000))

    def test_totp_2fa_generation_and_verification(self):
        # 16-byte base32 secret
        raw_secret = b"1234567890123456"
        secret_b32 = base64.b32encode(raw_secret).decode("utf-8")

        totp = TOTPAuthenticator(secret_b32=secret_b32)
        test_time = 1700000000.0

        token = totp.generate_token(for_time=test_time)
        self.assertEqual(len(token), 6)
        self.assertTrue(token.isdigit())

        # Verify within same time step
        self.assertTrue(totp.verify_token(token, current_time=test_time))

        # Verify within allowed window (1 step offset)
        self.assertTrue(totp.verify_token(token, current_time=test_time + 25))

        # Rejection outside window
        self.assertFalse(totp.verify_token("000000", current_time=test_time))

    def test_stack_buffer_overflow_and_canary_protection(self):
        # Normal write within bounds (buffer size 16)
        stack = VirtualStackFrame(buffer_size=16, enable_canary=True)
        res = stack.write_buffer(b"Hello CS50!")
        self.assertEqual(res["status"], "EXECUTION_SUCCESSFUL_NORMAL_RETURN")
        self.assertFalse(res["stack_smashed"])

        # Overflow write triggering Stack Canary defense
        stack_overflow = VirtualStackFrame(buffer_size=16, enable_canary=True)
        # 16 bytes buffer + 4 bytes corrupted canary + 8 bytes return address
        overflow_payload = b"A" * 16 + b"BAD!" + b"\x44\x33\x22\x11\x00\x00\x00\x00"
        res_smash = stack_overflow.write_buffer(overflow_payload)
        self.assertEqual(res_smash["status"], "TERMINATED_STACK_SMASHING_DETECTED")
        self.assertTrue(res_smash["stack_smashed"])

    def test_unix_permission_auditor(self):
        # Standard safe file: 0o644 (rw-r--r--)
        safe_audit = PermissionAuditor.audit_mode(0o644)
        self.assertTrue(safe_audit["is_secure"])
        self.assertFalse(safe_audit["world_writable"])

        # Insecure world-writable SUID file: 0o4777 (rwsrwxrwx)
        danger_audit = PermissionAuditor.audit_mode(0o4777)
        self.assertFalse(danger_audit["is_secure"])
        self.assertTrue(danger_audit["is_suid"])
        self.assertTrue(danger_audit["world_writable"])
        self.assertGreaterEqual(danger_audit["risk_score"], 80)

    def test_network_ipv4_checksum(self):
        # Construct sample IPv4 header (without checksum, checksum set to 0)
        # Version 4, IHL 5, ToS 0, Total Length 20, ID 0x1c46, Flags/Frag 0x4000, TTL 64, Protocol 6 (TCP), Checksum 0, Src 192.168.1.1, Dst 192.168.1.2
        header = bytearray([
            0x45, 0x00, 0x00, 0x14,
            0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0xC0, 0xA8, 0x01, 0x02
        ])
        checksum = IPv4Packet.calculate_checksum(bytes(header))
        self.assertIsInstance(checksum, int)
        self.assertGreater(checksum, 0)
        self.assertLessEqual(checksum, 0xFFFF)

    def test_tcp_three_way_handshake(self):
        sim = TCPHandshakeSimulator(initial_client_isn=2000, initial_server_isn=8000)

        # 1. SYN
        syn = sim.step1_send_syn()
        self.assertEqual(syn["flags"], ["SYN"])
        self.assertEqual(syn["seq_num"], 2000)

        # 2. SYN-ACK
        syn_ack = sim.step2_server_response(syn)
        self.assertEqual(syn_ack["flags"], ["SYN", "ACK"])
        self.assertEqual(syn_ack["ack_num"], 2001)
        self.assertEqual(syn_ack["seq_num"], 8000)

        # 3. ACK
        ack = sim.step3_client_ack(syn_ack)
        self.assertEqual(ack["flags"], ["ACK"])
        self.assertEqual(ack["seq_num"], 2001)
        self.assertEqual(ack["ack_num"], 8001)
        self.assertTrue(ack["handshake_successful"])
        self.assertEqual(sim.client_state, "ESTABLISHED")
        self.assertEqual(sim.server_state, "ESTABLISHED")

    def test_arp_cache_poison_detector(self):
        detector = ARPCacheAndPoisonDetector()

        # Legitimate gateway ARP entry
        res1 = detector.process_arp_packet("192.168.1.1", "00:11:22:33:44:55")
        self.assertIsNone(res1["alert"])

        # Spoofed ARP reply claiming same IP from different MAC
        res2 = detector.process_arp_packet("192.168.1.1", "AA:BB:CC:DD:EE:FF")
        self.assertIsNotNone(res2["alert"])
        self.assertEqual(res2["alert"]["type"], "ARP_POISONING_ATTACK_DETECTED")
        self.assertEqual(res2["alert"]["target_ip"], "192.168.1.1")

    def test_sql_injection_defense(self):
        malicious = "admin' OR 1=1 --"
        analysis = SQLInjectionDefense.analyze_input(malicious)
        self.assertTrue(analysis["is_suspicious"])

        # Safe parameterized execution
        template, params = SQLInjectionDefense.safe_parameterized_query(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            ("admin", "secretPass")
        )
        self.assertEqual(template.count("?"), len(params))

    def test_xss_sanitizer(self):
        payload = "<script>alert('XSS')</script>"
        threat = XSSDefenseSanitizer.detect_xss(payload)
        self.assertTrue(threat["has_xss_threat"])

        sanitized = XSSDefenseSanitizer.sanitize_for_html(payload)
        self.assertNotIn("<script>", sanitized)
        self.assertIn("&lt;script&gt;", sanitized)

    def test_csrf_token_lifecycle(self):
        engine = CSRFProtectionEngine(secret_key="harvard_secret_key_2026")
        session_id = "user_session_abc123"

        token = engine.generate_token(session_id)
        self.assertTrue(engine.validate_token(session_id, token))

        # Invalid session mismatch
        self.assertFalse(engine.validate_token("different_session_xyz", token))

    def test_file_integrity_baseline_auditor(self):
        baseline = {
            "/etc/passwd": FileIntegrityAuditor.compute_file_hash(b"root:x:0:0:root:/root:/bin/bash\n"),
            "/etc/shadow": FileIntegrityAuditor.compute_file_hash(b"root:$6$salt$hash:19000:0:99999:7:::\n")
        }

        current_files = {
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",  # Intact
            "/etc/shadow": b"TAMPERED_SHADOW_FILE\n",            # Modified
            "/bin/backdoor": b"malicious payload\n"               # Added
        }

        res = FileIntegrityAuditor.audit_manifest(baseline, current_files)
        self.assertTrue(res["is_compromised"])
        self.assertEqual(res["intact_count"], 1)
        self.assertEqual(len(res["modified"]), 1)
        self.assertEqual(res["modified"][0]["file"], "/etc/shadow")
        self.assertIn("/bin/backdoor", res["added"])

    def test_incident_log_analyzer_brute_force(self):
        analyzer = IncidentLogAnalyzer(brute_force_threshold=4, window_seconds=60)
        logs = [
            {"timestamp": 1000.0, "user": "admin", "ip": "198.51.100.42", "status": "FAIL"},
            {"timestamp": 1010.0, "user": "admin", "ip": "198.51.100.42", "status": "FAIL"},
            {"timestamp": 1020.0, "user": "admin", "ip": "198.51.100.42", "status": "FAIL"},
            {"timestamp": 1030.0, "user": "admin", "ip": "198.51.100.42", "status": "FAIL"},
            {"timestamp": 1040.0, "user": "admin", "ip": "198.51.100.42", "status": "SUCCESS"}
        ]

        report = analyzer.analyze_auth_logs(logs)
        self.assertGreaterEqual(report["incident_count"], 2)
        self.assertIn("admin", report["compromised_accounts"])


if __name__ == "__main__":
    unittest.main()
