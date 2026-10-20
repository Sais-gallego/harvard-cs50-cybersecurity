"""
CS50 Cybersecurity - Week 0 & 1: Account Security & Authentication
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
Harvard University CS50 Cybersecurity
"""

import math
import os
import hashlib
import hmac
import time
import struct
import base64
from typing import Dict, Tuple, List, Optional


class PasswordSecurityEvaluator:
    """Evaluates password entropy, strength classification, and attack crack resistance."""

    @staticmethod
    def calculate_pool_entropy(password: str) -> float:
        """
        Calculate password entropy in bits based on character pool size.
        E = L * log2(R)
        """
        if not password:
            return 0.0

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digits:
            pool_size += 10
        if has_special:
            pool_size += 32

        if pool_size == 0:
            return 0.0

        return len(password) * math.log2(pool_size)

    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        """
        Calculate information theoretic Shannon entropy:
        H = - sum(p_i * log2(p_i)) * len(password)
        """
        if not password:
            return 0.0

        length = len(password)
        freq = {}
        for c in password:
            freq[c] = freq.get(c, 0) + 1

        entropy_per_char = -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())
        return entropy_per_char * length

    @classmethod
    def evaluate_strength(cls, password: str) -> Dict[str, any]:
        """Classify password into security tier with estimated crack times."""
        pool_entropy = cls.calculate_pool_entropy(password)
        shannon_entropy = cls.calculate_shannon_entropy(password)

        # Assumptions:
        # Offline fast hashing (e.g. GPU MD5/SHA256): 10^10 guesses/sec
        # Slow KDF (e.g. PBKDF2/bcrypt): 10^4 guesses/sec
        combinations = 2 ** pool_entropy
        seconds_fast = combinations / 1e10 if combinations > 0 else 0
        seconds_slow = combinations / 1e4 if combinations > 0 else 0

        if pool_entropy < 28:
            tier = "VERY_WEAK"
        elif pool_entropy < 36:
            tier = "WEAK"
        elif pool_entropy < 60:
            tier = "MODERATE"
        elif pool_entropy < 80:
            tier = "STRONG"
        else:
            tier = "VERY_STRONG"

        return {
            "password_length": len(password),
            "pool_entropy_bits": round(pool_entropy, 2),
            "shannon_entropy_bits": round(shannon_entropy, 2),
            "tier": tier,
            "seconds_to_crack_fast_gpu": seconds_fast,
            "seconds_to_crack_slow_kdf": seconds_slow,
            "passes_cs50_standard": pool_entropy >= 60
        }


class CryptographicHasher:
    """Implements salted key derivation and timing-attack resistant verification."""

    DEFAULT_ITERATIONS = 100_000

    @classmethod
    def hash_password(cls, password: str, salt: Optional[bytes] = None, iterations: int = DEFAULT_ITERATIONS) -> Tuple[str, str]:
        """
        Derive cryptographically secure hash using PBKDF2 with HMAC-SHA256.
        Returns: (hex_salt, hex_derived_key)
        """
        if salt is None:
            salt = os.urandom(16)

        derived_key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt,
            iterations=iterations,
            dklen=32
        )
        return salt.hex(), derived_key.hex()

    @classmethod
    def verify_password(cls, password: str, hex_salt: str, expected_hex_key: str, iterations: int = DEFAULT_ITERATIONS) -> bool:
        """Verify password using constant-time comparison (hmac.compare_digest) to prevent timing attacks."""
        salt = bytes.fromhex(hex_salt)
        _, candidate_key = cls.hash_password(password, salt=salt, iterations=iterations)
        return hmac.compare_digest(candidate_key, expected_hex_key)


class TOTPAuthenticator:
    """
    Implements RFC 6238 Time-Based One-Time Password (TOTP) algorithm
    used in Two-Factor Authentication (2FA) systems.
    """

    def __init__(self, secret_b32: str, step_seconds: int = 30, digits: int = 6):
        self.secret_b32 = secret_b32.strip().replace(" ", "").upper()
        self.step_seconds = step_seconds
        self.digits = digits
        self.secret_bytes = base64.b32decode(self.secret_b32, casefold=True)

    def generate_token(self, for_time: Optional[float] = None) -> str:
        """Generate current TOTP token for given timestamp."""
        if for_time is None:
            for_time = time.time()

        time_step = int(for_time // self.step_seconds)
        time_bytes = struct.pack(">Q", time_step)

        # HMAC-SHA1 as per RFC 6238 / RFC 4226
        h = hmac.new(self.secret_bytes, time_bytes, hashlib.sha1).digest()

        # Dynamic truncation
        offset = h[-1] & 0x0F
        binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        token_num = binary % (10 ** self.digits)

        return str(token_num).zfill(self.digits)

    def verify_token(self, token: str, current_time: Optional[float] = None, window: int = 1) -> bool:
        """
        Verify token with drift window allowance (window=1 allows previous, current, next step).
        Prevents timing side-channel via hmac.compare_digest.
        """
        if current_time is None:
            current_time = time.time()

        token_str = token.strip()
        for offset in range(-window, window + 1):
            check_time = current_time + (offset * self.step_seconds)
            candidate = self.generate_token(for_time=check_time)
            if hmac.compare_digest(candidate, token_str):
                return True
        return False
