"""
CS50 Cybersecurity - Week 3: Network Security & Traffic Analysis
Author: Sergio Andrés Ipuz Saavedra (@Sais-gallego)
Harvard University CS50 Cybersecurity
"""

import struct
from typing import Dict, List, Optional, Tuple, Set


class IPv4Packet:
    """Simulates raw IPv4 packet header parser and checksum calculator (RFC 791)."""

    def __init__(self, src_ip: str, dst_ip: str, protocol: int = 6, ttl: int = 64, payload: bytes = b""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol  # 6=TCP, 17=UDP, 1=ICMP
        self.ttl = ttl
        self.payload = payload

    @staticmethod
    def calculate_checksum(header_bytes: bytes) -> int:
        """Calculate standard 16-bit one's complement Internet checksum."""
        if len(header_bytes) % 2 == 1:
            header_bytes += b"\x00"

        total = 0
        for i in range(0, len(header_bytes), 2):
            word = (header_bytes[i] << 8) + header_bytes[i + 1]
            total += word

        while (total >> 16) > 0:
            total = (total & 0xFFFF) + (total >> 16)

        return (~total) & 0xFFFF

    @staticmethod
    def ip_to_int(ip_str: str) -> int:
        parts = [int(p) for p in ip_str.split(".")]
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


class TCPHandshakeSimulator:
    """
    Simulates TCP 3-Way Handshake (SYN, SYN-ACK, ACK) and connection state machine (RFC 793).
    """

    STATES = ["CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT"]

    def __init__(self, initial_client_isn: int = 1000, initial_server_isn: int = 5000):
        self.client_isn = initial_client_isn
        self.server_isn = initial_server_isn
        self.client_state = "CLOSED"
        self.server_state = "LISTEN"
        self.client_seq = 0
        self.server_seq = 0

    def step1_send_syn(self) -> Dict[str, any]:
        """Client initiates connection with SYN packet."""
        self.client_state = "SYN_SENT"
        self.client_seq = self.client_isn
        return {
            "flags": ["SYN"],
            "seq_num": self.client_seq,
            "ack_num": 0,
            "client_state": self.client_state
        }

    def step2_server_response(self, syn_packet: Dict[str, any]) -> Dict[str, any]:
        """Server receives SYN, transitions to SYN_RCVD, replies with SYN-ACK."""
        if "SYN" not in syn_packet["flags"] or self.server_state != "LISTEN":
            raise ValueError("Invalid handshake initiation packet")

        self.server_state = "SYN_RCVD"
        self.server_seq = self.server_isn
        ack_val = syn_packet["seq_num"] + 1

        return {
            "flags": ["SYN", "ACK"],
            "seq_num": self.server_seq,
            "ack_num": ack_val,
            "server_state": self.server_state
        }

    def step3_client_ack(self, syn_ack_packet: Dict[str, any]) -> Dict[str, any]:
        """Client receives SYN-ACK, acknowledges, transitions to ESTABLISHED."""
        if "SYN" not in syn_ack_packet["flags"] or "ACK" not in syn_ack_packet["flags"]:
            raise ValueError("Invalid SYN-ACK packet")

        if syn_ack_packet["ack_num"] != self.client_seq + 1:
            raise ValueError("Handshake sequence synchronization error")

        self.client_state = "ESTABLISHED"
        self.server_state = "ESTABLISHED"
        self.client_seq = syn_ack_packet["ack_num"]
        final_ack = syn_ack_packet["seq_num"] + 1

        return {
            "flags": ["ACK"],
            "seq_num": self.client_seq,
            "ack_num": final_ack,
            "client_state": self.client_state,
            "server_state": self.server_state,
            "handshake_successful": True
        }


class ARPCacheAndPoisonDetector:
    """
    Maintains an ARP table and detects ARP Spoofing / Poisoning attacks
    (e.g., when multiple distinct MAC addresses claim the same IP address or gateway).
    """

    def __init__(self):
        self.arp_table: Dict[str, str] = {}  # IP -> MAC
        self.alerts: List[Dict[str, str]] = []

    def process_arp_packet(self, sender_ip: str, sender_mac: str, is_gratuitous: bool = False) -> Dict[str, any]:
        """Process incoming ARP reply/announcement."""
        sender_mac = sender_mac.lower()
        alert = None

        if sender_ip in self.arp_table:
            known_mac = self.arp_table[sender_ip]
            if known_mac != sender_mac:
                alert = {
                    "type": "ARP_POISONING_ATTACK_DETECTED",
                    "target_ip": sender_ip,
                    "legitimate_mac": known_mac,
                    "attacker_mac": sender_mac,
                    "is_gratuitous": is_gratuitous
                }
                self.alerts.append(alert)
        else:
            self.arp_table[sender_ip] = sender_mac

        return {
            "ip": sender_ip,
            "mac": sender_mac,
            "alert": alert,
            "table_size": len(self.arp_table)
        }
