"""
==============================================================================
 GPT-Powered Threat Analyzer — Packet Sniffer Module
==============================================================================
 University Capstone Project — Tier S
 
 Module 1: Network Packet Capture using Scapy's AsyncSniffer.
 
 Architecture:
   - Producer-Consumer pattern for thread-safe packet processing
   - AsyncSniffer runs in a background thread (producer)
   - Minimal processing in callback — only feature extraction + queue push
   - store=False to prevent RAM exhaustion during long captures
 
 Extracted Features per Packet:
   - Source/Destination IP addresses
   - Source/Destination ports
   - Protocol (TCP/UDP/ICMP/Other)
   - TCP flags (if TCP)
   - Payload hex dump (first N bytes)
   - Packet size
   - Timestamp
==============================================================================
"""

import time
import queue
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable

from scapy.all import (
    AsyncSniffer, IP, TCP, UDP, ICMP, DNS,
    Raw, conf, get_if_list, Ether
)

from config import settings

logger = logging.getLogger("ids.sniffer")


# ── Data Model ───────────────────────────────────────────────────────────────

@dataclass
class PacketRecord:
    """
    Lightweight representation of a captured network packet.
    Contains only the features needed for triage and LLM analysis.
    
    Attributes:
        timestamp: Unix timestamp of capture
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port (None for ICMP/non-port protocols)
        dst_port: Destination port (None for ICMP/non-port protocols)
        protocol: Protocol name (TCP/UDP/ICMP/Other)
        tcp_flags: TCP flag string (e.g., 'S', 'SA', 'FA') or None
        payload_hex: First N bytes of payload as hex string
        packet_size: Total packet size in bytes
        has_dns: Whether the packet contains a DNS layer
        dns_query: DNS query name if present
    """
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "Other"
    tcp_flags: Optional[str] = None
    payload_hex: Optional[str] = None
    packet_size: int = 0
    has_dns: bool = False
    dns_query: Optional[str] = None

    def to_summary(self) -> str:
        """
        Generate a human-readable one-line summary of the packet.
        Used for logging and quick inspection.
        """
        port_info = ""
        if self.src_port and self.dst_port:
            port_info = f":{self.src_port} → :{self.dst_port}"
        flags = f" [{self.tcp_flags}]" if self.tcp_flags else ""
        dns = f" DNS={self.dns_query}" if self.dns_query else ""
        return (
            f"{self.protocol}{flags} {self.src_ip}{port_info} → "
            f"{self.dst_ip} ({self.packet_size}B){dns}"
        )


# ── Packet Sniffer ───────────────────────────────────────────────────────────

class PacketSniffer:
    """
    Network packet capture engine using Scapy's AsyncSniffer.
    
    Implements the Producer side of the Producer-Consumer pattern:
    - Captures packets from the specified network interface
    - Extracts key features into PacketRecord objects
    - Pushes records into a thread-safe queue for the Triage engine
    
    Usage:
        packet_queue = queue.Queue(maxsize=10000)
        sniffer = PacketSniffer(packet_queue, interface="Wi-Fi")
        sniffer.start()
        # ... packets flow into packet_queue ...
        sniffer.stop()
    
    Thread Safety:
        - The callback function does minimal work (feature extraction only)
        - All heavy processing is deferred to the consumer thread
        - Counter updates use threading.Lock for accuracy
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        interface: str = None,
        bpf_filter: str = None
    ):
        """
        Initialize the packet sniffer.
        
        Args:
            packet_queue: Thread-safe queue to push PacketRecords into.
            interface: Network interface name (e.g., 'Wi-Fi', 'eth0').
            bpf_filter: Optional BPF filter for kernel-level filtering.
        """
        self.packet_queue = packet_queue
        self.interface = interface or settings.sniff_interface
        self.bpf_filter = bpf_filter or settings.sniff_bpf_filter or None
        
        # Internal state
        self._sniffer: Optional[AsyncSniffer] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # Counters (thread-safe via lock)
        self._packets_captured = 0
        self._packets_dropped = 0
        self._is_running = False
        
        logger.info(
            f"PacketSniffer initialized: interface={self.interface}, "
            f"filter={self.bpf_filter or 'none'}"
        )

    # ── Public Interface ─────────────────────────────────────────────────

    def start(self):
        """
        Start capturing packets in a background thread.
        Raises RuntimeError if already running.
        """
        if self._is_running:
            raise RuntimeError("Sniffer is already running")

        self._stop_event.clear()
        self._packets_captured = 0
        self._packets_dropped = 0

        # Configure AsyncSniffer
        sniffer_kwargs = {
            "prn": self._packet_callback,
            "store": False,                    # Don't store packets in memory
            "iface": self.interface,
        }
        if self.bpf_filter:
            sniffer_kwargs["filter"] = self.bpf_filter

        try:
            self._sniffer = AsyncSniffer(**sniffer_kwargs)
            self._sniffer.start()
            self._is_running = True
            logger.info(f"Sniffer started on interface: {self.interface}")
        except Exception as e:
            self._is_running = False
            logger.error(f"Failed to start sniffer: {e}")
            raise

    def stop(self):
        """
        Stop the packet capture gracefully.
        Waits for the sniffer thread to finish.
        """
        if not self._is_running:
            logger.warning("Sniffer is not running")
            return

        self._stop_event.set()
        
        try:
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer = None
        except Exception as e:
            logger.error(f"Error stopping sniffer: {e}")
        finally:
            self._is_running = False
            logger.info(
                f"Sniffer stopped. Captured: {self._packets_captured}, "
                f"Dropped: {self._packets_dropped}"
            )

    @property
    def is_running(self) -> bool:
        """Whether the sniffer is currently capturing packets."""
        return self._is_running

    @property
    def packets_captured(self) -> int:
        """Total number of packets successfully captured and enqueued."""
        return self._packets_captured

    @property
    def packets_dropped(self) -> int:
        """Number of packets dropped due to full queue."""
        return self._packets_dropped

    @property
    def status(self) -> dict:
        """Get current sniffer status as a dictionary."""
        return {
            "is_running": self._is_running,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "packets_captured": self._packets_captured,
            "packets_dropped": self._packets_dropped,
        }

    # ── Internal Callback ────────────────────────────────────────────────

    def _packet_callback(self, pkt):
        """
        Scapy callback invoked for each captured packet.
        
        IMPORTANT: Keep this function FAST and MINIMAL.
        - Only extract features and push to queue
        - No blocking operations, no LLM calls, no DB writes
        - Exceptions are caught to prevent sniffer thread crash
        """
        if self._stop_event.is_set():
            return

        try:
            # Only process IP packets
            if IP not in pkt:
                return

            record = self._extract_features(pkt)
            
            # Non-blocking put — drop packet if queue is full
            try:
                self.packet_queue.put_nowait(record)
                with self._lock:
                    self._packets_captured += 1
            except queue.Full:
                with self._lock:
                    self._packets_dropped += 1

        except Exception as e:
            # Never let an exception crash the sniffer thread
            logger.debug(f"Error processing packet: {e}")

    def _extract_features(self, pkt) -> PacketRecord:
        """
        Extract key network features from a Scapy packet object.
        
        Handles TCP, UDP, ICMP, and DNS layers with graceful fallbacks
        for missing layers.
        
        Args:
            pkt: Scapy packet object (must contain IP layer).
            
        Returns:
            PacketRecord with extracted features.
        """
        ip_layer = pkt[IP]
        record = PacketRecord(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            packet_size=len(pkt),
        )

        # ── Protocol-specific extraction ─────────────────────────────
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            record.protocol = "TCP"
            record.src_port = tcp_layer.sport
            record.dst_port = tcp_layer.dport
            record.tcp_flags = str(tcp_layer.flags)

        elif UDP in pkt:
            udp_layer = pkt[UDP]
            record.protocol = "UDP"
            record.src_port = udp_layer.sport
            record.dst_port = udp_layer.dport

        elif ICMP in pkt:
            record.protocol = "ICMP"

        else:
            record.protocol = "Other"

        # ── DNS extraction ───────────────────────────────────────────
        if DNS in pkt:
            record.has_dns = True
            try:
                dns_layer = pkt[DNS]
                if dns_layer.qd:
                    record.dns_query = dns_layer.qd.qname.decode(
                        'utf-8', errors='replace'
                    )
            except Exception:
                pass

        # ── Payload hex dump ─────────────────────────────────────────
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            max_bytes = settings.payload_hex_max_bytes
            record.payload_hex = payload[:max_bytes].hex()

        return record

    # ── Utility ──────────────────────────────────────────────────────────

    @staticmethod
    def list_interfaces() -> list:
        """
        List all available network interfaces on the system.
        Useful for the dashboard interface selector.
        
        Returns:
            List of interface name strings.
        """
        try:
            ifaces = get_if_list()
            return ifaces
        except Exception as e:
            logger.error(f"Failed to list interfaces: {e}")
            return []
