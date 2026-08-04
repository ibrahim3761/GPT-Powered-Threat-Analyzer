"""
==============================================================================
 GPT-Powered Threat Analyzer — Heuristic Triage Engine
==============================================================================
 
 Module 1b: Fast heuristic rule engine that pre-filters captured packets.
 
 Architecture:
   - Consumer side of the Producer-Consumer pattern
   - Pulls PacketRecords from the sniffer queue
   - Applies configurable heuristic rules with sliding window tracking
   - Suspicious packets are forwarded to the LLM analysis queue
   - Benign packets update internal statistics only
 
 Detection Rules:
   1. SYN Scan Detection — TCP SYN without ACK from same source
   2. Port Sweep — Same source hitting many destination ports
   3. ICMP Flood — High-rate ICMP from same source
   4. Large Payload — Unusually large payloads on non-standard ports
   5. Suspicious Ports — Destination port on known-bad list
   6. DNS Tunneling — Oversized DNS packets
   7. High Frequency — Excessive packet rate from same source
 
 Performance:
   - Sliding window with auto-expiring entries (deque + timestamps)
   - O(1) amortized per-packet processing
   - Minimal memory footprint with configurable window sizes
==============================================================================
"""

import time
import queue
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Callable

from modules.sniffer import PacketRecord
from config import settings

logger = logging.getLogger("ids.triage")


# ── Triage Flag Definitions ──────────────────────────────────────────────────

class TriageFlag:
    """Constants for triage classification flags."""
    PORT_SCAN = "PORT_SCAN"
    PORT_SWEEP = "PORT_SWEEP"
    SYN_FLOOD = "SYN_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    SUSPICIOUS_PAYLOAD = "SUSPICIOUS_PAYLOAD"
    SUSPICIOUS_PORT = "SUSPICIOUS_PORT"
    DNS_TUNNEL = "DNS_TUNNEL"
    HIGH_FREQUENCY = "HIGH_FREQUENCY"
    NULL_SCAN = "NULL_SCAN"
    XMAS_SCAN = "XMAS_SCAN"
    FIN_SCAN = "FIN_SCAN"


@dataclass
class TriagedPacket:
    """
    A packet that has been flagged by the triage engine.
    Contains the original record plus the flags that triggered.
    """
    record: PacketRecord
    flags: List[str] = field(default_factory=list)
    priority: int = 0  # Higher = more suspicious

    @property
    def flags_str(self) -> str:
        """Comma-separated flag string for database storage."""
        return ",".join(self.flags)


# ── Sliding Window Tracker ───────────────────────────────────────────────────

class SlidingWindowTracker:
    """
    Thread-safe sliding window counter for per-IP rate tracking.
    
    Uses a deque of timestamps per key, automatically pruning
    entries outside the time window on each access.
    
    Example:
        tracker = SlidingWindowTracker(window_seconds=10.0)
        tracker.add("192.168.1.1", time.time())
        count = tracker.count("192.168.1.1", time.time())
    """

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._data: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str, timestamp: float):
        """Add a timestamp entry for the given key."""
        with self._lock:
            self._data[key].append(timestamp)
            self._prune(key, timestamp)

    def count(self, key: str, current_time: float) -> int:
        """Count entries within the sliding window for the given key."""
        with self._lock:
            self._prune(key, current_time)
            return len(self._data[key])

    def unique_values(self, key: str, current_time: float) -> int:
        """Count unique entries (used for port tracking with modified storage)."""
        with self._lock:
            self._prune(key, current_time)
            return len(self._data[key])

    def _prune(self, key: str, current_time: float):
        """Remove entries outside the time window."""
        cutoff = current_time - self.window
        dq = self._data[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        # Clean up empty keys to prevent memory leak
        if not dq:
            del self._data[key]


class PortTracker:
    """
    Tracks unique destination ports per source IP within a time window.
    Used for port sweep detection.
    """

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._data: Dict[str, deque] = defaultdict(deque)
        self._ports: Dict[str, set] = defaultdict(set)
        self._lock = threading.Lock()

    def add(self, src_ip: str, dst_port: int, timestamp: float):
        """Record a destination port access from a source IP."""
        with self._lock:
            self._data[src_ip].append((timestamp, dst_port))
            self._ports[src_ip].add(dst_port)
            self._prune(src_ip, timestamp)

    def unique_port_count(self, src_ip: str, current_time: float) -> int:
        """Count unique destination ports accessed within the window."""
        with self._lock:
            self._prune(src_ip, current_time)
            return len(self._ports.get(src_ip, set()))

    def _prune(self, src_ip: str, current_time: float):
        """Remove entries outside the time window and rebuild port set."""
        cutoff = current_time - self.window
        dq = self._data[src_ip]
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            del self._data[src_ip]
            self._ports.pop(src_ip, None)
        else:
            # Rebuild port set from remaining entries
            self._ports[src_ip] = {port for _, port in dq}


# ── Triage Engine ────────────────────────────────────────────────────────────

class TriageEngine:
    """
    Heuristic triage engine for pre-filtering network packets.
    
    Runs as a consumer thread, pulling PacketRecords from the sniffer 
    queue and applying fast rule-based detection. Suspicious packets 
    are forwarded to the LLM queue for deep analysis.
    
    Usage:
        packet_queue = queue.Queue()
        llm_queue = queue.Queue()
        engine = TriageEngine(packet_queue, llm_queue)
        engine.start()  # Runs in background thread
        # ... packets flow through ...
        engine.stop()
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        llm_queue: queue.Queue,
        on_flag_callback: Optional[Callable] = None
    ):
        """
        Initialize the triage engine.
        
        Args:
            packet_queue: Input queue (from sniffer).
            llm_queue: Output queue (to LLM analyzer).
            on_flag_callback: Optional callback when a packet is flagged.
                              Signature: callback(triaged_packet: TriagedPacket)
        """
        self.packet_queue = packet_queue
        self.llm_queue = llm_queue
        self.on_flag_callback = on_flag_callback

        # Threading
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

        # Counters
        self._packets_processed = 0
        self._packets_flagged = 0

        # ── Sliding Window Trackers ──────────────────────────────────
        thresholds = settings.triage

        # Rate tracking: packets per source IP
        self._rate_tracker = SlidingWindowTracker(
            window_seconds=thresholds.high_freq_window_seconds
        )
        # SYN tracking: SYN packets per source IP
        self._syn_tracker = SlidingWindowTracker(
            window_seconds=thresholds.port_scan_window_seconds
        )
        # ICMP tracking: ICMP packets per source IP
        self._icmp_tracker = SlidingWindowTracker(
            window_seconds=thresholds.icmp_flood_window_seconds
        )
        # Port sweep tracking: unique dst ports per source IP
        self._port_tracker = PortTracker(
            window_seconds=thresholds.port_scan_window_seconds
        )

        logger.info("TriageEngine initialized with heuristic rules")

    # ── Public Interface ─────────────────────────────────────────────────

    def start(self):
        """Start the triage engine in a background daemon thread."""
        if self._is_running:
            raise RuntimeError("Triage engine is already running")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="TriageEngine",
            daemon=True
        )
        self._thread.start()
        self._is_running = True
        logger.info("Triage engine started")

    def stop(self):
        """Stop the triage engine gracefully."""
        if not self._is_running:
            return

        self._stop_event.set()
        # Push sentinel to unblock queue.get()
        try:
            self.packet_queue.put_nowait(None)
        except queue.Full:
            pass

        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        
        self._is_running = False
        logger.info(
            f"Triage engine stopped. Processed: {self._packets_processed}, "
            f"Flagged: {self._packets_flagged}"
        )

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def packets_processed(self) -> int:
        return self._packets_processed

    @property
    def packets_flagged(self) -> int:
        return self._packets_flagged

    @property
    def status(self) -> dict:
        return {
            "is_running": self._is_running,
            "packets_processed": self._packets_processed,
            "packets_flagged": self._packets_flagged,
            "flag_rate": (
                f"{(self._packets_flagged / max(1, self._packets_processed)) * 100:.1f}%"
            ),
        }

    # ── Core Processing Loop ────────────────────────────────────────────

    def _run_loop(self):
        """
        Main processing loop. Blocks on queue.get() waiting for packets.
        Applies all heuristic rules and forwards suspicious packets.
        """
        logger.info("Triage processing loop started")

        while not self._stop_event.is_set():
            try:
                # Block with timeout to allow periodic stop checks
                record = self.packet_queue.get(timeout=1.0)

                # Sentinel check (used for clean shutdown)
                if record is None:
                    continue

                # Process the packet through all rules
                self._process_packet(record)
                self._packets_processed += 1

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in triage loop: {e}", exc_info=True)

    def _process_packet(self, record: PacketRecord):
        """
        Apply all heuristic rules to a single packet.
        If any rule triggers, the packet is forwarded to the LLM queue.
        """
        flags: List[str] = []
        now = record.timestamp
        thresholds = settings.triage

        # ── Rule 1: SYN Scan Detection ───────────────────────────────
        if record.protocol == "TCP" and record.tcp_flags:
            flag_str = record.tcp_flags.upper()
            
            # Pure SYN (no ACK) — classic half-open scan
            if flag_str == "S":
                self._syn_tracker.add(record.src_ip, now)
                syn_count = self._syn_tracker.count(record.src_ip, now)
                if syn_count >= thresholds.port_scan_threshold:
                    flags.append(TriageFlag.PORT_SCAN)

            # NULL scan — no flags set
            elif flag_str == "" or flag_str == "0":
                flags.append(TriageFlag.NULL_SCAN)

            # XMAS scan — FIN, PSH, URG flags set
            elif all(f in flag_str for f in ["F", "P", "U"]):
                flags.append(TriageFlag.XMAS_SCAN)

            # FIN scan — only FIN flag
            elif flag_str == "F":
                flags.append(TriageFlag.FIN_SCAN)

        # ── Rule 2: Port Sweep Detection ─────────────────────────────
        if record.dst_port is not None:
            self._port_tracker.add(record.src_ip, record.dst_port, now)
            unique_ports = self._port_tracker.unique_port_count(record.src_ip, now)
            if unique_ports >= thresholds.port_scan_threshold:
                if TriageFlag.PORT_SWEEP not in flags:
                    flags.append(TriageFlag.PORT_SWEEP)

        # ── Rule 3: ICMP Flood Detection ─────────────────────────────
        if record.protocol == "ICMP":
            self._icmp_tracker.add(record.src_ip, now)
            icmp_count = self._icmp_tracker.count(record.src_ip, now)
            if icmp_count >= thresholds.icmp_flood_threshold:
                flags.append(TriageFlag.ICMP_FLOOD)

        # ── Rule 4: Large Payload Detection ──────────────────────────
        if (
            record.payload_hex
            and len(record.payload_hex) // 2 > thresholds.large_payload_threshold
            and record.dst_port
            and record.dst_port not in {80, 443, 8080, 8443}  # Exclude web traffic
        ):
            flags.append(TriageFlag.SUSPICIOUS_PAYLOAD)

        # ── Rule 5: Suspicious Port Detection ────────────────────────
        if record.dst_port and record.dst_port in thresholds.suspicious_ports:
            flags.append(TriageFlag.SUSPICIOUS_PORT)

        # ── Rule 6: DNS Tunneling Detection ──────────────────────────
        if record.has_dns and record.payload_hex:
            payload_size = len(record.payload_hex) // 2
            if payload_size > thresholds.dns_tunnel_payload_threshold:
                flags.append(TriageFlag.DNS_TUNNEL)

        # ── Rule 7: High Frequency Detection ─────────────────────────
        self._rate_tracker.add(record.src_ip, now)
        rate = self._rate_tracker.count(record.src_ip, now)
        if rate >= thresholds.high_freq_threshold:
            if TriageFlag.HIGH_FREQUENCY not in flags:
                flags.append(TriageFlag.HIGH_FREQUENCY)

        # ── Forward if flagged ───────────────────────────────────────
        if flags:
            triaged = TriagedPacket(
                record=record,
                flags=flags,
                priority=self._calculate_priority(flags)
            )
            
            try:
                self.llm_queue.put_nowait(triaged)
                self._packets_flagged += 1
                logger.info(
                    f"FLAGGED [{','.join(flags)}] {record.to_summary()}"
                )
                if self.on_flag_callback:
                    self.on_flag_callback(triaged)
            except queue.Full:
                logger.warning("LLM queue full — dropping flagged packet")

    def _calculate_priority(self, flags: List[str]) -> int:
        """
        Calculate a priority score based on the severity of triggered flags.
        Higher scores indicate more suspicious packets.
        """
        priority_map = {
            TriageFlag.PORT_SCAN: 6,
            TriageFlag.PORT_SWEEP: 5,
            TriageFlag.SYN_FLOOD: 8,
            TriageFlag.ICMP_FLOOD: 7,
            TriageFlag.SUSPICIOUS_PAYLOAD: 6,
            TriageFlag.SUSPICIOUS_PORT: 7,
            TriageFlag.DNS_TUNNEL: 8,
            TriageFlag.HIGH_FREQUENCY: 5,
            TriageFlag.NULL_SCAN: 9,
            TriageFlag.XMAS_SCAN: 9,
            TriageFlag.FIN_SCAN: 8,
        }
        return sum(priority_map.get(f, 1) for f in flags)
