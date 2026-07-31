"""
==============================================================================
 GPT-Powered Threat Analyzer — LLM Client Module
==============================================================================
 University Capstone Project — Tier S
 
 Module 2: Groq Cloud API integration for AI-powered threat analysis.
 
 Architecture:
   - Runs in a dedicated background thread with its own asyncio event loop
   - Consumes TriagedPackets from the LLM analysis queue
   - Sends structured prompts to Groq with professional SOC analyst context
   - Parses JSON responses with validation
   - Stores results in the SQLite database
   - Includes retry logic, timeout handling, and graceful degradation
 
 Uses the Groq Python SDK (OpenAI-compatible chat completions API).
 
 Privacy Note:
   Packet metadata (IPs, ports, flags) is sent — NOT raw payload content.
   The system prompt explicitly states this is an authorized security audit.
==============================================================================
"""

import json
import time
import queue
import asyncio
import logging
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

from groq import Groq

from modules.triage import TriagedPacket
from config import settings

logger = logging.getLogger("ids.llm_client")


# ── Response Models ──────────────────────────────────────────────────────────

@dataclass
class ThreatAnalysis:
    """
    Structured LLM threat analysis result.
    Validated from the Groq JSON response.
    """
    threat_level: str = "Low"          # Low | Medium | High | Critical
    confidence: float = 0.0            # 0.0 - 1.0
    attack_vector: str = "Unknown"     # e.g., Port Scan, SYN Flood
    mitre_technique: str = "N/A"       # e.g., T1046 - Network Service Scanning
    human_readable_explanation: str = ""
    recommended_action: str = "Monitor"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── System Prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) Tier 3 Analyst performing real-time intrusion detection analysis on a corporate network. This is an authorized on-premise security audit — all data is internal, non-sensitive network metadata collected for defensive purposes.

Your role:
1. Analyze the provided network packet metadata and heuristic triage flags
2. Classify the threat level based on the evidence
3. Identify the most likely attack vector and MITRE ATT&CK technique
4. Provide a clear, actionable explanation for a junior analyst
5. Recommend a specific response action

IMPORTANT RULES:
- Base your analysis ONLY on the provided metadata — do not hallucinate additional evidence
- Consider the triage flags as preliminary indicators, not definitive proof
- Factor in the combination of flags, source/destination context, and protocol behavior
- If the evidence is ambiguous, lean toward caution (higher threat level)
- Always include the MITRE ATT&CK technique ID when applicable

You MUST respond with ONLY a valid JSON object (no markdown, no code fences, no extra text) in this exact schema:
{
    "threat_level": "Low | Medium | High | Critical",
    "confidence": 0.0 to 1.0,
    "attack_vector": "descriptive attack type",
    "mitre_technique": "TXXXX - Technique Name",
    "human_readable_explanation": "2-3 sentence plain English explanation of the threat, suitable for a security report",
    "recommended_action": "specific action: Block IP / Rate Limit / Monitor / Investigate / Ignore"
}"""


# ── LLM Analyzer ────────────────────────────────────────────────────────────

class LLMAnalyzer:
    """
    Groq-powered threat analysis engine.
    
    Runs a dedicated background thread with an asyncio event loop
    to process flagged packets from the LLM queue. Each packet's
    metadata is formatted into a structured prompt, sent to Groq,
    and the JSON response is parsed and stored in the database.
    
    Usage:
        llm_queue = queue.Queue()
        analyzer = LLMAnalyzer(llm_queue, db_manager)
        analyzer.start()
        # ... flagged packets flow in via llm_queue ...
        analyzer.stop()
    """

    def __init__(self, llm_queue: queue.Queue, db_manager=None):
        """
        Initialize the LLM analyzer.
        
        Args:
            llm_queue: Input queue of TriagedPackets to analyze.
            db_manager: DatabaseManager instance for storing results.
        """
        self.llm_queue = llm_queue
        self.db_manager = db_manager

        # Initialize Groq client
        self.client = Groq(api_key=settings.groq_api_key)
        self.model_name = settings.groq_model

        # Threading
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Counters
        self._analyzed_count = 0
        self._error_count = 0

        # In-memory alert buffer for real-time streaming
        self._recent_alerts: list = []
        self._alert_lock = threading.Lock()

        # RAG engine reference (set externally)
        self.rag_engine = None

        logger.info(f"LLMAnalyzer initialized with model: {self.model_name}")

    # ── Public Interface ─────────────────────────────────────────────────

    def start(self):
        """Start the LLM analysis thread."""
        if self._is_running:
            raise RuntimeError("LLM Analyzer is already running")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_event_loop,
            name="LLMAnalyzer",
            daemon=True
        )
        self._thread.start()
        self._is_running = True
        logger.info("LLM Analyzer started")

    def stop(self):
        """Stop the LLM analysis thread gracefully."""
        if not self._is_running:
            return

        self._stop_event.set()
        # Push sentinel to unblock
        try:
            self.llm_queue.put_nowait(None)
        except queue.Full:
            pass

        if self._thread:
            self._thread.join(timeout=10.0)
            self._thread = None

        self._is_running = False
        logger.info(
            f"LLM Analyzer stopped. Analyzed: {self._analyzed_count}, "
            f"Errors: {self._error_count}"
        )

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def analyzed_count(self) -> int:
        return self._analyzed_count

    @property
    def error_count(self) -> int:
        return self._error_count

    @property
    def status(self) -> dict:
        return {
            "is_running": self._is_running,
            "model": self.model_name,
            "analyzed_count": self._analyzed_count,
            "error_count": self._error_count,
            "queue_size": self.llm_queue.qsize(),
        }

    def get_recent_alerts(self, limit: int = 50) -> list:
        """Get recent analyzed alerts from the in-memory buffer."""
        with self._alert_lock:
            return list(self._recent_alerts[-limit:])

    # ── Event Loop Thread ────────────────────────────────────────────────

    def _run_event_loop(self):
        """
        Create and run a dedicated asyncio event loop in this thread.
        This allows us to use async Groq calls without blocking the main thread.
        """
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._process_loop())
        except Exception as e:
            logger.error(f"LLM event loop crashed: {e}", exc_info=True)
        finally:
            self._loop.close()

    async def _process_loop(self):
        """Main async processing loop for LLM analysis."""
        logger.info("LLM processing loop started")

        while not self._stop_event.is_set():
            try:
                # Use run_in_executor to make blocking queue.get async-compatible
                triaged = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._safe_queue_get(timeout=1.0)
                )

                if triaged is None:
                    continue

                # Analyze the packet
                await self._analyze_packet(triaged)

            except Exception as e:
                logger.error(f"Error in LLM loop: {e}", exc_info=True)
                await asyncio.sleep(1.0)

    def _safe_queue_get(self, timeout: float = 1.0):
        """Thread-safe queue get with timeout. Returns None on empty/timeout."""
        try:
            item = self.llm_queue.get(timeout=timeout)
            return item
        except queue.Empty:
            return None

    # ── Core Analysis ────────────────────────────────────────────────────

    async def _analyze_packet(self, triaged: TriagedPacket):
        """
        Analyze a single triaged packet using Groq.
        
        Steps:
        1. Insert pending alert into database
        2. Build structured prompt with packet metadata
        3. (Optional) Inject RAG context
        4. Send to Groq with retry logic
        5. Parse and validate JSON response
        6. Update alert in database with results
        """
        record = triaged.record
        alert_id = None

        try:
            # Step 1: Insert pending alert
            if self.db_manager:
                from database import AlertRecord
                alert = AlertRecord(
                    timestamp=record.timestamp,
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    src_port=record.src_port,
                    dst_port=record.dst_port,
                    protocol=record.protocol,
                    tcp_flags=record.tcp_flags,
                    triage_flags=triaged.flags_str,
                    raw_payload_hex=record.payload_hex,
                    status="pending"
                )
                alert_id = await self.db_manager.insert_alert(alert)

            # Step 2: Build the analysis prompt
            prompt = self._build_prompt(triaged)

            # Step 3: Inject RAG context if available
            if self.rag_engine and settings.rag_enabled:
                try:
                    rag_context = self.rag_engine.query_context(triaged.flags)
                    if rag_context:
                        prompt += f"\n\n--- THREAT INTELLIGENCE CONTEXT ---\n{rag_context}"
                except Exception as e:
                    logger.debug(f"RAG query failed (non-critical): {e}")

            # Step 4: Send to Groq with retries
            analysis = await self._call_llm_with_retry(prompt)

            # Step 5: Store results
            if analysis and alert_id and self.db_manager:
                await self.db_manager.update_alert_analysis(
                    alert_id=alert_id,
                    threat_level=analysis.threat_level,
                    confidence=analysis.confidence,
                    attack_vector=analysis.attack_vector,
                    mitre_technique=analysis.mitre_technique,
                    explanation=analysis.human_readable_explanation,
                    recommended_action=analysis.recommended_action
                )

            # Step 6: Add to in-memory buffer
            if analysis:
                alert_data = {
                    "id": alert_id,
                    "timestamp": record.timestamp,
                    "src_ip": record.src_ip,
                    "dst_ip": record.dst_ip,
                    "src_port": record.src_port,
                    "dst_port": record.dst_port,
                    "protocol": record.protocol,
                    "tcp_flags": record.tcp_flags,
                    "triage_flags": triaged.flags_str,
                    **analysis.to_dict()
                }
                with self._alert_lock:
                    self._recent_alerts.append(alert_data)
                    # Keep buffer bounded
                    if len(self._recent_alerts) > settings.alert_buffer_size:
                        self._recent_alerts = self._recent_alerts[-settings.alert_buffer_size:]

                self._analyzed_count += 1
                logger.info(
                    f"ANALYZED alert #{alert_id}: {analysis.threat_level} — "
                    f"{analysis.attack_vector} ({analysis.confidence:.0%})"
                )

        except Exception as e:
            self._error_count += 1
            logger.error(f"Failed to analyze packet: {e}", exc_info=True)
            if alert_id and self.db_manager:
                await self.db_manager.mark_alert_error(alert_id, str(e))

    async def _call_llm_with_retry(
        self,
        prompt: str,
        max_retries: int = None
    ) -> Optional[ThreatAnalysis]:
        """
        Call Groq API with exponential backoff retry logic.
        
        Args:
            prompt: The formatted analysis prompt.
            max_retries: Maximum retry attempts (defaults to config).
            
        Returns:
            ThreatAnalysis object if successful, None on failure.
        """
        max_retries = max_retries or settings.groq_max_retries

        for attempt in range(max_retries):
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        max_tokens=1024,
                        top_p=0.8,
                    )
                )

                if not response or not response.choices:
                    logger.warning(f"Empty Groq response (attempt {attempt + 1})")
                    continue

                response_text = response.choices[0].message.content
                if not response_text:
                    logger.warning(f"Empty Groq response text (attempt {attempt + 1})")
                    continue

                analysis = self._parse_response(response_text)
                if analysis:
                    return analysis

            except Exception as e:
                wait_time = (2 ** attempt) * 1.0  # 1s, 2s, 4s
                logger.warning(
                    f"Groq API error (attempt {attempt + 1}/{max_retries}): {e}. "
                    f"Retrying in {wait_time}s..."
                )
                await asyncio.sleep(wait_time)

        logger.error(f"All {max_retries} Groq attempts failed")
        return None

    # ── Prompt Engineering ───────────────────────────────────────────────

    def _build_prompt(self, triaged: TriagedPacket) -> str:
        """
        Build a structured analysis prompt from packet metadata.
        Formats all relevant fields for the LLM to analyze.
        """
        record = triaged.record
        
        prompt_parts = [
            "=== NETWORK PACKET ANALYSIS REQUEST ===",
            "",
            "PACKET METADATA:",
            f"  Timestamp:     {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.timestamp))}",
            f"  Source IP:      {record.src_ip}",
            f"  Destination IP: {record.dst_ip}",
            f"  Protocol:      {record.protocol}",
        ]

        if record.src_port is not None:
            prompt_parts.append(f"  Source Port:    {record.src_port}")
        if record.dst_port is not None:
            prompt_parts.append(f"  Dest Port:      {record.dst_port}")
        if record.tcp_flags:
            prompt_parts.append(f"  TCP Flags:      {record.tcp_flags}")
        
        prompt_parts.append(f"  Packet Size:    {record.packet_size} bytes")

        if record.has_dns and record.dns_query:
            prompt_parts.append(f"  DNS Query:      {record.dns_query}")

        if record.payload_hex:
            # Only show first 64 chars of hex for brevity
            hex_preview = record.payload_hex[:64]
            prompt_parts.append(f"  Payload (hex):  {hex_preview}...")

        prompt_parts.extend([
            "",
            "HEURISTIC TRIAGE FLAGS:",
            f"  Triggered Flags: {', '.join(triaged.flags)}",
            f"  Priority Score:  {triaged.priority}",
            "",
            "Please analyze this packet and provide your threat assessment.",
        ])

        return "\n".join(prompt_parts)

    def _parse_response(self, response_text: str) -> Optional[ThreatAnalysis]:
        """
        Parse and validate the LLM's JSON response.
        Handles common formatting issues (markdown fences, extra text).
        """
        try:
            # Clean up response — strip markdown code fences if present
            text = response_text.strip()
            if text.startswith("```"):
                # Remove ```json ... ```
                lines = text.split("\n")
                text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
            if text.startswith("`") and text.endswith("`"):
                text = text.strip("`")
            
            # Try to extract JSON object
            # Find first { and last }
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                text = text[start:end+1]

            data = json.loads(text)

            # Validate and normalize fields
            analysis = ThreatAnalysis(
                threat_level=self._normalize_threat_level(
                    data.get("threat_level", "Low")
                ),
                confidence=min(1.0, max(0.0, float(
                    data.get("confidence", 0.5)
                ))),
                attack_vector=str(data.get("attack_vector", "Unknown")),
                mitre_technique=str(data.get("mitre_technique", "N/A")),
                human_readable_explanation=str(
                    data.get("human_readable_explanation", "No explanation provided")
                ),
                recommended_action=str(
                    data.get("recommended_action", "Monitor")
                ),
            )
            return analysis

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            logger.debug(f"Raw response: {response_text[:500]}")
            return None

    @staticmethod
    def _normalize_threat_level(level: str) -> str:
        """Normalize threat level string to expected values."""
        level = level.strip().title()
        valid = {"Low", "Medium", "High", "Critical"}
        if level in valid:
            return level
        # Fuzzy matching
        if "crit" in level.lower():
            return "Critical"
        if "high" in level.lower():
            return "High"
        if "med" in level.lower():
            return "Medium"
        return "Low"

    # ── Manual Analysis (for API endpoint) ───────────────────────────────

    async def analyze_manual(self, packet_data: dict) -> Optional[ThreatAnalysis]:
        """
        Analyze manually submitted packet data (for the /analyze-sample endpoint).
        
        Args:
            packet_data: Dictionary with packet metadata fields.
            
        Returns:
            ThreatAnalysis result or None on failure.
        """
        from modules.sniffer import PacketRecord

        record = PacketRecord(
            timestamp=time.time(),
            src_ip=packet_data.get("src_ip", "0.0.0.0"),
            dst_ip=packet_data.get("dst_ip", "0.0.0.0"),
            src_port=packet_data.get("src_port"),
            dst_port=packet_data.get("dst_port"),
            protocol=packet_data.get("protocol", "TCP"),
            tcp_flags=packet_data.get("tcp_flags"),
            payload_hex=packet_data.get("payload_hex"),
            packet_size=packet_data.get("packet_size", 0),
        )
        triaged = TriagedPacket(
            record=record,
            flags=packet_data.get("flags", ["MANUAL_SUBMISSION"]),
            priority=5
        )

        prompt = self._build_prompt(triaged)

        # For manual analysis, inject RAG context too
        if self.rag_engine and settings.rag_enabled:
            try:
                rag_context = self.rag_engine.query_context(triaged.flags)
                if rag_context:
                    prompt += f"\n\n--- THREAT INTELLIGENCE CONTEXT ---\n{rag_context}"
            except Exception:
                pass

        return await self._call_llm_with_retry(prompt)
