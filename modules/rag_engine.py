"""
==============================================================================
 GPT-Powered Threat Analyzer — RAG Knowledge Base
==============================================================================
 University Capstone Project — Tier S
 
 Bonus Feature: Retrieval-Augmented Generation (RAG) for threat intelligence.
 
 Uses ChromaDB (embedded vector database) to store and query threat
 intelligence data including MITRE ATT&CK techniques, common attack
 signatures, and known indicators of compromise.
 
 Before each LLM analysis call, the RAG engine is queried with the
 triage flags to retrieve relevant threat context. This context is
 injected into the LLM prompt to improve classification accuracy.
==============================================================================
"""

import json
import logging
import os
from typing import List, Optional

from config import settings

logger = logging.getLogger("ids.rag_engine")


class RAGEngine:
    """
    RAG-based threat knowledge base using ChromaDB.
    
    Provides contextual threat intelligence to augment LLM analysis.
    Seeded with MITRE ATT&CK techniques and common attack patterns.
    
    Usage:
        rag = RAGEngine()
        rag.initialize()
        context = rag.query_context(["PORT_SCAN", "SYN_FLOOD"])
    """

    def __init__(self):
        self._collection = None
        self._client = None
        self._initialized = False

    def initialize(self):
        """
        Initialize ChromaDB and load/seed the threat intelligence collection.
        Called once during application startup.
        """
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings

            self._client = chromadb.Client(ChromaSettings(
                anonymized_telemetry=False,
                is_persistent=True,
                persist_directory=settings.chroma_persist_dir,
            ))

            # Get or create the threat intel collection
            self._collection = self._client.get_or_create_collection(
                name="threat_intelligence",
                metadata={"description": "MITRE ATT&CK techniques and attack patterns"}
            )

            # Seed if empty
            if self._collection.count() == 0:
                self._seed_knowledge_base()

            self._initialized = True
            logger.info(
                f"RAG engine initialized with {self._collection.count()} documents"
            )

        except ImportError:
            logger.warning(
                "ChromaDB not installed — RAG features disabled. "
                "Install with: pip install chromadb"
            )
        except Exception as e:
            logger.error(f"Failed to initialize RAG engine: {e}")

    def _seed_knowledge_base(self):
        """
        Load threat intelligence data from the JSON file and 
        insert it into the ChromaDB collection.
        """
        json_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "knowledge_base",
            "threat_intel.json"
        )

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            documents = []
            metadatas = []
            ids = []

            for i, entry in enumerate(data.get("techniques", [])):
                # Build a rich document string for embedding
                doc = (
                    f"Technique: {entry.get('id', 'N/A')} — {entry.get('name', 'Unknown')}\n"
                    f"Tactic: {entry.get('tactic', 'Unknown')}\n"
                    f"Description: {entry.get('description', '')}\n"
                    f"Detection: {entry.get('detection', '')}\n"
                    f"Keywords: {', '.join(entry.get('keywords', []))}"
                )
                documents.append(doc)
                metadatas.append({
                    "technique_id": entry.get("id", ""),
                    "name": entry.get("name", ""),
                    "tactic": entry.get("tactic", ""),
                    "severity": entry.get("severity", "Medium"),
                })
                ids.append(f"mitre_{i}")

            if documents:
                # ChromaDB handles batching internally
                self._collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                logger.info(f"Seeded RAG with {len(documents)} threat intel documents")

        except FileNotFoundError:
            logger.warning(f"Threat intel file not found: {json_path}")
        except Exception as e:
            logger.error(f"Failed to seed knowledge base: {e}")

    def query_context(
        self,
        triage_flags: List[str],
        top_k: int = None
    ) -> Optional[str]:
        """
        Query the knowledge base for relevant threat intelligence
        based on the triage flags.
        
        Args:
            triage_flags: List of triage flag strings (e.g., ["PORT_SCAN", "SYN_FLOOD"])
            top_k: Number of results to return (defaults to config)
            
        Returns:
            Formatted context string for LLM prompt injection,
            or None if no relevant results found.
        """
        if not self._initialized or not self._collection:
            return None

        top_k = top_k or settings.rag_top_k

        try:
            # Build query from triage flags
            query_text = " ".join([
                flag.replace("_", " ").lower() for flag in triage_flags
            ])

            results = self._collection.query(
                query_texts=[query_text],
                n_results=top_k
            )

            if not results or not results.get("documents"):
                return None

            documents = results["documents"][0]
            metadatas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(documents)
            distances = results["distances"][0] if results.get("distances") else [0] * len(documents)

            # Format results for LLM context injection
            context_parts = ["Relevant MITRE ATT&CK Intelligence:"]
            for doc, meta, dist in zip(documents, metadatas, distances):
                relevance = max(0, 1 - dist)  # Convert distance to relevance score
                context_parts.append(
                    f"\n[Relevance: {relevance:.0%}] "
                    f"{meta.get('technique_id', 'N/A')} — {meta.get('name', 'Unknown')}\n"
                    f"{doc}"
                )

            return "\n".join(context_parts)

        except Exception as e:
            logger.debug(f"RAG query error: {e}")
            return None

    def add_document(self, technique_id: str, name: str, description: str, **kwargs):
        """
        Add a new threat intelligence document to the knowledge base.
        Can be used to dynamically update the knowledge base.
        """
        if not self._initialized or not self._collection:
            logger.warning("RAG engine not initialized — cannot add document")
            return

        doc = (
            f"Technique: {technique_id} — {name}\n"
            f"Description: {description}\n"
            f"Keywords: {', '.join(kwargs.get('keywords', []))}"
        )

        try:
            doc_id = f"custom_{technique_id.replace('.', '_')}"
            self._collection.upsert(
                documents=[doc],
                metadatas=[{
                    "technique_id": technique_id,
                    "name": name,
                    "severity": kwargs.get("severity", "Medium"),
                }],
                ids=[doc_id]
            )
            logger.info(f"Added RAG document: {technique_id} — {name}")
        except Exception as e:
            logger.error(f"Failed to add RAG document: {e}")

    @property
    def document_count(self) -> int:
        """Number of documents in the knowledge base."""
        if self._collection:
            return self._collection.count()
        return 0

    @property
    def is_initialized(self) -> bool:
        return self._initialized
