"""
Hallucination Mitigation Controls.

Detects controls for reducing and detecting LLM hallucinations.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class RAGImplementationDetector(BaseControlDetector):
    """HM-01: RAG Implementation - Retrieval-Augmented Generation for grounding."""

    control_id = "HM-01"
    control_name = "RAG Implementation"
    category = "hallucination"
    description = "Retrieval-Augmented Generation for grounding responses in facts"
    recommendations = [
        "Implement RAG using LangChain or LlamaIndex",
        "Use vector databases like Pinecone, Chroma, or Weaviate",
        "Ground LLM responses with retrieved context",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for vector database dependencies
        vector_dbs = ["pinecone", "chromadb", "weaviate", "qdrant", "milvus", "faiss", "pgvector"]
        for db in vector_dbs:
            if self.deps.has_package(db):
                evidence_items.append(self._evidence_from_dependency(
                    "", db, f"Vector database {db} found"
                ))

        # Check for RAG framework usage
        rag_frameworks = ["langchain", "llama-index", "llama_index", "haystack"]
        for framework in rag_frameworks:
            if self.deps.has_package(framework):
                evidence_items.append(self._evidence_from_dependency(
                    "", framework, f"RAG framework {framework} found"
                ))

        # Check for retrieval patterns in code
        retrieval_patterns = ["retrieve", "similarity_search", "vector_search", "RetrievalQA"]
        for pattern in retrieval_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Retrieval pattern: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class ConfidenceScoringDetector(BaseControlDetector):
    """HM-02: Confidence Scoring - Track and filter by confidence scores."""

    control_id = "HM-02"
    control_name = "Confidence Scoring"
    category = "hallucination"
    description = "Track confidence/probability scores and filter uncertain responses"
    recommendations = [
        "Use logprobs to assess response confidence",
        "Implement confidence thresholds for responses",
        "Add uncertainty indicators to user-facing outputs",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for logprobs usage
        logprob_patterns = ["logprobs", "log_probs", "top_logprobs"]
        for pattern in logprob_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Logprobs usage: {match.name}"
                ))

        # Check for confidence threshold patterns
        confidence_patterns = ["confidence", "threshold", "uncertainty", "score"]
        for pattern in confidence_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Confidence config: {match.key}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class SourceAttributionDetector(BaseControlDetector):
    """HM-03: Source Attribution - Cite sources for factual claims."""

    control_id = "HM-03"
    control_name = "Source Attribution"
    category = "hallucination"
    description = "Require and display source citations for factual claims"
    recommendations = [
        "Include source citations in LLM outputs",
        "Track and display source documents from RAG",
        "Implement citation verification",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for citation patterns in code
        citation_patterns = ["citation", "source", "reference", "attribute", "metadata"]
        for pattern in citation_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                if "source" in str(match.snippet).lower() or "cite" in str(match.snippet).lower():
                    evidence_items.append(self._evidence_from_ast(
                        match.file_path, match.line_number, match.snippet,
                        f"Citation pattern: {match.name}"
                    ))

        # Check for source_documents usage (common in RAG)
        source_patterns = ["source_documents", "retrieved_docs", "context_docs"]
        for pattern in source_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Source documents: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class TemperatureControlDetector(BaseControlDetector):
    """HM-04: Temperature Control - Control randomness for factual accuracy."""

    control_id = "HM-04"
    control_name = "Temperature Control"
    category = "hallucination"
    description = "Control temperature parameter for factual accuracy"
    recommendations = [
        "Use lower temperature (0-0.3) for factual tasks",
        "Make temperature configurable per use case",
        "Document temperature settings for different tasks",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for temperature configuration
        temp_patterns = ["temperature"]
        for pattern in temp_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Temperature config: {match.key}={match.value}"
                ))

        # Check for temperature in function calls
        matches = self.ast.find_function_calls("temperature")
        for match in matches[:2]:
            evidence_items.append(self._evidence_from_ast(
                match.file_path, match.line_number, match.snippet,
                f"Temperature setting: {match.name}"
            ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 2:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class FactCheckingDetector(BaseControlDetector):
    """HM-05: Fact Checking - Verify factual claims against sources."""

    control_id = "HM-05"
    control_name = "Fact Checking"
    category = "hallucination"
    description = "Verify factual claims against trusted sources"
    recommendations = [
        "Implement fact-checking against knowledge bases",
        "Use cross-validation with multiple sources",
        "Add human review for critical factual claims",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for fact checking patterns
        fact_patterns = ["fact_check", "verify", "validate", "cross_reference"]
        for pattern in fact_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Fact checking: {match.name}"
                ))

        # Check for external knowledge sources
        knowledge_patterns = ["wikipedia", "knowledge_base", "wikidata"]
        for pattern in knowledge_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Knowledge source: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class HallucinationControls(ControlCategory):
    """Hallucination Mitigation control category."""

    category_id = "hallucination"
    category_name = "Hallucination Mitigation"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            RAGImplementationDetector(self.ast, self.config, self.deps),
            ConfidenceScoringDetector(self.ast, self.config, self.deps),
            SourceAttributionDetector(self.ast, self.config, self.deps),
            TemperatureControlDetector(self.ast, self.config, self.deps),
            FactCheckingDetector(self.ast, self.config, self.deps),
        ]
