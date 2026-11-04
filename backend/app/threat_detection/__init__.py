"""Threat Detection & Defense module for PRIVGUARD AI."""

from app.threat_detection.schemas import (
    BehavioralEvent,
    ContentEnvelope,
    MemoryUpdateProposal,
    RetrievedDocumentChunk,
    SourceType,
    TaintRecord,
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
    TrustLevel,
)
from app.threat_detection.injection_detector import InjectionDetector
from app.threat_detection.content_analyzer import ContentAnalyzer
from app.threat_detection.memory_analyzer import MemoryAnalyzer
from app.threat_detection.behavior_analyzer import BehaviorAnalyzer
from app.threat_detection.exfiltration_detector import ExfiltrationDetector
from app.threat_detection.retrieval_security import RetrievalSecurityValidator
from app.threat_detection.response_engine import ThreatResponseEngine
from app.privacy.secret_scanner import secret_scanner

# Shared singleton instances
injection_detector = InjectionDetector()
content_analyzer = ContentAnalyzer(injection_detector)
memory_analyzer = MemoryAnalyzer(injection_detector)
behavior_analyzer = BehaviorAnalyzer()
exfiltration_detector = ExfiltrationDetector(secret_scanner=secret_scanner)
retrieval_validator = RetrievalSecurityValidator(injection_detector)
threat_response_engine = ThreatResponseEngine()

__all__ = [
    "BehavioralEvent",
    "ContentEnvelope",
    "MemoryUpdateProposal",
    "RetrievedDocumentChunk",
    "SourceType",
    "TaintRecord",
    "ThreatAction",
    "ThreatAssessment",
    "ThreatSeverity",
    "ThreatSignal",
    "ThreatType",
    "TrustLevel",
    "InjectionDetector",
    "ContentAnalyzer",
    "MemoryAnalyzer",
    "BehaviorAnalyzer",
    "ExfiltrationDetector",
    "RetrievalSecurityValidator",
    "ThreatResponseEngine",
    "injection_detector",
    "content_analyzer",
    "memory_analyzer",
    "behavior_analyzer",
    "exfiltration_detector",
    "retrieval_validator",
    "threat_response_engine",
]

