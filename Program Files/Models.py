from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

@dataclass
class Event:
    timestamp: datetime
    user: str
    ip_address: str
    host: str
    action: str
    message: str
    outcome: str
    source_file: str
    event_category: Optional[str] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    source_type: str = "event"
    severity: str = "low"
    session_id: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Document:
    path: Path
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    title: str = ""

    def __post_init__(self):
        # If no title is given, automatically use the file name (e.g., "EVAL_SET.md")
        if not self.title and self.path:
            self.title = self.path.name

@dataclass
class EvidenceStore:
    events: List[Event] = field(default_factory=list)
    documents: List[Document] = field(default_factory=list)

@dataclass
class DetectionResult:
    name: str
    triggered: bool
    confidence: float
    summary: str
    details: List[str] = field(default_factory=list)
    evidence: List[Event] = field(default_factory=list)
    recommendation: str = ""

@dataclass
class IncidentCluster:
    incident_id: str
    key: str
    events: List[Event] = field(default_factory=list)
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    