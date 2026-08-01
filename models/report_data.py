from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class ReportData:
    """Structure de données pour le rapport"""
    results: Dict[str, Any] = field(default_factory=dict)
    file_processed: str = ""
    total_logs: int = 0
    timestamp: str = ""
    alerts: List[str] = field(default_factory=list)
