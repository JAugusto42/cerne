from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class DependencyNode:
    name: str
    version: str
    children: List['DependencyNode'] = field(default_factory=list)

    # Security model
    vulnerable: bool = False
    vuln_summary: str = ""
    vuln_details: List[Dict[str, Any]] = field(default_factory=list)

    # UI
    expanded: bool = False