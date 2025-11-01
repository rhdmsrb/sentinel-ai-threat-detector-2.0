import re
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SignatureRule:
    id: str
    name: str
    pattern: str
    severity: str
    description: str
    enabled: bool = True

class SignatureIDS:
    def __init__(self):
        self.rules: List[SignatureRule] = []
        self.load_default_rules()
    
    def load_default_rules(self):
        default_rules = [
            SignatureRule(
                id="SIG_001",
                name="Port Scan Detection",
                pattern=r"dst_port:(22|23|80|443|3389)",
                severity="medium",
                description="Potential port scanning activity detected"
            ),
        ]
        self.rules.extend(default_rules)
    
    def check_packet(self, packet: Dict) -> List[Dict]:
        matches = []
        packet_str = json.dumps(packet)
        for rule in self.rules:
            if rule.enabled and re.search(rule.pattern, packet_str, re.IGNORECASE):
                matches.append({
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description
                })
        return matches
