import json
import os
from datetime import datetime
from typing import List, Dict

LOG_FILE = "logs/audit_log.json"


class LogStore:
    """
    Security Audit Logging System.
    Stores every prompt analysis event with full metadata.
    Persists to JSON file for audit trail.
    """

    def __init__(self):
        self.logs: List[Dict] = []
        os.makedirs("logs", exist_ok=True)
        self._load_from_file()

    def add(self, prompt: str, result: dict):
        entry = {
            "id": len(self.logs) + 1,
            "timestamp": datetime.now().isoformat(),
            "time_display": datetime.now().strftime("%H:%M:%S"),
            "prompt_preview": prompt[:60] + ("…" if len(prompt) > 60 else ""),
            "prompt_length": len(prompt),
            "detected": result.get("detected", False),
            "attack_type": result.get("attack_type", "None"),
            "risk_level": result.get("risk_level", "LOW"),
            "action": result.get("action", "ALLOW"),
            "confidence": result.get("confidence", 0),
            "method": result.get("method", "RULE-BASED"),
            "reason": result.get("reason", ""),
            "inspection_flags": result.get("inspection_flags", []),
            "sanitized": bool(result.get("sanitized_prompt")),
        }
        self.logs.insert(0, entry)
        self._save_to_file()

    def get_all(self) -> List[Dict]:
        return self.logs

    def get_stats(self) -> Dict:
        total = len(self.logs)
        blocked = sum(1 for l in self.logs if l["detected"])
        allowed = total - blocked
        critical = sum(1 for l in self.logs if l["risk_level"] == "CRITICAL")
        threat_rate = round((blocked / total * 100), 1) if total > 0 else 0

        attack_counts = {}
        for log in self.logs:
            t = log["attack_type"]
            if t != "None":
                attack_counts[t] = attack_counts.get(t, 0) + 1

        return {
            "total": total,
            "blocked": blocked,
            "allowed": allowed,
            "critical": critical,
            "threat_rate": threat_rate,
            "attack_breakdown": attack_counts
        }

    def clear(self):
        self.logs = []
        self._save_to_file()

    def _save_to_file(self):
        try:
            with open(LOG_FILE, "w") as f:
                json.dump(self.logs, f, indent=2)
        except Exception:
            pass

    def _load_from_file(self):
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    self.logs = json.load(f)
        except Exception:
            self.logs = []
