import requests
from typing import List, Dict, Any


class AbuseIPDBClient:
    base_url = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key or ""
        self.headers = {"Key": self.api_key, "Accept": "application/json"}

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def check(self, ip: str, max_age_days: int = 365) -> Dict[str, Any]:
        if not self.api_key:
            return {"ipAddress": ip, "configured": False}
        try:
            r = requests.get(
                f"{self.base_url}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days},
                headers=self.headers,
                timeout=20,
            )
            if r.status_code != 200:
                return {"ipAddress": ip, "error": r.text}
            return r.json().get("data", {})
        except Exception as exc:
            return {"ipAddress": ip, "error": str(exc)}

    def batch_check(self, ips: List[str], max_age_days: int = 365) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for ip in ips:
            results.append(self.check(ip, max_age_days=max_age_days))
        return results


