"""HTTP client for the Hive REST API (stdlib urllib only, so the Queen tools
run anywhere Python does — including a live Kali environment with no pip)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class HiveError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class HiveClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # -- plumbing ---------------------------------------------------------

    def _request(self, method: str, path: str, body: dict | None = None,
                 params: dict | None = None):
        url = f"{self.base_url}/api/v1{path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                ctype = resp.headers.get("Content-Type", "")
                return json.loads(raw) if "json" in ctype else raw
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read().decode()).get("error", exc.reason)
            except Exception:
                message = exc.reason
            raise HiveError(exc.code, message) from exc

    # -- auth -------------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        session = self._request("POST", "/login",
                                {"username": username, "password": password})
        self.token = session["token"]
        return session

    def logout(self) -> None:
        self._request("POST", "/logout")
        self.token = None

    # -- reads ------------------------------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/health")

    def stats(self) -> dict:
        return self._request("GET", "/stats")

    def devices(self) -> list[dict]:
        return self._request("GET", "/devices")["devices"]

    def events(self, **filters) -> list[dict]:
        return self._request("GET", "/events", params=filters)["events"]

    def incidents(self, status: str | None = None) -> list[dict]:
        return self._request("GET", "/incidents", params={"status": status})["incidents"]

    def incident(self, incident_id: int) -> dict:
        return self._request("GET", f"/incidents/{incident_id}")

    def cases(self, status: str | None = None) -> list[dict]:
        return self._request("GET", "/cases", params={"status": status})["cases"]

    def case(self, case_id: int) -> dict:
        return self._request("GET", f"/cases/{case_id}")

    def report(self, case_id: int, fmt: str = "json") -> str | dict:
        return self._request("GET", f"/cases/{case_id}/report", params={"format": fmt})

    def verify(self) -> dict:
        return self._request("GET", "/verify")

    def anchor(self) -> dict:
        return self._request("GET", "/anchor")

    def verify_anchor(self, anchor: dict) -> dict:
        return self._request("POST", "/anchor/verify", anchor)

    def export_case(self, case_id: int) -> dict:
        return self._request("POST", f"/cases/{case_id}/export")

    def audit(self, limit: int = 200) -> list[dict]:
        return self._request("GET", "/audit", params={"limit": limit})["audit"]

    # -- writes -----------------------------------------------------------

    def create_case(self, title: str, description: str = "") -> dict:
        return self._request("POST", "/cases", {"title": title, "description": description})

    def set_case_status(self, case_id: int, status: str) -> None:
        self._request("POST", f"/cases/{case_id}/status", {"status": status})

    def add_note(self, case_id: int, body: str) -> None:
        self._request("POST", f"/cases/{case_id}/notes", {"body": body})

    def assign_incident(self, incident_id: int, case_id: int) -> None:
        self._request("POST", f"/incidents/{incident_id}/assign", {"case_id": case_id})

    def set_incident_status(self, incident_id: int, status: str) -> None:
        self._request("POST", f"/incidents/{incident_id}/status", {"status": status})

    def tag_event(self, event_id: int, tag: str) -> None:
        self._request("POST", f"/events/{event_id}/tags", {"tag": tag})

    # -- IOCs -------------------------------------------------------------

    def iocs(self) -> list[dict]:
        return self._request("GET", "/iocs")["iocs"]

    def add_ioc(self, kind: str, value: str, note: str = "") -> int:
        return self._request("POST", "/iocs",
                             {"kind": kind, "value": value, "note": note})["ioc_id"]

    def delete_ioc(self, ioc_id: int) -> None:
        self._request("DELETE", f"/iocs/{ioc_id}")

    def ioc_hits(self, limit: int = 200) -> list[dict]:
        return self._request("GET", "/iocs/hits", params={"limit": limit})["hits"]

    # -- Hive Mind (local AI) --------------------------------------------

    def ai_status(self) -> dict:
        return self._request("GET", "/ai/status")

    def ai_ask(self, question: str, case_id: int | None = None) -> dict:
        return self._request("POST", "/ai/ask",
                             {"question": question, "case_id": case_id})

    def ai_summarize(self, case_id: int) -> dict:
        return self._request("POST", f"/ai/summarize/{case_id}")
