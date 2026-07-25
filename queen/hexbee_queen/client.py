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

    def ai_howto(self, question: str) -> dict:
        """Operator assistance, answered from the Hive's grounded manual."""
        return self._request("POST", "/ai/howto", {"question": question})

    def knowledge_search(self, query: str, limit: int = 5) -> list[dict]:
        return self._request("GET", "/knowledge/search",
                             params={"q": query, "limit": limit})["results"]

    # -- ingest (active tooling pushing its own findings) ------------------

    def ingest(self, events: list[dict], ingest_key: str) -> dict:
        """POST findings into the evidence chain.

        Uses the shared ingest key rather than the session token, so Queen
        tools follow exactly the same path as Scout, Comb, and Forager — one
        write path into the chain, no exceptions.
        """
        url = f"{self.base_url}/api/v1/ingest"
        req = urllib.request.Request(
            url, data=json.dumps(events).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "X-HexBee-Ingest-Key": ingest_key})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read().decode()).get("error", exc.reason)
            except Exception:
                message = exc.reason
            raise HiveError(exc.code, message) from exc

    # -- engagement scope --------------------------------------------------

    def scope_list(self, case_id: int | None = None) -> list[dict]:
        return self._request("GET", "/scope", params={"case_id": case_id})["scope"]

    def scope_add(self, kind: str, value: str, **fields) -> dict:
        body = {"kind": kind, "value": value}
        body.update({k: v for k, v in fields.items() if v is not None})
        return self._request("POST", "/scope", body)

    def scope_delete(self, rule_id: int) -> None:
        self._request("DELETE", f"/scope/{rule_id}")

    def scope_check(self, target: str, case_id: int | None = None) -> dict:
        return self._request("GET", "/scope/check",
                             params={"target": target, "case_id": case_id})

    def scope_violation(self, target: str, tool: str, reason: str,
                        extra: dict | None = None) -> dict:
        return self._request("POST", "/scope/violation",
                             {"target": target, "tool": tool,
                              "reason": reason, "extra": extra or {}})

    # -- ATT&CK ------------------------------------------------------------

    def attack_coverage(self, case_id: int | None = None) -> dict:
        path = f"/attack/coverage/{case_id}" if case_id else "/attack/coverage"
        return self._request("GET", path)

    def event_techniques(self, event_id: int) -> list[dict]:
        return self._request("GET", f"/events/{event_id}/techniques")["techniques"]

    # -- case mode ---------------------------------------------------------

    def set_case_mode(self, case_id: int, mode: str) -> dict:
        return self._request("POST", f"/cases/{case_id}/mode", {"mode": mode})

    # -- threat intel ------------------------------------------------------

    def intel_status(self) -> dict:
        return self._request("GET", "/intel/status")

    # -- engagement report -------------------------------------------------

    def engagement_data(self, case_id: int) -> dict:
        """Structured report data, assembled Hive-side.

        Same payload the dashboard preview uses, so the preview an analyst
        reviews and the document a client receives are built from one source.
        """
        return self._request("GET", f"/cases/{case_id}/engagement")
