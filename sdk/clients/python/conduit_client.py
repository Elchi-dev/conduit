"""A small Python client for the Conduit daemon API (standard library only).

    from conduit_client import Conduit
    c = Conduit("http://127.0.0.1:7600", api_key="cdt_live_...")
    for i in c.instances():
        print(i["id"], c.health(i["id"])["status"])
    out = c.invoke("web", "check_now")            # waits for approval if needed
    plan = c.invoke("dns", "set_record", {...}, dry_run=True)

Every call goes through the same permission policy as the app: if the key's
policy says "ask", invoke() returns once a person approved (or raises
Denied). See docs/api/README.md and api/openapi/daemon.yaml.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request


class ConduitError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Denied(ConduitError):
    """A person denied the approval, or it expired."""


class Conduit:
    def __init__(self, base_url="http://127.0.0.1:7600", api_key=None, timeout=60):
        self.base = base_url.rstrip("/") + "/api/v1"
        self.key = api_key
        self.timeout = timeout

    def request(self, method, path, body=None, query=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.key:
            req.add_header("Authorization", "Bearer " + self.key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                msg = json.loads(raw).get("error", e.reason)
            except ValueError:
                msg = e.reason
            raise ConduitError(e.code, msg) from None

    # --- reads -------------------------------------------------------------
    def me(self):
        return self.request("GET", "/me")[1]

    def modules(self):
        return self.request("GET", "/modules")[1]

    def instances(self):
        return self.request("GET", "/instances")[1]

    def health(self, instance):
        return self.request("GET", f"/instances/{instance}/health")[1]

    def audit(self, **query):
        return self.request("GET", "/audit", query=query)[1]

    def approvals(self, status="pending"):
        return self.request("GET", "/approvals", query={"status": status})[1]

    def ambient(self):
        return self.request("GET", "/ambient")[1]

    # --- actions -----------------------------------------------------------
    def invoke(self, instance, action, input=None, dry_run=False, wait_for_approval=True, poll=2.0, max_wait=900):
        """Call an action. Returns its output (or the plan for a dry run)."""
        body = {"dryRun": dry_run}
        if input is not None:
            body["input"] = input
        status, out = self.request("POST", f"/instances/{instance}/actions/{action}", body)
        if status == 202 and wait_for_approval:
            appr = out.get("approval") or {}
            deadline = time.time() + max_wait
            while time.time() < deadline:
                time.sleep(poll)
                a = self.request("GET", f"/approvals/{appr['id']}")[1]
                if a["status"] == "approved":
                    status, out = self.request("POST", f"/instances/{instance}/actions/{action}", body)
                    break
                if a["status"] in ("denied", "expired"):
                    raise Denied(403, f"approval {a['status']}")
            else:
                raise ConduitError(408, "still waiting for approval")
        result = (out or {}).get("result") or {}
        if dry_run:
            return result.get("plan")
        return result.get("output")

    def undo(self, seq):
        return self.request("POST", f"/audit/{seq}/undo")[1]
