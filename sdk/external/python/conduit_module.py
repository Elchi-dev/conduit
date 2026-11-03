"""Conduit external module kit for Python (protocol v1).

Copy this file next to your module, subclass Module, and call run(). No
dependencies beyond the standard library. See docs/protocol/external-modules.md.

    from conduit_module import Module, ActionError, run

    class Weather(Module):
        manifest = {...}
        def invoke(self, instance, action, input, dry_run):
            ...

    run(Weather())
"""
import json
import sys
import threading
import queue
import itertools

PROTOCOL = "1"


class ActionError(Exception):
    """Raise to fail an action with a message the person sees."""


class Host:
    """What Conduit gives a module: secrets, events and logs."""

    def __init__(self, conn):
        self._conn = conn

    def secret(self, ref):
        """Resolve a "secret://name" reference from this instance's settings."""
        return self._conn.call("host.secret", {"ref": ref})

    def publish(self, type, data=None, instance=None):
        ev = {"type": type, "module": "", "data": data}
        if instance:
            ev["instance"] = instance
        self._conn.notify("host.publish", ev)

    def log(self, msg, level="info", **kv):
        flat = []
        for k, v in kv.items():
            flat += [k, v]
        self._conn.notify("host.log", {"level": level, "msg": msg, "kv": flat})


class Module:
    """Override manifest and invoke; the rest has sensible defaults."""

    manifest = {"id": "example", "name": "Example", "version": "0.1.0", "actions": []}

    def configure(self, host, instance, config):
        """Validate and store an instance's settings. Raise to reject them."""

    def invoke(self, instance, action, input, dry_run):
        """Run an action. Return a dict: {"output": ...}, optionally with
        "plan" (for dry runs) or "undo"."""
        raise ActionError("unknown action " + action)

    def health(self, instance):
        return {"status": "ok"}

    def close(self, instance):
        pass


class _Conn:
    def __init__(self, inp, out):
        self._in, self._out = inp, out
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._pending = {}

    def send(self, msg):
        line = json.dumps(msg, separators=(",", ":"))
        with self._lock:
            self._out.write(line + "\n")
            self._out.flush()

    def call(self, method, params):
        i = next(self._ids)
        q = queue.Queue(1)
        self._pending[i] = q
        self.send({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
        msg = q.get(timeout=60)
        if "error" in msg:
            raise ActionError(msg["error"].get("message", "host error"))
        return msg.get("result")

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})


def run(module, inp=sys.stdin, out=sys.stdout):
    """Serve module over stdin/stdout until Conduit closes the stream."""
    conn = _Conn(inp, out)
    host = Host(conn)

    def handle(msg):
        method, params, mid = msg.get("method"), msg.get("params") or {}, msg.get("id")
        try:
            if method == "initialize":
                result = {"protocolVersion": PROTOCOL, "manifest": module.manifest}
            elif method == "configure":
                module.configure(host, params.get("instance"), params.get("config") or {})
                result = {}
            elif method == "invoke":
                result = module.invoke(params.get("instance"), params.get("action"), params.get("input"), bool(params.get("dryRun")))
                if result is None:
                    result = {}
            elif method == "health":
                result = module.health(params.get("instance"))
            elif method == "close":
                module.close(params.get("instance"))
                result = {}
            else:
                conn.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: " + str(method)}})
                return
            conn.send({"jsonrpc": "2.0", "id": mid, "result": result})
        except Exception as e:  # noqa: BLE001 - every failure goes back to Conduit
            conn.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": str(e)}})

    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "method" in msg:
            threading.Thread(target=handle, args=(msg,), daemon=True).start()
        elif "id" in msg and msg["id"] in conn._pending:
            conn._pending.pop(msg["id"]).put(msg)
