"""Protocol test: drives the kit like the daemon does. python3 test_conduit_module.py"""
import io
import json
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
code = r'''
import sys
sys.path.insert(0, %r)
from conduit_module import Module, run
class Echo(Module):
    manifest = {"id": "echo", "name": "Echo", "version": "1.0.0", "actions": [{"name": "echo", "risk": "read"}, {"name": "secret", "risk": "read"}]}
    def configure(self, host, instance, config):
        self.host = host
    def invoke(self, instance, action, input, dry_run):
        if action == "secret":
            return {"output": len(self.host.secret("secret://k"))}
        return {"output": input}
run(Echo())
''' % here
p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

def send(m):
    p.stdin.write(json.dumps(m) + "\n")
    p.stdin.flush()

def recv():
    return json.loads(p.stdout.readline())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1"}})
r = recv(); assert r["result"]["manifest"]["id"] == "echo", r
send({"jsonrpc": "2.0", "id": 2, "method": "configure", "params": {"instance": "e", "config": {}}})
assert recv()["id"] == 2
send({"jsonrpc": "2.0", "id": 3, "method": "invoke", "params": {"instance": "e", "action": "echo", "input": {"x": 1}}})
r = recv(); assert r["result"]["output"] == {"x": 1}, r
send({"jsonrpc": "2.0", "id": 4, "method": "invoke", "params": {"instance": "e", "action": "secret"}})
req = recv(); assert req["method"] == "host.secret", req
send({"jsonrpc": "2.0", "id": req["id"], "result": "abcdef"})
r = recv(); assert r["result"]["output"] == 6, r
send({"jsonrpc": "2.0", "id": 5, "method": "nope"})
r = recv(); assert r["error"]["code"] == -32601, r
p.stdin.close(); p.wait(timeout=5)
print("ok")
