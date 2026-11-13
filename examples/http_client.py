"""Minimal real Streamable HTTP client; start the two README servers first."""

import json
import os
from urllib.request import Request, urlopen


def main():
    url = os.environ.get("MCP_GUARD_URL", "http://127.0.0.1:8765/mcp")
    headers = {
        "Authorization": "Bearer " + os.environ["MCP_GUARD_TOKEN"],
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    def send(method, params=None, request_id=1):
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if request_id is not None:
            body["id"] = request_id
        request = Request(url, data=json.dumps(body).encode(), headers=headers)
        with urlopen(request, timeout=20) as response:
            data = response.read()
            return json.loads(data) if data else None, response.headers

    initialized, response_headers = send(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "example", "version": "1"},
        },
    )
    headers["Mcp-Session-Id"] = response_headers["Mcp-Session-Id"]
    headers["MCP-Protocol-Version"] = initialized["result"]["protocolVersion"]
    try:
        send("notifications/initialized", request_id=None)
        listed, _ = send("tools/list", request_id=2)
        print("Tools:", ", ".join(tool["name"] for tool in listed["result"]["tools"]))
        called, _ = send(
            "tools/call", {"name": "demo__echo", "arguments": {}}, request_id=3
        )
        print(json.dumps(called, indent=2))
    finally:
        with urlopen(Request(url, method="DELETE", headers=headers), timeout=20):
            pass


if __name__ == "__main__":
    main()
