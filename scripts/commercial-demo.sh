#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${ADSSH_DEMO_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/adssh-demo.XXXXXX")}"
BIN="$ROOT/adssh"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "demo: missing required command: $1" >&2
    exit 1
  }
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

need python3

mkdir -p "$DEMO_DIR"/{home,config,data,recordings}
POLICY="$DEMO_DIR/policy.rego"
PROFILE="$DEMO_DIR/profile.star"
RC="$DEMO_DIR/rc.star"
AUDIT="$DEMO_DIR/audit.log"
EVIDENCE="$DEMO_DIR/evidence.json"
TARGET_PORT="$(free_port)"
GATEWAY_PORT="$(free_port)"

cat >"$POLICY" <<EOF_POLICY
package adssh.authz

import future.keywords.in

default allow = false
default deny_reason = "demo policy denied this command"

allow {
  input.command in {"??", "why", "elevate", "lease", "evidence", "python3", "true"}
}

allow {
  input.command == "gateway"
  input.args[0] in {"start", "list", "stop"}
}

allow {
  input.command == "gateway"
  input.gateway.action == "connect"
  input.gateway.target_host == "127.0.0.1"
  input.gateway.target_port == "$TARGET_PORT"
  input.elevation.role == "prod-admin"
  input.elevation.reason != ""
}

deny_reason = "gateway to demo target requires prod-admin elevation" {
  input.command == "gateway"
  input.gateway.action == "connect"
  input.gateway.target_host == "127.0.0.1"
  input.gateway.target_port == "$TARGET_PORT"
  not input.elevation.role == "prod-admin"
}
EOF_POLICY

: >"$PROFILE"
: >"$RC"

python3 - "$TARGET_PORT" >"$DEMO_DIR/target.log" 2>&1 <<'PY' &
import socket
import sys
port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen()
print(f"demo target listening on 127.0.0.1:{port}", flush=True)
while True:
    conn, _ = srv.accept()
    with conn:
        data = conn.recv(4096)
        if data:
            conn.sendall(b"demo-target: " + data)
PY
TARGET_PID=$!
trap 'kill "$TARGET_PID" >/dev/null 2>&1 || true' EXIT
sleep 0.2

echo "demo: building adssh"
(cd "$ROOT" && /usr/local/bin/go build -o "$BIN" .)

cat >"$DEMO_DIR/input.adssh" <<EOF_INPUT
-gateway start --listen 127.0.0.1:$GATEWAY_PORT --target 127.0.0.1:$TARGET_PORT --name demo-prod
??
elevate request prod-admin --for 10m --reason "demo incident INC-1042"
gateway start --listen 127.0.0.1:$GATEWAY_PORT --target 127.0.0.1:$TARGET_PORT --name demo-prod
$ python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",$GATEWAY_PORT), timeout=3); s.sendall(b"hello\n"); print(s.recv(4096).decode().strip()); s.close()'
$ lease --from env:DEMO_TOKEN --as TOKEN --ttl 1m -- python3 -c 'import os; print("TOKEN=" + os.environ.get("TOKEN", ""))'
gateway list
gateway stop gw-1
evidence --out $EVIDENCE
exit
EOF_INPUT

echo "demo: running governed access walkthrough"
HOME="$DEMO_DIR/home" \
XDG_CONFIG_HOME="$DEMO_DIR/config" \
XDG_DATA_HOME="$DEMO_DIR/data" \
ADSSH_POLICY="$POLICY" \
ADSSH_PROFILE="$PROFILE" \
ADSSH_RC="$RC" \
ADSSH_AUDIT_LOG="$AUDIT" \
ADSSH_RECORD_DIR="$DEMO_DIR/recordings" \
ADSSH_GATEWAY_LOG="$DEMO_DIR/gateway_connections.jsonl" \
DEMO_TOKEN="demo-secret-token" \
"$BIN" "$DEMO_DIR/input.adssh" >"$DEMO_DIR/transcript.txt" 2>&1

python3 - "$DEMO_DIR/transcript.txt" <<'PY'
import re
import sys

raw = open(sys.argv[1], "rb").read().decode("utf-8", errors="replace")
raw = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", raw)
raw = raw.replace("\r", "\n").replace("\b", "")
interesting = (
    "DENIED",
    "elevate:",
    "gateway started:",
    "demo-target:",
    "TOKEN=",
    "gateway stopped:",
    "evidence written",
)
print("demo summary:")
for line in raw.splitlines():
    clean = line.strip()
    if clean and any(marker in clean for marker in interesting):
        print("  " + clean)
PY

echo
echo "demo complete:"
echo "  workspace:  $DEMO_DIR"
echo "  transcript: $DEMO_DIR/transcript.txt"
echo "  evidence:   $EVIDENCE"
echo "  audit:      $AUDIT"
echo "  recording:  $DEMO_DIR/recordings"
echo "  gateway log:$DEMO_DIR/gateway_connections.jsonl"
