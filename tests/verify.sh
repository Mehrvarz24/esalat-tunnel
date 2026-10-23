#!/usr/bin/env bash
# End-to-end verification of the PUBLISHED artifacts (esalat.sh + release binary).
# Everything runs on this box with two local "nodes"; nothing touches real servers.
set -uo pipefail

PORT=${PORT:-1599}
UPORT=${UPORT:-1600}
BIN=/usr/local/bin/easalt
TOKEN="VERIFY$(date +%s)"
PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
res()  { if [[ "$2" == ok ]]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; else FAIL=$((FAIL+1)); printf '  FAIL  %s  (%s)\n' "$1" "$3"; fi; }
hrs()  { printf '%s\n' "--------------------------------------------------------------"; }
wait_ready() {
  local i
  for i in $(seq 1 20); do
    if [[ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:$UPORT/big.bin)" == "200" ]]; then return 0; fi
    sleep 1
  done
  return 1
}


cd /tmp/esalat-verify || exit 1
SCRIPT=/tmp/esalat-verify/pub.sh
curl -fsSL -m 30 -o "$SCRIPT" "https://raw.githubusercontent.com/Mehrvarz24/esalat-tunnel/v1.0.6/esalat.sh" || { echo "cannot fetch script"; exit 1; }


hrs; say "phase 0: cleanup"
bash "$SCRIPT" uninstall --purge >/dev/null 2>&1
systemctl stop easalt-abroad easalt-iran >/dev/null 2>&1
pkill -x easalt >/dev/null 2>&1
sleep 1
say "  state clean: $([[ ! -e /etc/easalt ]] && echo yes || echo no)"

hrs; say "phase 1: install via the published one-liner (tls + udp)"
out=$(cat "$SCRIPT" | ESALAT_SKIP_DEPS=1 ESALAT_NONINTERACTIVE=1 bash -s install abroad --transport tls --port $PORT --token "$TOKEN" --decoy 127.0.0.1:9999 --decoy-tls 127.0.0.1:9998 --no-tune 2>&1)
echo "$out" | grep -q "service easalt-abroad is running" && res "abroad service started" ok || res "abroad service started" fail "$(echo "$out" | tail -2)"
PIN=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'pin +[A-Za-z0-9+/=]+' | awk '{print $2}' | head -1)
[[ -n "$PIN" ]] && res "installer printed a pin" ok || res "installer printed a pin" fail "no pin in output"
out2=$(cat "$SCRIPT" | ESALAT_SKIP_DEPS=1 ESALAT_NONINTERACTIVE=1 bash -s install iran --transport tls --port $PORT --listen :$UPORT --server 127.0.0.1 --target 127.0.0.1:8443 --udp --udp-target 127.0.0.1:9555 --token "$TOKEN" --pin "$PIN" --sessions 3 --no-tune 2>&1)
echo "$out2" | grep -q "service easalt-iran is running" && res "iran service started" ok || res "iran service started" fail "$(echo "$out2" | tail -2)"
wait_ready || true

SV=$(grep -m1 '^VERSION=' "$SCRIPT" | cut -d'"' -f2)
BV=$("$BIN" version 2>/dev/null | awk '{print $2}')
[[ -n "$BV" && "$BV" == "$SV" ]] && res "installed binary reports the script's version ($BV)" ok || res "installed binary reports the script's version" fail "script=$SV binary=$BV"

hrs; say "phase 2: sessions, pin, stats"
c=$(curl -s -m 5 http://127.0.0.1:9100/stats)
live=$(python3 -c "import json,sys;print(json.loads('''$c''').get('sessions_live'))" 2>/dev/null)
[[ "$live" == "3" ]] && res "session pool honours -sessions 3 (live=$live)" ok || res "session pool honours -sessions 3 (live=$live)" fail "$c"
grep -q "EASALT_PIN=$PIN" /etc/easalt/iran.env && res "client pin matches the printed one" ok || res "client pin matches the printed one" fail "$(grep EASALT_PIN /etc/easalt/iran.env)"
journalctl -u easalt-iran --since "-4 min" --no-pager -o cat 2>/dev/null | grep -qi "pin mismatch"

hrs; say "phase 3: TCP through the tunnel"
curl -s -m 90 -o /tmp/esalat-verify/out.bin -w '%{http_code} %{size_download} %{speed_download}\n' http://127.0.0.1:$UPORT/big.bin > /tmp/esalat-verify/tcp.txt 2>&1
read -r code size speed < /tmp/esalat-verify/tcp.txt
[[ "$code" == "200" && "$size" == "20000000" ]] && res "20MB over TCP (http=$code, ${speed%.*} B/s)" ok || res "20MB over TCP" fail "$(cat /tmp/esalat-verify/tcp.txt)"
a=$(sha256sum /tmp/tun-test/big.bin | cut -d' ' -f1); b=$(sha256sum /tmp/esalat-verify/out.bin | cut -d' ' -f1)
[[ "$a" == "$b" ]] && res "payload is bit-identical" ok || res "payload is bit-identical" fail "$a vs $b"

hrs; say "phase 4: UDP through the same port"
python3 - <<'PY' > /tmp/esalat-verify/udp.txt 2>&1
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(6)
ok = 0
for i in range(20):
    c.sendto(b"pkt%02d" % i, ("127.0.0.1", 1600))
try:
    while True:
        d, _ = c.recvfrom(65535); ok += 1
except Exception:
    pass
c2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c2.settimeout(6)
c2.sendto(b"x"*1200, ("127.0.0.1", 1600))
big = False
try:
    d, _ = c2.recvfrom(65535); big = d == b"echo:" + b"x"*1200
except Exception:
    pass
print(f"datagrams={ok} big_ok={big}")
PY
grep -q "datagrams=20" /tmp/esalat-verify/udp.txt && res "udp: 20/20 datagrams returned, boundaries kept" ok || res "udp datagrams" fail "$(cat /tmp/esalat-verify/udp.txt)"
grep -q "big_ok=True" /tmp/esalat-verify/udp.txt && res "udp: 1200B datagram intact" ok || res "udp 1200B datagram" fail "$(cat /tmp/esalat-verify/udp.txt)"

hrs; say "phase 5: probes and wrong credentials"
p1=$(curl -s -m 6 http://127.0.0.1:$PORT/ | head -c 15)
[[ "$p1" == *DOCTYPE* || "$p1" == *html* ]] && res "plain HTTP probe gets the decoy site" ok || res "plain HTTP probe gets the decoy site" fail "$p1"
p2=$(curl -sk -m 8 https://127.0.0.1:$PORT/ | head -c 12)
[[ "$p2" == "hello-decoy"* ]] && res "TLS probe gets the TLS decoy" ok || res "TLS probe gets the TLS decoy" fail "$p2"
timeout 8 "$BIN" client -server 127.0.0.1 -link-port $PORT -token WRONG -listen 127.0.0.1:1611 -target 127.0.0.1:8443 -sessions 1 -stats "" > /tmp/esalat-verify/wrong.log 2>&1
sleep 2
w=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:1611/big.bin)
errs=$(curl -s -m 5 http://127.0.0.1:9101/stats | python3 -c "import json,sys;print(json.load(sys.stdin)['errors'])" 2>/dev/null)
[[ "$w" == "000" && "$errs" -gt 0 ]] && res "wrong token: user gets nothing, server counts errors" ok || res "wrong token" fail "http=$w errors=$errs"

hrs; say "phase 6: restart resilience"
systemctl stop easalt-abroad; sleep 1
t0=$(date +%s.%N)
curl -s -m 20 -o /dev/null -w '%{http_code}' http://127.0.0.1:$UPORT/big.bin > /dev/null 2>&1
t1=$(date +%s.%N)
down=$(python3 -c "print(f'{$t1-$t0:.2f}')")
systemctl start easalt-abroad
rec=""
for i in $(seq 1 10); do
  sleep 1
  if [[ "$(curl -s -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:$UPORT/big.bin)" == "200" ]]; then rec="$i"; break; fi
done
[[ -n "$rec" ]] && res "recovers after the peer returns (down ${down}s, back ${rec}s)" ok || res "recovers after the peer returns" fail "still failing after 10s"

hrs; say "phase 7: websocket transport (fresh install)"
bash "$SCRIPT" uninstall --purge >/dev/null 2>&1; sleep 1
outws=$(cat "$SCRIPT" | ESALAT_SKIP_DEPS=1 ESALAT_NONINTERACTIVE=1 bash -s install abroad --transport ws --ws-path /ws --port $PORT --token "$TOKEN" --decoy 127.0.0.1:9999 --decoy-tls 127.0.0.1:9998 --no-tune 2>&1)
echo "$outws" | grep -q "running" && res "ws: abroad installed" ok || res "ws: abroad installed" fail "$(echo "$outws" | tail -2)"
PIN2=$("$BIN" pin -cert-dir /var/lib/esalat 2>&1 | sed 's/.*: //')
cat "$SCRIPT" | ESALAT_SKIP_DEPS=1 ESALAT_NONINTERACTIVE=1 bash -s install iran --transport ws --ws-path /ws --ws-host example.com --port $PORT --listen :$UPORT --server 127.0.0.1 --target 127.0.0.1:8443 --token "$TOKEN" --pin "$PIN2" --sessions 2 --no-tune >/dev/null 2>&1
wait_ready || true
code=$(curl -s -m 60 -o /tmp/esalat-verify/ws.bin -w '%{http_code}' http://127.0.0.1:$UPORT/big.bin)
b=$(sha256sum /tmp/esalat-verify/ws.bin 2>/dev/null | cut -d' ' -f1)
[[ "$code" == "200" && "$a" == "$b" ]] && res "20MB over the websocket transport" ok || res "20MB over the websocket transport" fail "http=$code"
p3=$(curl -s -m 6 http://127.0.0.1:$PORT/ | head -c 12)
[[ "$p3" == *DOCTYPE* || "$p3" == *html* ]] && res "ws port also serves the decoy to a browser" ok || res "ws port decoy" fail "$p3"

hrs; say "phase 8: interactive behaviour (prompts + Ctrl+C)"
IPY=$(cat <<'EOP'
import os, pty, select, time, sys
def run(inputs, max_wait=25):
    pid, fd = pty.fork()
    if pid == 0:
        e = dict(os.environ); e.update({"ESALAT_SKIP_DEPS":"1","ESALAT_BIN_URL":os.environ.get("ESALAT_BIN_URL","")})
        e["TERM"]="xterm-256color"
        os.execvpe("bash", ["bash", "/tmp/esalat-verify/pub.sh"], e); os._exit(1)
    out=b""
    def drain(t):
        nonlocal out
        end=time.time()+t
        while time.time()<end:
            r,_,_=select.select([fd],[],[],0.05)
            if r:
                try: c=os.read(fd,65536)
                except OSError: return False
                if not c: return False
                out+=c
        return True
    def alive():
        try:
            w,_=os.waitpid(pid, os.WNOHANG); return w==0
        except ChildProcessError: return False
    drain(1.5)
    for item in inputs:
        os.write(fd, item.encode())
        drain(0.8)
    t0=time.time(); exited=False
    while time.time()-t0<max_wait:
        drain(0.3)
        if not alive(): exited=True; break
    if not exited:
        os.kill(pid,9)
    try: os.waitpid(pid,0)
    except OSError: pass
    return out.decode("utf-8","replace"), exited
o1,e1=run(["1\n","\x03"],max_wait=8)
o2,e2=run(["1\n","abroad\n","\x03"],max_wait=8)
o3,_=run(["1\n","abroad\n","tls\n","1599\n"],max_wait=20)
clean=lambda t: __import__("re").sub(r"\x1b\[[0-9;]*m","",t)
print("CTRLC_MENU", "ok" if e1 else "fail")
print("CTRLC_QUESTION", "ok" if e2 else "fail")
print("PROMPTS", "ok" if ("tunnel port [440] > 1599" in clean(o3) or "tunnel port [440] › 1599" in clean(o3)) else "fail")
EOP
)
ires=$(python3 -c "$IPY" 2>/dev/null)
grep -q "CTRLC_MENU ok" <<<"$ires" && res "Ctrl+C exits from the menu" ok || res "Ctrl+C exits from the menu" fail "$ires"
grep -q "CTRLC_QUESTION ok" <<<"$ires" && res "Ctrl+C exits at a question" ok || res "Ctrl+C exits at a question" fail "$ires"
grep -q "PROMPTS ok" <<<"$ires" && res "answers are actually read (port 1599 applied)" ok || res "answers are actually read" fail "$ires"

hrs
printf 'results: %s passed, %s failed\n' "$PASS" "$FAIL"
bash "$SCRIPT" uninstall --purge >/dev/null 2>&1
pkill -x easalt >/dev/null 2>&1
exit $(( FAIL > 0 ))
