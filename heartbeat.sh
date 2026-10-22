#!/usr/bin/env bash
# Sends a short liveness line every 2 min. Status text comes from
# /root/esalat-tunnel/STATUS.txt (first line = what I am doing now).
while true; do
  sleep 120
  NOW=$(date -u '+%H:%M:%S')
  ST=$(head -1 /root/esalat-tunnel/STATUS.txt 2>/dev/null)
  SB=$(curl -s -m 2 http://127.0.0.1:9100/stats 2>/dev/null | head -c 120)
  SS=$(curl -s -m 2 http://127.0.0.1:9101/stats 2>/dev/null | head -c 120)
  MSG="⏱ زنده‌ام · $NOW UTC
کار: ${ST:-–}
کلاینت: ${SB:-off}
سرور: ${SS:-off}"
  printf '%s\n' "$MSG" | hermes send -t telegram >/dev/null 2>&1
done
