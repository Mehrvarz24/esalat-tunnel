#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  esalat-tunnel — one-script installer / manager
#
#    curl -fsSL https://raw.githubusercontent.com/Mehrvarz24/esalat-tunnel/main/esalat.sh | bash
#
#  Installs the easalt binary, writes a hardened systemd unit, tunes the host
#  (BBR, fq, socket buffers, DNS) and manages the link between an Iran box and
#  an abroad box. Everything runs from the standard library — no third-party
#  runtime, no telemetry, no phone-home.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
GH_REPO="${ESALAT_REPO:-Mehrvarz24/esalat-tunnel}"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac
BIN_URL="${ESALAT_BIN_URL:-https://github.com/${GH_REPO}/releases/latest/download/easalt-linux-${ARCH}}"
BIN=/usr/local/bin/easalt
CONF_DIR=/etc/easalt
STATE_DIR=/var/lib/esalat
UNITS=(easalt-abroad easalt-iran)
DEFAULT_PORT=440
DEFAULT_TARGET=127.0.0.1:8443
DEFAULT_DECOY=www.cloudflare.com:80
DEFAULT_DECOY_TLS=www.cloudflare.com:443
DEFAULT_SNI=www.microsoft.com
DEFAULT_WS_PATH=/ws

C_OK=$'\033[38;5;114m'; C_WARN=$'\033[38;5;179m'; C_ERR=$'\033[38;5;203m'
C_DIM=$'\033[38;5;245m'; C_GOLD=$'\033[38;5;179m'; C_B=$'\033[1m'; C_0=$'\033[0m'

banner() {
  cat <<EOF
${C_GOLD}
   ███████╗ ███████╗  █████╗  ██╗      █████╗  ████████╗
   ██╔════╝ ██╔════╝ ██╔══██╗ ██║     ██╔══██╗ ╚══██╔══╝
   █████╗   ███████╗ ███████║ ██║     ███████║    ██║
   ██╔══╝   ╚════██║ ██╔══██║ ██║     ██╔══██║    ██║
   ███████╗ ███████║ ██║  ██║ ███████╗██║  ██║    ██║
   ╚══════╝ ╚══════╝ ╚═╝  ╚═╝ ╚══════╝╚═╝  ╚═╝    ╚═╝
${C_0}${C_DIM}      🔒 t u n n e l 🔒   Iran ⇄ abroad · one port · no trace
      v${VERSION} · tls / websocket · decoy fallback · no telemetry${C_0}
EOF
}

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✅%s %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s⚠️%s %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '%s❌%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$C_DIM" "────────────────────────────────────────────────────────────" "$C_0"; }

# interactive input that also works under `curl | bash`.
# The terminal test has to happen HERE, at top level: ask() is called inside a
# command substitution, and a subshell's stdout is a pipe, so `[[ -t 1 ]]`
# evaluated inside it would always be false and every question would silently
# take its default.
INTERACTIVE=0
TTY_IN=""
if [[ "${ESALAT_NONINTERACTIVE:-0}" != 1 ]]; then
  if [[ -t 1 || -t 2 ]]; then
    if [[ -r /dev/tty ]]; then TTY_IN=/dev/tty; INTERACTIVE=1
    elif [[ -t 0 ]]; then TTY_IN=/dev/stdin; INTERACTIVE=1; fi
  fi
fi

ask() { # ask <prompt> <default> -> echoes answer
  local p="$1" d="${2:-}" a=""
  if [[ "$INTERACTIVE" != 1 ]]; then
    printf '%s' "$d"; return
  fi
  read -r -p "$(printf '%s%s%s%s' "$C_B" "$p" "$C_0" "${d:+ [$d]}") " a < "$TTY_IN" || true
  printf '%s' "${a:-$d}"
}

need_root() { [[ "$(id -u)" == 0 ]] || die "run as root (sudo)"; }

have() { command -v "$1" >/dev/null 2>&1; }

install_deps() {
  say "${C_DIM}📦 installing deps…${C_0}"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq curl ca-certificates iproute2 >/dev/null 2>&1 || true
  elif have dnf; then
    dnf install -y -q curl ca-certificates iproute >/dev/null 2>&1 || true
  elif have apk; then
    apk add --no-cache curl ca-certificates iproute2 >/dev/null 2>&1 || true
  fi
  have curl && ok "curl present" || warn "curl missing — binary download will need another way"
}

fetch_binary() {
  local src="$1"
  if [[ -n "$src" && -f "$src" ]]; then install -m 0755 "$src" "$BIN"; ok "installed local binary → $BIN"; return; fi
  have curl || die "curl is required to download the binary"
  say "${C_DIM}⬇️  downloading $BIN_URL${C_0}"
  local tmp; tmp="$(mktemp)"
  if curl -fsSL --retry 3 -o "$tmp" "$BIN_URL"; then
    install -m 0755 "$tmp" "$BIN"; rm -f "$tmp"; ok "installed $BIN"
  else
    rm -f "$tmp"
    die "download failed. Set ESALAT_BIN_URL or pass --bin /path/to/easalt (build: go build -o easalt .)"
  fi
}

gen_token() { head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 40; }

read_conf_value() { [[ -f "$1" ]] && grep -E "^$2=" "$1" | cut -d= -f2- || true; }

# ── install ───────────────────────────────────────────────────────────────────
cmd_install() {
  local role="$1" transport= port= server= token= target= sessions=4 pin= sni= decoy= decoy_tls= ws_path= tune=1 bin="" listen=""
  shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --transport) transport="$2"; shift 2;; --port|--link-port) port="$2"; shift 2;;
      --server) server="$2"; shift 2;; --token) token="$2"; shift 2;;
      --target) target="$2"; shift 2;; --sessions) sessions="$2"; shift 2;;
      --pin) pin="$2"; shift 2;; --sni) sni="$2"; shift 2;;
      --decoy) decoy="$2"; shift 2;; --decoy-tls) decoy_tls="$2"; shift 2;;
      --ws-path) ws_path="$2"; shift 2;; --listen) listen="$2"; shift 2;;
      --no-tune) tune=0; shift;;
      --tune) tune=1; shift;; --bin) bin="$2"; shift 2;;
      *) die "unknown option: $1";;
    esac
  done

  [[ "$role" == abroad || "$role" == iran ]] || die "role must be abroad or iran"
  hr
  if [[ "$role" == abroad ]]; then say "🌍 ${C_B}role${C_0}     abroad (tunnel server)"; else say "🇮🇷 ${C_B}role${C_0}     iran (tunnel client)"; fi

  transport="$(ask "protocol [tls/ws/tcp]" "${transport:-tls}")"
  [[ "$transport" =~ ^(tls|ws|tcp)$ ]] || die "protocol must be tls, ws or tcp"
  [[ "$transport" == tcp ]] && warn "tcp has no encryption — testing only 🧪"

  port="$(ask "tunnel port" "${port:-$DEFAULT_PORT}")"
  [[ "$port" =~ ^[0-9]+$ ]] || die "port must be a number"
  [[ "$transport" == ws ]] && ws_path="$(ask "websocket path" "${ws_path:-$DEFAULT_WS_PATH}")"
  if [[ "$role" == iran ]]; then listen="$(ask "listen address for users" "${listen:-:$port}")"; else listen=":$port"; fi
  [[ -z "$ws_path" ]] && ws_path="$DEFAULT_WS_PATH"

  if [[ "$role" == iran ]]; then
    server="$(ask "abroad server IP/host" "$server")"
    [[ -n "$server" ]] || die "abroad server address is required"
    target="$(ask "target on the abroad side" "${target:-$DEFAULT_TARGET}")"
    sessions="$(ask "parallel sessions" "${sessions:-4}")"
    pin="$(ask "server certificate pin (optional, from the abroad setup)" "${pin:-}")"
    sni="$(ask "SNI to send" "${sni:-$DEFAULT_SNI}")"
    decoy=""; decoy_tls=""
  else
    decoy="$(ask "plain-HTTP decoy host:port" "${decoy:-$DEFAULT_DECOY}")"
    decoy_tls="$(ask "TLS decoy host:port" "${decoy_tls:-$DEFAULT_DECOY_TLS}")"
    sni="$(ask "certificate name(s)" "${sni:-$DEFAULT_SNI}")"
  fi

  # an explicit --token always wins; otherwise reuse whatever this role was
  # installed with, so re-running the installer cannot split the two ends
  local existing="$CONF_DIR/$role.env"
  if [[ -z "$token" ]]; then
    token="$(read_conf_value "$existing" EASALT_TOKEN)"
    [[ -z "$token" ]] || warn "reusing the token from $existing"
  fi
  [[ -n "$token" ]] || token="$(gen_token)"

  install_deps
  fetch_binary "$bin"

  install -d -m 0750 "$CONF_DIR"
  if [[ "$role" == abroad ]]; then
    cat > "$existing" <<EOF
# esalat-tunnel — abroad (server)
EASALT_TOKEN=$token
EASALT_TRANSPORT=$transport
EASALT_WS_PATH=$ws_path
EASALT_LISTEN=:$port
EASALT_ALLOW=127.0.0.1
EASALT_DECOY=$decoy
EASALT_DECOY_TLS=$decoy_tls
EASALT_SNI=$sni
EASALT_STATS=127.0.0.1:9101
EOF
  else
    cat > "$existing" <<EOF
# esalat-tunnel — iran (client)
EASALT_TOKEN=$token
EASALT_TRANSPORT=$transport
EASALT_WS_PATH=$ws_path
EASALT_SERVER=$server
EASALT_LINK_PORT=$port
EASALT_LISTEN=$listen
EASALT_TARGET=$target
EASALT_SESSIONS=$sessions
EASALT_PIN=$pin
EASALT_SNI=$sni
EASALT_STATS=127.0.0.1:9100
EOF
  fi
  chmod 0600 "$existing"
  ok "config → $existing 🔐"

  if [[ "${ESALAT_NO_SYSTEMD:-0}" == 1 ]]; then
    warn "ESALAT_NO_SYSTEMD=1 — skipping unit + service start"
  else
    write_unit "$role"
    systemctl daemon-reload
    systemctl enable --now "easalt-$role" >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet "easalt-$role"; then ok "easalt-$role is running 🟢"
    else warn "service did not start — journalctl -u easalt-$role -n 30 🔴"; fi
  fi

  if [[ "$tune" == 1 && "${ESALAT_NO_SYSTEMD:-0}" != 1 ]]; then
    cmd_tune --yes || true
  fi

  [[ "$role" == abroad ]] && sleep 1 && cmd_pin || true
  show_summary "$role"
}

write_unit() {
  local role="$1"
  local unit="/etc/systemd/system/easalt-$role.service"
  local exec
  if [[ "$role" == abroad ]]; then
    exec='/usr/local/bin/easalt server -listen ${EASALT_LISTEN} -token ${EASALT_TOKEN} -transport ${EASALT_TRANSPORT} -ws-path ${EASALT_WS_PATH} -allow ${EASALT_ALLOW} -decoy ${EASALT_DECOY} -decoy-tls ${EASALT_DECOY_TLS} -sni ${EASALT_SNI} -stats ${EASALT_STATS}'
  else
    exec='/usr/local/bin/easalt client -server ${EASALT_SERVER} -link-port ${EASALT_LINK_PORT} -token ${EASALT_TOKEN} -transport ${EASALT_TRANSPORT} -ws-path ${EASALT_WS_PATH} -listen ${EASALT_LISTEN} -target ${EASALT_TARGET} -sessions ${EASALT_SESSIONS} -sni ${EASALT_SNI} -pin ${EASALT_PIN} -stats ${EASALT_STATS}'
  fi
  cat > "$unit" <<EOF
[Unit]
Description=esalat-tunnel ($role)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONF_DIR/$role.env
ExecStart=$exec
Restart=always
RestartSec=3
LimitNOFILE=1048576
StateDirectory=esalat
StateDirectoryMode=0750
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
  ok "systemd unit → $unit 🛠️"
}

cmd_pin() {
  if [[ -x "$BIN" ]]; then
    local p; p="$("$BIN" pin -cert-dir "$STATE_DIR" 2>&1 | sed 's/.*: //' || true)"
    [[ -n "$p" ]] && say "🔐 ${C_B}server pin${C_0}  $p   ${C_DIM}(paste this on the iran side)${C_0}"
  fi
}

show_summary() {
  local role="$1" c="$CONF_DIR/$role.env"
  hr
  say "🎉 ${C_B}summary${C_0}"
  say "  📌 role      : $role"
  say "  🔑 token     : $(read_conf_value "$c" EASALT_TOKEN)"
  say "  📡 protocol  : $(read_conf_value "$c" EASALT_TRANSPORT)"
  say "  🔌 port      : $(read_conf_value "$c" EASALT_LISTEN)"
  if [[ "$role" == iran ]]; then
    say "  🌍 server    : $(read_conf_value "$c" EASALT_SERVER)"
    say "  🎯 target    : $(read_conf_value "$c" EASALT_TARGET)"
    say "  👥 clients connect to this box on port $(read_conf_value "$c" EASALT_LISTEN | tr -d ':')"
  else
    say "  🛡️  allow     : $(read_conf_value "$c" EASALT_ALLOW)   🎭 decoy: $(read_conf_value "$c" EASALT_DECOY)"
    say "  ➡️  next      : run this script on the iran box, role=iran, same token"
  fi
  hr
  say "${C_DIM}📊 status: systemctl status easalt-$role${C_0}"
  say "${C_DIM}📜 logs  : journalctl -u easalt-$role -f${C_0}"
  say "${C_DIM}📈 stats : curl -s 127.0.0.1:$([[ "$role" == iran ]] && echo 9100 || echo 9101)/stats${C_0}"
}

# ── other commands ────────────────────────────────────────────────────────────
cmd_status() {
  hr
  for u in "${UNITS[@]}"; do
    if systemctl list-unit-files | grep -q "^$u.service"; then
      local st; st="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
      local icon="🔴"; [[ "$st" == active ]] && icon="🟢"
      printf '%s %-14s %s\n' "$icon" "$u" "$st"
    fi
  done
  hr
  for p in 9100 9101; do
    local j; j="$(curl -s -m 2 "http://127.0.0.1:$p/stats" || true)"
    [[ -n "$j" ]] && say "📈 $([[ $p == 9100 ]] && echo client || echo server)  $p : $j"
  done
  [[ -x "$BIN" ]] && say "binary   : $($BIN -h 2>&1 | head -0; echo "$BIN ($(stat -c%s "$BIN") bytes)")"
}

cmd_uninstall() {
  need_root
  local purge="${1:-}"
  hr
  for u in "${UNITS[@]}"; do
    if systemctl list-unit-files | grep -q "^$u.service"; then
      systemctl disable --now "$u" >/dev/null 2>&1 || true
      ok "stopped and disabled $u 🧹"
    fi
  done
  if [[ "$purge" == "--purge" ]]; then
    rm -f /etc/systemd/system/easalt-*.service
    rm -rf "$CONF_DIR" "$STATE_DIR"
    rm -f /usr/local/bin/easalt /etc/sysctl.d/99-esalat.conf /etc/security/limits.d/99-esalat.conf
    systemctl daemon-reload
    ok "removed binary, configs, state and tuning 🗑️"
  else
    rm -f /etc/systemd/system/easalt-*.service
    systemctl daemon-reload
    ok "units removed; config kept in $CONF_DIR (add --purge to wipe everything) 📁"
  fi
}

cmd_tune() {
  need_root
  local best_effort=0
  [[ "${1:-}" == "--yes" ]] && best_effort=1
  local cc; cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  if [[ "$cc" != *bbr* ]]; then
    warn "BBR not available in this kernel — skipping congestion-control change"
  fi
  cat > /etc/sysctl.d/99-esalat.conf <<'EOF'
# esalat-tunnel node tuning
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.core.netdev_max_backlog = 8192
fs.file-max = 1000000
EOF
  if [[ "$cc" == *bbr* ]]; then
    cat >> /etc/sysctl.d/99-esalat.conf <<'EOF'
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
  fi
  sysctl --system >/dev/null 2>&1 || true
  cat > /etc/security/limits.d/99-esalat.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
  ok "tuned ⚡ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo n/a) / $(sysctl -n net.core.default_qdisc 2>/dev/null || echo n/a) · fd limit raised"
  if have getent; then
    if getent hosts github.com >/dev/null 2>&1; then ok "dns answers 🌐"
    else
      warn "dns is not answering — writing fallback resolvers 🌐"
      printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\noptions timeout:2 attempts:2\n' > /etc/resolv.conf
    fi
  fi
  [[ "$best_effort" == 1 ]] && return 0
}

cmd_menu() {
  banner
  hr
  say "${C_B}1${C_0}) 🚀 install      ${C_DIM}abroad or iran node${C_0}"
  say "${C_B}2${C_0}) 📊 status       ${C_DIM}services + live stats${C_0}"
  say "${C_B}3${C_0}) ⚡ tune host    ${C_DIM}BBR, fq, buffers, dns${C_0}"
  say "${C_B}4${C_0}) 🔑 regenerate token"
  say "${C_B}5${C_0}) 🧹 uninstall    ${C_DIM}keep config${C_0}"
  say "${C_B}6${C_0}) 🗑️  purge        ${C_DIM}remove everything${C_0}"
  say "${C_B}7${C_0}) 👋 exit"
  hr
  local choice; choice="$(ask "👉 choose" "1")"
  case "$choice" in
    1)
      local role; role="$(ask "which side is this box? [abroad/iran]" "abroad")"
      need_root
      cmd_install "$role" ;;
    2) cmd_status ;;
    3) cmd_tune ;;
    4)
      need_root
      local t; t="$(gen_token)"
      for r in abroad iran; do
        local f="$CONF_DIR/$r.env"
        [[ -f "$f" ]] || continue
        sed -i "s|^EASALT_TOKEN=.*|EASALT_TOKEN=$t|" "$f"
        systemctl restart "easalt-$r" >/dev/null 2>&1 || true
        ok "new token for $r 🔑 — update the other side too"
      done
      say "token: $t" ;;
    5) cmd_uninstall ;;
    6) cmd_uninstall --purge ;;
    7|q|exit) exit 0 ;;
    *) die "unknown choice" ;;
  esac
}

usage() {
  banner
  cat <<EOF

${C_B}usage${C_0}
  esalat.sh                            interactive menu
  esalat.sh install <abroad|iran> [options]
  esalat.sh status | tune | uninstall [--purge] | pin

${C_B}install options${C_0}
  --transport tls|ws|tcp   wire protocol        (default tls)
  --port N                 tunnel port          (default $DEFAULT_PORT)
  --server IP              abroad address        (iran role, required)
  --target HOST:PORT       what the server dials (iran role, default $DEFAULT_TARGET)
  --sessions N             parallel sessions     (iran role, default 4)
  --pin PIN                server cert pin       (iran role, from the abroad side)
  --sni NAME               SNI to send / cert name
  --decoy HOST:PORT        plain-HTTP decoy      (abroad role)
  --decoy-tls HOST:PORT    TLS decoy             (abroad role)
  --ws-path PATH           websocket path        (transport ws)
  --token SECRET           shared secret         (generated if omitted)
  --bin PATH               use a local easalt binary instead of downloading
  --no-tune                skip host tuning

${C_B}env${C_0}
  ESALAT_BIN_URL   override the download URL
  ESALAT_NO_SYSTEMD=1   write files only (tests)
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    "")            cmd_menu ;;
    install)       shift; need_root; cmd_install "$@" ;;
    status)        cmd_status ;;
    tune)          shift; cmd_tune "$@" ;;
    uninstall)     shift; cmd_uninstall "$@" ;;
    purge)         cmd_uninstall --purge ;;
    pin)           cmd_pin ;;
    -h|--help|help) usage ;;
    *)             usage; exit 2 ;;
  esac
}

main "$@"
