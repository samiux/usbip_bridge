#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0
# Copyright (C) 2026 Samiux
# Full license text: https://www.gnu.org/licenses/gpl-3.0.txt
# License overview: https://www.gnu.org/licenses/gpl-3.0.html

"""usbip-bridge — HTTP/SSE bridge in front of the usbipctl bash supervisor.

Corrected for the client + tunnel topology:

    Browser ─► usbip-bridge ─► ssh -N -L 3240:127.0.0.1:3240 ─► remote usbipd

On the client there is NO local usbipd — the daemon lives on the remote
host and is reached through the loopback tunnel. The bridge therefore
detects CLIENT, TUNNEL, and REMOTE separately.

Stdlib only. Binds 127.0.0.1:8098 by default.
"""
from __future__ import annotations
import argparse, json, os, queue, re, shlex, socket, stat, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
CONF_PATH   = os.environ.get("USBIP_CONF_PATH", "/etc/usbip/usbip.conf")
STATIC_DIR  = os.environ.get("USBIP_BRIDGE_STATIC", "/var/lib/usbip-tunnel/static")
BIND_HOST   = os.environ.get("USBIP_BRIDGE_BIND", "127.0.0.1")
BIND_PORT   = int(os.environ.get("USBIP_BRIDGE_PORT", "8098"))
RATE_PER_MIN = int(os.environ.get("USBIP_BRIDGE_RATE", "240"))

UNIT_SERVER   = os.environ.get("USBIP_UNIT_SERVER",   "usbip-server.service")
UNIT_CLIENT   = os.environ.get("USBIP_UNIT_CLIENT",   "usbip-client.service")
UNIT_TUNNEL   = os.environ.get("USBIP_UNIT_TUNNEL",   "usbip-tunnel.service")
UNIT_FIREWALL = os.environ.get("USBIP_UNIT_FIREWALL", "usbip-tunnel-firewall.service")

ALLOWED_ORIGINS = {
    f"http://{BIND_HOST}:{BIND_PORT}",
    f"http://127.0.0.1:{BIND_PORT}",
    f"http://localhost:{BIND_PORT}",
}

ALLOWED_BINARIES = {"systemctl", "journalctl", "usbip", "usbipd", "pgrep", "modprobe", "ss", "lsmod"}
ALLOWED_UNITS = {UNIT_SERVER, UNIT_CLIENT, UNIT_TUNNEL, UNIT_FIREWALL}
ALLOWED_ACTIONS = {"start", "stop", "restart", "enable", "disable", "status"}

BUSID_RE   = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+){0,3}$")
HOST_RE    = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$")
LOG_FAC_RE = re.compile(r"^[a-z]+\.[a-z]+$")
OPTS_RE    = re.compile(r"^[A-Za-z0-9 _\-]+$")
SS_PID_RE  = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}

# The one and only port usbip CLI can talk to
USBIP_CLI_PORT = 3240

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

# ---------------------------------------------------------------------------
# Safe exec
# ---------------------------------------------------------------------------
def run(argv: list[str], timeout: float = 15.0) -> tuple[int, str, str]:
    if not argv or argv[0] not in ALLOWED_BINARIES:
        raise ApiError(500, f"binary not allowed: {argv[0] if argv else '?'}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env=SAFE_ENV, check=False)
    except FileNotFoundError:
        return 127, "", f"not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout: {' '.join(argv)}"
    return p.returncode, p.stdout, p.stderr

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def v_busid(s: Any) -> str:
    s = (s or "").strip()
    if not BUSID_RE.match(s):
        raise ApiError(400, f"invalid busid: {s!r}")
    return s

def v_host(s: Any) -> str:
    s = (s or "").strip()
    if not HOST_RE.match(s):
        raise ApiError(400, f"invalid host: {s!r}")
    return s

def v_port(n: Any, lo: int = 1) -> int:
    try: n = int(n)
    except Exception: raise ApiError(400, "invalid port")
    if not (lo <= n <= 65535):
        raise ApiError(400, "invalid port range")
    return n

def v_int(n: Any, lo: int, hi: int, field: str) -> int:
    try: n = int(n)
    except Exception: raise ApiError(400, f"{field} must be integer")
    if not (lo <= n <= hi):
        raise ApiError(400, f"{field} out of range [{lo},{hi}]")
    return n

def v_flag(n: Any, field: str) -> int:
    try: n = int(n)
    except Exception: raise ApiError(400, f"{field} must be 0 or 1")
    if n not in (0, 1):
        raise ApiError(400, f"{field} must be 0 or 1")
    return n

# ---------------------------------------------------------------------------
# Config file (schema-only write)
# ---------------------------------------------------------------------------
KV_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")

def parse_conf(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): continue
        m = KV_RE.match(line)
        if not m: continue
        key, val = m.group(1), m.group(2).strip()
        if val.startswith("(") and val.endswith(")"):
            inner = val[1:-1].strip()
            out[key] = shlex.split(inner) if inner else []
        else:
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            out[key] = val
    return out

def compose_conf(v: dict[str, Any]) -> str:
    def q(s): return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'
    def arr(items): return "()" if not items else "(" + " ".join(q(x) for x in items) + ")"
    return "\n".join([
        "# /etc/usbip/usbip.conf  —  must have root rights，640/600",
        "",
        "# ========== COMMON =============",
        f"LOG_FACILITY={v['LOG_FACILITY']}",
        f"NOTIFY_ENABLED={v['NOTIFY_ENABLED']}",
        "",
        "# ========== SERVER SECTION ==========",
        f"SRV_INTERVAL={v['SRV_INTERVAL']}",
        f"SRV_EXPORT_ONLY={arr(v['SRV_EXPORT_ONLY'])}",
        f"SRV_UNBIND_ON_STOP={v['SRV_UNBIND_ON_STOP']}",
        f"SRV_USBIPD_OPTS={q(v['SRV_USBIPD_OPTS'])}",
        "",
        "# ========== CLIENT SECTION ==========",
        f"CLI_INTERVAL={v['CLI_INTERVAL']}",
        f"CLI_SERVERS={arr(v['CLI_SERVERS'])}",
        f"CLI_TCP_PORT={v['CLI_TCP_PORT']}",
        f"CLI_DEVICES={arr(v['CLI_DEVICES'])}",
        f"CLI_DETACH_ON_REMOVE={v['CLI_DETACH_ON_REMOVE']}",
        f"CLI_DETACH_ON_STOP={v['CLI_DETACH_ON_STOP']}",
        f"CLI_LIST_TIMEOUT={v['CLI_LIST_TIMEOUT']}",
        "",
    ])

def validate_conf(v: dict[str, Any]) -> dict[str, Any]:
    out = {}
    out["LOG_FACILITY"] = str(v.get("LOG_FACILITY", "daemon.info")).strip()
    if not LOG_FAC_RE.match(out["LOG_FACILITY"]):
        raise ApiError(400, "LOG_FACILITY must look like facility.level")
    out["NOTIFY_ENABLED"]     = v_flag(v.get("NOTIFY_ENABLED", 1), "NOTIFY_ENABLED")
    out["SRV_INTERVAL"]       = v_int(v.get("SRV_INTERVAL", 3), 1, 3600, "SRV_INTERVAL")
    out["SRV_EXPORT_ONLY"]    = [v_busid(x) for x in (v.get("SRV_EXPORT_ONLY") or [])][:64]
    out["SRV_UNBIND_ON_STOP"] = v_flag(v.get("SRV_UNBIND_ON_STOP", 1), "SRV_UNBIND_ON_STOP")
    opts = str(v.get("SRV_USBIPD_OPTS", "-4")).strip()
    if opts and not OPTS_RE.match(opts):
        raise ApiError(400, "SRV_USBIPD_OPTS contains disallowed characters")
    out["SRV_USBIPD_OPTS"]      = opts
    out["CLI_INTERVAL"]         = v_int(v.get("CLI_INTERVAL", 5), 1, 3600, "CLI_INTERVAL")
    servers = [v_host(h) for h in (v.get("CLI_SERVERS") or [])][:8]
    out["CLI_SERVERS"]          = servers or ["127.0.0.1"]
    out["CLI_TCP_PORT"]         = v_port(v.get("CLI_TCP_PORT", 3240))
    out["CLI_DEVICES"]          = [v_busid(x) for x in (v.get("CLI_DEVICES") or [])][:64]
    out["CLI_DETACH_ON_REMOVE"] = v_flag(v.get("CLI_DETACH_ON_REMOVE", 1), "CLI_DETACH_ON_REMOVE")
    out["CLI_DETACH_ON_STOP"]   = v_flag(v.get("CLI_DETACH_ON_STOP", 1), "CLI_DETACH_ON_STOP")
    out["CLI_LIST_TIMEOUT"]     = v_int(v.get("CLI_LIST_TIMEOUT", 5), 1, 120, "CLI_LIST_TIMEOUT")
    return out

def read_conf_raw() -> tuple[str, dict[str, Any]]:
    try:
        text = open(CONF_PATH).read()
    except FileNotFoundError:
        return "", {}
    except PermissionError:
        raise ApiError(403, f"cannot read {CONF_PATH}")
    return text, parse_conf(text)

def conf_meta() -> dict[str, Any]:
    if not os.path.exists(CONF_PATH):
        return {"path": CONF_PATH, "exists": False}
    st = os.stat(CONF_PATH)
    return {"path": CONF_PATH, "exists": True, "owner": st.st_uid,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "root_owned": st.st_uid == 0,
            "safe_mode": stat.S_IMODE(st.st_mode) in (0o640, 0o600)}

def write_conf(v: dict[str, Any]) -> None:
    meta = conf_meta()
    if not meta.get("exists"): raise ApiError(409, f"{CONF_PATH} does not exist — create it first")
    if not meta["root_owned"]: raise ApiError(409, "config file must be owned by root")
    if not meta["safe_mode"]: raise ApiError(409, "config file must be mode 0640 or 0600")
    tmp = CONF_PATH + ".tmp"
    os.makedirs(os.path.dirname(CONF_PATH) or ".", exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(compose_conf(v)); f.flush(); os.fsync(f.fileno())
        try: os.chown(tmp, 0, 0)
        except PermissionError: pass
        os.replace(tmp, CONF_PATH)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

# ---------------------------------------------------------------------------
# systemd helpers
# ---------------------------------------------------------------------------
def unit_state(unit: str) -> dict[str, Any]:
    if unit not in ALLOWED_UNITS: raise ApiError(400, f"unknown unit: {unit}")
    _, active, _  = run(["systemctl", "is-active", unit], timeout=4)
    _, enabled, _ = run(["systemctl", "is-enabled", unit], timeout=4)
    return {"unit": unit,
            "active":  active.strip()  or "unknown",
            "enabled": enabled.strip() or "unknown"}

def all_units_state() -> list[dict[str, Any]]:
    return [unit_state(u) for u in ALLOWED_UNITS]

# ---------------------------------------------------------------------------
# Network helpers (NEW)
# ---------------------------------------------------------------------------
def tcp_connect(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def listening_on_loopback(port: int) -> dict[str, Any]:
    """Return {listening, process, pid, addr} for 127.0.0.1:port.

    Tries `ss -ltnp` first (root sees process owners), falls back to
    `ss -ltn` and then /proc/net/tcp if ss is unavailable.
    """
    result = {"listening": False, "process": None, "pid": None,
              "addr": None, "via": None}
    # --- ss with -p (root) ---------------------------------------------------
    rc, out, _ = run(["ss", "-ltnpH", f"sport = :{port}"], timeout=3)
    if rc == 0:
        for line in out.splitlines():
            if "127.0.0.1:" + str(port) not in line and "[::ffff:127.0.0.1]:" + str(port) not in line:
                continue
            result["listening"] = True
            result["addr"] = f"127.0.0.1:{port}"
            result["via"] = "ss+pid"
            m = SS_PID_RE.search(line)
            if m:
                result["process"] = m.group(1)
                result["pid"] = int(m.group(2))
            break
        if result["listening"]:
            return result
    # --- ss without -p (non-root) -------------------------------------------
    rc, out, _ = run(["ss", "-ltnH", f"sport = :{port}"], timeout=3)
    if rc == 0 and ("127.0.0.1:" + str(port) in out or "[::ffff:127.0.0.1]:" + str(port) in out):
        result["listening"] = True
        result["addr"] = f"127.0.0.1:{port}"
        result["via"] = "ss"
        return result
    # --- /proc/net/tcp fallback ---------------------------------------------
    try:
        with open("/proc/net/tcp") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":  # 0A = LISTEN
                    continue
                local = parts[1]
                if local.endswith(f":{port:04X}") and local.startswith(("0100007F", "00000000")):
                    result["listening"] = True
                    result["addr"] = f"127.0.0.1:{port}"
                    result["via"] = "/proc/net/tcp"
                    return result
    except OSError:
        pass
    return result

# ---------------------------------------------------------------------------
# Component detection (NEW)
# ---------------------------------------------------------------------------
def detect_client_supervisor() -> dict[str, Any]:
    """Client supervisor = usbipctl client, either via systemd or manual."""
    state = unit_state(UNIT_CLIENT)
    if state["active"] == "active":
        return {"active": True, "method": "systemd", "unit": state, "pid": None}
    rc, out, _ = run(["pgrep", "-af", "usbipctl client"], timeout=3)
    if rc == 0 and out.strip():
        first = out.strip().splitlines()[0]
        parts = first.split(None, 1)
        pid = None
        try: pid = int(parts[0])
        except (ValueError, IndexError): pass
        return {"active": True, "method": "pgrep", "unit": state, "pid": pid}
    return {"active": False, "method": None, "unit": state, "pid": None}

def detect_server_supervisor() -> dict[str, Any]:
    state = unit_state(UNIT_SERVER)
    if state["active"] == "active":
        return {"active": True, "method": "systemd", "unit": state, "pid": None}
    rc, out, _ = run(["pgrep", "-af", "usbipctl server"], timeout=3)
    if rc == 0 and out.strip():
        first = out.strip().splitlines()[0]
        parts = first.split(None, 1)
        pid = None
        try: pid = int(parts[0])
        except (ValueError, IndexError): pass
        return {"active": True, "method": "pgrep", "unit": state, "pid": pid}
    return {"active": False, "method": None, "unit": state, "pid": None}

def local_usbipd() -> dict[str, Any]:
    rc, out, _ = run(["pgrep", "-x", "usbipd"], timeout=3)
    pid = None
    if rc == 0 and out.strip():
        try: pid = int(out.split()[0])
        except ValueError: pid = None
    version = ""
    rc2, out2, _ = run(["usbip", "version"], timeout=2)
    if rc2 == 0 and out2.strip():
        version = out2.strip().splitlines()[0]
    return {"running": pid is not None, "pid": pid, "version": version}

def detect_tunnel() -> dict[str, Any]:
    """Detect the SSH tunnel via ss (primary), systemd, and pgrep (fallback)."""
    port = USBIP_CLI_PORT
    info = {
        "detected": False,
        "method": None,
        "port": port,
        "listening": False,
        "process": None,
        "pid": None,
        "addr": None,
        "unit": None,
        "detail": "",
    }
    # 1. ss / port check — reliable regardless of how the tunnel was launched
    lp = listening_on_loopback(port)
    info.update({k: lp[k] for k in ("listening", "process", "pid", "addr") if k in lp})

    # 2. systemd unit (authoritative if present)
    info["unit"] = unit_state(UNIT_TUNNEL)

    # 3. Decide
    if info["listening"] and info["process"] == "ssh":
        info["detected"] = True
        info["method"] = "ss+ssh"
        info["detail"] = f"ssh (pid {info['pid']}) listening on {info['addr']}"
    elif info["listening"] and info["process"] in ("usbipd",):
        # Local usbipd on the client — server-mode, not a tunnel
        info["detail"] = f"local usbipd on {info['addr']} (server mode, not a tunnel)"
    elif info["unit"]["active"] == "active":
        info["detected"] = True
        info["method"] = "systemd"
        info["detail"] = f"{UNIT_TUNNEL} is active"
        rc, out, _ = run(["systemctl", "show", "-p", "MainPID", "--value", UNIT_TUNNEL], timeout=3)
        if rc == 0 and out.strip() and out.strip() != "0":
            try: info["pid"] = int(out.strip())
            except ValueError: pass
    elif info["listening"]:
        info["detected"] = True
        info["method"] = "port"
        info["detail"] = f"{info['addr']} listening (process: {info['process'] or '?'})"
    else:
        rc, out, _ = run(["pgrep", "-af", f"ssh .*-[NL].*{port}"], timeout=3)
        if rc == 0 and out.strip():
            info["detected"] = True
            info["method"] = "pgrep"
            first = out.strip().splitlines()[0]
            info["detail"] = first[:200]
            try: info["pid"] = int(first.split(None, 1)[0])
            except (ValueError, IndexError): pass
        else:
            info["detail"] = f"nothing on 127.0.0.1:{port}; {UNIT_TUNNEL} is {info['unit']['active']}"
    return info

def probe_remote_daemon(host: str) -> dict[str, Any]:
    """Probe a usbipd via TCP + `usbip list -r`. usbip CLI always uses port 3240."""
    tcp_ok = tcp_connect(host, USBIP_CLI_PORT, timeout=3)
    if not tcp_ok:
        return {"reachable": False, "host": host, "port": USBIP_CLI_PORT,
                "tcp_ok": False, "usbip_ok": False,
                "device_count": 0, "error": f"TCP connect to {host}:{USBIP_CLI_PORT} failed"}
    rc, out, err = run(["usbip", "list", "-r", host], timeout=10)
    if rc != 0:
        combined = (out + " " + err).strip()
        return {"reachable": False, "host": host, "port": USBIP_CLI_PORT,
                "tcp_ok": True, "usbip_ok": False,
                "device_count": 0, "error": combined[:300]}
    devices = parse_usbip_list_remote(out)
    return {"reachable": True, "host": host, "port": USBIP_CLI_PORT,
            "tcp_ok": True, "usbip_ok": True,
            "device_count": len(devices), "error": ""}

# ---------------------------------------------------------------------------
# usbip output parsers
# ---------------------------------------------------------------------------
BUSID_LINE = re.compile(
    r"^\s*-\s*busid\s+([0-9][0-9a-z.\-]*)\s*\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)")

def parse_usbip_list_local(out: str) -> list[dict[str, Any]]:
    devs, cur = [], None
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line: continue
        m = BUSID_LINE.match(line)
        if m:
            busid = m.group(1)
            cur = {"busid": busid, "vid": m.group(2).lower(), "pid": m.group(3).lower(),
                   "vendor": "", "product": "", "exported": False}
            link = Path(f"/sys/bus/usb/devices/{busid}/driver")
            if link.exists():
                try: cur["exported"] = link.resolve().name == "usbip-host"
                except OSError: pass
            devs.append(cur); continue
        if cur is not None:
            m2 = re.match(r"^\s*(\S[^:]*?)\s*:\s*(.+?)\s*$", line)
            if m2 and not cur["vendor"]:
                cur["vendor"] = m2.group(1).strip()
                cur["product"] = m2.group(2).strip()
    return devs

REMOTE_PARSABLE = re.compile(r"^\s*busid=([0-9][0-9a-z.\-]*)")
REMOTE_LEGACY   = re.compile(
    r"^\s*-?\s*([0-9]+-[0-9]+(?:\.[0-9]+)*):\s*(.*?)\s*\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)\s*$")

def parse_usbip_list_remote(out: str) -> list[dict[str, Any]]:
    devs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in out.splitlines():
        m = REMOTE_PARSABLE.match(raw)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            devs.append({"busid": m.group(1), "vid": "", "pid": "",
                         "vendor": "", "product": ""})
    if devs:
        return devs
    for raw in out.splitlines():
        m = REMOTE_LEGACY.match(raw)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            desc = m.group(2)
            vendor, product = desc, ""
            if ":" in desc:
                vendor, product = [x.strip() for x in desc.split(":", 1)]
            devs.append({"busid": m.group(1),
                         "vid": m.group(3).lower(), "pid": m.group(4).lower(),
                         "vendor": vendor.strip(), "product": product.strip()})
    return devs

PORT_HEADER = re.compile(r"^Port\s+(\d+):")
PORT_BUSID  = re.compile(r"^\s+([0-9]+-[0-9]+(?:\.[0-9]+)*)\s+->\s+usbip://([^/]+)/([^\s]+)")

def parse_usbip_port(out: str) -> list[dict[str, Any]]:
    ports, cur = [], None
    for raw in out.splitlines():
        line = raw.rstrip()
        m = PORT_HEADER.match(line)
        if m:
            if cur is not None: ports.append(cur)
            cur = {"port": int(m.group(1)), "busid": "", "server": "",
                   "vendor": "", "product": "", "vid": "", "pid": ""}
            continue
        if cur is None: continue
        m = PORT_BUSID.match(line)
        if m:
            cur["busid"], cur["server"] = m.group(1), m.group(2)
            continue
        m2 = re.match(r"^\s+(\S[^:]*?)\s*:\s*(.+?)\s*\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)\s*$", line)
        if m2 and not cur["vendor"]:
            cur["vendor"] = m2.group(1).strip()
            cur["product"] = m2.group(2).strip()
            cur["vid"], cur["pid"] = m2.group(3).lower(), m2.group(4).lower()
    if cur is not None: ports.append(cur)
    return ports

def read_vhci_status() -> list[dict[str, Any]]:
    paths = sorted(Path("/sys/devices/platform").glob("vhci_hcd.*/status"))
    if not paths: return []
    try: text = paths[0].read_text()
    except OSError: return []
    ports = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 7 or parts[0] == "hub": continue
        hub, port, sta, spd, dev, sockfd, busid = parts[:7]
        try: port_num = int(port, 16)
        except ValueError: continue
        ports.append({"hub": hub, "port": port_num, "sta": sta, "spd": spd,
                      "dev": dev, "sockfd": sockfd, "busid": busid})
    return ports

def journal_lines(unit: str, n: int = 200) -> list[dict[str, str]]:
    if unit not in ALLOWED_UNITS: raise ApiError(400, "unknown unit")
    n = max(1, min(int(n), 1000))
    rc, out, _ = run(
        ["journalctl", "-u", unit, "-n", str(n), "--no-pager",
         "-o", "short-iso", "--output-fields=MESSAGE"], timeout=10)
    lines = []
    for raw in out.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+?)\[(\d+)\]:\s*(.*)$", raw)
        if m:
            lines.append({"ts": m.group(1), "host": m.group(2),
                          "proc": m.group(3), "pid": m.group(4), "msg": m.group(5)})
        elif raw.strip():
            lines.append({"ts": "", "host": "", "proc": "", "pid": "", "msg": raw})
    return lines

# ---------------------------------------------------------------------------
# Composite status (NEW STRUCTURE)
# ---------------------------------------------------------------------------
def compute_topology(client, server_local, tunnel, remote_daemon) -> str:
    if server_local["supervisor_active"] or server_local["usbipd_running"]:
        return "server"
    if client["supervisor_active"]:
        if tunnel["detected"]:
            return "tunnel"
        if remote_daemon["reachable"]:
            return "direct"
        return "client-orphan"
    if tunnel["detected"]:
        return "tunnel-only"
    return "unknown"

def compute_health(client, server_local, tunnel, remote_daemon) -> str:
    server_ok = server_local["supervisor_active"] and server_local["usbipd_running"]
    if server_ok: return "ok"
    client_ok = client["supervisor_active"]
    remote_ok = remote_daemon["reachable"]
    tunnel_ok = tunnel["detected"]
    if client_ok and remote_ok: return "ok"
    if client_ok and tunnel_ok and not remote_ok: return "err"
    if client_ok and not tunnel_ok and not remote_ok: return "warn"
    if not client_ok and not server_local["supervisor_active"]: return "err"
    return "warn"

def full_status() -> dict[str, Any]:
    _, cfg = read_conf_raw()

    # Units
    units = {u["unit"]: u for u in all_units_state()}

    # Components
    client = detect_client_supervisor()
    server_local = detect_server_supervisor()
    daemon = local_usbipd()
    modules = {m: Path(f"/sys/module/{m}").is_dir()
               for m in ("usbip_core", "usbip_host", "vhci_hcd")}
    tunnel = detect_tunnel()

    # Effective remote host
    servers = cfg.get("CLI_SERVERS") or ["127.0.0.1"]
    client_active = client["active"]
    if client_active and tunnel["detected"]:
        effective_host = "127.0.0.1"     # via tunnel
        via = "tunnel"
    elif client_active and servers:
        effective_host = servers[0]      # direct
        via = "direct"
    elif tunnel["detected"]:
        effective_host = "127.0.0.1"
        via = "tunnel"
    else:
        effective_host = servers[0] if servers else "127.0.0.1"
        via = "none"
    remote = probe_remote_daemon(effective_host)
    remote["via"] = via

    # Ports
    rc, out, _ = run(["usbip", "port"], timeout=4)
    attached = parse_usbip_port(out) if rc == 0 else []
    vhci = read_vhci_status()

    # Assemble
    client_view = {
        "supervisor_active": client_active,
        "method": client["method"],
        "pid": client["pid"],
        "unit": units.get(UNIT_CLIENT),
        "vhci_loaded": modules.get("vhci_hcd", False),
        "usbip_core_loaded": modules.get("usbip_core", False),
        "attached_count": len(attached),
    }
    server_view = {
        "supervisor_active": server_local["active"],
        "method": server_local["method"],
        "pid": server_local["pid"],
        "unit": units.get(UNIT_SERVER),
        "usbipd_running": daemon["running"],
        "usbipd_pid": daemon["pid"],
        "version": daemon["version"],
    }
    return {
        "role": ("mixed" if client_active and server_local["active"]
                 else "client" if client_active
                 else "server" if server_local["active"]
                 else "unknown"),
        "topology": compute_topology(client_view, server_view, tunnel, remote),
        "overall_health": compute_health(client_view, server_view, tunnel, remote),

        "client": client_view,
        "server_local": server_view,
        "tunnel": tunnel,
        "remote_daemon": remote,

        "units": units,
        "config": cfg,
        "conf_meta": conf_meta(),
        "modules": modules,
        "ports": {"attached": attached, "vhci": vhci},
    }

# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------
def diagnose() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def chk(name, ok, detail, severity="err"):
        checks.append({"name": name, "ok": ok, "detail": detail, "severity": severity})

    chk("bridge", True, "running", "ok")

    for mod in ("usbip_core", "usbip_host", "vhci_hcd"):
        loaded = Path(f"/sys/module/{mod}").is_dir()
        chk(f"module {mod}", loaded, "loaded" if loaded else f"modprobe {mod}", "warn")

    for unit in (UNIT_CLIENT, UNIT_SERVER, UNIT_TUNNEL):
        state = unit_state(unit)
        chk(unit, state["active"] == "active",
            f"active={state['active']} enabled={state['enabled']}", "warn")

    lp = listening_on_loopback(USBIP_CLI_PORT)
    chk(f"127.0.0.1:{USBIP_CLI_PORT} listening", lp["listening"],
        f"{lp['addr']} via {lp['via']} (process: {lp['process'] or '?'}, pid: {lp['pid'] or '?'})",
        "err")
    if lp["listening"] and lp["process"] == "ssh":
        chk("listener is ssh", True, f"pid {lp['pid']} — tunnel is up", "ok")
    elif lp["listening"]:
        chk("listener is ssh", False,
            f"process is {lp['process'] or '?'}, not ssh — this is likely a local usbipd, not a tunnel", "warn")

    probe = probe_remote_daemon("127.0.0.1")
    chk("remote daemon via 127.0.0.1",
        probe["reachable"],
        (f"reachable — {probe['device_count']} exportable device(s)" if probe["reachable"]
         else f"unreachable — tcp_ok={probe['tcp_ok']} usbip_ok={probe['usbip_ok']} err={probe['error']}"),
        "err")

    return {"checks": checks, "timestamp": int(time.time())}

# ---------------------------------------------------------------------------
# SSE poller
# ---------------------------------------------------------------------------
class Poller(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True, name="poller")
        self.subs: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.last: dict[str, Any] = {}

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=200)
        with self.lock: self.subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock: self.subs.discard(q)

    def publish(self, ev: dict[str, Any]) -> None:
        msg = ("data: " + json.dumps(ev, ensure_ascii=False) + "\n\n").encode()
        with self.lock:
            dead = []
            for q in self.subs:
                try: q.put_nowait(msg)
                except queue.Full: dead.append(q)
            for q in dead: self.subs.discard(q)

    def run(self) -> None:
        tick = 0
        while True:
            tick += 1
            try:
                snap = full_status()
                keys = ("overall_health", "topology", "client", "tunnel",
                        "remote_daemon", "server_local", "ports")

                # cheap keys every 2 s
                payload = {k: snap.get(k) for k in keys}

                # heavier keys every 5 s (4th tick of 2 s cycle ≈ 8 s)
                if tick % 4 == 0:
                    rc, out, _ = run(["usbip", "list", "-l"], timeout=8)
                    payload["local"] = parse_usbip_list_local(out) if rc == 0 else []

                    host = "127.0.0.1"
                    if snap["tunnel"]["detected"] or snap["remote_daemon"]["via"] == "tunnel":
                        host = "127.0.0.1"
                    else:
                        servers = snap["config"].get("CLI_SERVERS") or ["127.0.0.1"]
                        host = servers[0]
                    rc, out, _ = run(["usbip", "list", "-r", host], timeout=8)
                    payload["remote"] = {
                        "host": host,
                        "devices": parse_usbip_list_remote(out) if rc == 0 else [],
                        "reachable": rc == 0,
                    }
                    payload["units"] = {u["unit"]: u for u in all_units_state()}

                for k, v in payload.items():
                    if self.last.get(k) != v:
                        self.last[k] = v
                        self.publish({"type": k, "data": v})
            except Exception as e:
                self.publish({"type": "error", "data": str(e)})
            time.sleep(2)

POLLER = Poller()

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, per_min: int) -> None:
        self.per_min = per_min; self.buckets: dict[str, tuple[float, int]] = {}
        self.lock = threading.Lock()
    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            start, count = self.buckets.get(key, (now, 0))
            if now - start >= 60: start, count = now, 0
            if count >= self.per_min: return False
            self.buckets[key] = (start, count + 1); return True

LIMITER = RateLimiter(RATE_PER_MIN)

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "usbip-bridge/2.0"

    def log_message(self, fmt, *args):
        msg = fmt % args
        if '"/api/' in msg and " 200 " in msg: return
        sys.stderr.write(msg + "\n")

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try: length = int(self.headers.get("Content-Length") or 0)
        except ValueError: length = 0
        if length <= 0 or length > 1 << 20: return b""
        return self.rfile.read(length)

    def _json_body(self):
        raw = self._read_body()
        if not raw: return {}
        try: obj = json.loads(raw.decode())
        except Exception: raise ApiError(400, "invalid JSON body")
        if not isinstance(obj, dict): raise ApiError(400, "JSON body must be an object")
        return obj

    def _guard(self, method):
        if not LIMITER.allow(self.client_address[0]):
            raise ApiError(429, "rate limited")
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            raise ApiError(403, "origin not allowed")
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            if self.headers.get("X-Requested-With") != "usbip-bridge":
                raise ApiError(403, "missing X-Requested-With: usbip-bridge")

    def do_GET(self):
        try: self._guard("GET"); self._route("GET")
        except ApiError as e: self._send_json(e.code, {"error": e.message})
        except Exception as e: self._send_json(500, {"error": str(e)})

    def do_PUT(self):
        try: self._guard("PUT"); self._route("PUT")
        except ApiError as e: self._send_json(e.code, {"error": e.message})
        except Exception as e: self._send_json(500, {"error": str(e)})

    def do_POST(self):
        try: self._guard("POST"); self._route("POST")
        except ApiError as e: self._send_json(e.code, {"error": e.message})
        except Exception as e: self._send_json(500, {"error": str(e)})

    def _route(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)

        if method == "GET":
            if path == "/api/version":
                return self._send_json(200, {"name": "usbip-bridge", "version": "2.0", "api": "2"})
            if path == "/api/status":
                return self._send_json(200, full_status())
            if path == "/api/diagnose":
                return self._send_json(200, diagnose())
            if path == "/api/config":
                text, cfg = read_conf_raw()
                return self._send_json(200, {"meta": conf_meta(), "raw": text, "values": cfg})
            if path == "/api/units":
                return self._send_json(200, all_units_state())
            if path == "/api/devices/local":
                rc, out, _ = run(["usbip", "list", "-l"], timeout=10)
                return self._send_json(200, parse_usbip_list_local(out) if rc == 0 else [])
            if path == "/api/devices/remote":
                host = v_host((qs.get("host") or [""])[0])
                rc, out, _ = run(["usbip", "list", "-r", host], timeout=10)
                if rc != 0: raise ApiError(502, f"usbip list -r {host} failed")
                return self._send_json(200, parse_usbip_list_remote(out))
            if path == "/api/ports":
                rc, out, _ = run(["usbip", "port"], timeout=4)
                return self._send_json(200, {
                    "attached": parse_usbip_port(out) if rc == 0 else [],
                    "vhci":     read_vhci_status(),
                })
            if path == "/api/logs":
                unit = (qs.get("unit") or [""])[0]
                n = int((qs.get("n") or ["200"])[0])
                return self._send_json(200, journal_lines(unit, n))
            if path == "/api/events":
                return self._serve_events()
            if path in ("/", "", "/index.html"):
                return self._serve_static("index.html")
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            raise ApiError(404, "not found")

        if method == "PUT":
            if path == "/api/config":
                body = self._json_body()
                clean = validate_conf(body)
                write_conf(clean)
                POLLER.publish({"type": "config", "values": clean})
                return self._send_json(200, {"ok": True, "values": clean})
            raise ApiError(404, "not found")

        if method == "POST":
            if path == "/api/tunnel/probe":
                return self._send_json(200, diagnose())
            if path.startswith("/api/units/"):
                parts = path.split("/")
                if len(parts) != 5: raise ApiError(400, "bad unit path")
                name, action = parts[3], parts[4]
                if name not in ALLOWED_UNITS: raise ApiError(400, "unknown unit")
                if action not in ALLOWED_ACTIONS: raise ApiError(400, "unknown action")
                if action == "status":
                    return self._send_json(200, unit_state(name))
                rc, out, err = run(["systemctl", action, name], timeout=20)
                if rc != 0:
                    raise ApiError(500, f"systemctl {action} {name}: {(err or out).strip()}")
                return self._send_json(200, {"ok": True, "unit": name, "action": action})
            if path == "/api/bind":
                b = self._json_body(); busid = v_busid(b.get("busid"))
                rc, out, err = run(["usbip", "bind", "-b", busid], timeout=10)
                if rc != 0: raise ApiError(500, f"usbip bind -b {busid}: {(err or out).strip()}")
                POLLER.publish({"type": "bind", "busid": busid})
                return self._send_json(200, {"ok": True})
            if path == "/api/unbind":
                b = self._json_body(); busid = v_busid(b.get("busid"))
                rc, out, err = run(["usbip", "unbind", "-b", busid], timeout=10)
                if rc != 0: raise ApiError(500, f"usbip unbind -b {busid}: {(err or out).strip()}")
                POLLER.publish({"type": "unbind", "busid": busid})
                return self._send_json(200, {"ok": True})
            if path == "/api/attach":
                b = self._json_body()
                host  = v_host(b.get("host"))
                busid = v_busid(b.get("busid"))
                rc, out, err = run(["usbip", "attach", "-r", host, "-b", busid], timeout=30)
                if rc != 0: raise ApiError(500, f"usbip attach -r {host} -b {busid}: {(err or out).strip()}")
                POLLER.publish({"type": "attach", "host": host, "busid": busid})
                return self._send_json(200, {"ok": True})
            if path == "/api/detach":
                b = self._json_body()
                port = v_int(b.get("port", 0), 0, 32, "port")
                rc, out, err = run(["usbip", "detach", "-p", str(port)], timeout=10)
                if rc != 0: raise ApiError(500, f"usbip detach -p {port}: {(err or out).strip()}")
                POLLER.publish({"type": "detach", "port": port})
                return self._send_json(200, {"ok": True})
            raise ApiError(404, "not found")

        raise ApiError(405, "method not allowed")

    def _serve_static(self, rel):
        rel = rel.lstrip("/")
        base = Path(STATIC_DIR).resolve()
        target = (base / rel).resolve()
        try: target.relative_to(base)
        except ValueError: raise ApiError(403, "forbidden")
        if not target.is_file(): raise ApiError(404, "not found")
        ctype = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
                 ".ico": "image/x-icon"}.get(target.suffix.lower(), "application/octet-stream")
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_events(self):
        q = POLLER.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b": connected\n\n"); self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=20)
                    self.wfile.write(msg); self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n"); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            POLLER.unsubscribe(q)

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main():
    global CONF_PATH, STATIC_DIR
    ap = argparse.ArgumentParser(description="usbip-bridge — HTTP front for usbipctl")
    ap.add_argument("--bind",   default=BIND_HOST)
    ap.add_argument("--port",   type=int, default=BIND_PORT)
    ap.add_argument("--conf",   default=CONF_PATH)
    ap.add_argument("--static", default=STATIC_DIR)
    args = ap.parse_args()
    CONF_PATH, STATIC_DIR = args.conf, args.static
    if os.geteuid() != 0:
        sys.stderr.write("warning: not running as root — ss -p may not show process owners\n")
    POLLER.start()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    sys.stderr.write(f"usbip-bridge listening on http://{args.bind}:{args.port}\n")
    sys.stderr.write(f"  conf   = {CONF_PATH}\n")
    sys.stderr.write(f"  static = {STATIC_DIR}\n")
    try: httpd.serve_forever()
    except KeyboardInterrupt: pass
    finally: httpd.server_close()

if __name__ == "__main__":
    main()
