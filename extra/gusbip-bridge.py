#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
"""
gusbip-bridge.py — Tkinter desktop console for USB/IP Bridge.

Run as your normal user (NOT with sudo). Privileged operations are
escalated per-command via `sudo -n` or `pkexec`.

The Remote USB Devices area shows a "no exported devices" row and a
raw-output viewer so you can see exactly what usbip returned.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "USB/IP Bridge — GUI Console"
CONF_PATH = Path(os.environ.get("USBIP_CONF_PATH", "/etc/usbip/usbip.conf"))
USBIP_PORT = 3240

UNIT_SERVER = os.environ.get("USBIP_UNIT_SERVER", "usbip-server.service")
UNIT_CLIENT = os.environ.get("USBIP_UNIT_CLIENT", "usbip-client.service")
UNIT_TUNNEL = os.environ.get("USBIP_UNIT_TUNNEL", "usbip-tunnel.service")
UNIT_FIREWALL = os.environ.get(
    "USBIP_UNIT_FIREWALL", "usbip-tunnel-firewall.service"
)

UNITS = {
    "server": UNIT_SERVER,
    "client": UNIT_CLIENT,
    "tunnel": UNIT_TUNNEL,
    "firewall": UNIT_FIREWALL,
}

ALLOWED_BINARIES = {
    "systemctl", "journalctl", "usbip", "usbipd",
    "pgrep", "modprobe", "ss", "lsmod",
    "cat", "tee",
}

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}

BUSID_RE = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+){0,3}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$")
SS_PID_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
UNIT_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-@.]+\.service$")

HTTP_URL_SERVER = os.environ.get(
    "USBIP_HTTP_URL_SERVER", "http://127.0.0.1:18098"
)
HTTP_URL_CLIENT = os.environ.get(
    "USBIP_HTTP_URL_CLIENT", "http://127.0.0.1:8098"
)

LOCALHOSTS = {"127.0.0.1", "localhost", "::1"}


# ---------------------------------------------------------------------------
# Privilege layer
# ---------------------------------------------------------------------------

_PRIV_PREFIX: list[str] = []
_PRIV_MODE: str = "none"


def detect_privilege_mode() -> str:
    global _PRIV_PREFIX, _PRIV_MODE
    if os.geteuid() == 0:
        _PRIV_PREFIX = []
        _PRIV_MODE = "root"
        return "root"
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            timeout=3, env=dict(SAFE_ENV),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r.returncode == 0:
            _PRIV_PREFIX = ["sudo", "-n"]
            _PRIV_MODE = "sudo"
            return "sudo"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if shutil.which("pkexec"):
        _PRIV_PREFIX = ["pkexec"]
        _PRIV_MODE = "pkexec"
        return "pkexec"
    _PRIV_PREFIX = []
    _PRIV_MODE = "none"
    return "none"


def _priv_env() -> dict[str, str]:
    if _PRIV_PREFIX == ["pkexec"]:
        return dict(os.environ)
    return dict(SAFE_ENV)


# ---------------------------------------------------------------------------
# Safe subprocess helper
# ---------------------------------------------------------------------------

def run_cmd(
    argv: list[str],
    timeout: float = 20.0,
    env_extra: dict[str, str] | None = None,
    as_root: bool = False,
) -> tuple[int, str, str]:
    if not argv or argv[0] not in ALLOWED_BINARIES:
        raise RuntimeError(f"command not allowed: {argv[0] if argv else '?'}")
    if as_root and _PRIV_PREFIX:
        argv = [*_PRIV_PREFIX, *argv]
        if _PRIV_PREFIX == ["pkexec"]:
            timeout = max(timeout, 60.0)
    env = _priv_env()
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout, env=env, check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout: {' '.join(argv)}"


def check_cmd(
    argv: list[str], timeout: float = 20.0,
    action: str = "", as_root: bool = False,
) -> str:
    rc, out, err = run_cmd(argv, timeout=timeout, as_root=as_root)
    if rc != 0:
        raise RuntimeError(
            f"{action or argv[0]} failed ({rc}): {(err or out).strip()[:800]}"
        )
    return out


# ---------------------------------------------------------------------------
# Local HTTP probe
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: float = 6.0) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError(f"unsupported URL scheme: {parsed.scheme!r}")
    if parsed.hostname not in LOCALHOSTS:
        raise RuntimeError(
            f"only localhost URLs are allowed, got {parsed.hostname!r}"
        )
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "usbip-bridge-gui/1.0", "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(64 * 1024).decode("utf-8", errors="replace")
            return {
                "url": url, "status": resp.status, "reason": resp.reason,
                "headers": dict(resp.headers), "body": body, "error": "",
            }
    except urllib.error.HTTPError as exc:
        return {
            "url": url, "status": exc.code, "reason": exc.reason,
            "headers": dict(exc.headers or {}), "body": "", "error": str(exc),
        }
    except Exception as exc:
        raise RuntimeError(f"GET {url} failed: {exc}")


def probe_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

BUSID_LINE = re.compile(
    r"^\s*-\s*busid\s+([0-9][0-9a-z.\-]*)\s*\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)"
)
REMOTE_PARSABLE = re.compile(r"^\s*busid=([0-9][0-9a-z.\-]*)")
REMOTE_LEGACY = re.compile(
    r"^\s*-?\s*([0-9]+-[0-9]+(?:\.[0-9]+)*):\s*(.*?)\s*"
    r"\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)\s*$"
)
PORT_HEADER = re.compile(r"^Port\s+(\d+):")
PORT_BUSID = re.compile(
    r"^\s+([0-9]+-[0-9]+(?:\.[0-9]+)*)\s+->\s+usbip://([^/]+)/([^\s]+)"
)


def parse_local_usbip(
    out: str, check_sysfs: bool = True
) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        m = BUSID_LINE.match(line)
        if m:
            busid = m.group(1)
            current = {
                "busid": busid,
                "vid": m.group(2).lower(),
                "pid": m.group(3).lower(),
                "vendor": "", "product": "", "exported": False,
            }
            if check_sysfs:
                driver = Path(f"/sys/bus/usb/devices/{busid}/driver")
                if driver.exists():
                    try:
                        current["exported"] = (
                            driver.resolve().name == "usbip-host"
                        )
                    except OSError:
                        pass
            devices.append(current)
            continue
        if current is not None:
            m2 = re.match(r"^\s*(\S[^:]*?)\s*:\s*(.+?)\s*$", line)
            if m2 and not current["vendor"]:
                current["vendor"] = m2.group(1).strip()
                current["product"] = m2.group(2).strip()
    return devices


def parse_remote_usbip(out: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in out.splitlines():
        m = REMOTE_PARSABLE.match(raw)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            devices.append({
                "busid": m.group(1), "vid": "", "pid": "",
                "vendor": "", "product": "",
            })
    if devices:
        return devices
    for raw in out.splitlines():
        m = REMOTE_LEGACY.match(raw)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            desc = m.group(2)
            vendor, product = desc, ""
            if ":" in desc:
                vendor, product = [x.strip() for x in desc.split(":", 1)]
            devices.append({
                "busid": m.group(1),
                "vid": m.group(3).lower(), "pid": m.group(4).lower(),
                "vendor": vendor.strip(), "product": product.strip(),
            })
    return devices


def parse_usbip_port(out: str) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in out.splitlines():
        line = raw.rstrip()
        m = PORT_HEADER.match(line)
        if m:
            if current is not None:
                ports.append(current)
            current = {
                "port": int(m.group(1)),
                "busid": "", "server": "", "vendor": "",
                "product": "", "vid": "", "pid": "",
            }
            continue
        if current is None:
            continue
        m = PORT_BUSID.match(line)
        if m:
            current["busid"], current["server"] = m.group(1), m.group(2)
            continue
        m2 = re.match(
            r"^\s+(\S[^:]*?)\s*:\s*(.+?)\s*\(([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\)\s*$",
            line,
        )
        if m2 and not current["vendor"]:
            current["vendor"] = m2.group(1).strip()
            current["product"] = m2.group(2).strip()
            current["vid"], current["pid"] = (
                m2.group(3).lower(), m2.group(4).lower()
            )
    if current is not None:
        ports.append(current)
    return ports


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class USBIPBackend:
    def unit_state(self, unit: str) -> dict[str, str]:
        _, active, _ = run_cmd(["systemctl", "is-active", unit], timeout=4)
        _, enabled, _ = run_cmd(["systemctl", "is-enabled", unit], timeout=4)
        return {
            "unit": unit,
            "active": active.strip() or "unknown",
            "enabled": enabled.strip() or "unknown",
        }

    def all_units(self) -> dict[str, dict[str, str]]:
        return {name: self.unit_state(unit) for name, unit in UNITS.items()}

    def list_loaded_usbip_units(self) -> list[dict[str, str]]:
        rc, out, err = run_cmd(
            ["systemctl", "list-units", "--type=service", "--all",
             "--no-pager", "--no-legend"], timeout=10,
        )
        result: list[dict[str, str]] = []
        if rc not in (0, 1):
            raise RuntimeError(
                f"systemctl list-units failed ({rc}): "
                f"{(err or out).strip()[:400]}"
            )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("●"):
                line = line[1:].strip()
            parts = line.split(None, 4)
            if not parts or "usbip" not in parts[0].lower():
                continue
            result.append({
                "unit": parts[0],
                "load": parts[1] if len(parts) > 1 else "",
                "active": parts[2] if len(parts) > 2 else "",
                "sub": parts[3] if len(parts) > 3 else "",
            })
        return result

    def list_installed_usbip_units(self) -> list[dict[str, str]]:
        rc, out, err = run_cmd(
            ["systemctl", "list-unit-files", "--type=service",
             "--no-pager", "--no-legend"], timeout=10,
        )
        result: list[dict[str, str]] = []
        if rc not in (0, 1):
            raise RuntimeError(
                f"systemctl list-unit-files failed ({rc}): "
                f"{(err or out).strip()[:400]}"
            )
        for line in out.splitlines():
            parts = line.split()
            if not parts or "usbip" not in parts[0].lower():
                continue
            result.append({
                "unit": parts[0],
                "state": parts[1] if len(parts) > 1 else "",
            })
        return result

    def local_devices(self) -> list[dict[str, Any]]:
        out = check_cmd(["usbip", "list", "-l"], timeout=10, action="usbip list -l")
        return parse_local_usbip(out, check_sysfs=True)

    # -- remote listing: capture raw, try parseable fallback -------------

    def remote_devices(self, host: str = "127.0.0.1") -> dict[str, Any]:
        host = host.strip() or "127.0.0.1"
        if not HOST_RE.match(host):
            raise RuntimeError(f"invalid host: {host!r}")

        tcp_ok = probe_tcp(host, USBIP_PORT, timeout=3)

        rc, out, err = run_cmd(["usbip", "list", "-r", host], timeout=10)
        raw_human = (out or "") + (("\n[stderr]\n" + err) if err.strip() else "")

        if rc != 0:
            return {
                "host": host, "devices": [], "reachable": False,
                "tcp_ok": tcp_ok,
                "error": (err or out).strip()[:500] or f"usbip list -r exit {rc}",
                "raw": raw_human,
            }

        devices = parse_remote_usbip(out)
        raw = raw_human

        # If human format didn't parse but there is output, try -p mode.
        if not devices and out.strip():
            rc2, out2, err2 = run_cmd(
                ["usbip", "list", "-r", host, "-p"], timeout=10
            )
            if rc2 == 0 and out2.strip():
                devices = parse_remote_usbip(out2)
                raw = (
                    raw_human
                    + "\n\n--- usbip list -r -p ---\n"
                    + out2
                    + (("\n[stderr]\n" + err2) if err2.strip() else "")
                )
            else:
                raw = (
                    raw_human
                    + "\n\n--- usbip list -r -p (exit "
                    + str(rc2)
                    + ") ---\n"
                    + (out2 or err2 or "")
                )

        return {
            "host": host,
            "devices": devices,
            "reachable": True,
            "tcp_ok": tcp_ok,
            "error": "",
            "raw": raw,
        }

    def ports(self) -> list[dict[str, Any]]:
        rc, out, _ = run_cmd(["usbip", "port"], timeout=8)
        return parse_usbip_port(out) if rc == 0 else []

    def bind(self, busid: str) -> str:
        busid = self._validate_busid(busid)
        return check_cmd(
            ["usbip", "bind", "-b", busid],
            action="usbip bind", as_root=True,
        )

    def unbind(self, busid: str) -> str:
        busid = self._validate_busid(busid)
        return check_cmd(
            ["usbip", "unbind", "-b", busid],
            action="usbip unbind", as_root=True,
        )

    def attach(self, busid: str, host: str = "127.0.0.1") -> str:
        busid = self._validate_busid(busid)
        host = host.strip() or "127.0.0.1"
        if not HOST_RE.match(host):
            raise RuntimeError(f"invalid host: {host!r}")
        return check_cmd(
            ["usbip", "attach", "-r", host, "-b", busid],
            action="usbip attach", as_root=True,
        )

    def detach(self, port: int) -> str:
        return check_cmd(
            ["usbip", "detach", "-p", str(int(port))],
            action="usbip detach", as_root=True,
        )

    def unit_action(self, action: str, unit: str) -> str:
        if action not in {"start", "stop", "restart", "enable", "disable"}:
            raise RuntimeError(f"invalid systemctl action: {action}")
        if not UNIT_NAME_RE.match(unit):
            raise RuntimeError(f"invalid unit: {unit!r}")
        return check_cmd(
            ["systemctl", action, unit], timeout=30,
            action=f"systemctl {action} {unit}", as_root=True,
        )

    def journal(self, unit: str, lines: int = 250) -> str:
        if not UNIT_NAME_RE.match(unit):
            raise RuntimeError(f"invalid unit: {unit!r}")
        argv = [
            "journalctl", "-u", unit, "-n",
            str(max(1, min(int(lines), 2000))),
            "--no-pager", "-o", "short-iso",
        ]
        rc, out, err = run_cmd(argv, timeout=15)
        if rc == 0:
            return out
        merged = (err or out).lower()
        if any(k in merged for k in ("permission", "insufficient", "not seeing")):
            rc2, out2, err2 = run_cmd(argv, timeout=60, as_root=True)
            if rc2 == 0:
                return out2
        raise RuntimeError((err or out).strip()[:800])

    def read_conf(self) -> str:
        try:
            return CONF_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""
        except PermissionError:
            pass
        argv = ["cat", str(CONF_PATH)]
        if _PRIV_PREFIX:
            argv = [*_PRIV_PREFIX, *argv]
        env = _priv_env()
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=30, env=env, check=False,
            )
        except Exception as exc:
            raise RuntimeError(f"cannot read {CONF_PATH}: {exc}")
        if p.returncode != 0:
            detail = (p.stderr or p.stdout).strip()[:400]
            raise RuntimeError(f"cannot read {CONF_PATH}: {detail}")
        return p.stdout

    def save_conf(self, text: str) -> str:
        if not CONF_PATH.exists():
            raise RuntimeError(f"{CONF_PATH} does not exist")
        st = CONF_PATH.stat()
        if st.st_uid != 0:
            raise RuntimeError(f"{CONF_PATH} must be owned by root")
        if (st.st_mode & 0o777) not in (0o640, 0o600):
            raise RuntimeError(f"{CONF_PATH} must have mode 0640 or 0600")
        argv = ["tee", str(CONF_PATH)]
        if _PRIV_PREFIX:
            argv = [*_PRIV_PREFIX, *argv]
        env = _priv_env()
        try:
            p = subprocess.Popen(
                argv, stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, env=env,
            )
            _, err = p.communicate(text, timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError("write timed out")
        except Exception as exc:
            raise RuntimeError(f"write failed: {exc}")
        if p.returncode != 0:
            raise RuntimeError(
                f"write failed ({p.returncode}): {(err or '').strip()[:500]}"
            )
        return f"Saved {CONF_PATH}"

    def detect_tunnel(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "detected": False, "method": None, "detail": "",
            "process": None, "pid": None,
        }
        rc, out, _ = run_cmd(
            ["ss", "-ltnpH", f"sport = :{USBIP_PORT}"], timeout=4
        )
        if rc == 0:
            for line in out.splitlines():
                if f"127.0.0.1:{USBIP_PORT}" not in line:
                    continue
                info["detected"] = True
                info["method"] = "ss"
                m = SS_PID_RE.search(line)
                if m:
                    info["process"] = m.group(1)
                    info["pid"] = int(m.group(2))
                info["detail"] = line.strip()[:300]
                return info
        rc, out, _ = run_cmd(
            ["pgrep", "-af", rf"ssh .*-[NL].*{USBIP_PORT}"], timeout=4
        )
        if rc == 0 and out.strip():
            first = out.strip().splitlines()[0]
            info["detected"] = True
            info["method"] = "pgrep"
            info["detail"] = first[:300]
            try:
                info["pid"] = int(first.split(None, 1)[0])
            except (ValueError, IndexError):
                pass
            return info
        info["detail"] = f"nothing listening on 127.0.0.1:{USBIP_PORT}"
        return info

    def detect_http_console(self, url: str) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        info: dict[str, Any] = {
            "url": url, "host": host, "port": port,
            "listening": False, "http_ok": False, "detail": "",
        }
        if not probe_tcp(host, port, timeout=2):
            info["detail"] = f"{host}:{port} not reachable"
            return info
        info["listening"] = True
        try:
            r = http_get(url.rstrip("/") + "/", timeout=4)
            info["http_ok"] = True
            info["detail"] = (
                f"HTTP {r['status']} {r['reason']} "
                f"({r['headers'].get('Content-Type', 'unknown')})"
            )
        except Exception as exc:
            info["detail"] = f"TCP ok but HTTP probe failed: {exc}"
        return info

    def local_usbipd(self) -> dict[str, Any]:
        rc, out, _ = run_cmd(["pgrep", "-x", "usbipd"], timeout=4)
        running = rc == 0 and bool(out.strip())
        pid = None
        if running:
            try:
                pid = int(out.split()[0])
            except ValueError:
                pass
        version = ""
        rc2, out2, _ = run_cmd(["usbip", "version"], timeout=3)
        if rc2 == 0 and out2.strip():
            version = out2.strip().splitlines()[0]
        return {"running": running, "pid": pid, "version": version}

    def probe_remote(self, host: str) -> dict[str, Any]:
        tcp_ok = probe_tcp(host, USBIP_PORT, timeout=3)
        rc, out, err = run_cmd(["usbip", "list", "-r", host], timeout=10)
        if rc != 0:
            return {
                "host": host, "reachable": False, "tcp_ok": tcp_ok,
                "device_count": 0, "error": (err or out).strip()[:500],
            }
        devices = parse_remote_usbip(out)
        return {
            "host": host, "reachable": True, "tcp_ok": True,
            "device_count": len(devices), "error": "",
        }

    def status(self) -> dict[str, Any]:
        units = self.all_units()
        modules = {
            m: Path(f"/sys/module/{m}").is_dir()
            for m in ("usbip_core", "usbip_host", "vhci_hcd")
        }
        client_active = units["client"]["active"] == "active"
        server_active = units["server"]["active"] == "active"
        usbipd = self.local_usbipd()
        tunnel = self.detect_tunnel()
        http_server = self.detect_http_console(HTTP_URL_SERVER)
        http_client = self.detect_http_console(HTTP_URL_CLIENT)
        remote = self.probe_remote("127.0.0.1")
        ports = self.ports()

        if server_active or usbipd["running"]:
            topology = "server"
        elif client_active and tunnel["detected"]:
            topology = "client via SSH tunnel"
        elif tunnel["detected"]:
            topology = "tunnel only"
        else:
            topology = "unknown"

        if server_active and usbipd["running"]:
            health = "OK"
        elif client_active and remote["reachable"]:
            health = "OK"
        elif client_active and tunnel["detected"]:
            health = "ERROR — tunnel up, remote daemon unreachable"
        elif client_active:
            health = "WARNING — client active, tunnel down"
        else:
            health = "ERROR — no supervisor detected"

        return {
            "role": (
                "mixed" if client_active and server_active
                else "client" if client_active
                else "server" if server_active
                else "unknown"
            ),
            "topology": topology,
            "health": health,
            "client_active": client_active,
            "server_active": server_active,
            "tunnel": tunnel,
            "http_server": http_server,
            "http_client": http_client,
            "remote": remote,
            "usbipd": usbipd,
            "units": units,
            "modules": modules,
            "ports": ports,
            "priv_mode": _PRIV_MODE,
        }

    def diagnose(self) -> list[dict[str, Any]]:
        checks: list[dict[str, Any]] = []

        def add(name, ok, detail, severity="error"):
            checks.append({
                "name": name, "ok": ok, "detail": detail,
                "severity": severity,
            })

        add("bridge", True, "GUI running", "ok")
        add(
            "privilege escalation", _PRIV_MODE != "none",
            (
                f"mode={_PRIV_MODE}"
                if _PRIV_MODE != "none"
                else "no sudo -n or pkexec available — privileged actions "
                     "will fail; configure NOPASSWD or install polkit"
            ),
            "error",
        )
        for module in ("usbip_core", "usbip_host", "vhci_hcd"):
            loaded = Path(f"/sys/module/{module}").is_dir()
            add(
                f"module {module}", loaded,
                "loaded" if loaded else f"sudo modprobe {module}",
                "warning",
            )
        for name, unit in UNITS.items():
            st = self.unit_state(unit)
            add(
                unit, st["active"] == "active",
                f"active={st['active']} enabled={st['enabled']}",
                "warning",
            )
        tunnel = self.detect_tunnel()
        add(
            f"127.0.0.1:{USBIP_PORT} listening",
            tunnel["detected"], tunnel["detail"], "error",
        )
        for label, url in [
            ("HTTP console (server)", HTTP_URL_SERVER),
            ("HTTP console (client)", HTTP_URL_CLIENT),
        ]:
            info = self.detect_http_console(url)
            add(
                f"{label} {url}", info["http_ok"],
                info["detail"], "warning",
            )
        remote = self.probe_remote("127.0.0.1")
        add(
            "remote daemon via 127.0.0.1",
            remote["reachable"],
            (
                f"reachable — {remote['device_count']} exportable device(s)"
                if remote["reachable"]
                else f"unreachable — {remote['error']}"
            ),
            "error",
        )
        return checks

    @staticmethod
    def _validate_busid(busid: str) -> str:
        busid = (busid or "").strip()
        if not BUSID_RE.match(busid):
            raise RuntimeError(f"invalid bus id: {busid!r}")
        return busid


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class USBIPGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1200x880")
        self.minsize(1000, 720)
        self.backend = USBIPBackend()

        self._status_pending = False
        self._local_pending = False
        self._remote_pending = False
        self._ports_pending = False
        self._system_units_pending = False
        self._last_remote_raw: str = ""

        self._build_style()
        self._build_header()
        self._build_notebook()

        self._maybe_warn_privilege()

        self.after(200, self.refresh_status)
        self.after(400, self.refresh_local)
        self.after(600, self.refresh_remote)
        self.after(800, self.refresh_ports)
        self.after(1200, self.refresh_system_units)
        self.after(3000, self._status_tick)

    def _maybe_warn_privilege(self) -> None:
        if _PRIV_MODE == "none":
            self.after(400, lambda: messagebox.showwarning(
                "No privilege escalation",
                "This GUI cannot escalate privileges.\n\n"
                "Privileged actions (bind, unbind, attach, detach, "
                "systemctl start/stop/restart/enable/disable, and "
                "reading/writing usbip.conf) will fail.\n\n"
                "Either install polkit (for pkexec) or add NOPASSWD "
                "sudoers rules for the commands above.\n\n"
                "Run without sudo so Firefox launches correctly.",
            ))

    # ------------------------------------------------------------------
    # Styles and header
    # ------------------------------------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=26)
        style.configure("Headline.TLabel", font=("TkDefaultFont", 14, "bold"))
        style.configure("Url.TLabel", font=("TkFixedFont", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#555")
        style.configure("Status.TLabel", font=("TkDefaultFont", 10, "bold"))
        style.configure("Good.TLabel", foreground="#16794b")
        style.configure("Warn.TLabel", foreground="#9a6700")
        style.configure("Bad.TLabel", foreground="#b42318")

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(header, text="USB/IP Bridge", style="Headline.TLabel").pack(side="left")

        self.health_var = tk.StringVar(value="checking…")
        self.topology_var = tk.StringVar(value="…")
        self.role_var = tk.StringVar(value="…")

        sb = ttk.Frame(header)
        sb.pack(side="right")
        ttk.Label(sb, text="Health:").pack(side="left")
        self.health_label = ttk.Label(
            sb, textvariable=self.health_var, style="Status.TLabel"
        )
        self.health_label.pack(side="left", padx=(4, 18))
        ttk.Label(sb, text="Topology:").pack(side="left")
        ttk.Label(sb, textvariable=self.topology_var).pack(side="left", padx=(4, 18))
        ttk.Label(sb, text="Role:").pack(side="left")
        ttk.Label(sb, textvariable=self.role_var).pack(side="left", padx=(4, 0))

    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.dashboard_tab = ttk.Frame(self.notebook)
        self.devices_tab = ttk.Frame(self.notebook)
        self.ports_tab = ttk.Frame(self.notebook)
        self.services_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        self.diagnostics_tab = ttk.Frame(self.notebook)
        self.remote_server_tab = ttk.Frame(self.notebook)

        for name, frame in [
            ("Dashboard", self.dashboard_tab),
            ("Devices", self.devices_tab),
            ("VHCI Ports", self.ports_tab),
            ("Services", self.services_tab),
            ("Logs", self.logs_tab),
            ("Configuration", self.config_tab),
            ("Diagnostics", self.diagnostics_tab),
            ("Remote Server", self.remote_server_tab),
        ]:
            self.notebook.add(frame, text=name)

        self._build_dashboard()
        self._build_devices()
        self._build_ports()
        self._build_services()
        self._build_logs()
        self._build_config()
        self._build_diagnostics()
        self._build_remote_server()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def _build_dashboard(self) -> None:
        outer = ttk.Frame(self.dashboard_tab, padding=12)
        outer.pack(fill="both", expand=True)

        cards = ttk.Frame(outer)
        cards.pack(fill="x", pady=(0, 12))

        self.card_vars: dict[str, tk.StringVar] = {}
        card_defs = [
            ("client", "Client supervisor"),
            ("server", "Local usbipd"),
            ("tunnel", "USB/IP tunnel"),
            ("priv_mode", "Privilege mode"),
            ("http_server", "HTTP :18098"),
            ("http_client", "HTTP :8098"),
            ("ports", "Attached ports"),
        ]
        for idx, (key, label) in enumerate(card_defs):
            card = ttk.LabelFrame(cards, text=label, padding=10)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0, 6))
            cards.columnconfigure(idx, weight=1)
            var = tk.StringVar(value="…")
            self.card_vars[key] = var
            ttk.Label(
                card, textvariable=var, justify="left", wraplength=160
            ).pack(anchor="w")

        ttk.Label(outer, text="Units", style="Headline.TLabel").pack(
            anchor="w", pady=(4, 6)
        )
        self.dashboard_units_tree = self._make_tree(
            outer, ("unit", "active", "enabled"),
            {"unit": 260, "active": 120, "enabled": 120}, height=6,
        )
        self._tree_parent(self.dashboard_units_tree).pack(fill="x")

        ttk.Label(
            outer, text="Diagnosis summary", style="Headline.TLabel"
        ).pack(anchor="w", pady=(14, 6))
        self.dashboard_diag_text = scrolledtext.ScrolledText(
            outer, height=8, wrap="word", state="disabled"
        )
        self.dashboard_diag_text.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Devices / ports
    # ------------------------------------------------------------------

    def _build_devices(self) -> None:
        outer = ttk.Frame(self.devices_tab, padding=12)
        outer.pack(fill="both", expand=True)

        local_frame = ttk.LabelFrame(outer, text="Local USB devices", padding=8)
        local_frame.pack(fill="both", expand=True, pady=(0, 8))
        self.local_tree = self._make_tree(
            local_frame,
            ("busid", "vidpid", "vendor", "product", "exported"),
            {"busid": 100, "vidpid": 110, "vendor": 200,
             "product": 260, "exported": 90},
        )
        self._tree_parent(self.local_tree).pack(fill="both", expand=True)
        lb = ttk.Frame(local_frame)
        lb.pack(fill="x", pady=(8, 0))
        ttk.Button(lb, text="Refresh local", command=self.refresh_local).pack(side="left")
        ttk.Button(lb, text="Bind selected", command=self.bind_selected).pack(side="left", padx=(8, 0))
        ttk.Button(lb, text="Unbind selected", command=self.unbind_selected).pack(side="left", padx=(8, 0))

        remote_frame = ttk.LabelFrame(
            outer, text="Remote USB devices (via tunnel / direct)", padding=8
        )
        remote_frame.pack(fill="both", expand=True)

        hr = ttk.Frame(remote_frame)
        hr.pack(fill="x", pady=(0, 4))
        ttk.Label(hr, text="Remote host:").pack(side="left")
        self.remote_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(hr, textvariable=self.remote_host_var, width=20).pack(
            side="left", padx=(6, 8)
        )
        ttk.Button(hr, text="Refresh remote", command=self.refresh_remote).pack(side="left")
        ttk.Button(hr, text="Attach selected", command=self.attach_selected).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(hr, text="Show raw output", command=self.show_remote_raw).pack(
            side="left", padx=(8, 0)
        )

        self.remote_tunnel_var = tk.StringVar(value="")
        ttk.Label(
            remote_frame, textvariable=self.remote_tunnel_var,
            style="Hint.TLabel", wraplength=1100, justify="left",
        ).pack(fill="x", pady=(0, 4))

        self.remote_tree = self._make_tree(
            remote_frame, ("busid", "vidpid", "vendor", "product"),
            {"busid": 100, "vidpid": 110, "vendor": 240, "product": 320},
        )
        self._tree_parent(self.remote_tree).pack(fill="both", expand=True)

    def _build_ports(self) -> None:
        outer = ttk.Frame(self.ports_tab, padding=12)
        outer.pack(fill="both", expand=True)
        self.ports_tree = self._make_tree(
            outer,
            ("port", "busid", "server", "vidpid", "vendor", "product"),
            {"port": 70, "busid": 100, "server": 170,
             "vidpid": 110, "vendor": 200, "product": 260},
        )
        self._tree_parent(self.ports_tree).pack(fill="both", expand=True)
        b = ttk.Frame(outer)
        b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Refresh ports", command=self.refresh_ports).pack(side="left")
        ttk.Button(b, text="Detach selected", command=self.detach_selected).pack(
            side="left", padx=(8, 0)
        )

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def _build_services(self) -> None:
        outer = ttk.Frame(self.services_tab, padding=12)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer, text="Bridge units (configured)", style="Headline.TLabel"
        ).pack(anchor="w", pady=(0, 4))

        self.services_tree = self._make_tree(
            outer, ("name", "unit", "active", "enabled"),
            {"name": 100, "unit": 300, "active": 120, "enabled": 120},
            height=5,
        )
        self._tree_parent(self.services_tree).pack(fill="x", pady=(0, 12))

        ttk.Label(
            outer,
            text="All usbip* units detected by systemd",
            style="Headline.TLabel",
        ).pack(anchor="w", pady=(0, 4))

        self.services_system_tree = self._make_tree(
            outer, ("unit", "load", "active", "sub", "source"),
            {"unit": 340, "load": 80, "active": 80,
             "sub": 100, "source": 200},
            height=8,
        )
        self._tree_parent(self.services_system_tree).pack(fill="both", expand=True)

        self.services_status = tk.StringVar(value="")
        ttk.Label(outer, textvariable=self.services_status).pack(
            anchor="w", pady=(6, 0)
        )

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(8, 0))
        for label, action in [
            ("Start", "start"), ("Stop", "stop"), ("Restart", "restart"),
            ("Enable", "enable"), ("Disable", "disable"),
        ]:
            ttk.Button(
                buttons, text=label,
                command=lambda a=action: self.service_action(a),
            ).pack(side="left", padx=(0, 8))
        ttk.Button(
            buttons, text="Refresh system units",
            command=self.refresh_system_units,
        ).pack(side="left", padx=(16, 0))
        ttk.Button(
            buttons, text="Refresh", command=self.refresh_status
        ).pack(side="right")

    # ------------------------------------------------------------------
    # Logs / config / diagnostics
    # ------------------------------------------------------------------

    def _build_logs(self) -> None:
        outer = ttk.Frame(self.logs_tab, padding=12)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Unit:").pack(side="left")
        self.log_unit_var = tk.StringVar(value=UNIT_TUNNEL)
        self.log_combo = ttk.Combobox(
            top, textvariable=self.log_unit_var,
            values=list(UNITS.values()), state="readonly", width=34,
        )
        self.log_combo.pack(side="left", padx=(6, 8))
        ttk.Button(top, text="Reload logs", command=self.refresh_logs).pack(side="left")
        self.log_text = scrolledtext.ScrolledText(
            outer, wrap="none", font=("TkFixedFont", 10)
        )
        self.log_text.pack(fill="both", expand=True)

    def _build_config(self) -> None:
        outer = ttk.Frame(self.config_tab, padding=12)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, 6))
        self.conf_path_var = tk.StringVar(value=str(CONF_PATH))
        ttk.Label(top, textvariable=self.conf_path_var).pack(side="left")
        ttk.Button(top, text="Reload", command=self.refresh_config).pack(
            side="right", padx=(8, 0)
        )
        ttk.Button(top, text="Save", command=self.save_config).pack(side="right")
        self.config_text = scrolledtext.ScrolledText(
            outer, wrap="none", font=("TkFixedFont", 10)
        )
        self.config_text.pack(fill="both", expand=True)

    def _build_diagnostics(self) -> None:
        outer = ttk.Frame(self.diagnostics_tab, padding=12)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(
            top, text="Run diagnosis", command=self.run_diagnostics
        ).pack(side="left")
        self.diag_tree = self._make_tree(
            outer, ("check", "status", "detail"),
            {"check": 250, "status": 100, "detail": 600},
        )
        self._tree_parent(self.diag_tree).pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Remote Server tab
    # ------------------------------------------------------------------

    def _build_remote_server(self) -> None:
        outer = ttk.Frame(self.remote_server_tab, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer, text="Remote console access", style="Headline.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                "The usbip_bridge web console is served over plain HTTP. "
                "Open one of these URLs in a browser on this machine."
            ),
            wraplength=1000, justify="left",
        ).pack(anchor="w", pady=(4, 16))

        for label, url in [
            ("Server only", HTTP_URL_SERVER),
            ("Client & server", HTTP_URL_CLIENT),
        ]:
            card = ttk.LabelFrame(outer, text=label, padding=12)
            card.pack(fill="x", pady=(0, 12))
            ttk.Label(card, text=url, style="Url.TLabel").pack(anchor="w")
            row = ttk.Frame(card)
            row.pack(fill="x", pady=(8, 0))
            ttk.Button(
                row, text="Copy URL",
                command=lambda u=url: self._copy_to_clipboard(u),
            ).pack(side="left")
            ttk.Button(
                row, text="Open in browser",
                command=lambda u=url: self._open_url(u),
            ).pack(side="left", padx=(8, 0))

        notes = scrolledtext.ScrolledText(
            outer, height=10, wrap="word", font=("TkDefaultFont", 10)
        )
        notes.pack(fill="both", expand=True, pady=(12, 0))
        notes.insert("end", self._remote_server_notes())
        notes.configure(state="disabled")

    def _remote_server_notes(self) -> str:
        sp = HTTP_URL_SERVER.rsplit(":", 1)[-1]
        cp = HTTP_URL_CLIENT.rsplit(":", 1)[-1]
        return f"""Notes
=====

- The GUI does not proxy the console. Use a browser on this machine.
- If a browser cannot be launched here, copy one of the URLs above and
  paste it into the browser on your laptop after forwarding the port:

      ssh -L {sp}:127.0.0.1:{sp} user@server-host
      ssh -L {cp}:127.0.0.1:{cp} user@client-host

- Verify the console is up from a shell on this machine:

      curl -sS {HTTP_URL_SERVER}/ | head -c 400
      curl -sS {HTTP_URL_CLIENT}/ | head -c 400
"""

    def _copy_to_clipboard(self, text: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", f"Copied to clipboard:\n\n{text}")
        except Exception as exc:
            messagebox.showerror("Copy", str(exc))

    # ------------------------------------------------------------------
    # Browser launch
    # ------------------------------------------------------------------

    def _find_firefox(self) -> str | None:
        for name in ("firefox", "firefox-esr"):
            path = shutil.which(name)
            if path:
                return path
        for path in (
            "/usr/bin/firefox", "/usr/bin/firefox-esr",
            "/snap/bin/firefox", "/usr/local/bin/firefox",
        ):
            if os.path.exists(path):
                return path
        return None

    def _detect_x_display(self) -> str:
        try:
            matches = sorted(Path("/tmp/.X11-unix").glob("X*"))
        except OSError:
            matches = []
        nums = []
        for m in matches:
            suffix = m.name[1:]
            if suffix.isdigit():
                nums.append(int(suffix))
        if nums:
            return f":{min(nums)}"
        return os.environ.get("DISPLAY", ":0")

    def _launch_firefox_as_user(
        self, sudo_user: str, url: str, firefox: str
    ) -> bool:
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            uid, home = pw.pw_uid, pw.pw_dir
        except KeyError:
            uid, home = 1000, f"/home/{sudo_user}"
        xauth = ""
        for cand in (
            os.path.join(home, ".Xauthority"),
            f"/run/user/{uid}/gdm/Xauthority",
            f"/run/user/{uid}/Xauthority",
        ):
            if os.path.exists(cand):
                xauth = cand
                break
        if not xauth:
            runtime = Path(f"/run/user/{uid}")
            if runtime.is_dir():
                for pattern in (".mutter-Xwaylandauth.*", "xauth_*"):
                    hits = sorted(runtime.glob(pattern))
                    if hits:
                        xauth = str(hits[0])
                        break
        display = self._detect_x_display()
        path = f"{home}/bin:/usr/local/bin:/usr/bin:/bin:/usr/games"
        inner = [
            "env",
            f"HOME={home}", f"USER={sudo_user}", f"LOGNAME={sudo_user}",
            f"DISPLAY={display}", f"PATH={path}",
            f"XDG_RUNTIME_DIR=/run/user/{uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        ]
        if xauth:
            inner.append(f"XAUTHORITY={xauth}")
        inner.extend([firefox, "--new-tab", url])
        try:
            proc = subprocess.Popen(
                ["sudo", "-u", sudo_user, "--", *inner],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            time.sleep(0.3)
            if proc.poll() is not None and proc.returncode != 0:
                return False
            return True
        except Exception:
            return False

    def _open_url(self, url: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
        except Exception:
            pass
        sudo_user = os.environ.get("SUDO_USER")
        is_root = os.geteuid() == 0
        drop = is_root and bool(sudo_user) and sudo_user != "root"
        firefox = self._find_firefox()
        launched = False
        reason = ""
        if firefox:
            if drop:
                if self._launch_firefox_as_user(sudo_user, url, firefox):
                    launched = True
                else:
                    reason = f"sudo -u {sudo_user} firefox failed"
            else:
                try:
                    subprocess.Popen(
                        [firefox, "--new-tab", url],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                    )
                    launched = True
                except Exception as exc:
                    reason = f"firefox: {exc}"
        if not launched:
            try:
                if webbrowser.open(url, new=2):
                    launched = True
            except Exception as exc:
                reason = (reason + "; " if reason else "") + f"webbrowser: {exc}"
        if not launched:
            for cmd in ("xdg-open", "gio"):
                exe = shutil.which(cmd)
                if not exe:
                    continue
                argv = [exe, url] if cmd == "xdg-open" else [exe, "open", url]
                try:
                    subprocess.Popen(
                        argv,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                    )
                    launched = True
                    break
                except Exception as exc:
                    reason = (reason + "; " if reason else "") + f"{cmd}: {exc}"
        if launched:
            messagebox.showinfo(
                "Browser",
                f"Launched browser for {url}\n\nURL also copied to clipboard.",
            )
        else:
            port = url.rsplit(":", 1)[-1]
            messagebox.showinfo(
                "Open in browser failed",
                "Could not launch a browser on this machine.\n\n"
                f"{('Reason: ' + reason + chr(10) + chr(10)) if reason else ''}"
                "The URL has been copied to your clipboard:\n\n"
                f"{url}\n\n"
                "Paste it into Firefox on your desktop.\n\n"
                "If you're SSH'd into this host, forward the port:\n\n"
                f"    ssh -L {port}:127.0.0.1:{port} user@this-host\n",
            )

    # ------------------------------------------------------------------
    # Tree helper
    # ------------------------------------------------------------------

    def _make_tree(self, parent, columns, widths, height=12) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(
            frame, columns=columns, show="headings",
            height=height, selectmode="browse",
        )
        for col in columns:
            tree.heading(col, text=col.replace("_", " ").title())
            tree.column(col, width=widths.get(col, 100), anchor="w")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree._container = frame  # type: ignore[attr-defined]
        return tree

    @staticmethod
    def _tree_parent(tree: ttk.Treeview) -> tk.Widget:
        return getattr(tree, "_container", tree.master)

    # ------------------------------------------------------------------
    # Threading
    # ------------------------------------------------------------------

    def _bg(self, fn: Callable[[], Any], on_done: Callable[[Any], None]) -> None:
        def worker() -> None:
            try:
                result = fn()
            except Exception as exc:
                result = exc
            self.after(0, lambda: on_done(result))
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def _status_tick(self) -> None:
        self.refresh_status()
        self.after(4000, self._status_tick)

    def refresh_status(self) -> None:
        if self._status_pending:
            return
        self._status_pending = True

        def done(result: Any) -> None:
            self._status_pending = False
            if isinstance(result, Exception):
                self.health_var.set("ERROR")
                self.health_label.configure(style="Bad.TLabel")
                self._clear_tree(self.services_tree)
                self.services_tree.insert(
                    "", "end",
                    values=("ERROR", f"status() failed: {result}", "", ""),
                )
                return
            self._apply_status(result)

        self._bg(self.backend.status, done)

    def _apply_status(self, status: dict[str, Any]) -> None:
        try:
            self._apply_status_inner(status)
        except Exception as exc:
            self.health_var.set("ERROR")
            self.health_label.configure(style="Bad.TLabel")
            self._clear_tree(self.services_tree)
            self.services_tree.insert(
                "", "end",
                values=("ERROR", f"render error: {exc}", "", ""),
            )

    def _apply_status_inner(self, status: dict[str, Any]) -> None:
        health = status.get("health", "unknown")
        self.health_var.set(health)
        if health == "OK":
            self.health_label.configure(style="Good.TLabel")
        elif health.startswith("WARNING"):
            self.health_label.configure(style="Warn.TLabel")
        else:
            self.health_label.configure(style="Bad.TLabel")

        self.topology_var.set(status.get("topology", "—"))
        self.role_var.set(status.get("role", "—"))

        tunnel = status.get("tunnel", {})
        http_s = status.get("http_server", {})
        http_c = status.get("http_client", {})
        usbipd = status.get("usbipd", {})
        units = status.get("units", {})
        ports = status.get("ports", [])
        priv = status.get("priv_mode", "none")

        self.card_vars["client"].set(
            "ACTIVE" if status.get("client_active") else "inactive"
        )
        self.card_vars["server"].set(
            f"running — pid {usbipd.get('pid')}"
            if usbipd.get("running")
            else "not running"
        )
        self.card_vars["tunnel"].set(
            f"UP — {tunnel.get('method', '?')}\n{tunnel.get('detail', '')}"
            if tunnel.get("detected")
            else "DOWN"
        )
        priv_labels = {
            "root": "root (direct)",
            "sudo": "sudo -n",
            "pkexec": "pkexec",
            "none": "NONE — actions will fail",
        }
        self.card_vars["priv_mode"].set(priv_labels.get(priv, priv))
        self.card_vars["http_server"].set(
            http_s.get("detail", "")
            if http_s.get("http_ok")
            else f"DOWN\n{http_s.get('detail', '')}"
        )
        self.card_vars["http_client"].set(
            http_c.get("detail", "")
            if http_c.get("http_ok")
            else f"DOWN\n{http_c.get('detail', '')}"
        )
        self.card_vars["ports"].set(str(len(ports)))

        self._clear_tree(self.services_tree)
        for name, state in units.items():
            self.services_tree.insert(
                "", "end",
                values=(name, state.get("unit", ""),
                        state.get("active", ""), state.get("enabled", "")),
            )
        self._clear_tree(self.dashboard_units_tree)
        for name, state in units.items():
            self.dashboard_units_tree.insert(
                "", "end",
                values=(state.get("unit", ""),
                        state.get("active", ""), state.get("enabled", "")),
            )

    # ------------------------------------------------------------------
    # Services discovery
    # ------------------------------------------------------------------

    def refresh_system_units(self) -> None:
        if self._system_units_pending:
            return
        self._system_units_pending = True
        self.services_status.set("querying systemd…")

        def work():
            return (
                self.backend.list_loaded_usbip_units(),
                self.backend.list_installed_usbip_units(),
            )

        def done(result: Any) -> None:
            self._system_units_pending = False
            self._clear_tree(self.services_system_tree)
            if isinstance(result, Exception):
                self.services_status.set(f"systemd query failed: {result}")
                self.services_system_tree.insert(
                    "", "end",
                    values=("ERROR", "", "", "", str(result)[:200]),
                )
                return
            loaded, installed = result
            seen: set[str] = set()
            for u in loaded:
                self.services_system_tree.insert(
                    "", "end",
                    values=(
                        u["unit"], u.get("load", ""),
                        u.get("active", ""), u.get("sub", ""),
                        "loaded",
                    ),
                )
                seen.add(u["unit"])
            installed_only = 0
            for u in installed:
                if u["unit"] in seen:
                    continue
                installed_only += 1
                self.services_system_tree.insert(
                    "", "end",
                    values=(
                        u["unit"], "", "", "",
                        f"installed ({u.get('state', '')})",
                    ),
                )
            if not loaded and not installed:
                self.services_status.set(
                    "no usbip* units found in systemd — is this a "
                    "systemd machine, and are the bridge units installed?"
                )
            else:
                self.services_status.set(
                    f"{len(loaded)} loaded, "
                    f"{installed_only} installed-but-inactive "
                    f"— {len(loaded) + installed_only} usbip* unit(s) total"
                )
            values = list(UNITS.values())
            for u in loaded + installed:
                if u["unit"] not in values:
                    values.append(u["unit"])
            self.log_combo.configure(values=values)

        self._bg(work, done)

    def _selected_unit(self) -> str | None:
        sel = self.services_system_tree.selection()
        if sel:
            values = self.services_system_tree.item(sel[0], "values")
            if values and UNIT_NAME_RE.match(values[0]):
                return values[0]
        sel = self.services_tree.selection()
        if sel:
            values = self.services_tree.item(sel[0], "values")
            if len(values) > 1 and UNIT_NAME_RE.match(values[1]):
                return values[1]
        return None

    def service_action(self, action: str) -> None:
        unit = self._selected_unit()
        if not unit:
            messagebox.showinfo(
                "Select a unit",
                "Select a systemd unit (from either list) first.",
            )
            return
        if action in {"stop", "restart"} and not messagebox.askyesno(
            f"{action.title()} unit", f"{action.title()} {unit}?"
        ):
            return

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror(f"{action} failed", str(result))
            else:
                messagebox.showinfo(action.title(), f"{action} {unit}: done.")
                self.refresh_status()
                self.refresh_system_units()

        self._bg(lambda: self.backend.unit_action(action, unit), done)

    # ------------------------------------------------------------------
    # Device refreshers and actions
    # ------------------------------------------------------------------

    def refresh_local(self) -> None:
        if self._local_pending:
            return
        self._local_pending = True

        def done(result: Any) -> None:
            self._local_pending = False
            self._clear_tree(self.local_tree)
            if isinstance(result, Exception):
                messagebox.showerror("Local devices", str(result))
                return
            for dev in result:
                self.local_tree.insert(
                    "", "end",
                    values=(
                        dev["busid"],
                        f"{dev['vid']}:{dev['pid']}",
                        dev["vendor"], dev["product"],
                        "yes" if dev["exported"] else "no",
                    ),
                )

        self._bg(self.backend.local_devices, done)

    def refresh_remote(self) -> None:
        if self._remote_pending:
            return
        self._remote_pending = True
        host = self.remote_host_var.get().strip() or "127.0.0.1"

        def done(result: Any) -> None:
            self._remote_pending = False
            self._clear_tree(self.remote_tree)
            self._last_remote_raw = ""

            if isinstance(result, Exception):
                self.remote_tunnel_var.set(f"error: {result}")
                self.remote_tree.insert(
                    "", "end",
                    values=("—", "—", "ERROR", str(result)[:200]),
                )
                return

            self._last_remote_raw = result.get("raw", "")
            tcp_ok = result.get("tcp_ok", False)

            if tcp_ok:
                self.remote_tunnel_var.set(
                    f"tunnel 127.0.0.1:{USBIP_PORT} is reachable"
                )
            else:
                self.remote_tunnel_var.set(
                    f"tunnel 127.0.0.1:{USBIP_PORT} is NOT reachable — "
                    f"ensure {UNIT_TUNNEL} forwards local :{USBIP_PORT} "
                    f"to the server's :{USBIP_PORT} (usbipd). "
                    f"Click 'Show raw output' for details."
                )

            if not result["reachable"]:
                err = (result.get("error") or "").strip()
                self.remote_tree.insert(
                    "", "end",
                    values=("—", "—", "unreachable", err[:200] or "(no detail)"),
                )
                return

            devices = result["devices"]
            if not devices:
                self.remote_tree.insert(
                    "", "end",
                    values=(
                        "—", "—",
                        "no exported devices",
                        "on the server, run: usbip bind -b <busid>",
                    ),
                )
                return

            for dev in devices:
                self.remote_tree.insert(
                    "", "end",
                    values=(
                        dev["busid"],
                        f"{dev['vid']}:{dev['pid']}".strip(":"),
                        dev["vendor"], dev["product"],
                    ),
                )

        self._bg(lambda: self.backend.remote_devices(host), done)

    def show_remote_raw(self) -> None:
        raw = self._last_remote_raw or ""
        if not raw:
            messagebox.showinfo(
                "Raw output",
                "Nothing captured yet — click 'Refresh remote' first.",
            )
            return
        top = tk.Toplevel(self)
        top.title("usbip list -r — raw output")
        top.geometry("900x560")
        hdr = ttk.Label(
            top,
            text=f"raw output for host {self.remote_host_var.get().strip() or '127.0.0.1'}",
            padding=(8, 6),
        )
        hdr.pack(fill="x")
        text = scrolledtext.ScrolledText(
            top, wrap="none", font=("TkFixedFont", 10)
        )
        text.pack(fill="both", expand=True)
        text.insert("end", raw)
        text.configure(state="disabled")

    def refresh_ports(self) -> None:
        if self._ports_pending:
            return
        self._ports_pending = True

        def done(result: Any) -> None:
            self._ports_pending = False
            self._clear_tree(self.ports_tree)
            if isinstance(result, Exception):
                messagebox.showerror("VHCI ports", str(result))
                return
            for p in result:
                self.ports_tree.insert(
                    "", "end",
                    values=(
                        p["port"], p["busid"], p["server"],
                        f"{p['vid']}:{p['pid']}".strip(":"),
                        p["vendor"], p["product"],
                    ),
                )

        self._bg(self.backend.ports, done)

    def _selected_values(self, tree: ttk.Treeview) -> list[str] | None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Select a row", "Please select a device first.")
            return None
        return list(tree.item(sel[0], "values"))

    def bind_selected(self) -> None:
        values = self._selected_values(self.local_tree)
        if not values:
            return
        busid = values[0]

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror("Bind failed", str(result))
            else:
                messagebox.showinfo("Bind", f"Bound {busid}.")
                self.refresh_local()

        self._bg(lambda: self.backend.bind(busid), done)

    def unbind_selected(self) -> None:
        values = self._selected_values(self.local_tree)
        if not values:
            return
        busid = values[0]

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror("Unbind failed", str(result))
            else:
                messagebox.showinfo("Unbind", f"Unbound {busid}.")
                self.refresh_local()

        self._bg(lambda: self.backend.unbind(busid), done)

    def attach_selected(self) -> None:
        values = self._selected_values(self.remote_tree)
        if not values:
            return
        busid = values[0]
        if busid == "—":
            messagebox.showinfo(
                "Attach",
                "Select a real device row, not the status row.",
            )
            return
        host = self.remote_host_var.get().strip() or "127.0.0.1"

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror("Attach failed", str(result))
            else:
                messagebox.showinfo("Attach", f"Attached {busid} from {host}.")
                self.refresh_ports()

        self._bg(lambda: self.backend.attach(busid, host), done)

    def detach_selected(self) -> None:
        values = self._selected_values(self.ports_tree)
        if not values:
            return
        try:
            port = int(values[0])
        except ValueError:
            messagebox.showerror("Detach", "Invalid port number.")
            return
        if not messagebox.askyesno("Detach port", f"Detach VHCI port {port}?"):
            return

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror("Detach failed", str(result))
            else:
                messagebox.showinfo("Detach", f"Detached port {port}.")
                self.refresh_ports()

        self._bg(lambda: self.backend.detach(port), done)

    # ------------------------------------------------------------------
    # Logs / config / diagnostics
    # ------------------------------------------------------------------

    def refresh_logs(self) -> None:
        unit = self.log_unit_var.get()
        if not UNIT_NAME_RE.match(unit):
            messagebox.showerror("Logs", f"invalid unit: {unit!r}")
            return

        def done(result: Any) -> None:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            if isinstance(result, Exception):
                self.log_text.insert("end", str(result))
            else:
                self.log_text.insert("end", result)
            self.log_text.configure(state="disabled")

        self._bg(lambda: self.backend.journal(unit), done)

    def refresh_config(self) -> None:
        def done(result: Any) -> None:
            self.config_text.delete("1.0", "end")
            if isinstance(result, Exception):
                messagebox.showerror("Configuration", str(result))
            else:
                self.config_text.insert("1.0", result)

        self._bg(self.backend.read_conf, done)

    def save_config(self) -> None:
        text = self.config_text.get("1.0", "end-1c")
        if not messagebox.askyesno(
            "Save configuration",
            f"Write changes to {CONF_PATH}?\n\n"
            "The file must remain root-owned and mode 0640/0600.",
        ):
            return

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                messagebox.showerror("Save failed", str(result))
            else:
                messagebox.showinfo("Configuration", str(result))

        self._bg(lambda: self.backend.save_conf(text), done)

    def run_diagnostics(self) -> None:
        def done(result: Any) -> None:
            self._clear_tree(self.diag_tree)
            self.dashboard_diag_text.configure(state="normal")
            self.dashboard_diag_text.delete("1.0", "end")
            if isinstance(result, Exception):
                messagebox.showerror("Diagnostics", str(result))
                self.dashboard_diag_text.insert("end", str(result))
                self.dashboard_diag_text.configure(state="disabled")
                return
            for check in result:
                ok = check["ok"]
                self.diag_tree.insert(
                    "", "end",
                    values=(
                        check["name"],
                        "OK" if ok else check.get("severity", "error").upper(),
                        check["detail"],
                    ),
                )
                self.dashboard_diag_text.insert(
                    "end",
                    f"[{'OK' if ok else check.get('severity', 'error').upper()}] "
                    f"{check['name']}\n    {check['detail']}\n",
                )
            self.dashboard_diag_text.configure(state="disabled")

        self._bg(self.backend.diagnose, done)

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    detect_privilege_mode()
    app = USBIPGui()
    app.after(500, app.refresh_logs)
    app.after(500, app.refresh_config)
    app.after(900, app.run_diagnostics)
    app.mainloop()


if __name__ == "__main__":
    main()
