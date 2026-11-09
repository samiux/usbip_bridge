# USB/IP Bridge (Console)

A self‑hosted control plane for **USB/IP** on Linux. Share USB devices from a **server**, attach them on a **client**, and manage both ends from a **web console** at `http://localhost:8098` — with all USB/IP traffic carried inside an encrypted, key‑only SSH tunnel.

```
┌───────────────────────────────┐            SSH tunnel (TCP 22)            ┌───────────────────────────────┐
│            SERVER             │  ══════════════════════════════════════►  │            CLIENT             │
│                               │        usbip-tunnel.service               │                               │
│  USB devices (lsusb)          │                                           │  vhci_hcd (virtual host)      │
│  usbipd            (TCP 3240) │  ◄────── USB/IP over loopback ──────►     │  usbip attach                 │
│  usbip-server.service         │                                           │  usbip-client.service         │
│  99-usbip-hotplug.rules       │                                           │  usbip-tunnel-firewall.service│
│  usbip-bridge.service         │                                           │  usbip-bridge.service         │
│   └─ Web console :8098        │                                           │   └─ Web console :8098        │
└───────────────────────────────┘                                           └───────────────────────────────┘
```

---

## Table of contents

1. [Overview](#1-overview)
2. [Features](#2-features)
   - [2.1 Known issues](#21-known-issues)
3. [How it works](#3-how-it-works)
4. [Repository layout](#4-repository-layout)
5. [Requirements](#5-requirements)
6. [Before you begin](#6-before-you-begin)
7. [Server installation](#7-server-installation)
8. [Client installation](#8-client-installation)
9. [Establish the SSH tunnel](#9-establish-the-ssh-tunnel)
10. [Verify the installation](#10-verify-the-installation)
11. [Starting and using the web console](#11-starting-and-using-the-web-console)
12. [Configuration reference](#12-configuration-reference)
13. [Debugging & troubleshooting](#13-debugging--troubleshooting)
14. [Security notes](#14-security-notes)
15. [Uninstall](#15-uninstall)
16. [License](#16-license)

---

## 1. Overview

**USB/IP Bridge (Console)** is a small set of scripts, systemd units and a FastAPI web application that turns the raw `usbip` toolchain into a manageable service:

* The **server** exports local USB devices over USB/IP (`usbipd`, port `3240`).
* The **client** imports them through `vhci_hcd` and exposes them as if they were plugged in locally.
* The USB/IP traffic is **never exposed to the network**: it travels over an SSH tunnel between the two hosts.
* A **web console** runs on each side on **port `8098`** ([Section 11](#11-starting-and-using-the-web-console)) so you can see what is exported, what is attached, and whether the tunnel is healthy.

Typical use cases: a headless home server sharing a Zigbee/Z‑Wave dongle, a lab machine sharing a serial adapter or a license dongle, or a VM host sharing a USB programmer.

---

## 2. Features

* 🖥️ **Web console** — FastAPI + Uvicorn backend, static HTML frontend. Open it at **`http://localhost:8098`** or **`http://127.0.0.1:8098`** ([Section 11](#11-starting-and-using-the-web-console)).
* 🔌 **Hot‑plug aware** — a udev rule (`99-usbip-hotplug.rules`) binds newly inserted devices automatically ([Section 7](#7-server-installation)).
* 🧰 **`usbipctl` helper** — a single CLI for list/bind/unbind/attach/detach/status ([Section 4](#4-repository-layout)).
* 🔐 **Key‑only SSH tunnel** — the client's key is restricted to port forwarding; no shell, no PTY ([Section 8](#8-client-installation), [Section 9](#9-establish-the-ssh-tunnel)).
* 🧱 **Least privilege** — the tunnel runs as the unprivileged system user `usbip-tunnel` (`/sbin/nologin`).
* ♻️ **systemd‑managed** — server, client, tunnel and firewall are separate units ([Section 4](#4-repository-layout)).
* 🚫 **No public USB/IP port** — `usbipd` traffic stays on loopback inside the tunnel ([Section 14](#14-security-notes)).

### 2.1 Known issues

| ID | Issue | Status |
|---|---|---|
| **KI‑1** | On the **client**, `vhci_hcd` may **not detach an imported device automatically** when the server goes offline or when the USB device is no longer exported. The port stays marked as *in use* until it is detached manually. | Open — upstream `vhci_hcd` behaviour; **easily resolved from the console page** |

**KI‑1 — summary.** When the server side disappears abruptly — network loss, `usbipd` stopped, device unbound/unplugged on the server, or the SSH tunnel dropped — the client's `vhci_hcd` can miss the disconnect event and keep the virtual port occupied. The root cause is in **`vhci_hcd`**, not in the bridge, the `usbipctl` helper or the systemd units shipped here.

**Easy solution — detach from the console.** The simplest fix is to open the web console on the **client** and detach the affected device with one click:

1. Open **`http://localhost:8098`** (or **`http://127.0.0.1:8098`**) on the client — see [Section 11](#11-starting-and-using-the-web-console).
2. Find the device still shown as **attached** in the device list.
3. Click **Detach** next to that device.

The port is released immediately and the device can be re‑attached once the server and tunnel are back. No reboot and no kernel module reload is needed.

**Manual fallback (CLI).** If the console is unavailable, detach from a terminal:

```bash
usbip port                 # note the stale port number (00, 01, ...)
sudo usbip detach -p 00    # repeat for each stale port
```

Full procedure and diagnostics: [Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline).

**Symptoms.** `usbip port` shows the port as `Port in Use` after the server is gone; `lsusb` may still list a stale entry; a later `usbip attach` fails until the port is freed; the console shows the device as attached while the tunnel is down.

**Prevention.** Prefer an orderly shutdown on the server (stop the export before taking the host down) and keep the SSH tunnel healthy, so the client sees a clean disconnect. See [Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline).

---

## 3. How it works

1. **Hot‑plug (server).** `udev` matches a new USB device and runs `usbipctl`, which binds the device to the `usbip-host` driver ([Section 7](#7-server-installation)).
2. **Export (server).** `usbip-server.service` keeps `usbipd` running on `TCP 3240`, reachable only on loopback.
3. **Tunnel (client → server).** `usbip-tunnel.service` opens a persistent SSH session as `usbip-tunnel` and forwards loopback port `3240`. The server's `authorized_keys` entry allows **only** port forwarding ([Section 9](#9-establish-the-ssh-tunnel)).
4. **Attach (client).** `usbip-client.service` asks the local `vhci_hcd` driver to attach the remote bus ID via `localhost:3240` ([Section 8](#8-client-installation)).
5. **Observe (both).** `usbip-bridge.service` serves the web console on **port `8098`** plus a JSON API describing device, tunnel and service state ([Section 11](#11-starting-and-using-the-web-console)).

---

## 4. Repository layout

| File | Installed to | Purpose |
|---|---|---|
| `usbip-bridge.py` | `/usr/bin/` | FastAPI application: console backend + JSON API (listens on `:8098`) |
| `index.html` | `/var/lib/usbip-tunnel/static/` | Web console frontend |
| `usbipctl` | `/usr/bin/` | Helper CLI around `usbip` |
| `usbip.conf` | `/etc/usbip/usbip.conf` | Configuration (root‑owned, mode `640`) |
| `usbip-server.service` | `/lib/systemd/system/` | Server: `usbipd` + export handling |
| `usbip-client.service` | `/lib/systemd/system/` | Client: attach remote devices |
| `usbip-bridge.service` | `/lib/systemd/system/` | Web console on `:8098` (both sides) |
| `usbip-tunnel.service` | `/lib/systemd/system/` | SSH tunnel (client). Contains `Environment=SERVER_IP=` |
| `usbip-tunnel-firewall.service` | `/lib/systemd/system/` | Firewall rules required by the tunnel |
| `99-usbip-hotplug.rules` | `/etc/udev/rules.d/` | Server: auto‑bind on hot‑plug |

> All commands below are run **from the root of the cloned repository** unless stated otherwise.

---

## 5. Requirements

* **Ubuntu 22.04 / 24.04** (or a comparable Debian derivative) with `systemd`.
* A kernel that ships the USB/IP modules: `usbip-core`, `usbip-host`, `vhci-hcd`, `usbip-vudc`.
* `linux-tools-common` + `linux-tools-generic` (provides `/usr/bin/usbip` and `usbipd`).
* `python3-fastapi`, `python3-uvicorn`, `python3-pydantic`.
* `openssh-server` on the **server**, `openssh-client` on the **client**.
* Root/sudo on both machines.

> ⚠️ `usbip` uses a versioned protocol. Run `usbip version` on both ends and keep them on the same major version (ideally the same Ubuntu release).

---

## 6. Before you begin

1. **Find the server's LAN IP address** — you will need it twice (tunnel config and `ssh-keyscan`):

   ```bash
   ip -4 -o addr show scope global | awk '{print $2, $4}'
   ```

   Example output: `eth0 192.168.1.10/24` → the server IP is `192.168.1.10`.

2. Make sure the client can reach the server on **TCP 22**:

   ```bash
   nc -zv 192.168.1.10 22
   ```

3. Keep note of these values:

   | Variable | Example | Where used |
   |---|---|---|
   | `SERVER_IP` | `192.168.1.10` | `usbip-tunnel.service`, `ssh-keyscan` ([Section 8.9](#89-set-server_ip-in-the-tunnel-unit--required)) |
   | Console port | `8098` | Web console URL on both hosts ([Section 11](#11-starting-and-using-the-web-console)) |
   | USB/IP port | `3240` | `usbipd` + SSH forward ([Section 9](#9-establish-the-ssh-tunnel)) |
   | `$USER` | your admin user | `dialout` group ([Section 7.3](#73-serialusb-permissions), [Section 8.3](#83-serialusb-permissions)) |

---

## 7. Server installation

### 7.1 Packages

```bash
sudo apt update
sudo apt install -y linux-tools-common linux-tools-generic
sudo apt install -y python3-fastapi python3-uvicorn python3-pydantic
sudo apt install -y openssh-server
```

### 7.2 Load USB/IP modules at boot

```bash
echo "usbip_host" | sudo tee -a /etc/modules
echo "usbip_core" | sudo tee -a /etc/modules
```

Load them now, without rebooting:

```bash
sudo modprobe usbip_core usbip_host
```

### 7.3 Serial/USB permissions

```bash
sudo usermod $USER -a -G dialout
```

> Log out and back in (or reboot) before the group membership takes effect.

### 7.4 Install configuration, CLI and units

```bash
sudo install -d -m 755 -o root -g root /etc/usbip
sudo install -m 640 -o root -g root usbip.conf        /etc/usbip/usbip.conf
sudo install -m 755                  usbipctl          /usr/bin/usbipctl

sudo install -m 644 usbip-server.service       /lib/systemd/system/
sudo install -m 644 usbip-bridge.service       /lib/systemd/system/
sudo install -m 644 99-usbip-hotplug.rules     /etc/udev/rules.d/

sudo install -m 755 usbip-bridge.py            /usr/bin/
```

### 7.5 Install the web frontend and the tunnel user

```bash
sudo mkdir -p /var/lib/usbip-tunnel/static
sudo install -m 644 index.html /var/lib/usbip-tunnel/static/

sudo useradd -r -s /sbin/nologin -d /nonexistent usbip-tunnel

sudo mkdir -p /var/lib/usbip-tunnel/.ssh
sudo chmod 700 /var/lib/usbip-tunnel/.ssh
sudo chown -R usbip-tunnel:usbip-tunnel /var/lib/usbip-tunnel
```

### 7.6 Install the client's public key (after step 8.7)

The file you copy over is the client's `authorized_keys` (containing the client's public key). Once copied to the server ([Section 8.7](#87-copy-the-file-to-the-server-then-remove-the-local-copy)):

```bash
sudo chmod 600 /var/lib/usbip-tunnel/.ssh/authorized_keys
sudo chown usbip-tunnel:usbip-tunnel /var/lib/usbip-tunnel/.ssh/authorized_keys
```

### 7.7 Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable usbip-server.service usbip-bridge.service
sudo systemctl start  usbip-server.service usbip-bridge.service
```

The console is now available on the server at **`http://localhost:8098`** / **`http://127.0.0.1:8098`** ([Section 11](#11-starting-and-using-the-web-console)).

---

## 8. Client installation

### 8.1 Packages

```bash
sudo apt update
sudo apt install -y linux-tools-common linux-tools-generic
sudo apt install -y python3-fastapi python3-uvicorn python3-pydantic
sudo apt install -y openssh-client
```

### 8.2 Load USB/IP modules at boot

The client needs both sides of USB/IP: `vhci_hcd` to attach devices, `usbip-host`/`usbip-vudc` for the virtual device controller.

```bash
echo "usbip_core" | sudo tee -a /etc/modules
echo "usbip_vudc" | sudo tee -a /etc/modules
echo "usbip_host" | sudo tee -a /etc/modules
echo "vhci_hcd"  | sudo tee -a /etc/modules
```

Load them now:

```bash
sudo modprobe usbip_core usbip_vudc usbip_host vhci_hcd
```

### 8.3 Serial/USB permissions

```bash
sudo usermod $USER -a -G dialout
```

### 8.4 Install configuration, CLI and tunnel user

```bash
sudo install -d -m 755 -o root -g root /etc/usbip
sudo install -m 640 -o root -g root usbip.conf /etc/usbip/usbip.conf
sudo install -m 755                  usbipctl   /usr/bin/usbipctl

sudo useradd -r -s /sbin/nologin -d /nonexistent usbip-tunnel

sudo mkdir -p /var/lib/usbip-tunnel/.ssh
sudo chmod 700 /var/lib/usbip-tunnel/.ssh
sudo chown -R usbip-tunnel:usbip-tunnel /var/lib/usbip-tunnel
```

### 8.5 Generate the tunnel key pair

```bash
sudo -u usbip-tunnel ssh-keygen -t ed25519 -N "" \
     -f /var/lib/usbip-tunnel/.ssh/id_ed25519
```

### 8.6 Build the `authorized_keys` file to ship to the server

```bash
echo 'restrict,port-forwarding,permitlisten="localhost:3240"' \
  | tee -a /var/lib/usbip-tunnel/.ssh/authorized_keys
sudo cat /var/lib/usbip-tunnel/.ssh/id_ed25519.pub \
  >> /var/lib/usbip-tunnel/.ssh/authorized_keys
```

> 🔎 **Important:** `sshd` applies options only when they are on the **same line** as the key. The two commands above produce a *separate* options line followed by a plain key, so the restrictions will **not** be enforced. If you want the lock‑down, write it as one line:
>
> ```bash
> sudo sh -c 'echo -n "restrict,port-forwarding,permitlisten=\"localhost:3240\" " \
>   >  /var/lib/usbip-tunnel/.ssh/authorized_keys
>   cat /var/lib/usbip-tunnel/.ssh/id_ed25519.pub \
>   >> /var/lib/usbip-tunnel/.ssh/authorized_keys'
> ```
>
> Verify with `ssh-keygen -l -f /var/lib/usbip-tunnel/.ssh/authorized_keys` — it must print the key fingerprint *and* the options.

### 8.7 Copy the file to the server, then remove the local copy

Copy it with **your** admin account (the tunnel key does not work yet — see the [chicken‑and‑egg note](#chicken-and-egg) in [Section 9](#9-establish-the-ssh-tunnel)):

```bash
scp /var/lib/usbip-tunnel/.ssh/authorized_keys $USER@SERVER_IP:/tmp/authorized_keys
```

On the **server**:

```bash
sudo install -o usbip-tunnel -g usbip-tunnel -m 600 \
     /tmp/authorized_keys /var/lib/usbip-tunnel/.ssh/authorized_keys
shred -u /tmp/authorized_keys
```

Back on the **client**, remove the local copy (it belongs to the server now):

```bash
sudo rm -f /var/lib/usbip-tunnel/.ssh/authorized_keys
```

### 8.8 Pin the server host key

Replace `[server_ip]` with the real server address:

```bash
sudo -u usbip-tunnel ssh-keyscan -H [server_ip] \
  | sudo -u usbip-tunnel tee /var/lib/usbip-tunnel/.ssh/known_hosts
sudo chmod 640 /var/lib/usbip-tunnel/.ssh/known_hosts
```

### 8.9 Set `SERVER_IP` in the tunnel unit — **required**

The tunnel unit ships with a placeholder. Edit it **before** starting anything:

```bash
sudo sed -i 's|^Environment=SERVER_IP=.*|Environment=SERVER_IP=192.168.1.10|' \
     /lib/systemd/system/usbip-tunnel.service
grep SERVER_IP /lib/systemd/system/usbip-tunnel.service   # confirm
```

### 8.10 Install units, frontend and bridge

```bash
sudo install -m 644 usbip-client.service            /lib/systemd/system/
sudo install -m 644 usbip-bridge.service            /lib/systemd/system/
sudo install -m 644 usbip-tunnel.service            /lib/systemd/system/
sudo install -m 644 usbip-tunnel-firewall.service   /lib/systemd/system/

sudo install -m 755 usbip-bridge.py /usr/bin/

sudo mkdir -p /var/lib/usbip-tunnel/static
sudo install -m 644 index.html /var/lib/usbip-tunnel/static/
```

### 8.11 Enable and start

```bash
sudo systemctl daemon-reload

sudo systemctl enable usbip-client.service
sudo systemctl enable usbip-bridge.service
sudo systemctl enable usbip-tunnel.service
sudo systemctl enable usbip-tunnel-firewall.service

sudo systemctl start usbip-tunnel-firewall.service
sudo systemctl start usbip-tunnel.service      # tunnel first: the client needs it
sudo systemctl start usbip-client.service
sudo systemctl start usbip-bridge.service
```

The console is now available on the client at **`http://localhost:8098`** / **`http://127.0.0.1:8098`** ([Section 11](#11-starting-and-using-the-web-console)).

> The tunnel is started before the client on purpose: `usbip-client.service` attaches to `localhost:3240`, which only exists once the tunnel is up.

---

## 9. Establish the SSH tunnel

The tunnel is the only path between the two hosts. Three things must be true:

| # | Requirement | Where to check |
|---|---|---|
| 1 | Client's key is in the server's `authorized_keys` | server: `/var/lib/usbip-tunnel/.ssh/authorized_keys` ([Section 7.6](#76-install-the-clients-public-key-after-step-87)) |
| 2 | Server's host key is in the client's `known_hosts` | client: `/var/lib/usbip-tunnel/.ssh/known_hosts` ([Section 8.8](#88-pin-the-server-host-key)) |
| 3 | `Environment=SERVER_IP=` points at the server | client: `/lib/systemd/system/usbip-tunnel.service` ([Section 8.9](#89-set-server_ip-in-the-tunnel-unit--required)) |

Manual test (do this before debugging the units):

```bash
sudo -u usbip-tunnel ssh -vvv -N usbip-tunnel@SERVER_IP
```

What success looks like: `Authenticated to SERVER_IP ([...]:22)` and the command stays in the foreground. With `restrict` applied you will **not** get a shell — that is expected and correct ([Section 8.6](#86-build-the-authorized_keys-file-to-ship-to-the-server)). Press `Ctrl‑C` to stop it, then start the unit:

```bash
sudo systemctl restart usbip-tunnel.service
sudo systemctl status  usbip-tunnel.service
```

<a id="chicken-and-egg"></a>
> **Chicken‑and‑egg note:** until [Section 8.7](#87-copy-the-file-to-the-server-then-remove-the-local-copy) is done, `usbip-tunnel` cannot log in. Use your normal admin account to copy the file; do **not** try to `scp` as `usbip-tunnel` first.

---

## 10. Verify the installation

Run these in order. Every command should produce a sane, non‑empty answer.

**Server**

```bash
lsmod | grep -E 'usbip|vhci'                 # usbip_core, usbip_host present
usbip version                                # client and server must match
systemctl status usbip-server.service        # active (running)
systemctl status usbip-bridge.service        # active (running)
ss -tlnp | grep -E '3240|8098'               # usbipd + console listening
usbip list -l                                # devices visible locally
sudo usbip list -l | grep -i bound           # devices actually bound
```

**Client**

```bash
lsmod | grep -E 'usbip|vhci'                 # vhci_hcd must be present
systemctl status usbip-tunnel.service        # active (running)
systemctl status usbip-client.service        # active (running)
systemctl status usbip-bridge.service        # active (running)
ss -tlnp | grep -E '3240|8098'               # loopback forward + console
usbip list -r localhost                      # device list fetched THROUGH the tunnel
usbip port                                   # devices attached locally
lsusb                                        # imported device appears here
```

If `usbip list -r localhost` returns the server's exports, the whole chain is working.

---

## 11. Starting and using the web console

The console is served by `usbip-bridge.service` from the FastAPI app in `/usr/bin/usbip-bridge.py` and the static frontend in `/var/lib/usbip-tunnel/static/index.html`. It listens on **port `8098`** on both the server and the client.

### 11.1 Start the console

On **either** host:

```bash
sudo systemctl start usbip-bridge.service
sudo systemctl status usbip-bridge.service --no-pager
```

To start it automatically on every boot:

```bash
sudo systemctl enable usbip-bridge.service
```

### 11.2 Open the console

Point a browser on the **same machine** at either address:

```
http://localhost:8098
http://127.0.0.1:8098
```

Both URLs reach the same instance. Use `localhost` / `127.0.0.1` because the bridge is intended for local/loopback management; exposing port `8098` on a LAN interface is a deliberate firewall decision ([Section 14](#14-security-notes)).

Quick health check without a browser:

```bash
curl -s http://localhost:8098/ | head -20
curl -s http://127.0.0.1:8098/ | head -20
```

### 11.3 Restart / stop the console

```bash
sudo systemctl restart usbip-bridge.service   # after editing index.html or usbip-bridge.py
sudo systemctl stop    usbip-bridge.service   # take the console offline
sudo journalctl -u usbip-bridge.service -b --no-pager   # read its log
```

### 11.4 What the console shows

The console reports:

* USB devices visible on that host and their export/attach state,
* the state of `usbip-server`, `usbip-client`, `usbip-tunnel`, `usbip-tunnel-firewall`,
* tunnel reachability (server console) / attach status (client console).

**Detaching a stuck device.** Because of [KI‑1](#21-known-issues), a client console can show a port as attached while the server/tunnel is already gone. In that case, click **Detach** next to the affected device on the console page — the port is released immediately ([Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline)).

The FastAPI backend also exposes JSON endpoints (interactive docs are normally available at `/docs` if enabled in the app). `curl -s http://localhost:8098/ | head` is the quickest health check.

> The console is an **administrative** interface. Do not expose it to untrusted networks without a firewall rule or an authenticating reverse proxy ([Section 14](#14-security-notes)).

---

## 12. Configuration reference

| Setting | File | Notes |
|---|---|---|
| `SERVER_IP` | `/lib/systemd/system/usbip-tunnel.service` (`Environment=`) | **Must** be edited before starting the tunnel ([Section 8.9](#89-set-server_ip-in-the-tunnel-unit--required)) |
| Console port | `usbip-bridge.py` / `usbip-bridge.service` | `8098` — browsed at `http://localhost:8098` or `http://127.0.0.1:8098` ([Section 11](#11-starting-and-using-the-web-console)) |
| USB/IP port | `usbipd` default | `3240`; forwarded on loopback only ([Section 9](#9-establish-the-ssh-tunnel)) |
| Bridge settings | `/etc/usbip/usbip.conf` (mode `640`, root‑owned) | Read by `usbipctl` / bridge; comments in the file document each key |
| Static frontend | `/var/lib/usbip-tunnel/static/index.html` | Replace to customize the UI |
| Hot‑plug behaviour | `/etc/udev/rules.d/99-usbip-hotplug.rules` | Calls `usbipctl` on device add/remove ([Section 7.4](#74-install-configuration-cli-and-units)) |
| Runtime state | `/var/lib/usbip-tunnel/` | Owned by `usbip-tunnel:usbip-tunnel` |
| Tunnel key | `/var/lib/usbip-tunnel/.ssh/id_ed25519` (client) | Never copy the private key to the server ([Section 8.5](#85-generate-the-tunnel-key-pair)) |

After editing any unit file:

```bash
sudo systemctl daemon-reload
sudo systemctl restart <unit>
```

---

## 13. Debugging & troubleshooting

### 13.1 Work layer by layer

Almost every failure is one of five things. Test them in this order — do not skip ahead.

| Layer | Question | Command |
|---|---|---|
| **L1 Kernel** | Are the modules loaded? | `lsmod \| grep -E 'usbip\|vhci'` ([Section 7.2](#72-load-usbip-modules-at-boot), [Section 8.2](#82-load-usbip-modules-at-boot)) |
| **L2 Daemon** | Is `usbipd` running and reachable? | `ss -tlnp \| grep 3240`, `systemctl status usbip-server` ([Section 13.2](#132-server-side-debugging)) |
| **L3 Export** | Is the device bound? | `usbip list -l`, `usbip list -r localhost` ([Section 13.2](#132-server-side-debugging)) |
| **L4 Tunnel** | Does the SSH session come up? | `systemctl status usbip-tunnel`, manual `ssh -vvv` ([Section 13.4](#134-ssh-tunnel-debugging)) |
| **L5 Attach** | Did the client import it? | `usbip port`, `lsusb`, `dmesg \| tail` ([Section 13.3](#133-client-side-debugging)) |

### 13.2 Server‑side debugging

```bash
# Unit and daemon
sudo systemctl status usbip-server.service --no-pager
sudo journalctl -u usbip-server.service -b --no-pager
sudo ss -tlnp | grep 3240

# Run the daemon in the foreground to see protocol errors
sudo systemctl stop usbip-server.service
sudo usbipd -d

# Device visibility and binding
lsusb
usbip list -l
sudo usbip bind -b 1-1          # bind manually to test
sudo usbip unbind -b 1-1

# udev hot-plug rule
sudo udevadm control --reload-rules
sudo udevadm monitor --udev --subsystem-match=usb
# plug a device in another terminal and watch for your rule firing
sudo udevadm test /sys/bus/usb/devices/1-1 2>&1 | grep -i usbip

# Kernel side
sudo dmesg -T | tail -50
```

**`usbip bind` fails with "device not available"** → the device is already claimed by another driver, or the bus ID is wrong. Check `usbip list -l` for the exact `busid` and `lsusb -t` for the driver.

### 13.3 Client‑side debugging

```bash
sudo systemctl status usbip-client.service --no-pager
sudo journalctl -u usbip-client.service -b --no-pager

# Is the tunnel's loopback listener there?
ss -tlnp | grep 3240

# Through the tunnel
usbip list -r localhost
sudo usbip attach -r localhost -b 1-1
usbip port
lsusb
sudo dmesg -T | tail -30
```

**`vhci_hcd` missing** (`usbip attach` complains or nothing appears in `usbip port`):

```bash
sudo modprobe vhci_hcd
lsmod | grep vhci
```

Then confirm `vhci_hcd` is listed in `/etc/modules` so it survives reboot ([Section 8.2](#82-load-usbip-modules-at-boot)).

### 13.4 SSH tunnel debugging

```bash
sudo systemctl status usbip-tunnel.service --no-pager
sudo journalctl -u usbip-tunnel.service -b --no-pager -n 100

# Permissions — the usual culprit
sudo ls -la /var/lib/usbip-tunnel/.ssh/
# expected: .ssh 700, id_ed25519 600, known_hosts 640, owner usbip-tunnel

# Interactive check
sudo -u usbip-tunnel ssh -vvv -N usbip-tunnel@SERVER_IP

# Non-interactive auth check: expect "Authenticated to ..." even though the
# session is then refused because the key is restricted to port forwarding
sudo -u usbip-tunnel ssh -o BatchMode=yes usbip-tunnel@SERVER_IP true
```

On the **server**:

```bash
sudo journalctl -u ssh --no-pager | tail -50
sudo tail -50 /var/log/auth.log
sudo sshd -T | grep -Ei 'allowtcpforwarding|permitopen|allowusers|gatewayports'
```

| Server‑side cause | Symptom | Fix |
|---|---|---|
| Key not installed / wrong path | `Permission denied (publickey)` | Re‑check [Section 7.6](#76-install-the-clients-public-key-after-step-87) and [Section 8.7](#87-copy-the-file-to-the-server-then-remove-the-local-copy) |
| `AllowTcpForwarding no` in `sshd_config` | `administratively prohibited: open failed` | Set `AllowTcpForwarding yes` (or `local`/`remote` as appropriate), restart `ssh` |
| `AllowUsers` excludes `usbip-tunnel` | `Permission denied` | Add `usbip-tunnel` to `AllowUsers` |
| `permitlisten` too strict | `remote port forwarding failed for listen port 3240` | Make sure the option matches the forward actually used ([Section 8.6](#86-build-the-authorized_keys-file-to-ship-to-the-server)) |
| Host key changed / re‑IP'd | `Host key verification failed` | Re‑run [Section 8.8](#88-pin-the-server-host-key) |

**Known‑hosts fixes** — delete the stale entry then re‑scan:

```bash
sudo -u usbip-tunnel ssh-keygen -R SERVER_IP
sudo -u usbip-tunnel ssh-keyscan -H SERVER_IP \
  | sudo -u usbip-tunnel tee /var/lib/usbip-tunnel/.ssh/known_hosts
sudo chmod 640 /var/lib/usbip-tunnel/.ssh/known_hosts
```

### 13.5 Firewall service

```bash
sudo systemctl status usbip-tunnel-firewall.service --no-pager
sudo journalctl -u usbip-tunnel-firewall.service -b --no-pager
sudo nft list ruleset 2>/dev/null || sudo iptables -S
```

If the firewall unit is down or failed, the tunnel may come up while forwards are silently blocked. Restart it and re‑test with `ss -tlnp | grep 3240` on the client.

<a id="136-stale-vhci_hcd-attach-after-the-server-goes-offline"></a>
### 13.6 Stale `vhci_hcd` attach after the server goes offline

This is the [KI‑1 known issue](#21-known-issues): the client's `vhci_hcd` does not always detach automatically when the server disappears or stops exporting the device.

**Quick fix — detach from the console.** The fastest way to release a stuck port is the web console on the client ([Section 11](#11-starting-and-using-the-web-console)):

1. Open **`http://localhost:8098`** (or **`http://127.0.0.1:8098`**).
2. Locate the device.
3. Click **Detach** next to it.

The port is freed immediately and the device will be attached back automatically. No reboot or module reload is needed.

**Confirm the condition** (optional, for diagnosis):

```bash
# Client: port still "in use" ...
usbip port

# ... while the tunnel / server side is clearly gone
systemctl status usbip-tunnel.service --no-pager
ss -tlnp | grep 3240            # no loopback listener => no tunnel
sudo dmesg -T | tail -30        # vhci_hcd / usbip messages
```

| Observation | Meaning |
|---|---|
| `usbip port` shows `Port in Use`, `ss` shows no `3240` listener | Stale attach ([KI‑1](#21-known-issues)) — use the console **Detach** button, or the CLI below |
| `usbip port` shows `Port in Use`, `3240` listener present, `usbip list -r localhost` works | Tunnel fine; the device was unbound/unplugged on the server — detach and re‑attach |
| `usbip port` empty, device missing from `lsusb` | Not a stale attach; go back to [Section 13.3](#133-client-side-debugging) |

**Fallback — manual detach (CLI).**

```bash
# 1. List and note the stale port number
usbip port

# 2. Detach it explicitly
sudo usbip detach -p 00          # repeat for each stale port

# 3. If detach does not free the port, reset the controller
sudo systemctl stop usbip-client.service
sudo modprobe -r vhci_hcd || sudo rmmod vhci_hcd
sudo modprobe vhci_hcd
lsmod | grep vhci

# 4. Confirm the port table is empty
usbip port

# 5. Bring the client back (tunnel must be up first)
systemctl is-active usbip-tunnel.service || sudo systemctl start usbip-tunnel.service
sudo systemctl start usbip-client.service
usbip port
```

**Prevention / mitigation**

* On the **server**, stop the export before taking it offline: `sudo systemctl stop usbip-server.service` and, if needed, `sudo usbip unbind -b <busid>` ([Section 13.2](#132-server-side-debugging)).
* Keep the **tunnel** healthy — a clean SSH disconnect is more likely to produce a clean USB/IP disconnect than a network drop ([Section 13.4](#134-ssh-tunnel-debugging)).
* Use the **web console** on the client to spot the “attached but tunnel down” mismatch early, then click **Detach** ([Section 11.4](#114-what-the-console-shows)).
* A reboot always clears the state (`sudo reboot`), at the cost of downtime.

> `sudo modprobe -r vhci_hcd` failing with `Module vhci_hcd is in use` is expected while a stale attach still holds it. Stop `usbip-client.service`, detach every listed port, then retry — or reboot.

### 13.7 Web console debugging (port 8098)

```bash
sudo systemctl status usbip-bridge.service --no-pager
sudo journalctl -u usbip-bridge.service -b --no-pager
curl -sv http://localhost:8098/ | head -20        # HTML
curl -sv http://127.0.0.1:8098/ | head -20        # same instance, different name
curl -s  http://localhost:8098/docs | head        # FastAPI docs, if enabled
ss -tlnp | grep 8098                              # is the port actually bound?
```

* **Blank page** → `index.html` missing or wrong mode under `/var/lib/usbip-tunnel/static/` ([Section 7.5](#75-install-the-web-frontend-and-the-tunnel-user)).
* **`curl: (7) Failed to connect`** → `usbip-bridge.service` not running, or bound to a different address/port. Check `ss -tlnp | grep 8098`.
* **`Address already in use`** on start → another process owns `8098`. Find it with `sudo ss -tlnp | grep 8098` and stop it, or change the port in the bridge unit.
* **502 / connection refused** → console port blocked by the host firewall ([Section 14](#14-security-notes)).
* **Console up but data stale** → `usbipctl` failing; run it manually. For a port that stays “attached” after the server is gone, see [Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline).
* **500 errors** → `journalctl -u usbip-bridge.service -n 100` will show the traceback.

### 13.8 Common error messages

| Message | Likely cause | Fix |
|---|---|---|
| `usbip: command not found` | tools not installed, or versioned package missing | `sudo apt install linux-tools-common linux-tools-generic` (on newer kernels also `linux-tools-$(uname -r)`) ([Section 7.1](#71-packages), [Section 8.1](#81-packages)) |
| `libusbip: error: recv op_common` / `connection reset` | `usbipd` down, port blocked, tunnel down, wrong host | Check L2/L4 in [Section 13.1](#131-work-layer-by-layer) |
| `Permission denied (publickey)` | key not installed, `.ssh` perms wrong, wrong user | [Section 7.6](#76-install-the-clients-public-key-after-step-87) / [Section 8.7](#87-copy-the-file-to-the-server-then-remove-the-local-copy); `ls -la /var/lib/usbip-tunnel/.ssh` |
| `Host key verification failed` | stale/absent `known_hosts` | [Section 13.4](#134-ssh-tunnel-debugging) |
| `Address already in use` on `3240` | stale `usbipd` or leftover SSH forward | `sudo ss -tlnp \| grep 3240`, kill the PID |
| `Address already in use` on `8098` | another process owns the console port | `sudo ss -tlnp \| grep 8098`, stop it or change the port |
| `No device of requested type available` | bus ID wrong or device unplugged | `usbip list -r localhost` to refresh |
| `usbip attach` succeeds but no `lsusb` entry | device still bound to old driver, or `vhci_hcd` not loaded | `lsmod \| grep vhci`, `sudo dmesg -T \| tail` ([Section 13.3](#133-client-side-debugging)) |
| `Port in Use` persists after the server is offline | **KI‑1**: `vhci_hcd` did not auto‑detach | Click **Detach** on the console, or see [Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline) |
| `Module vhci_hcd is in use` on `modprobe -r` | stale attach still holds the controller | Detach all ports first ([Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline)) |
| `dialout` group not applied | session started before `usermod` | Log out/in or reboot; verify with `id` ([Section 7.3](#73-serialusb-permissions)) |
| `vhci_hcd` gone after reboot | missing from `/etc/modules` | [Section 8.2](#82-load-usbip-modules-at-boot) |
| Service dead after reboot | unit not enabled | `sudo systemctl is-enabled <unit>` ([Section 7.7](#77-enable-and-start), [Section 8.11](#811-enable-and-start)) |

### 13.9 Manual end‑to‑end test (bypassing the units)

Useful to prove whether the problem is USB/IP or systemd.

**Server**

```bash
sudo modprobe usbip_core usbip_host
sudo usbipd -D
usbip list -l
sudo usbip bind -b 1-1
```

**Client**

```bash
sudo modprobe usbip_core vhci_hcd
usbip list -r localhost                     # via the tunnel
sudo usbip attach -r localhost -b 1-1
usbip port
lsusb
```

Then clean up:

```bash
# client
sudo usbip detach -p 00
# server
sudo usbip unbind -b 1-1
```

### 13.10 Collecting a debug bundle

Paste the output of this block when opening an issue:

```bash
{
  echo "== uname ==";        uname -a
  echo "== usbip ==";        usbip version
  echo "== modules ==";      lsmod | grep -E 'usbip|vhci'
  echo "== listeners ==";    ss -tlnp | grep -E '3240|8098|:22'
  echo "== units ==";        systemctl --no-pager --failed
  echo "== usbip units ==";  systemctl status usbip-* --no-pager -l
  echo "== journals ==";     sudo journalctl -u 'usbip-*' -b --no-pager -n 200
  echo "== usb list ==";     usbip list -l
  echo "== usb ports ==";    usbip port
  echo "== console ==";      curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8098/
  echo "== dmesg ==";        sudo dmesg -T | tail -100
} > /tmp/usbip-debug.txt 2>&1
```

> When reporting [KI‑1](#21-known-issues), also include the output of `usbip port`, `ss -tlnp | grep 3240` and `dmesg | tail` captured **after** the server went offline and **before** running the recovery procedure.

### 13.11 Clean reset

```bash
# Client
sudo systemctl stop usbip-client usbip-tunnel usbip-bridge usbip-tunnel-firewall
sudo usbip port                       # note any stale port, then:
sudo usbip detach -p 00 2>/dev/null
sudo modprobe -r vhci_hcd 2>/dev/null
sudo modprobe vhci_hcd

# Server
sudo systemctl stop usbip-server usbip-bridge
sudo pkill -f usbipd
sudo usbip unbind -b 1-1 2>/dev/null
sudo modprobe -r usbip_host usbip_core
sudo modprobe usbip_core usbip_host

# Bring everything back, tunnel first
sudo systemctl start usbip-server usbip-bridge          # server
sudo systemctl start usbip-tunnel-firewall usbip-tunnel usbip-client usbip-bridge   # client

# Confirm the console answers again
curl -s -o /dev/null -w 'console HTTP %{http_code}\n' http://localhost:8098/
```

---

## 14. Security notes

* **No public USB/IP port.** `usbipd` is reached only through the loopback SSH forward ([Section 9](#9-establish-the-ssh-tunnel)). Do not add a firewall rule opening `3240`.
* **Console on loopback.** The web console listens on **`8098`** and is intended to be reached at `http://localhost:8098` / `http://127.0.0.1:8098` ([Section 11](#11-starting-and-using-the-web-console)). Keep it on loopback; do not expose `8098` to untrusted networks.
* **Key‑only tunnel.** The `usbip-tunnel` account has `/sbin/nologin`, no password, and its `authorized_keys` entry is intended to be limited with `restrict,port-forwarding,permitlisten="localhost:3240"` (see the warning in [Section 8.6](#86-build-the-authorized_keys-file-to-ship-to-the-server) — put the options on the *same line* as the key).
* **Private key never leaves the client.** Only `id_ed25519.pub` (inside `authorized_keys`) is copied to the server ([Section 8.5](#85-generate-the-tunnel-key-pair)).
* **Console exposure.** The web console has no built‑in multi‑user authentication. Keep it on a trusted management network, restrict it with `nft`/`iptables`, or place an authenticating reverse proxy in front of it.
* **Config file mode.** `/etc/usbip/usbip.conf` is installed `640 root:root` ([Section 7.4](#74-install-configuration-cli-and-units)) — keep it that way if it ever contains credentials.
* **Firmware/USB trust.** Any USB device shared this way is usable as if locally plugged in. Only attach devices from servers you control.
* **Stale attach is not a security boundary.** A stale `vhci_hcd` port keeps a device node visible on the client after the server is gone ([Section 13.6](#136-stale-vhci_hcd-attach-after-the-server-goes-offline)). Do not rely on the disappearance of the remote device as an access control; revoke access on the server side (unbind, stop `usbipd`, remove the key).

---

## 15. Uninstall

**Client**

```bash
sudo systemctl disable --now usbip-client usbip-tunnel usbip-bridge usbip-tunnel-firewall
sudo usbip port && sudo usbip detach -p 00 2>/dev/null   # clear stale attaches first
sudo rm -f /lib/systemd/system/usbip-{client,tunnel,bridge,tunnel-firewall}.service \
           /usr/bin/usbip-bridge.py /usr/bin/usbipctl \
           /etc/usbip/usbip.conf
sudo rm -rf /var/lib/usbip-tunnel
sudo userdel usbip-tunnel
sudo systemctl daemon-reload
```

**Server**

```bash
sudo systemctl disable --now usbip-server usbip-bridge
sudo rm -f /lib/systemd/system/usbip-{server,bridge}.service \
           /usr/bin/usbip-bridge.py /usr/bin/usbipctl \
           /etc/usbip/usbip.conf /etc/udev/rules.d/99-usbip-hotplug.rules
sudo rm -rf /var/lib/usbip-tunnel /etc/usbip
sudo userdel usbip-tunnel
sudo udevadm control --reload-rules
sudo systemctl daemon-reload
```

Optionally remove the `usbip_host` / `usbip_core` / `usbip_vudc` / `vhci_hcd` lines from `/etc/modules` ([Section 7.2](#72-load-usbip-modules-at-boot), [Section 8.2](#82-load-usbip-modules-at-boot)).

---

## 16. License

This project is licensed under the **GNU General Public License, version 3.0**.

You are free to use, study, share and modify the software under the terms of the GPL. Any distributed derivative work must also be licensed under the GPL‑3.0 and must make the corresponding source code available.

* SPDX identifier: **`GPL-3.0`**
* Full license text: <https://www.gnu.org/licenses/gpl-3.0.txt>
* License overview: <https://www.gnu.org/licenses/gpl-3.0.html>

Include the license in the repository as `LICENSE` (or `COPYING`), and use the following header in source files:

```text
SPDX-License-Identifier: GPL-3.0
Copyright (C) <year> <author>
```

> USB/IP itself is part of the Linux kernel and the `linux-tools` package; the `vhci_hcd` behaviour described in [KI‑1](#21-known-issues) is subject to the kernel's own licensing and upstream bug tracking.
