"""
wifi-connect2.py  —  Evil-Twin Aware Edition
=============================================
Three layers of protection over the original:

  1. Trusted-BSSID store  (~/.config/wifi-guardian/trusted_bssids.json)
     First successful connection → BSSID saved as trusted.
     Future scans compare every observed BSSID against it.

  2. Scan-time threat analysis  (three rules, see detect_evil_twins())
     • LA-bit rule   – BSSID with Locally Administered bit AND != trusted → CRITICAL
     • Clone rule    – two BSSIDs differ ≤2 octets, one not trusted → HIGH
     • Channel/signal – multi-channel + >10 dBm spread → MEDIUM

  3. Connection gate
     CRITICAL → blocked outright
     HIGH     → must type "yes" to override
     MEDIUM   → confirm prompt
     Post-connect: verifies connected BSSID matches trusted record.
"""

import os, sys, json, subprocess, time, re, getpass
from collections import defaultdict
from pathlib import Path

CONFIG_FILE    = "/tmp/wpa_supplicant_temp.conf"
TRUST_DIR      = Path.home() / ".config" / "wifi-guardian"
TRUST_FILE     = TRUST_DIR / "trusted_bssids.json"
INTERFACE_NAME = None


# ──────────────────────────────────────────────────────────
# Trusted-BSSID store
# ──────────────────────────────────────────────────────────

def load_trusted() -> dict:
    if TRUST_FILE.exists():
        try:
            return json.loads(TRUST_FILE.read_text())
        except Exception:
            pass
    return {}


def save_trusted(ssid: str, bssid: str) -> None:
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    store = load_trusted()
    store[ssid] = bssid.upper()
    try:
        TRUST_FILE.write_text(json.dumps(store, indent=2))
        TRUST_FILE.chmod(0o600)
    except OSError as e:
        print(f"⚠️  Could not save trust store: {e}")


# ──────────────────────────────────────────────────────────
# MAC helpers
# ──────────────────────────────────────────────────────────

def is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def mac_octet_distance(mac1: str, mac2: str) -> int:
    try:
        return sum(a != b for a, b in zip(mac1.upper().split(":"),
                                          mac2.upper().split(":")))
    except Exception:
        return 6


# ──────────────────────────────────────────────────────────
# Evil-twin detection
# ──────────────────────────────────────────────────────────

def detect_evil_twins(ssid_map: dict, trusted: dict) -> dict:
    """
    Rules
    ─────
    1. LA-bit + NOT trusted BSSID          → CRITICAL
       (Trusted APs may legitimately use LA MACs, e.g. modern mesh/ISP CPE,
        so the trusted BSSID is excluded from this rule.)
    2. Two BSSIDs differ ≤ 2 octets,
       at least one is not the trusted BSSID → HIGH
    3. Multiple channels + signal spread >10 dBm → MEDIUM
    """
    threats = defaultdict(list)

    for ssid, entries in ssid_map.items():
        if not entries:
            continue
        t = trusted.get(ssid, "").upper()

        # Rule 1 – LA bit on untrusted BSSID
        for e in entries:
            if e["la"] and e["bssid"] != t:
                ctx = (f"(trusted BSSID is {t})" if t
                       else "(no trusted BSSID recorded — first visit)")
                threats[ssid].append((
                    "CRITICAL",
                    f"BSSID {e['bssid']} has the Locally Administered bit set "
                    f"{ctx}. Software-assigned MACs on APs indicate spoofing.",
                ))

        # Rule 2 – Near-clone MAC
        if len(entries) > 1:
            for i, a in enumerate(entries):
                for b in entries[i + 1:]:
                    d = mac_octet_distance(a["bssid"], b["bssid"])
                    if 0 < d <= 2 and not (a["bssid"] == t and b["bssid"] == t):
                        threats[ssid].append((
                            "HIGH",
                            f"BSSIDs {a['bssid']} and {b['bssid']} differ by only "
                            f"{d} octet(s) — possible cloned/incremented MAC.",
                        ))

        # Rule 3 – Channel / signal anomaly
        if len(entries) > 1:
            chans = {e["channel"] for e in entries if e["channel"]}
            if len(chans) > 1:
                spread = max(e["signal"] for e in entries) - min(e["signal"] for e in entries)
                if spread > 10:
                    threats[ssid].append((
                        "MEDIUM",
                        f"Multiple BSSIDs on channels "
                        f"{', '.join(str(c) for c in sorted(chans))} "
                        f"with {spread:.0f} dBm signal spread.",
                    ))

    return dict(threats)


# ──────────────────────────────────────────────────────────
# System helpers
# ──────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        print("🚨 Must be run as root (sudo).")
        sys.exit(1)


def run_command(cmd, check_result=True, error_msg=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=check_result, shell=False)
    except subprocess.CalledProcessError as e:
        if check_result:
            print(f"🚨 {error_msg or 'Command failed.'}")
            print(f"   cmd: {' '.join(cmd)}")
            print(f"   err: {e.stderr.strip()}")
            sys.exit(1)
        return e
    except FileNotFoundError:
        print(f"🚨 '{cmd[0]}' not found — install iw/wpa_supplicant/dhclient.")
        sys.exit(1)


def get_wireless_interface() -> str:
    print("Searching for wireless interface…")
    res = run_command(["iw", "dev"])
    for line in res.stdout.split("\n"):
        m = re.search(r"Interface\s+(\S+)", line)
        if m:
            iface = m.group(1)
            print(f"✅ Found: {iface}")
            return iface
    print("🚨 No wireless interface found.")
    sys.exit(1)


# ──────────────────────────────────────────────────────────
# Scan — full per-BSS records
# ──────────────────────────────────────────────────────────

def scan_networks(interface: str):
    print(f"\n🔍 Scanning for networks on {interface}…\n")
    run_command(["ip", "link", "set", interface, "up"], check_result=False)
    time.sleep(1)

    scan = run_command(["iw", interface, "scan"], check_result=False)
    if not scan or scan.returncode != 0:
        print("⚠️  Scan failed — retrying…")
        time.sleep(2)
        scan = run_command(["iw", interface, "scan"], check_result=True,
                           error_msg="Scan failed.")

    ssid_map: dict = defaultdict(list)
    cur_bssid = cur_signal = cur_channel = cur_ssid = None

    def commit():
        nonlocal cur_bssid, cur_signal, cur_channel, cur_ssid
        if cur_bssid and cur_ssid:
            ssid_map[cur_ssid].append({
                "bssid"  : cur_bssid.upper(),
                "signal" : cur_signal if cur_signal is not None else -100.0,
                "channel": cur_channel,
                "la"     : is_locally_administered(cur_bssid),
            })
        cur_bssid = cur_signal = cur_channel = cur_ssid = None

    for raw in scan.stdout.split("\n"):
        line = raw.strip()
        bss_m = re.match(r"BSS\s+([0-9A-Fa-f:]{17})", line)
        if bss_m:
            commit()
            cur_bssid = bss_m.group(1)
            continue
        if line.startswith("SSID:"):
            cur_ssid = line[5:].strip() or None
        sig_m = re.search(r"signal:\s*([-\d.]+)", line)
        if sig_m:
            cur_signal = float(sig_m.group(1))
        ch_m = re.search(r"(?:DS Parameter set: channel|primary channel:)\s*(\d+)", line)
        if ch_m:
            cur_channel = int(ch_m.group(1))
    commit()

    ssid_map = {k: v for k, v in ssid_map.items() if k}
    best = {s: max(e["signal"] for e in es) for s, es in ssid_map.items()}
    return dict(ssid_map), sorted(best.items(), key=lambda x: x[1], reverse=True)


# ──────────────────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────────────────

SEV_ICON  = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "⚡"}
SEV_LABEL = {"CRITICAL": "EVIL TWIN DETECTED", "HIGH": "SUSPICIOUS AP", "MEDIUM": "ANOMALY"}


def _wrap(text: str, width=64) -> list:
    words, line, out = text.split(), [], []
    for w in words:
        if len(" ".join(line + [w])) > width:
            out.append(" ".join(line)); line = [w]
        else:
            line.append(w)
    if line: out.append(" ".join(line))
    return out


def display_networks(sorted_list, ssid_map, threats, trusted):
    print("Available WiFi Networks:")
    print("=" * 72)
    print(f"{'#':<4} {'SSID':<38} {'Signal':>8}   Status")
    print("-" * 72)

    for idx, (ssid, signal) in enumerate(sorted_list, 1):
        strength = ("Excellent" if signal > -50 else "Good" if signal > -60
                    else "Fair" if signal > -70 else "Weak")
        ssid_threats = threats.get(ssid, [])
        t = trusted.get(ssid)

        if ssid_threats:
            worst  = ssid_threats[0][0]
            status = f"{SEV_ICON[worst]} {SEV_LABEL[worst]}"
        elif t:
            status = f"✅ Trusted ({t})"
        else:
            status = "➖ First-time (unverified)"

        print(f"{idx:<4} {ssid:<38} {signal:>6.1f} ({strength:<9})   {status}")
        for sev, desc in ssid_threats:
            for i, chunk in enumerate(_wrap(desc)):
                prefix = f"       {SEV_ICON[sev]} " if i == 0 else "          "
                print(f"{prefix}{chunk}")

    print("=" * 72)
    if threats:
        total = sum(len(v) for v in threats.values())
        print(f"\n{'━'*72}")
        print(f"  ⚠️  {total} indicator(s) across {len(threats)} flagged SSID(s).")
        print(f"  Connecting to a flagged network may expose your credentials.")
        print(f"{'━'*72}\n")


# ──────────────────────────────────────────────────────────
# User interaction
# ──────────────────────────────────────────────────────────

def get_user_selection(sorted_list, threats) -> str:
    while True:
        try:
            choice = input(f"Select network (1-{len(sorted_list)}) or 'q' to quit: ").strip()
            if choice.lower() == "q":
                sys.exit(0)
            n = int(choice)
            if not (1 <= n <= len(sorted_list)):
                print(f"⚠️  Enter 1–{len(sorted_list)}.")
                continue

            ssid         = sorted_list[n - 1][0]
            ssid_threats = threats.get(ssid, [])
            severities   = [t[0] for t in ssid_threats]

            if "CRITICAL" in severities:
                print(f"\n{'!'*62}")
                print(f"  🚨  BLOCKED  —  '{ssid}' is a likely EVIL TWIN.")
                print(f"  Reasons:")
                for _, d in ssid_threats:
                    for chunk in _wrap(d, 56):
                        print(f"    • {chunk}")
                print(f"{'!'*62}\n")
                continue

            if "HIGH" in severities:
                print(f"\n⚠️  '{ssid}' has HIGH-severity indicators:")
                for _, d in ssid_threats:
                    print(f"  • {d}")
                if input("Connect anyway? [yes/N]: ").strip().lower() != "yes":
                    print("Cancelled.\n"); continue

            elif "MEDIUM" in severities:
                print(f"\n⚡ '{ssid}' has minor anomalies:")
                for _, d in ssid_threats:
                    print(f"  • {d}")
                if input("Continue? [Y/n]: ").strip().lower() == "n":
                    print("Cancelled.\n"); continue

            return ssid
        except ValueError:
            print("⚠️  Invalid input.")
        except KeyboardInterrupt:
            print("\nExiting."); sys.exit(0)


def get_password() -> str:
    while True:
        try:
            return getpass.getpass("Enter WiFi password (or press Enter for open): ")
        except KeyboardInterrupt:
            print("\nExiting."); sys.exit(0)


# ──────────────────────────────────────────────────────────
# Config & Connection
# ──────────────────────────────────────────────────────────

def create_config(ssid: str, password: str) -> None:
    print(f"\nGenerating config for '{ssid}'…")
    try:
        if password:
            res = subprocess.run(["wpa_passphrase", ssid, password],
                                 capture_output=True, text=True, check=True)
            cfg = "\n".join(l for l in res.stdout.splitlines()
                            if not l.strip().startswith("#psk=")) + "\n"
        else:
            cfg = f'network={{\n    ssid="{ssid}"\n    key_mgmt=NONE\n}}\n'
        with open(CONFIG_FILE, "w") as f:
            f.write(cfg)
        os.chmod(CONFIG_FILE, 0o600)
        print("✅ Config written.")
    except subprocess.CalledProcessError as e:
        print(f"🚨 wpa_passphrase failed: {e.stderr.strip()}"); sys.exit(1)


def connect_to_network(interface: str, ssid: str, trusted: dict) -> bool:
    print("\n🔧 Stopping old wpa_supplicant…")
    run_command(["pkill", "wpa_supplicant"], check_result=False); time.sleep(1)

    print(f"🔧 Bringing {interface} up…")
    run_command(["ip", "link", "set", interface, "up"], check_result=False); time.sleep(1)

    print(f"🔧 Starting wpa_supplicant for '{ssid}'…")
    run_command(["wpa_supplicant", "-B", "-i", interface,
                 "-c", CONFIG_FILE, "-D", "nl80211"], check_result=False)

    print("⏳ Waiting 10 s for authentication…"); time.sleep(10)

    print("🔧 Requesting DHCP lease…")
    run_command(["dhclient", "-r", interface], check_result=False); time.sleep(1)
    run_command(["dhclient", "-v", interface], check_result=False); time.sleep(2)

    print("\n🔍 Verifying connection…")
    ip_res = run_command(["ip", "addr", "show", "dev", interface])
    ip_m   = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", ip_res.stdout)

    if not ip_m:
        print("\n❌ CONNECTION FAILED — no IP obtained."); return False

    print("\n" + "=" * 50)
    print("✅ CONNECTION SUCCESSFUL!")
    print("=" * 50)
    print(f"SSID:      {ssid}")
    print(f"Interface: {interface}")
    print(f"IP:        {ip_m.group(1)}")
    print("=" * 50)

    iw_res = run_command(["iw", "dev", interface, "link"], check_result=False)
    connected_bssid = None
    if iw_res and iw_res.returncode == 0:
        print("\nConnection Details:\n" + iw_res.stdout)
        bm = re.search(r"Connected to\s+([0-9A-Fa-f:]{17})", iw_res.stdout)
        if bm:
            connected_bssid = bm.group(1).upper()

    if connected_bssid:
        t = trusted.get(ssid, "").upper()
        if t and connected_bssid != t:
            print(f"\n{'!'*54}")
            print(f"  🚨  POST-CONNECT BSSID MISMATCH!")
            print(f"     Expected : {t}")
            print(f"     Got      : {connected_bssid}")
            print(f"  You may be on a rogue AP.  Disconnect immediately:")
            print(f"  pkill wpa_supplicant && dhclient -r {interface}")
            print(f"{'!'*54}")
        elif not t:
            save_trusted(ssid, connected_bssid)
            print(f"\n📌 Saved {connected_bssid} as trusted BSSID for '{ssid}'.")
            print(f"   Subsequent connections will be checked against this value.")
        else:
            print(f"\n✅ BSSID verified — matches trusted record.")

    print("\n🌐 Testing internet…")
    ping = run_command(["ping", "-c", "3", "-W", "5", "8.8.8.8"], check_result=False)
    print("✅ Internet working!\n" if ping and ping.returncode == 0
          else "⚠️  No internet — may need captive portal.\n")
    return True


# ──────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────

def main():
    global INTERFACE_NAME
    check_root()

    print("=" * 60)
    print("WiFi Connection Manager  —  Evil-Twin Aware Edition")
    print("=" * 60)

    INTERFACE_NAME = get_wireless_interface()
    trusted        = load_trusted()
    if trusted:
        print(f"📂 Trust store: {len(trusted)} known SSID(s).")

    ssid_map, sorted_list = scan_networks(INTERFACE_NAME)
    if not sorted_list:
        print("🚨 No networks found."); sys.exit(1)

    threats = detect_evil_twins(ssid_map, trusted)
    display_networks(sorted_list, ssid_map, threats, trusted)

    selected = get_user_selection(sorted_list, threats)
    print(f"\n📡 Selected: {selected}")

    password = get_password()
    create_config(selected, password)
    del password

    success = connect_to_network(INTERFACE_NAME, selected, trusted)
    if success:
        print(f"To disconnect: sudo pkill wpa_supplicant && sudo dhclient -r {INTERFACE_NAME}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
