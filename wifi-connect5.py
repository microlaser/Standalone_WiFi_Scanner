"""
wifi-connect5.py  —  Evil-Twin Aware Edition (OUI-family + band-count aware)
=============================================================================
Four layers of protection over the original, plus OUI-family recognition
and a hard physical-band ceiling to eliminate false positives while still
catching genuinely impossible scenarios:

  1. Trusted-BSSID store  (~/.config/wifi-guardian/trusted_bssids.json)
     First successful connection → BSSID saved as trusted.
     A single SSID can hold MULTIPLE trusted BSSIDs, since one physical
     tri-band gateway (2.4/5/6 GHz) legitimately broadcasts several
     distinct BSSIDs for the same SSID.

  2. Scan-time threat analysis  (see detect_evil_twins())
     • LA-bit / baseline rule – LA-bit BSSID with no established trust
                        baseline yet → HIGH (overridable, since there's no
                        prior data to compare against). LA-bit BSSID that
                        conflicts with an ESTABLISHED baseline → CRITICAL
                        (hard block — this is a real detected anomaly).
                        LA-bit BSSID sharing a trusted OUI family → INFO
                        (recognized sibling radio, not a threat).
     • Clone rule    – two BSSIDs differ ≤2 octets AND come from DIFFERENT
                        hardware families → HIGH
     • Channel/signal – multiple DISTINCT hardware families + multi-channel
                        + >10 dBm spread → MEDIUM
     • Band-count ceiling – more than 3 distinct WiFi bands (2.4/5/6 GHz)
                        detected for one SSID → CRITICAL, always, no
                        exceptions. Only 3 bands physically exist, so this
                        is not a heuristic — it's a hard ceiling.

  3. Connection gate
     CRITICAL → blocked outright, no override
     HIGH     → must type "yes" to override
     MEDIUM   → confirm prompt
     INFO     → informational only, never blocks
     Post-connect: verifies connected BSSID matches trusted record or
     family; auto-extends trust to sibling radios of a known gateway.

  4. Band reporting
     Every scan result shows the exact count and list of WiFi bands
     detected for that SSID, not just when something is flagged.
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
    """Adds bssid to the trusted list for ssid. Stored as a list because a
    single physical gateway can legitimately broadcast the same SSID from
    several radios (2.4/5/6 GHz), each with its own derived BSSID."""
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    store = load_trusted()
    entry = store.get(ssid, [])
    if isinstance(entry, str):  # migrate old single-BSSID format
        entry = [entry]
    bssid = bssid.upper()
    if bssid not in entry:
        entry.append(bssid)
    store[ssid] = entry
    try:
        TRUST_FILE.write_text(json.dumps(store, indent=2))
        TRUST_FILE.chmod(0o600)
    except OSError as e:
        print(f"⚠️  Could not save trust store: {e}")


def trusted_bssids_for(ssid: str, trusted: dict) -> list:
    """Normalizes a trust-store entry (old single-string or new list format)
    into a list of trusted BSSIDs for the given SSID."""
    entry = trusted.get(ssid, [])
    if isinstance(entry, str):
        return [entry.upper()] if entry else []
    return [b.upper() for b in entry]


# ──────────────────────────────────────────────────────────
# MAC helpers
# ──────────────────────────────────────────────────────────

def is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def clear_la_bit(mac: str) -> str:
    """
    Returns the MAC with the Locally Administered bit cleared in its first
    octet. Many multi-radio gateways (tri-band routers, mesh CPE) derive
    each radio's BSSID from one hardware-assigned base MAC by flipping this
    bit and incrementing the last octet — e.g. 0C:FE:7B:B0:DA:61 (hardware
    base) -> 0E:FE:7B:B0:DA:61 (derived radio). Clearing the bit recovers
    the underlying OUI family for comparison.
    """
    try:
        octets = mac.upper().split(":")
        octets[0] = f"{int(octets[0], 16) & ~0x02:02X}"
        return ":".join(octets)
    except Exception:
        return mac.upper()


def oui_family(mac: str) -> str:
    """First 3 octets of the MAC after clearing the LA bit — identifies the
    hardware vendor block a BSSID was derived from, independent of which
    radio/band it represents."""
    cleared = clear_la_bit(mac)
    return ":".join(cleared.split(":")[:3])


def mac_octet_distance(mac1: str, mac2: str) -> int:
    try:
        return sum(a != b for a, b in zip(mac1.upper().split(":"),
                                          mac2.upper().split(":")))
    except Exception:
        return 6


def classify_band(freq) -> str:
    """
    Classifies a frequency (MHz) into one of the three WiFi bands that
    physically exist. There is no fourth band — a legitimate device can
    broadcast on at most 2.4GHz, 5GHz, and 6GHz, so more than 3 distinct
    bands for one SSID is not just suspicious, it's physically impossible
    for a single piece of consumer hardware to justify.
    """
    if freq is None:
        return "unknown"
    try:
        f = float(freq)
    except (TypeError, ValueError):
        return "unknown"
    if 2400 <= f <= 2495:
        return "2.4GHz"
    if 5150 <= f <= 5895:
        return "5GHz"
    if 5925 <= f <= 7125:
        return "6GHz"
    return "unknown"


# ──────────────────────────────────────────────────────────
# Evil-twin detection
# ──────────────────────────────────────────────────────────

def detect_evil_twins(ssid_map: dict, trusted: dict) -> dict:
    """
    Rules
    ─────
    0. Sibling-radio recognition (not a threat, informational only)
       A BSSID with the LA bit set whose OUI family (LA bit cleared)
       matches a trusted BSSID's family is treated as another radio on the
       SAME physical gateway — e.g. a tri-band router broadcasting one SSID
       on 2.4/5/6 GHz from BSSIDs like 0E:FE:7B:B0:DA:61 and
       0E:FE:7B:B7:DA:62, both derived from hardware base 0C:FE:7B:xx:xx:xx.
       These are auto-trusted and reported as INFO, not CRITICAL.

    1. LA-bit + family NOT recognized as trusted → CRITICAL
       (First-visit networks have no trusted family yet, so any LA-bit
        BSSID is flagged until the user establishes trust.)

    2. Two BSSIDs differ ≤ 2 octets AND do NOT share an OUI family with
       any trusted BSSID → HIGH
       (Siblings of a known gateway are expected to differ by 1-2 octets;
        that alone is no longer suspicious once the family is trusted.)

    3. Multiple DISTINCT OUI families present + multi-channel + signal
       spread >10 dBm → MEDIUM
       (A single tri-band gateway spanning 2.4/5/6 GHz is normal and no
        longer flagged by channel spread alone — this rule now only fires
        when more than one hardware family is competing for the SSID.)
    """
    threats = defaultdict(list)

    for ssid, entries in ssid_map.items():
        if not entries:
            continue
        trusted_list = trusted_bssids_for(ssid, trusted)
        trusted_families = {oui_family(b) for b in trusted_list}

        # Rule 0 / 1 – LA bit: recognized sibling vs. genuinely unrecognized
        for e in entries:
            if not e["la"] or e["bssid"] in trusted_list:
                continue
            if trusted_families and oui_family(e["bssid"]) in trusted_families:
                threats[ssid].append((
                    "INFO",
                    f"BSSID {e['bssid']} shares its hardware OUI family with a "
                    f"trusted BSSID — looks like another radio/band on the "
                    f"same gateway, not a separate device.",
                ))
            elif trusted_families:
                # We HAVE a known-good baseline for this SSID and this BSSID
                # doesn't match it or any sibling family — a real detected
                # anomaly against a trusted reference. Hard-block.
                threats[ssid].append((
                    "CRITICAL",
                    f"BSSID {e['bssid']} has the Locally Administered bit set "
                    f"and does NOT match the established family "
                    f"{sorted(trusted_families)} for this SSID. This looks "
                    f"like a genuine rogue AP impersonating a known network.",
                ))
            else:
                # No baseline exists yet — first time this SSID has been
                # seen. We can't distinguish "my own new router" from "an
                # attacker's rogue AP" with zero prior data, so this is
                # uncertain rather than confirmed-hostile. Require explicit
                # override instead of an unrecoverable hard block.
                threats[ssid].append((
                    "HIGH",
                    f"BSSID {e['bssid']} has the Locally Administered bit set "
                    f"and no trusted BSSID exists yet for '{ssid}' (first "
                    f"visit). Software-assigned MACs are normal for many "
                    f"consumer routers, but also possible on a rogue AP — "
                    f"verify this is really your gateway before proceeding.",
                ))

        # Rule 2 – Near-clone MAC, only across DIFFERENT hardware families
        if len(entries) > 1:
            for i, a in enumerate(entries):
                for b in entries[i + 1:]:
                    if a["bssid"] == b["bssid"]:
                        continue
                    same_family = oui_family(a["bssid"]) == oui_family(b["bssid"])
                    if same_family:
                        continue  # expected sibling-radio pattern, not a clone
                    d = mac_octet_distance(a["bssid"], b["bssid"])
                    if 0 < d <= 2:
                        threats[ssid].append((
                            "HIGH",
                            f"BSSIDs {a['bssid']} and {b['bssid']} differ by only "
                            f"{d} octet(s) but come from DIFFERENT hardware "
                            f"families — possible cloned/incremented MAC.",
                        ))

        # Rule 3 – Multiple distinct hardware families sharing this SSID
        if len(entries) > 1:
            families = {oui_family(e["bssid"]) for e in entries}
            if len(families) > 1:
                chans = {e["channel"] for e in entries if e["channel"]}
                if len(chans) > 1:
                    spread = max(e["signal"] for e in entries) - min(e["signal"] for e in entries)
                    if spread > 10:
                        threats[ssid].append((
                            "MEDIUM",
                            f"Multiple DIFFERENT hardware families "
                            f"({len(families)}) broadcasting this SSID across "
                            f"channels {', '.join(str(c) for c in sorted(chans))} "
                            f"with {spread:.0f} dBm signal spread.",
                        ))

        # Rule 4 – Band count ceiling
        # Only 3 WiFi bands exist (2.4GHz, 5GHz, 6GHz). A legitimate device,
        # no matter how many radios it has, cannot broadcast on a 4th band.
        # More than 3 distinct bands for one SSID means more than one
        # physical transmitter is involved — this is blocked automatically,
        # regardless of any other rule's outcome.
        bands = {e["band"] for e in entries if e["band"] != "unknown"}
        band_count = len(bands)
        if band_count > 3:
            threats[ssid].append((
                "CRITICAL",
                f"{band_count} distinct WiFi bands detected for this SSID "
                f"({', '.join(sorted(bands))}) — only 3 bands (2.4GHz, "
                f"5GHz, 6GHz) physically exist. This is impossible for a "
                f"single legitimate device and means multiple transmitters "
                f"are broadcasting this SSID. Automatically blocked.",
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
    cur_bssid = cur_signal = cur_channel = cur_ssid = cur_freq = None

    def commit():
        nonlocal cur_bssid, cur_signal, cur_channel, cur_ssid, cur_freq
        if cur_bssid and cur_ssid:
            ssid_map[cur_ssid].append({
                "bssid"  : cur_bssid.upper(),
                "signal" : cur_signal if cur_signal is not None else -100.0,
                "channel": cur_channel,
                "freq"   : cur_freq,
                "band"   : classify_band(cur_freq),
                "la"     : is_locally_administered(cur_bssid),
            })
        cur_bssid = cur_signal = cur_channel = cur_ssid = cur_freq = None

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
        freq_m = re.search(r"freq:\s*([\d.]+)", line)
        if freq_m:
            cur_freq = float(freq_m.group(1))
    commit()

    ssid_map = {k: v for k, v in ssid_map.items() if k}
    best = {s: max(e["signal"] for e in es) for s, es in ssid_map.items()}
    return dict(ssid_map), sorted(best.items(), key=lambda x: x[1], reverse=True)


# ──────────────────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────────────────

SEV_ICON  = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "⚡", "INFO": "📻"}
SEV_LABEL = {"CRITICAL": "EVIL TWIN DETECTED", "HIGH": "SUSPICIOUS AP",
             "MEDIUM": "ANOMALY", "INFO": "KNOWN GATEWAY (multi-radio)"}
# Only these severities gate/block a connection; INFO is purely descriptive.
BLOCKING_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")


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

    RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}

    for idx, (ssid, signal) in enumerate(sorted_list, 1):
        strength = ("Excellent" if signal > -50 else "Good" if signal > -60
                    else "Fair" if signal > -70 else "Weak")
        ssid_threats = threats.get(ssid, [])
        t = trusted_bssids_for(ssid, trusted)
        blocking = [x for x in ssid_threats if x[0] in BLOCKING_SEVERITIES]

        if blocking:
            worst  = max(blocking, key=lambda x: RANK[x[0]])[0]
            status = f"{SEV_ICON[worst]} {SEV_LABEL[worst]}"
        elif t:
            status = f"✅ Trusted ({', '.join(t)})"
        elif ssid_threats:  # INFO only
            status = f"{SEV_ICON['INFO']} New device, known family"
        else:
            status = "➖ First-time (unverified)"

        print(f"{idx:<4} {ssid:<38} {signal:>6.1f} ({strength:<9})   {status}")

        bands = sorted({e["band"] for e in ssid_map.get(ssid, []) if e["band"] != "unknown"})
        band_note = f"⚠️  {len(bands)} bands" if len(bands) > 3 else f"{len(bands)} band(s)"
        print(f"       📶 Bands detected: {band_note} — {', '.join(bands) if bands else 'unknown'}")

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
            ssid_threats = [x for x in threats.get(ssid, []) if x[0] in BLOCKING_SEVERITIES]
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
        t = trusted_bssids_for(ssid, trusted)
        t_families = {oui_family(b) for b in t}

        if t and connected_bssid in t:
            print(f"\n✅ BSSID verified — matches trusted record.")
        elif t and oui_family(connected_bssid) in t_families:
            save_trusted(ssid, connected_bssid)
            print(f"\n📻 New radio on known gateway family — added "
                  f"{connected_bssid} to trusted list for '{ssid}'.")
        elif t:
            print(f"\n{'!'*54}")
            print(f"  🚨  POST-CONNECT BSSID MISMATCH!")
            print(f"     Expected one of : {', '.join(t)}")
            print(f"     Got             : {connected_bssid}")
            print(f"  Different hardware family too — you may be on a rogue AP.")
            print(f"  Disconnect immediately:")
            print(f"  pkill wpa_supplicant && dhclient -r {interface}")
            print(f"{'!'*54}")
        else:
            save_trusted(ssid, connected_bssid)
            print(f"\n📌 Saved {connected_bssid} as trusted BSSID for '{ssid}'.")
            print(f"   Subsequent connections will be checked against this value.")

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
