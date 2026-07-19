# wifi-connect5.py

An evil-twin-aware WiFi connection manager for Linux. Scans nearby networks,
flags suspicious access points *before* you connect, and remembers trusted
BSSIDs across sessions — while correctly recognizing that a single physical
gateway (tri-band router, mesh CPE) can legitimately broadcast one SSID from
several different BSSIDs at once, and enforcing a hard ceiling on how many
WiFi bands a legitimate device can possibly use.

## Why

Most "evil twin" detectors treat any BSSID with the
[locally-administered bit](https://en.wikipedia.org/wiki/MAC_address#Universal_vs._local)
set as inherently suspicious. In practice this produces constant false
positives: nearly every modern consumer gateway (Comcast XB-series,
mesh systems, dual/tri-band routers) derives a distinct BSSID for each
radio band from one hardware-assigned base MAC by flipping that bit and
incrementing the last octet. A tri-band gateway broadcasting the same SSID
on 2.4 GHz, 5 GHz, and 6 GHz is completely normal — and naive detectors
flag it as three attacking devices.

`wifi-connect5.py` fixes this by recovering each BSSID's underlying
hardware **OUI family** (the vendor-assigned block, before the
locally-administered bit was set) and using that to tell "another radio on
my own router" apart from "an unrelated device impersonating my network."
It also adds a hard physical ceiling: there are only three WiFi bands in
existence, so more than three for one SSID is never legitimate, no matter
what else is or isn't recognized.

## How detection works

| Rule | Trigger | Severity | Notes |
|---|---|---|---|
| Sibling recognition | LA-bit BSSID whose OUI family matches a trusted BSSID | `INFO` | Not blocked — this is normal multi-radio behavior |
| First-visit, LA-bit | LA-bit BSSID, no trust baseline exists yet for this SSID | `HIGH` | Requires typed `yes` to override — uncertain, not confirmed hostile |
| Baseline conflict | LA-bit BSSID that does NOT match any established trusted family | `CRITICAL` | Blocks connection outright — a real anomaly against a known-good reference |
| Near-clone | Two BSSIDs differ by ≤2 octets **and** belong to different hardware families | `HIGH` | Requires typed `yes` to override |
| Multi-family spread | More than one hardware family broadcasting the same SSID across multiple channels with >10 dBm signal spread | `MEDIUM` | Confirm prompt |
| **Band-count ceiling** | **More than 3 distinct WiFi bands (2.4/5/6 GHz) detected for one SSID** | **`CRITICAL`** | **Always blocks, no override — physically impossible for one device** |

Trust is established the first time you successfully connect to a network;
the connected BSSID is saved to a local trust store. Once one radio of a
gateway is trusted, its siblings (same OUI family) are automatically
recognized on future scans — no need to individually approve every band.

**Why first-visit and baseline-conflict are treated differently:** with zero
prior data for a network, the script has no way to distinguish "my own new
router" from "an attacker's rogue AP" — that's genuine uncertainty, so it
asks for confirmation rather than hard-blocking a connection you can never
recover from. Once a baseline exists, though, a BSSID that doesn't match it
is a real detected change, not a guess — that's what triggers the hard block.

**Why the band ceiling is unconditional:** unlike every other rule, this
one isn't a heuristic weighing likelihoods — it's a statement of physical
fact. WiFi only operates in three bands (2.4 GHz, 5 GHz, 6 GHz). A device
broadcasting a 4th, 5th, etc. distinct band under the same SSID cannot be
a single legitimate transmitter, full stop. This rule fires regardless of
trust state, OUI family, or any other signal.

## Example

Every scan shows the exact band count, always:

```
1    TheCatsMeow                             -35.0 (Excellent)   ✅ Trusted (0E:FE:7B:B0:DA:61)
       📶 Bands detected: 3 band(s) — 2.4GHz, 5GHz, 6GHz
```

A genuine tri-band gateway, first visit (no trust yet):

```
2    TheCatsMeow                             -35.0 (Excellent)   ⚠️  SUSPICIOUS AP
       📶 Bands detected: 3 band(s) — 2.4GHz, 5GHz, 6GHz
       ⚠️  BSSID 0E:FE:7B:B0:DA:61 has the Locally Administered bit set and no
          trusted BSSID exists yet for 'TheCatsMeow' (first visit).
```

After connecting once and trusting `0E:FE:7B:B0:DA:61`:

```
📻 BSSID 0E:FE:7B:B7:DA:62 shares its hardware OUI family with a
   trusted BSSID — looks like another radio/band on the same
   gateway, not a separate device.
```

An impossible scenario — automatically blocked regardless of anything else:

```
🚨 4 distinct WiFi bands detected for this SSID (2.4GHz, 5GHz, 6GHz,
   phantom4) — only 3 bands (2.4GHz, 5GHz, 6GHz) physically exist. This
   is impossible for a single legitimate device and means multiple
   transmitters are broadcasting this SSID. Automatically blocked.
```

## Requirements

- Linux with a wireless interface supporting `iw` scanning
- `iw`, `wpa_supplicant`, `dhclient`
- Root privileges (needed for interface control, scanning, and DHCP)

## Usage

```bash
sudo python3 wifi-connect5.py
```

You'll be shown a numbered list of nearby SSIDs with their trust/threat
status and exact band count, prompted to select one, and (if flagged)
walked through an appropriate confirmation before the script writes a
`wpa_supplicant` config, brings the interface up, authenticates, and
requests a DHCP lease.

To disconnect:

```bash
sudo pkill wpa_supplicant && sudo dhclient -r <interface>
```

## Trust store

Trusted BSSIDs are stored per-SSID in:

```
~/.config/wifi-guardian/trusted_bssids.json
```

Each SSID maps to a **list** of trusted BSSIDs (not a single value), since
one gateway can have multiple legitimate radios. File permissions are set
to `0600` on write.

## Limitations

- The CRITICAL baseline-conflict rule currently only examines BSSIDs that
  have the locally-administered bit set. An attacker impersonating a
  trusted SSID from a plain, non-locally-administered MAC (a different
  vendor's real hardware OUI) won't trip that specific rule — it's only
  caught by the weaker multi-family channel-spread heuristic, which needs
  multiple channels and a signal-spread threshold to fire, or by the
  band-count ceiling if it pushes the total past 3. Don't treat the
  absence of a CRITICAL flag as proof of safety on its own.
- OUI-family recognition assumes the standard "flip LA bit, increment last
  octet" derivation pattern used by most consumer gateway chipsets. A
  sophisticated attacker who deliberately clones a MAC into the *same* OUI
  family as your trusted gateway (rather than a visibly different vendor
  block) would not be caught by this alone — treat this as one signal
  among several, not a guarantee.
- Band classification depends on `freq:` being present in `iw scan`
  output; if a driver omits it, that BSSID's band is reported as
  "unknown" and excluded from the band-count check.
- Detection is scan-time and BSSID-based; it does not verify
  cryptographic AP identity (e.g. 802.11w/PMF, WPA3-SAE). For high-assurance
  environments, pair this with certificate-based network authentication
  rather than relying on MAC heuristics alone.
- Only tested against `iwlwifi` and typical consumer mesh/gateway hardware
  patterns; other vendors may derive BSSIDs differently.

## License

MIT
