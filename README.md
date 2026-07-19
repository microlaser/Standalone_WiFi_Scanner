# wifi-connect4.py

An evil-twin-aware WiFi connection manager for Linux. Scans nearby networks,
flags suspicious access points *before* you connect, and remembers trusted
BSSIDs across sessions — while correctly recognizing that a single physical
gateway (tri-band router, mesh CPE) can legitimately broadcast one SSID from
several different BSSIDs at once.

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

`wifi-connect4.py` fixes this by recovering each BSSID's underlying
hardware **OUI family** (the vendor-assigned block, before the
locally-administered bit was set) and using that to tell "another radio on
my own router" apart from "an unrelated device impersonating my network."

## How detection works

| Rule | Trigger | Severity | Notes |
|---|---|---|---|
| Sibling recognition | LA-bit BSSID whose OUI family matches a trusted BSSID | `INFO` | Not blocked — this is normal multi-radio behavior |
| First-visit, LA-bit | LA-bit BSSID, no trust baseline exists yet for this SSID | `HIGH` | Requires typed `yes` to override — uncertain, not confirmed hostile |
| Baseline conflict | LA-bit BSSID that does NOT match any established trusted family | `CRITICAL` | Blocks connection outright — a real anomaly against a known-good reference |
| Near-clone | Two BSSIDs differ by ≤2 octets **and** belong to different hardware families | `HIGH` | Requires typed `yes` to override |
| Multi-family spread | More than one hardware family broadcasting the same SSID across multiple channels with >10 dBm signal spread | `MEDIUM` | Confirm prompt |

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

## Example

A genuine tri-band gateway, first visit (no trust yet):

```
⚠️  BSSID 0E:FE:7B:B0:DA:61 has the Locally Administered bit set and no
    trusted BSSID exists yet for 'TheCatsMeow' (first visit). Software-
    assigned MACs are normal for many consumer routers, but also possible
    on a rogue AP — verify this is really your gateway before proceeding.
⚠️  BSSID 0E:FE:7B:B7:DA:62 has the Locally Administered bit set and no
    trusted BSSID exists yet for 'TheCatsMeow' (first visit).
```

After connecting once and trusting `0E:FE:7B:B0:DA:61`:

```
📻 BSSID 0E:FE:7B:B7:DA:62 shares its hardware OUI family with a
   trusted BSSID — looks like another radio/band on the same
   gateway, not a separate device.
```

A real evil twin appearing after a trust baseline is established:

```
🚨 BSSID AA:BB:CC:11:22:33 has the Locally Administered bit set and does
   NOT match the established family ['0E:FE:7B'] for this SSID. This
   looks like a genuine rogue AP impersonating a known network.
```

## Requirements

- Linux with a wireless interface supporting `iw` scanning
- `iw`, `wpa_supplicant`, `dhclient`
- Root privileges (needed for interface control, scanning, and DHCP)

## Usage

```bash
sudo python3 wifi-connect4.py
```

You'll be shown a numbered list of nearby SSIDs with their trust/threat
status, prompted to select one, and (if flagged) walked through an
appropriate confirmation before the script writes a `wpa_supplicant`
config, brings the interface up, authenticates, and requests a DHCP lease.

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
  multiple channels and a signal-spread threshold to fire. Don't treat
  the absence of a CRITICAL flag as proof of safety on its own.
- OUI-family recognition assumes the standard "flip LA bit, increment last
  octet" derivation pattern used by most consumer gateway chipsets. A
  sophisticated attacker who deliberately clones a MAC into the *same* OUI
  family as your trusted gateway (rather than a visibly different vendor
  block) would not be caught by this alone — treat this as one signal
  among several, not a guarantee.
- Detection is scan-time and BSSID-based; it does not verify
  cryptographic AP identity (e.g. 802.11w/PMF, WPA3-SAE). For high-assurance
  environments, pair this with certificate-based network authentication
  rather than relying on MAC heuristics alone.
- Only tested against `iwlwifi` and typical consumer mesh/gateway hardware
  patterns; other vendors may derive BSSIDs differently.

## License

MIT
